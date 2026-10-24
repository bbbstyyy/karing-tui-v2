//go:build linux

package core

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestExecRunnerRejectsRelativeExecutable(t *testing.T) {
	if _, err := NewExecRunner(ExecConfig{Executable: "sing-box"}); err == nil {
		t.Fatal("expected relative executable to be rejected")
	}
}

func TestExecRunnerRejectsWritableExecutable(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "core")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o777); err != nil {
		t.Fatal(err)
	}
	runner, err := NewExecRunner(ExecConfig{Executable: path})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Start(context.Background()); err == nil {
		t.Fatal("expected group/other-writable executable to be rejected")
	}
}

func TestRingBufferKeepsNewestBytes(t *testing.T) {
	buffer := NewRingBuffer(5)
	_, _ = buffer.Write([]byte("abc"))
	_, _ = buffer.Write([]byte("defg"))
	if got := string(buffer.Bytes()); got != "cdefg" {
		t.Fatalf("buffer = %q, want cdefg", got)
	}
	_, _ = buffer.Write([]byte("123456"))
	if got := string(buffer.Bytes()); got != "23456" {
		t.Fatalf("buffer = %q, want 23456", got)
	}
}

func TestRingBufferConcurrentWritersRemainBounded(t *testing.T) {
	const capacity = 4096
	buffer := NewRingBuffer(capacity)

	var wg sync.WaitGroup
	for writer := 0; writer < 16; writer++ {
		wg.Add(1)
		go func(writer int) {
			defer wg.Done()
			payload := []byte("0123456789abcdef")
			for i := 0; i < 1000; i++ {
				if _, err := buffer.Write(payload); err != nil {
					t.Errorf("writer %d: %v", writer, err)
					return
				}
				_ = buffer.Bytes()
			}
		}(writer)
	}
	wg.Wait()

	if got := len(buffer.Bytes()); got > capacity {
		t.Fatalf("buffer length = %d, capacity = %d", got, capacity)
	}
}

func TestExecRunnerLargeOutputDoesNotBlockManagedProcess(t *testing.T) {
	executable := writeExecutableFixture(
		t,
		"#!/bin/sh\n"+
			"dd if=/dev/zero bs=4096 count=512 2>/dev/null\n"+
			"dd if=/dev/zero bs=4096 count=512 1>&2 2>/dev/null\n"+
			"exit 0\n",
	)
	stdout := NewRingBuffer(4096)
	stderr := NewRingBuffer(4096)
	runner, err := NewExecRunner(ExecConfig{
		Executable: executable,
		Stdout:     stdout,
		Stderr:     stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	process, err := runner.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- process.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		_ = process.Kill()
		t.Fatal("large stdout/stderr blocked managed process completion")
	}
	if len(stdout.Bytes()) != 4096 || len(stderr.Bytes()) != 4096 {
		t.Fatalf("bounded log tails = stdout:%d stderr:%d, want 4096 each", len(stdout.Bytes()), len(stderr.Bytes()))
	}
}

func TestExecRunnerKillsManagedChildWhenParentDies(t *testing.T) {
	const (
		parentHelperEnv = "KARING_TUI_EXEC_PARENT_HELPER"
		childHelperEnv  = "KARING_TUI_EXEC_CHILD_HELPER"
	)

	if os.Getenv(childHelperEnv) == "1" {
		for {
			time.Sleep(time.Hour)
		}
	}
	if os.Getenv(parentHelperEnv) == "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		runner, err := NewExecRunner(ExecConfig{
			Executable: executable,
			Args:       []string{"-test.run=^TestExecRunnerKillsManagedChildWhenParentDies$"},
			Env:        []string{childHelperEnv + "=1"},
		})
		if err != nil {
			t.Fatal(err)
		}
		process, err := runner.Start(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		fmt.Printf("CHILD_PID %d\n", process.PID())
		for {
			time.Sleep(time.Hour)
		}
	}

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	parent := exec.Command(executable, "-test.run=^TestExecRunnerKillsManagedChildWhenParentDies$")
	parent.Env = append(os.Environ(), parentHelperEnv+"=1")
	stdout, err := parent.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	parent.Stderr = &stderr
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(stdout)
	childPID := 0
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) != 2 || fields[0] != "CHILD_PID" {
			continue
		}
		childPID, err = strconv.Atoi(fields[1])
		if err != nil {
			t.Fatalf("parse child pid %q: %v", fields[1], err)
		}
		break
	}
	if childPID <= 0 {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatalf("parent helper did not report child pid: scan=%v stderr=%s", scanner.Err(), stderr.String())
	}
	defer syscall.Kill(childPID, syscall.SIGKILL)

	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if processNoLongerRunning(childPID) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("managed child pid %d survived parent death", childPID)
}

func processNoLongerRunning(pid int) bool {
	err := syscall.Kill(pid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true
	}
	if err != nil {
		return false
	}

	content, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	fields := strings.Fields(string(content))
	return len(fields) > 2 && fields[2] == "Z"
}
