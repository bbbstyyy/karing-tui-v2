//go:build linux

package core

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
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
