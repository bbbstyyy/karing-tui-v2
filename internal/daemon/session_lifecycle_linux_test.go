//go:build linux

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

const managementClientDeathHelperEnv = "KARING_TUI_CLIENT_DEATH_HELPER"

func TestManagementClientProcessDeathDoesNotStopDaemon(t *testing.T) {
	if os.Getenv(managementClientDeathHelperEnv) == "1" {
		runManagementClientDeathHelper(t)
		return
	}

	base := t.TempDir()
	if err := os.Chmod(base, 0o700); err != nil {
		t.Fatal(err)
	}
	paths := runtimepath.Paths{
		Config:   filepath.Join(base, "config"),
		Data:     filepath.Join(base, "data"),
		State:    filepath.Join(base, "state"),
		Cache:    filepath.Join(base, "cache"),
		Runtime:  filepath.Join(base, "runtime"),
		Socket:   filepath.Join(base, "runtime", "daemon.sock"),
		Database: filepath.Join(base, "state", "state.db"),
	}
	t.Setenv(corePathEnv, "")
	t.Setenv(coreControlPortEnv, "")
	t.Setenv(storageKeepConfirmedEnv, "")
	t.Setenv(storageGenerationQuotaEnv, "")

	ctx, cancel := context.WithCancel(context.Background())
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- New(paths).Run(ctx)
	}()
	defer func() {
		cancel()
		select {
		case err := <-serverDone:
			if err != nil {
				t.Errorf("daemon shutdown after client-death test: %v", err)
			}
		case <-time.After(4 * time.Second):
			t.Errorf("daemon did not shut down after client-death test")
		}
	}()

	api := client.New(paths.Socket)
	initial := waitSessionLifecycleStatus(t, api)

	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestManagementClientProcessDeathDoesNotStopDaemon$")
	cmd.Env = append(
		os.Environ(),
		managementClientDeathHelperEnv+"=1",
		"KARING_TUI_CLIENT_DEATH_SOCKET="+paths.Socket,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	scanner := bufio.NewScanner(stdout)
	ready := false
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "READY" {
			ready = true
			break
		}
	}
	if !ready {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("management client helper did not become ready: scan=%v stderr=%s", scanner.Err(), stderr.String())
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	after := waitSessionLifecycleStatus(t, api)
	if after.PID != initial.PID || after.StartedAt != initial.StartedAt {
		t.Fatalf("management client death restarted daemon: before=%+v after=%+v", initial, after)
	}
}

func runManagementClientDeathHelper(t *testing.T) {
	t.Helper()
	socket := os.Getenv("KARING_TUI_CLIENT_DEATH_SOCKET")
	if socket == "" {
		t.Fatal("management client helper socket is empty")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := client.New(socket).Status(ctx); err != nil {
		t.Fatalf("management client helper status: %v", err)
	}
	fmt.Println("READY")
	for {
		time.Sleep(time.Hour)
	}
}

func waitSessionLifecycleStatus(t *testing.T, api *client.Client) apiv1.StatusResponse {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		status, err := api.Status(ctx)
		cancel()
		if err == nil {
			return status
		}
		lastErr = err
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("daemon did not become ready: %v", lastErr)
	return apiv1.StatusResponse{}
}

func TestSystemdUserUnitIsSessionIndependent(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate lifecycle test source")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	unitPath := filepath.Join(root, "packaging", "systemd", "karing-tui-v2.service")
	content, err := os.ReadFile(unitPath)
	if err != nil {
		t.Fatal(err)
	}
	unit := string(content)

	for _, required := range []string{
		"ExecStart=%h/.local/bin/karing-tui daemon run",
		"Restart=on-failure",
		"KillMode=control-group",
		"WantedBy=default.target",
	} {
		if !strings.Contains(unit, required) {
			t.Fatalf("systemd unit is missing %q: %s", required, unit)
		}
	}
	for _, forbidden := range []string{
		"graphical-session.target",
		"PartOf=",
		"BindsTo=",
		"StandardInput=tty",
		"TTYPath=",
	} {
		if strings.Contains(unit, forbidden) {
			t.Fatalf("systemd unit is tied to a terminal/session through %q: %s", forbidden, unit)
		}
	}
}
