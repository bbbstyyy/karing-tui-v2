//go:build linux

package core

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

type ExecConfig struct {
	Executable string
	Args       []string
	Env        []string
	Dir        string
	Stdout     io.Writer
	Stderr     io.Writer
}

type ExecRunner struct {
	config ExecConfig
}

func NewExecRunner(config ExecConfig) (*ExecRunner, error) {
	if config.Executable == "" || !filepath.IsAbs(config.Executable) {
		return nil, errors.New("core executable must be an absolute path")
	}
	if config.Dir != "" && !filepath.IsAbs(config.Dir) {
		return nil, errors.New("core working directory must be an absolute path")
	}
	if config.Stdout == nil {
		config.Stdout = io.Discard
	}
	if config.Stderr == nil {
		config.Stderr = io.Discard
	}
	return &ExecRunner{config: config}, nil
}

func (r *ExecRunner) Start(ctx context.Context) (Process, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}

	info, err := os.Lstat(r.config.Executable)
	if err != nil {
		return nil, fmt.Errorf("inspect core executable: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing symlink core executable %s", r.config.Executable)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("core executable %s is not a regular file", r.config.Executable)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("core executable %s is not executable", r.config.Executable)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("core executable %s is writable by group or others", r.config.Executable)
	}

	cmd := exec.Command(r.config.Executable, r.config.Args...)
	cmd.Dir = r.config.Dir
	cmd.Env = append(os.Environ(), r.config.Env...)
	cmd.Stdout = r.config.Stdout
	cmd.Stderr = r.config.Stderr
	// Normal shutdown is owned by Supervisor, but an abrupt daemon death must
	// not leave the managed core detached from its owner. SIGKILL is
	// intentional here: after parent death there is no supervisor left to
	// escalate a graceful termination timeout.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start core executable: %w", err)
	}
	return &execProcess{cmd: cmd, pid: cmd.Process.Pid}, nil
}

type execProcess struct {
	cmd *exec.Cmd
	pid int
}

func (p *execProcess) PID() int {
	return p.pid
}

func (p *execProcess) Wait() error {
	return p.cmd.Wait()
}

func (p *execProcess) Terminate() error {
	return signalOwnedProcessGroup(p.pid, syscall.SIGTERM)
}

func (p *execProcess) Kill() error {
	return signalOwnedProcessGroup(p.pid, syscall.SIGKILL)
}

func signalOwnedProcessGroup(pid int, signal syscall.Signal) error {
	if pid <= 0 {
		return errors.New("invalid core process pid")
	}
	if err := syscall.Kill(-pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
