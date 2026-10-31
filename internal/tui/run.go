package tui

import (
	"context"
	"errors"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/client"
)

var ErrNotTerminal = errors.New("tui requires an interactive terminal")

// Run owns only the terminal UI. Exiting it never calls core stop, changes a
// persisted desired state, or shuts down the daemon.
func Run(ctx context.Context, socketPath string) error {
	stdin, err := os.Stdin.Stat()
	if err != nil {
		return ErrNotTerminal
	}
	stdout, err := os.Stdout.Stat()
	if err != nil {
		return ErrNotTerminal
	}
	if stdin.Mode()&os.ModeCharDevice == 0 || stdout.Mode()&os.ModeCharDevice == 0 {
		return ErrNotTerminal
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	_, err = tea.NewProgram(NewModel(runCtx, client.New(socketPath)), tea.WithAltScreen()).Run()
	return err
}

var _ API = (*client.Client)(nil)
