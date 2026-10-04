package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/daemon"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/version"
)

func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "daemon":
		return runDaemon(args[1:], stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "capabilities":
		return runCapabilities(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintf(stdout, "karing-tui-v2 %s (%s, %s)\n", version.Version, version.Commit, version.Date)
		return 0
	case "help", "-h", "--help":
		printUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

func runDaemon(args []string, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "run" {
		fmt.Fprintln(stderr, "usage: karing-tui daemon run")
		return 2
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintf(stderr, "runtime paths: %v\n", err)
		return 1
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := daemon.New(paths).Run(ctx); err != nil {
		if errors.Is(err, daemon.ErrAlreadyRunning) {
			fmt.Fprintln(stderr, "daemon is already running")
		} else {
			fmt.Fprintf(stderr, "daemon failed: %v\n", err)
		}
		return 1
	}
	return 0
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOutput := fs.Bool("json", false, "print machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintf(stderr, "runtime paths: %v\n", err)
		return 1
	}
	status, err := client.New(paths.Socket).Status(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "daemon status unavailable: %v\n", err)
		return 1
	}
	if *jsonOutput {
		return printJSON(stdout, stderr, status)
	}
	fmt.Fprintf(
		stdout,
		"daemon: running\napi: %s\nversion: %s\nrevision: %d\napplied generation: %s\nlast-known-good: %s\nrecovery required: %t\ncore: %s\n",
		status.APIVersion,
		status.DaemonVersion,
		status.ConfigRevision,
		formatGenerationID(status.AppliedGenerationID),
		formatGenerationID(status.LastKnownGoodGenerationID),
		status.RecoveryRequired,
		status.CoreState,
	)
	return 0
}

func runCapabilities(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: karing-tui capabilities")
		return 2
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintf(stderr, "runtime paths: %v\n", err)
		return 1
	}
	caps, err := client.New(paths.Socket).Capabilities(context.Background())
	if err != nil {
		fmt.Fprintf(stderr, "daemon capabilities unavailable: %v\n", err)
		return 1
	}
	return printJSON(stdout, stderr, caps)
}

func printJSON(stdout, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "encode output: %v\n", err)
		return 1
	}
	return 0
}

func formatGenerationID(id *int64) string {
	if id == nil {
		return "none"
	}
	return strconv.FormatInt(*id, 10)
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, `karing-tui-v2 (early development)

Usage:
  karing-tui daemon run       run the management daemon in the foreground
  karing-tui status [--json]  query daemon status over the Unix socket
  karing-tui capabilities     show implemented capability flags
  karing-tui version          show build version

The daemon intentionally requires XDG_RUNTIME_DIR (or the explicit
KARING_TUI_RUNTIME_DIR override) and never creates a shared /tmp socket.`)
}
