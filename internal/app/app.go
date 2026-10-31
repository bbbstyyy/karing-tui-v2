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
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/daemon"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/tui"
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
	case "core":
		return runCore(args[1:], stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "capabilities":
		return runCapabilities(args[1:], stdout, stderr)
	case "storage":
		return runStorage(args[1:], stdout, stderr)
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "profiles":
		return runProfiles(args[1:], stdout, stderr)
	case "tui":
		return runTUI(args[1:], stderr)
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

func runConfig(args []string, stdout, stderr io.Writer) int {
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintln(stderr, "config runtime paths unavailable")
		return 1
	}
	api := client.New(paths.Socket)
	if len(args) > 0 && args[0] == "recovery-audit" {
		return runRecoveryAuditCLI(context.Background(), api, args[1:], stdout, stderr)
	}
	if len(args) > 0 && (args[0] == "apply-preview" || args[0] == "apply") {
		return runCheckedApplyCLI(context.Background(), api, args, stdout, stderr)
	}
	return runRouteConfigCommand(context.Background(), api, args, stdout, stderr)
}

func runTUI(args []string, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: karing-tui tui")
		return 2
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintln(stderr, "tui runtime paths unavailable")
		return 1
	}
	if err := tui.Run(context.Background(), paths.Socket); err != nil {
		if errors.Is(err, tui.ErrNotTerminal) {
			fmt.Fprintln(stderr, "tui requires an interactive terminal")
		} else {
			fmt.Fprintln(stderr, "tui closed with an error (details suppressed)")
		}
		return 1
	}
	return 0
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

func runCore(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "start" && args[0] != "stop") {
		fmt.Fprintln(stderr, "usage: karing-tui core <start|stop>")
		return 2
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintf(stderr, "runtime paths: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	api := client.New(paths.Socket)
	switch args[0] {
	case "start":
		err = api.CoreStart(ctx)
	case "stop":
		err = api.CoreStop(ctx)
	}
	if err != nil {
		fmt.Fprintf(stderr, "core %s failed: %v\n", args[0], err)
		return 1
	}
	fmt.Fprintf(stdout, "core: %s\n", map[string]string{"start": "running", "stop": "stopped"}[args[0]])
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
		"daemon: running\napi: %s\nversion: %s\nrevision: %d\napplied generation: %s\nlast-known-good: %s\nrecovery required: %t\ndesired core: %s\ncore configured: %t\ncore: %s\ncore pid: %d\ncore failures: %d\ncore circuit open: %t\n",
		status.APIVersion,
		status.DaemonVersion,
		status.ConfigRevision,
		formatGenerationID(status.AppliedGenerationID),
		formatGenerationID(status.LastKnownGoodGenerationID),
		status.RecoveryRequired,
		status.CoreDesiredState,
		status.CoreConfigured,
		status.CoreState,
		status.CorePID,
		status.CoreConsecutiveFailures,
		status.CoreCircuitOpen,
	)
	if status.ActiveOperation != "" {
		fmt.Fprintf(stdout, "active operation: %s\n", status.ActiveOperation)
	}
	if status.CoreLastError != "" {
		fmt.Fprintf(stdout, "core error: %s\n", status.CoreLastError)
	}
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

func runStorage(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "retention" && args[0] != "prune") {
		fmt.Fprintln(stderr, "usage: karing-tui storage <retention|prune>")
		return 2
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintf(stderr, "runtime paths: %v\n", err)
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	api := client.New(paths.Socket)
	var report any
	switch args[0] {
	case "retention":
		report, err = api.StorageRetention(ctx)
	case "prune":
		report, err = api.StoragePrune(ctx)
	}
	if err != nil {
		fmt.Fprintf(stderr, "storage %s failed: %v\n", args[0], err)
		return 1
	}
	return printJSON(stdout, stderr, report)
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
  karing-tui tui              open the terminal dashboard with guarded selection
  karing-tui daemon run       run the management daemon in the foreground
  karing-tui core start       start the confirmed applied core generation
  karing-tui core stop        stop the managed core and persist stop intent
  karing-tui status [--json]  query daemon status over the Unix socket
  karing-tui capabilities      show implemented capability flags
  karing-tui storage retention show generation retention policy and usage
  karing-tui storage prune     compact audit and prune old generations
  karing-tui config route-preview --help  read and compile one guarded route/DNS edit
  karing-tui config route-stage --receipt=FILE --confirm  stage previewed edit only
  karing-tui config apply-preview [--out=FILE]  inspect current unapplied declaration
  karing-tui config apply --receipt=FILE --confirm  apply checked receipt (disruptive)
  karing-tui config recovery-audit  read-only historical generation verification (no rollback)
  karing-tui profiles help     list safe profile and node-management commands
  karing-tui version           show build version

The daemon intentionally requires XDG_RUNTIME_DIR (or the explicit
KARING_TUI_RUNTIME_DIR override) and never creates a shared /tmp socket.`)
}
