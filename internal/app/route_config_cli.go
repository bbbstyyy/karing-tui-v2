package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type routeConfigCLIClient interface {
	RouteEditContext(context.Context) (apiv1.RouteEditContext, error)
	PreviewRouteEdit(context.Context, apiv1.RouteEditRequest) (apiv1.RouteEditPreviewResponse, error)
	StageRouteEdit(context.Context, apiv1.RouteEditStageRequest) (apiv1.RouteEditStageResponse, error)
}

func runRouteConfigCommand(ctx context.Context, api routeConfigCLIClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printRouteConfigUsage(stderr)
		return 2
	}
	switch args[0] {
	case "route-preview":
		return runRouteConfigPreview(ctx, api, args[1:], stdout, stderr)
	case "route-stage":
		return runRouteConfigStage(ctx, api, args[1:], stdout, stderr)
	default:
		printRouteConfigUsage(stderr)
		return 2
	}
}

func printRouteConfigUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: karing-tui config route-preview --layer=L --group=ID (--target-kind=K [--profile-id=P --node-id=N|--urltest-group-id=G] | --dns-profile-id=ID | --enabled=true|false) [--out=PRIVATE_NEW_FILE]")
	fmt.Fprintln(w, "       karing-tui config route-stage --receipt=PRIVATE_FILE --confirm")
	fmt.Fprintln(w, "Preview compiles but does not stage/apply; stage commits a new declaration revision ONLY. Never retry an uncertain stage response without re-reading context.")
}

func runRouteConfigPreview(ctx context.Context, api routeConfigCLIClient, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config route-preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	layer := fs.String("layer", "", "one of custom, geosite, geoip, acl, final")
	group := fs.String("group", "", "existing group ID, or FINAL")
	targetKind := fs.String("target-kind", "", "target kind when changing the outbound")
	profileID := fs.String("profile-id", "", "specific node profile")
	nodeID := fs.String("node-id", "", "specific node stable ID")
	urlGroupID := fs.String("urltest-group-id", "", "custom URLTest group")
	dnsID := fs.String("dns-profile-id", "", "group DNS profile, or empty string to clear")
	enabled := fs.String("enabled", "", "true or false")
	output := fs.String("out", "", "new 0600 receipt path (must not exist)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if len(fs.Args()) != 0 || !visited["layer"] || !visited["group"] || *group == "" {
		printRouteConfigUsage(stderr)
		return 2
	}
	var patch apiv1.RouteEditRequest
	patch.Layer = domain.RoutingLayer(*layer)
	patch.GroupID = *group
	fields := 0
	if visited["target-kind"] {
		fields++
		target := domain.TargetRef{Kind: domain.TargetKind(*targetKind)}
		if visited["profile-id"] {
			target.ProfileID = *profileID
		}
		if visited["node-id"] {
			target.NodeID = *nodeID
		}
		if visited["urltest-group-id"] {
			target.GroupID = *urlGroupID
		}
		if err := target.Validate(); err != nil {
			fmt.Fprintln(stderr, "invalid target reference")
			return 2
		}
		patch.Target = &target
	} else if visited["profile-id"] || visited["node-id"] || visited["urltest-group-id"] {
		fmt.Fprintln(stderr, "node/URLTest IDs require --target-kind")
		return 2
	}
	if visited["dns-profile-id"] {
		fields++
		id := *dnsID
		patch.DNSProfileID = &id
	}
	if visited["enabled"] {
		fields++
		if *enabled != "true" && *enabled != "false" {
			fmt.Fprintln(stderr, "--enabled must be true or false")
			return 2
		}
		b := *enabled == "true"
		patch.Enabled = &b
	}
	if fields != 1 {
		fmt.Fprintln(stderr, "exactly one of --target-kind, --dns-profile-id or --enabled is required")
		return 2
	}
	switch patch.Layer {
	case domain.LayerCustom, domain.LayerGeoSite, domain.LayerGeoIP, domain.LayerACL, domain.LayerFinal:
	default:
		fmt.Fprintln(stderr, "unsupported routing layer")
		return 2
	}
	if patch.Layer == domain.LayerFinal && (patch.GroupID != "FINAL" || patch.Target == nil) {
		fmt.Fprintln(stderr, "FINAL permits target changes only")
		return 2
	}
	if visited["out"] && *output == "" {
		fmt.Fprintln(stderr, "--out path is empty")
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	binding, err := api.RouteEditContext(bounded)
	if err != nil {
		fmt.Fprintf(stderr, "route edit context unavailable: %s\n", safeSourceCLIError(err))
		return 1
	}
	if binding.DeclarationRevision == 0 || !validStageSHA256(binding.DeclarationSHA256) ||
		(binding.AppliedGenerationID != nil && *binding.AppliedGenerationID <= 0) {
		fmt.Fprintln(stderr, "route edit context invalid; no preview sent")
		return 1
	}
	patch.ExpectedDeclarationRevision = binding.DeclarationRevision
	patch.ExpectedDeclarationSHA256 = binding.DeclarationSHA256
	patch.ExpectedConfigRevision = binding.ConfigRevision
	patch.ExpectedGenerationID = binding.AppliedGenerationID
	patch.ExpectedSelectionRevision = binding.SelectionRevision
	result, err := api.PreviewRouteEdit(bounded, patch)
	if err != nil {
		fmt.Fprintf(stderr, "route edit preview rejected: %s\n", safeSourceCLIError(err))
		return 1
	}
	if result.Request.ExpectedDeclarationRevision != patch.ExpectedDeclarationRevision ||
		result.CandidateSHA256 == "" || !validStageSHA256(result.CandidateSHA256) ||
		!validStageSHA256(result.NativeConfigSHA256) ||
		!result.CompilerValidated || result.Staged || result.Applied || result.CoreValidated {
		fmt.Fprintln(stderr, "inconsistent route edit preview (discarded)")
		return 1
	}
	if !visited["out"] {
		return printJSON(stdout, stderr, result)
	}
	if err := writeNewPrivateReceipt(*output, result); err != nil {
		fmt.Fprintln(stderr, "cannot create private preview receipt (no existing file overwritten)")
		return 1
	}
	fmt.Fprintln(stdout, "route edit receipt saved with private permissions; run config route-stage --receipt=PATH --confirm")
	return 0
}

func writeNewPrivateReceipt(path string, receipt apiv1.RouteEditPreviewResponse) error {
	// O_EXCL prevents following a pre-existing symlink and overwriting an
	// existing receipt. The operator controls the directory.
	if path == "" || filepath.Base(path) == "." {
		return errors.New("invalid path")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(receipt); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := f.Sync(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func runRouteConfigStage(ctx context.Context, api routeConfigCLIClient, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config route-stage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("receipt", "", "private JSON file from route-preview")
	confirm := fs.Bool("confirm", false, "explicitly commit candidate declaration without applying core")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if len(fs.Args()) != 0 || !visited["receipt"] || *path == "" || !visited["confirm"] || !*confirm {
		printRouteConfigUsage(stderr)
		return 2
	}
	receipt, err := readPrivateRouteReceipt(*path)
	if err != nil {
		fmt.Fprintln(stderr, "cannot read verified private receipt (regular owned 0600 file required)")
		return 2
	}
	if receipt.APIVersion != "v1" || !receipt.CompilerValidated || receipt.CoreValidated ||
		receipt.Staged || receipt.Applied ||
		receipt.Request.ExpectedDeclarationRevision == 0 ||
		!validStageSHA256(receipt.Request.ExpectedDeclarationSHA256) ||
		!validStageSHA256(receipt.CandidateSHA256) ||
		!validStageSHA256(receipt.NativeConfigSHA256) {
		fmt.Fprintln(stderr, "receipt is incomplete or inconsistent")
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	outcome, err := api.StageRouteEdit(bounded, apiv1.RouteEditStageRequest{
		RouteEditRequest:   receipt.Request,
		CandidateSHA256:    receipt.CandidateSHA256,
		NativeConfigSHA256: receipt.NativeConfigSHA256,
	})
	if err != nil {
		fmt.Fprintf(stderr, "route edit stage result uncertain or rejected: %s; inspect current declaration before any retry\n",
			safeSourceCLIError(err))
		return 1
	}
	if outcome.DeclarationSHA256 != receipt.CandidateSHA256 ||
		outcome.DeclarationRevision != receipt.Request.ExpectedDeclarationRevision+1 ||
		!outcome.Staged || outcome.Applied || outcome.CoreValidated {
		fmt.Fprintln(stderr, "route edit stage returned inconsistent result; inspect daemon state")
		return 1
	}
	return printJSON(stdout, stderr, outcome)
}

func readPrivateRouteReceipt(path string) (apiv1.RouteEditPreviewResponse, error) {
	// Open without following symlinks, then inspect the actual inode rather
	// than checking a pathname before opening it (TOCTOU).
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return apiv1.RouteEditPreviewResponse{}, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	stat, err := f.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0o077 != 0 || stat.Size() > 16<<10 {
		return apiv1.RouteEditPreviewResponse{}, errors.New("unsafe file")
	}
	if u, ok := stat.Sys().(*syscall.Stat_t); !ok || u.Uid != uint32(os.Geteuid()) {
		return apiv1.RouteEditPreviewResponse{}, errors.New("receipt owner mismatch")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 16<<10+1))
	decoder.DisallowUnknownFields()
	var receipt apiv1.RouteEditPreviewResponse
	if err := decoder.Decode(&receipt); err != nil {
		return apiv1.RouteEditPreviewResponse{}, err
	}
	var more any
	if err := decoder.Decode(&more); !errors.Is(err, io.EOF) {
		return apiv1.RouteEditPreviewResponse{}, errors.New("receipt has trailing data")
	}
	return receipt, nil
}

var _ routeConfigCLIClient = (*client.Client)(nil)
