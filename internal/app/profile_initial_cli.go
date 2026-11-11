package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const initialProxyOnlyRoutingMode = "proxy-only-no-cn"

// Initial source setup is deliberately separate from regular declaration
// preview/stage. It works only before any declaration exists, and it never
// checks, starts, stops or applies the Core.
type profileInitialCLIClient interface {
	PreviewInitialProfileDeclaration(context.Context, string, apiv1.InitialProfileDeclarationPreviewRequest) (apiv1.InitialProfileDeclarationPreviewResponse, error)
	StageInitialProfileDeclaration(context.Context, string, apiv1.InitialProfileDeclarationStageRequest) (apiv1.InitialProfileDeclarationStageResponse, error)
}

func runProfileInitialCommand(ctx context.Context, api profileInitialCLIClient, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || (args[0] != "init-preview" && args[0] != "init-stage") {
		printProfilesUsage(stderr)
		return 2
	}
	id := args[1]
	if profile.ValidateProfileID(id) != nil {
		fmt.Fprintln(stderr, "invalid profile ID")
		return 2
	}
	switch args[0] {
	case "init-preview":
		return runInitialPreviewCLI(ctx, api, id, args[2:], stdout, stderr)
	case "init-stage":
		return runInitialStageCLI(ctx, api, id, args[2:], stdout, stderr)
	default:
		return 2
	}
}

// A DNS resolver must be supplied explicitly, not silently inferred from
// platform defaults or a remote subscription. Require an IP-literal address.
func validateInitialResolver(value string) (string, bool) {
	address, err := netip.ParseAddrPort(value)
	if err != nil || !address.IsValid() || address.Port() == 0 ||
		address.Addr().IsUnspecified() || address.Addr().IsMulticast() ||
		address.Addr().Zone() != "" {
		return "", false
	}
	return address.String(), true
}

func runInitialPreviewCLI(ctx context.Context, api profileInitialCLIClient, id string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("profiles init-preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	snapshot := fs.Int64("snapshot-id", 0, "required accepted snapshot ID")
	node := fs.String("selected-node-id", "", "selected stable node ID from profiles nodes")
	resolver := fs.String("resolver", "", "explicit DNS IP:port (no default)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	canonical, valid := validateInitialResolver(*resolver)
	if len(fs.Args()) != 0 || !flagWasSet(fs, "snapshot-id") || !flagWasSet(fs, "selected-node-id") ||
		!flagWasSet(fs, "resolver") || *snapshot <= 0 ||
		profile.ValidateNodeID(*node) != nil || !valid {
		fmt.Fprintln(stderr, "init-preview requires positive --snapshot-id, valid --selected-node-id and explicit --resolver=IP:port")
		return 2
	}
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := api.PreviewInitialProfileDeclaration(requestCtx, id, apiv1.InitialProfileDeclarationPreviewRequest{
		SnapshotID: *snapshot, SelectedNodeID: *node, ResolverAddress: canonical,
	})
	if err != nil {
		fmt.Fprintf(stderr, "first-run preview rejected: %s\n", safeSourceCLIError(err))
		return 1
	}
	if result.ProfileID != id || result.SnapshotID != *snapshot ||
		result.BaseDeclarationRevision != 0 || result.SourceRevision == 0 ||
		result.EffectiveNodeCount <= 0 || result.SelectedNodeID != *node ||
		result.ResolverAddress != canonical || !validStageSHA256(result.CandidateSHA256) ||
		!validStageSHA256(result.RuntimeOverlaySHA256) ||
		result.RoutingMode != initialProxyOnlyRoutingMode || result.CNRulesReady ||
		result.CoreValidated || result.Applied {
		fmt.Fprintln(stderr, "inconsistent first-run preview; do not stage or apply")
		return 1
	}
	return printJSON(stdout, stderr, result)
}

func runInitialStageCLI(ctx context.Context, api profileInitialCLIClient, id string, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("profiles init-stage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	snapshot := fs.Int64("snapshot-id", 0, "accepted snapshot ID from init-preview")
	source := fs.Uint64("expected-source-revision", 0, "accepted source revision from init-preview")
	node := fs.String("selected-node-id", "", "selected stable node ID from init-preview")
	resolver := fs.String("resolver", "", "exact DNS IP:port from init-preview")
	candidate := fs.String("candidate-sha256", "", "canonical declaration SHA-256 from init-preview")
	overlay := fs.String("runtime-overlay-sha256", "", "runtime overlay SHA-256 from init-preview")
	ack := fs.Bool("acknowledge-proxy-only-no-cn", false, "explicitly accept proxy-only mode WITHOUT CN presets; does not apply the Core")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	canonical, valid := validateInitialResolver(*resolver)
	if len(fs.Args()) != 0 || *snapshot <= 0 || *source == 0 ||
		profile.ValidateNodeID(*node) != nil || !valid ||
		!validStageSHA256(*candidate) || !validStageSHA256(*overlay) ||
		!flagWasSet(fs, "snapshot-id") || !flagWasSet(fs, "expected-source-revision") ||
		!flagWasSet(fs, "selected-node-id") || !flagWasSet(fs, "resolver") ||
		!flagWasSet(fs, "candidate-sha256") || !flagWasSet(fs, "runtime-overlay-sha256") ||
		!flagWasSet(fs, "acknowledge-proxy-only-no-cn") || !*ack {
		fmt.Fprintln(stderr, "init-stage requires exact init-preview snapshot/source/node/DNS/digests and --acknowledge-proxy-only-no-cn; CN rules are NOT available")
		return 2
	}
	requestCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	result, err := api.StageInitialProfileDeclaration(requestCtx, id, apiv1.InitialProfileDeclarationStageRequest{
		SnapshotID: *snapshot, ExpectedSourceRevision: *source,
		SelectedNodeID: *node, ResolverAddress: canonical,
		CandidateSHA256: *candidate, RuntimeOverlaySHA256: *overlay,
		AcknowledgeProxyOnlyNoCN: true,
	})
	if err != nil {
		fmt.Fprintf(stderr, "first-run stage rejected or outcome uncertain: %s; inspect current declaration before further action, NEVER auto-retry\n", safeSourceCLIError(err))
		return 1
	}
	if result.ProfileID != id || result.SnapshotID != *snapshot ||
		result.SourceRevision != *source || result.DeclarationRevision != 1 ||
		result.DeclarationSHA256 != *candidate ||
		result.RoutingMode != initialProxyOnlyRoutingMode || result.CNRulesReady ||
		result.CoreValidated || result.Applied {
		fmt.Fprintln(stderr, "inconsistent first-run stage acknowledgement; inspect current declaration (do not retry)")
		return 1
	}
	return printJSON(stdout, stderr, result)
}

var _ profileInitialCLIClient = (*client.Client)(nil)
