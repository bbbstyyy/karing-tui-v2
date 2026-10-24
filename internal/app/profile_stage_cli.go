package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

type profileStageCLIClient interface {
	StageProfileDeclaration(context.Context, string, apiv1.ProfileDeclarationStageRequest) (apiv1.ProfileDeclarationStageResponse, error)
}

// Stage is intentionally distinct from preview and from applying the core.
// The operator must explicitly acknowledge the two digests printed by preview.
func runProfileStageCommand(ctx context.Context, api profileStageCLIClient, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "stage" {
		printProfilesUsage(stderr)
		return 2
	}
	profileID := args[1]
	if err := profile.ValidateProfileID(profileID); err != nil {
		fmt.Fprintln(stderr, "invalid profile ID")
		return 2
	}
	fs := flag.NewFlagSet("profiles stage", flag.ContinueOnError)
	fs.SetOutput(stderr)
	snapshotID := fs.Int64("snapshot-id", 0, "current accepted snapshot ID from preview")
	expectedSource := fs.Uint64("expected-source-revision", 0, "source revision from preview")
	expected := fs.Uint64("expected-declaration-revision", 0, "base declaration revision from preview")
	candidateHash := fs.String("candidate-sha256", "", "candidate declaration SHA-256 from preview")
	overlayHash := fs.String("runtime-overlay-sha256", "", "runtime overlay SHA-256 from preview")
	confirm := fs.Bool("confirm", false, "explicitly stage declaration; does not apply core")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	visited := make(map[string]bool)
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if len(fs.Args()) != 0 || !visited["snapshot-id"] || !visited["expected-source-revision"] || !visited["expected-declaration-revision"] ||
		!visited["candidate-sha256"] || !visited["runtime-overlay-sha256"] || !visited["confirm"] ||
		*snapshotID <= 0 || *expectedSource == 0 || *expected == 0 || !*confirm ||
		!validStageSHA256(*candidateHash) || !validStageSHA256(*overlayHash) {
		fmt.Fprintln(stderr, "stage requires positive --snapshot-id, --expected-source-revision and --expected-declaration-revision, both 64-character lowercase preview SHA-256 digests, and --confirm")
		return 2
	}
	requestCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
	defer cancel()
	result, err := api.StageProfileDeclaration(requestCtx, profileID, apiv1.ProfileDeclarationStageRequest{
		SnapshotID: *snapshotID, ExpectedSourceRevision: *expectedSource,
		ExpectedDeclarationRevision: *expected,
		CandidateSHA256:             *candidateHash, RuntimeOverlaySHA256: *overlayHash,
	})
	if err != nil {
		fmt.Fprintf(stderr, "profile declaration stage failed: %s\n", safeSourceCLIError(err))
		return 1
	}
	return printJSON(stdout, stderr, result)
}

func validStageSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

var _ profileStageCLIClient = (*client.Client)(nil)
