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

type profilePreviewCLIClient interface {
	PreviewProfileDeclaration(context.Context, string, apiv1.ProfileDeclarationPreviewRequest) (apiv1.ProfileDeclarationPreviewResponse, error)
}

func runProfilePreviewCommand(ctx context.Context, api profilePreviewCLIClient, args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "preview" {
		printProfilesUsage(stderr)
		return 2
	}
	profileID := args[1]
	if err := profile.ValidateProfileID(profileID); err != nil {
		fmt.Fprintln(stderr, "invalid profile ID")
		return 2
	}
	fs := flag.NewFlagSet("profiles preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	snapshotID := fs.Int64("snapshot-id", 0, "required current accepted snapshot ID")
	expected := fs.Uint64("expected-declaration-revision", 0, "required current declaration revision")
	if err := fs.Parse(args[2:]); err != nil {
		return 2
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	if len(fs.Args()) != 0 || !visited["snapshot-id"] || !visited["expected-declaration-revision"] ||
		*snapshotID <= 0 || *expected == 0 {
		fmt.Fprintln(stderr, "preview requires positive --snapshot-id=N and --expected-declaration-revision=N")
		return 2
	}
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := api.PreviewProfileDeclaration(requestCtx, profileID, apiv1.ProfileDeclarationPreviewRequest{
		SnapshotID: *snapshotID, ExpectedDeclarationRevision: *expected,
	})
	if err != nil {
		fmt.Fprintf(stderr, "profile declaration preview failed: %s\n", safeSourceCLIError(err))
		return 1
	}
	return printJSON(stdout, stderr, result)
}

var _ profilePreviewCLIClient = (*client.Client)(nil)
