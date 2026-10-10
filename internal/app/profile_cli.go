package app

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type profileCLIClient interface {
	ProfileSources(context.Context) (apiv1.ProfileSourceListResponse, error)
	ProfileNodes(context.Context, string, int, int) (apiv1.ProfileNodeListResponse, error)
	PutProfileNodeOverlay(context.Context, string, string, apiv1.ProfileNodeOverlayPutRequest) (apiv1.ProfileNodeOverlayResponse, error)
}

type safeProfileSummary struct {
	ProfileID         string `json:"profile_id"`
	Revision          uint64 `json:"revision"`
	Format            string `json:"format"`
	Enabled           bool   `json:"enabled"`
	CurrentSnapshotID *int64 `json:"current_snapshot_id,omitempty"`
	LastSuccessAt     string `json:"last_success_at,omitempty"`
}

func runProfiles(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printProfilesUsage(stderr)
		return 2
	}
	if args[0] == "help" || args[0] == "--help" {
		printProfilesUsage(stdout)
		return 0
	}
	paths, err := runtimepath.Resolve()
	if err != nil {
		fmt.Fprintf(stderr, "runtime paths: %v\n", err)
		return 1
	}
	api := client.New(paths.Socket)
	if args[0] == "put" || args[0] == "refresh" {
		return runProfileSourceCommand(context.Background(), api, args, os.Stdin, stdout, stderr)
	}
	if args[0] == "preview" {
		return runProfilePreviewCommand(context.Background(), api, args, stdout, stderr)
	}
	if args[0] == "stage" {
		return runProfileStageCommand(context.Background(), api, args, stdout, stderr)
	}
	return runProfileCommand(context.Background(), api, args, stdout, stderr)
}

func runProfileCommand(ctx context.Context, api profileCLIClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printProfilesUsage(stderr)
		return 2
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("profiles list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		asJSON := fs.Bool("json", false, "emit credential-safe JSON")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		if len(fs.Args()) != 0 {
			printProfilesUsage(stderr)
			return 2
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		response, err := api.ProfileSources(requestCtx)
		if err != nil {
			fmt.Fprintf(stderr, "list profiles: %v\n", err)
			return 1
		}
		items := make([]safeProfileSummary, 0, len(response.Profiles))
		for _, state := range response.Profiles {
			items = append(items, safeProfileSummary{
				ProfileID: state.ProfileID, Revision: state.Revision, Format: state.Source.Format,
				Enabled: state.Source.Enabled, CurrentSnapshotID: state.CurrentSnapshotID,
				LastSuccessAt: state.LastSuccessAt,
			})
		}
		if *asJSON {
			return printJSON(stdout, stderr, items)
		}
		for _, item := range items {
			snapshot := "none"
			if item.CurrentSnapshotID != nil {
				snapshot = strconv.FormatInt(*item.CurrentSnapshotID, 10)
			}
			fmt.Fprintf(stdout, "%s\t%s\tenabled=%t\trevision=%d\tsnapshot=%s\n",
				item.ProfileID, item.Format, item.Enabled, item.Revision, snapshot)
		}
		return 0
	case "nodes":
		if len(args) < 2 {
			printProfilesUsage(stderr)
			return 2
		}
		profileID := args[1]
		fs := flag.NewFlagSet("profiles nodes", flag.ContinueOnError)
		fs.SetOutput(stderr)
		offset := fs.Int("offset", 0, "zero-based source-order offset")
		limit := fs.Int("limit", storage.DefaultProfileNodePageSize, "page size 1..200")
		asJSON := fs.Bool("json", false, "emit credential-safe JSON")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		if len(fs.Args()) != 0 || *offset < 0 || *offset > storage.MaxProfileNodePageOffset ||
			*limit <= 0 || *limit > storage.MaxProfileNodePageSize {
			printProfilesUsage(stderr)
			return 2
		}
		requestCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		page, err := api.ProfileNodes(requestCtx, profileID, *offset, *limit)
		if err != nil {
			fmt.Fprintf(stderr, "list profile nodes: %v\n", err)
			return 1
		}
		if *asJSON {
			return printJSON(stdout, stderr, page)
		}
		snapshot := "none"
		if page.SnapshotID != nil {
			snapshot = strconv.FormatInt(*page.SnapshotID, 10)
		}
		fmt.Fprintf(stdout, "profile=%s snapshot=%s total=%d offset=%d limit=%d\n",
			page.ProfileID, snapshot, page.Total, page.Offset, page.Limit)
		for _, node := range page.Nodes {
			fmt.Fprintf(stdout, "%s\t%s\tdisabled=%t\tfavorite=%t\trevision=%d\n",
				node.NodeID, node.DisplayName, node.Disabled, node.Favorite, node.OverlayRevision)
		}
		return 0
	case "replace-overlay":
		if len(args) < 3 {
			printProfilesUsage(stderr)
			return 2
		}
		profileID, nodeID := args[1], args[2]
		fs := flag.NewFlagSet("profiles replace-overlay", flag.ContinueOnError)
		fs.SetOutput(stderr)
		revision := fs.Uint64("expected-revision", 0, "required overlay CAS revision; zero for new overlay")
		disabled := fs.Bool("disabled", false, "complete replacement disabled value")
		favorite := fs.Bool("favorite", false, "complete replacement favorite value")
		alias := fs.String("alias", "", "complete replacement alias value, can be empty")
		rank := fs.String("sort-rank", "", "required: non-negative integer or none")
		if err := fs.Parse(args[3:]); err != nil {
			return 2
		}
		visited := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
		if len(fs.Args()) != 0 || !visited["expected-revision"] ||
			!visited["disabled"] || !visited["favorite"] || !visited["alias"] || !visited["sort-rank"] {
			fmt.Fprintln(stderr, "replace-overlay requires all state flags and --expected-revision (full replacement)")
			return 2
		}
		var sortRank *int64
		if *rank != "none" {
			value, err := strconv.ParseInt(*rank, 10, 64)
			if err != nil || value < 0 {
				fmt.Fprintln(stderr, "sort-rank must be a non-negative integer or none")
				return 2
			}
			sortRank = &value
		}
		request := apiv1.ProfileNodeOverlayPutRequest{
			ExpectedRevision: *revision,
			Overlay:          apiv1.ProfileNodeOverlaySpec{Disabled: *disabled, Favorite: *favorite, Alias: *alias, SortRank: sortRank},
		}
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		response, err := api.PutProfileNodeOverlay(requestCtx, profileID, nodeID, request)
		if err != nil {
			fmt.Fprintf(stderr, "replace node overlay: %v\n", err)
			return 1
		}
		return printJSON(stdout, stderr, response)
	default:
		fmt.Fprintf(stderr, "unknown profiles command %q\n", args[0])
		printProfilesUsage(stderr)
		return 2
	}
}

func printProfilesUsage(w io.Writer) {
	fmt.Fprintln(w, `usage:
  karing-tui profiles list [--json]
  karing-tui profiles nodes <profile-id> [--offset=N] [--limit=N] [--json]
  karing-tui profiles replace-overlay <profile-id> <node-id> --expected-revision=N --disabled=true|false --favorite=true|false --alias=NAME --sort-rank=N|none
  karing-tui profiles put <profile-id> --expected-revision=N --stdin
  karing-tui profiles refresh <profile-id> --expected-revision=N [--allow-empty]
  karing-tui profiles preview <profile-id> --snapshot-id=N --expected-declaration-revision=N
  karing-tui profiles stage <profile-id> --snapshot-id=N --expected-source-revision=N --expected-declaration-revision=N --candidate-sha256=HASH --runtime-overlay-sha256=HASH --confirm

Overlay replacement requires every state flag and the known CAS revision so omitted flags cannot silently reset a previous favorite, alias or sort rank.
An overlay change does not update the declaration or apply/restart the core.
Profile lists and node pages exclude source locations, source keys, and proxy credentials.
Profile put consumes one strict, bounded JSON object from stdin; do not place token-bearing URLs in shell arguments.
Refresh accepts and snapshots supported nodes only; it never implicitly applies a core configuration.
Preview verifies a candidate declaration without committing it, core-checking it or changing any applied generation.
Stage requires both preview digests and explicit --confirm. It commits only a declaration revision; it does not check, apply, or restart the core.`)
}

var _ profileCLIClient = (*client.Client)(nil)
