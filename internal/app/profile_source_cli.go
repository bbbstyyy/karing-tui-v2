package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

const (
	maxSourceCLIBytes         = 16 << 10
	maxRefreshDiagnosticCodes = 32
)

type profileSourceCLIClient interface {
	PutProfileSource(context.Context, string, apiv1.ProfileSourcePutRequest) (apiv1.ProfileSourceResponse, error)
	RefreshProfileSource(context.Context, string, apiv1.ProfileRefreshRequest) (apiv1.ProfileRefreshResponse, error)
}

type safeRefreshDiagnostic struct {
	Level string `json:"level"`
	Code  string `json:"code"`
}

type safeRefreshSummary struct {
	ProfileID         string                  `json:"profile_id"`
	SourceRevision    uint64                  `json:"source_revision"`
	NotModified       bool                    `json:"not_modified"`
	CurrentSnapshotID *int64                  `json:"current_snapshot_id,omitempty"`
	NodeCount         int                     `json:"node_count"`
	DiagnosticCount   int                     `json:"diagnostic_count"`
	Diagnostics       []safeRefreshDiagnostic `json:"diagnostics"`
}

func runProfileSourceCommand(ctx context.Context, api profileSourceCLIClient, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) < 2 || (args[0] != "put" && args[0] != "refresh") {
		printProfilesUsage(stderr)
		return 2
	}
	profileID := args[1]
	if err := profile.ValidateProfileID(profileID); err != nil {
		fmt.Fprintln(stderr, "invalid profile ID")
		return 2
	}
	switch args[0] {
	case "put":
		fs := flag.NewFlagSet("profiles put", flag.ContinueOnError)
		fs.SetOutput(stderr)
		expected := fs.Uint64("expected-revision", 0, "expected source CAS revision; zero creates a source")
		fromStdin := fs.Bool("stdin", false, "read one complete source spec object from standard input")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		present := map[string]bool{}
		fs.Visit(func(f *flag.Flag) { present[f.Name] = true })
		if len(fs.Args()) != 0 || !present["expected-revision"] || !present["stdin"] || !*fromStdin {
			fmt.Fprintln(stderr, "put requires --expected-revision=N and --stdin (JSON source spec on standard input)")
			return 2
		}
		source, err := readProfileSourceCLIJSON(stdin)
		if err != nil {
			fmt.Fprintf(stderr, "invalid source input: %v\n", err)
			return 2
		}
		requestCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		result, err := api.PutProfileSource(requestCtx, profileID, apiv1.ProfileSourcePutRequest{
			ExpectedRevision: *expected, Source: source,
		})
		if err != nil {
			fmt.Fprintf(stderr, "profile source write failed: %s\n", safeSourceCLIError(err))
			return 1
		}
		return printJSON(stdout, stderr, safeProfileSummary{
			ProfileID: result.ProfileID, Revision: result.Revision, Format: result.Source.Format,
			Enabled: result.Source.Enabled, CurrentSnapshotID: result.CurrentSnapshotID,
			LastSuccessAt: result.LastSuccessAt,
		})
	case "refresh":
		fs := flag.NewFlagSet("profiles refresh", flag.ContinueOnError)
		fs.SetOutput(stderr)
		expected := fs.Uint64("expected-revision", 0, "required current source revision")
		allowEmpty := fs.Bool("allow-empty", false, "explicitly allow an empty accepted snapshot")
		if err := fs.Parse(args[2:]); err != nil {
			return 2
		}
		provided := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "expected-revision" {
				provided = true
			}
		})
		if len(fs.Args()) != 0 || !provided || *expected == 0 {
			fmt.Fprintln(stderr, "refresh requires a positive --expected-revision=N")
			return 2
		}
		requestCtx, cancel := context.WithTimeout(ctx, 75*time.Second)
		defer cancel()
		result, err := api.RefreshProfileSource(requestCtx, profileID, apiv1.ProfileRefreshRequest{
			ExpectedSourceRevision: *expected, AllowEmpty: *allowEmpty,
		})
		if err != nil {
			fmt.Fprintf(stderr, "profile refresh failed: %s\n", safeSourceCLIError(err))
			return 1
		}
		safe := safeRefreshSummary{
			ProfileID: result.ProfileID, SourceRevision: result.SourceRevision,
			NotModified: result.NotModified, CurrentSnapshotID: result.CurrentSnapshotID,
			NodeCount: result.NodeCount, DiagnosticCount: len(result.Diagnostics),
			Diagnostics: make([]safeRefreshDiagnostic, 0),
		}
		for _, diagnostic := range result.Diagnostics {
			if len(safe.Diagnostics) >= maxRefreshDiagnosticCodes {
				break
			}
			safe.Diagnostics = append(safe.Diagnostics, safeRefreshDiagnostic{
				Level: safeDiagnosticToken(diagnostic.Level), Code: safeDiagnosticToken(diagnostic.Code),
			})
		}
		return printJSON(stdout, stderr, safe)
	default:
		printProfilesUsage(stderr)
		return 2
	}
}

func readProfileSourceCLIJSON(stdin io.Reader) (apiv1.ProfileSourceSpec, error) {
	if stdin == nil {
		return apiv1.ProfileSourceSpec{}, errors.New("standard input is unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(stdin, maxSourceCLIBytes+1))
	if err != nil {
		return apiv1.ProfileSourceSpec{}, errors.New("cannot read standard input")
	}
	if len(data) > maxSourceCLIBytes {
		return apiv1.ProfileSourceSpec{}, errors.New("source JSON exceeds 16 KiB")
	}
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return apiv1.ProfileSourceSpec{}, errors.New("expected one source JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var source apiv1.ProfileSourceSpec
	if err := decoder.Decode(&source); err != nil {
		return apiv1.ProfileSourceSpec{}, errors.New("malformed source JSON or unknown fields")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return apiv1.ProfileSourceSpec{}, errors.New("source input must contain exactly one JSON object")
	}
	return source, nil
}

func safeSourceCLIError(err error) string {
	if errors.Is(err, context.Canceled) {
		return "request canceled"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	// Never echo errors from fetch/validation: an upstream client or daemon can
	// carry a secret-bearing subscription URL in an otherwise useful error.
	const prefix = "daemon returned "
	if strings.HasPrefix(err.Error(), prefix) {
		rest := strings.TrimPrefix(err.Error(), prefix)
		if len(rest) >= 3 && rest[0] >= '0' && rest[0] <= '9' &&
			rest[1] >= '0' && rest[1] <= '9' && rest[2] >= '0' && rest[2] <= '9' {
			return "daemon HTTP " + rest[:3] + " (details suppressed)"
		}
	}
	return "request failed (details suppressed to protect subscription credentials)"
}

func safeDiagnosticToken(value string) string {
	if len(value) == 0 || len(value) > 64 {
		return "other"
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z') && !(ch >= 'A' && ch <= 'Z') &&
			!(ch >= '0' && ch <= '9') && ch != '_' && ch != '-' && ch != '.' {
			return "other"
		}
	}
	return value
}

var _ profileSourceCLIClient = (*client.Client)(nil)
