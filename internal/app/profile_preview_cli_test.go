package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeProfilePreviewCLI struct {
	calls     int
	profileID string
	request   apiv1.ProfileDeclarationPreviewRequest
	response  apiv1.ProfileDeclarationPreviewResponse
	err       error
}

func (f *fakeProfilePreviewCLI) PreviewProfileDeclaration(_ context.Context, id string, req apiv1.ProfileDeclarationPreviewRequest) (apiv1.ProfileDeclarationPreviewResponse, error) {
	f.calls++
	f.profileID = id
	f.request = req
	return f.response, f.err
}
func runProfilePreviewTest(api *fakeProfilePreviewCLI, args []string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runProfilePreviewCommand(context.Background(), api, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}
func TestProfilePreviewCLIRequiresExplicitPositiveIDs(t *testing.T) {
	fake := &fakeProfilePreviewCLI{}
	for _, args := range [][]string{
		{"preview", "work"},
		{"preview", "work", "--snapshot-id=1"},
		{"preview", "work", "--expected-declaration-revision=1"},
		{"preview", "work", "--snapshot-id=0", "--expected-declaration-revision=1"},
		{"preview", "work", "--snapshot-id=1", "--expected-declaration-revision=0"},
		{"preview", "work", "--snapshot-id=-1", "--expected-declaration-revision=1"},
		{"preview", "work", "--snapshot-id=1", "--expected-declaration-revision=1", "extra"},
		{"preview"},
	} {
		code, _, _ := runProfilePreviewTest(fake, args)
		if code != 2 {
			t.Fatalf("invalid preview accepted: %v", args)
		}
	}
	if fake.calls != 0 {
		t.Fatalf("invalid preview made RPC: %d", fake.calls)
	}
}
func TestProfilePreviewCLIPropagatesRevisionAndSafeOutput(t *testing.T) {
	fake := &fakeProfilePreviewCLI{response: apiv1.ProfileDeclarationPreviewResponse{
		ProfileID: "work", SnapshotID: 42, BaseDeclarationRevision: 7,
		SnapshotNodeCount: 4, EffectiveNodeCount: 3, AddedNodeCount: 1, RemovedNodeCount: 0,
		CandidateSHA256: strings.Repeat("a", 64), CoreValidated: false, Applied: false,
	}}
	args := []string{"preview", "work", "--snapshot-id=42", "--expected-declaration-revision=7"}
	code, out, stderr := runProfilePreviewTest(fake, args)
	if code != 0 || stderr != "" || fake.calls != 1 || fake.profileID != "work" ||
		fake.request.SnapshotID != 42 || fake.request.ExpectedDeclarationRevision != 7 ||
		!strings.Contains(out, "\"candidate_sha256\"") || !strings.Contains(out, "\"core_validated\": false") ||
		!strings.Contains(out, "\"applied\": false") {
		t.Fatalf("preview CLI output: %d %s %s", code, out, stderr)
	}
	fake.err = errors.New("daemon returned 422 Unprocessable Entity: https://sub?key=SECRET_TOKEN")
	code, out, stderr = runProfilePreviewTest(fake, args)
	if code != 1 || out != "" || strings.Contains(stderr, "SECRET_TOKEN") || !strings.Contains(stderr, "HTTP 422") {
		t.Fatalf("preview error leaked source details: %d %s %s", code, out, stderr)
	}
}
