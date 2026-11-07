package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeProfileStageCLI struct {
	calls     int
	profileID string
	request   apiv1.ProfileDeclarationStageRequest
	response  apiv1.ProfileDeclarationStageResponse
	err       error
}

func (f *fakeProfileStageCLI) StageProfileDeclaration(_ context.Context, id string, req apiv1.ProfileDeclarationStageRequest) (apiv1.ProfileDeclarationStageResponse, error) {
	f.calls++
	f.profileID = id
	f.request = req
	return f.response, f.err
}

func runProfileStageTest(api *fakeProfileStageCLI, args []string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runProfileStageCommand(context.Background(), api, args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func validStageFlags() []string {
	return []string{
		"stage", "work", "--snapshot-id=42", "--expected-source-revision=3", "--expected-declaration-revision=7",
		"--candidate-sha256=" + strings.Repeat("a", 64),
		"--runtime-overlay-sha256=" + strings.Repeat("1", 64),
		"--confirm",
	}
}

func TestProfileStageCLIRequiresExplicitAcknowledgement(t *testing.T) {
	good := validStageFlags()
	bad := [][]string{
		{"stage"},
		{"stage", "bad/profile"},
		good[:len(good)-1],
		append(append([]string{}, good...), "extra"),
	}
	for _, removed := range []string{"snapshot-id", "expected-source-revision", "expected-declaration-revision", "candidate-sha256", "runtime-overlay-sha256"} {
		filtered := append([]string{}, good[:2]...)
		for _, flag := range good[2:] {
			if !strings.HasPrefix(flag, "--"+removed+"=") {
				filtered = append(filtered, flag)
			}
		}
		bad = append(bad, filtered)
	}
	for _, changed := range []string{
		"--snapshot-id=0", "--expected-source-revision=0", "--expected-declaration-revision=0",
		"--candidate-sha256=BAD", "--candidate-sha256=" + strings.Repeat("A", 64),
		"--runtime-overlay-sha256=" + strings.Repeat("z", 64), "--confirm=false",
	} {
		modified := append([]string{}, good...)
		key := changed
		if idx := strings.IndexByte(key, '='); idx >= 0 {
			key = key[:idx]
		}
		for i, flag := range modified {
			if flag == key || strings.HasPrefix(flag, key+"=") {
				modified[i] = changed
			}
		}
		bad = append(bad, modified)
	}
	api := &fakeProfileStageCLI{}
	for _, args := range bad {
		code, out, _ := runProfileStageTest(api, args)
		if code != 2 || out != "" {
			t.Fatalf("invalid stage arguments accepted: %q, exit=%d, out=%q", args, code, out)
		}
	}
	if api.calls != 0 {
		t.Fatalf("invalid stage called daemon %d times", api.calls)
	}
}

func TestProfileStageCLIAcknowledgesDigestsAndRedactsErrors(t *testing.T) {
	api := &fakeProfileStageCLI{response: apiv1.ProfileDeclarationStageResponse{
		ProfileID: "work", SnapshotID: 42, SourceRevision: 3, DeclarationRevision: 8,
		DeclarationSHA256: strings.Repeat("a", 64), CoreValidated: false, Applied: false,
	}}
	code, out, stderr := runProfileStageTest(api, validStageFlags())
	if code != 0 || stderr != "" || api.calls != 1 || api.profileID != "work" ||
		api.request.SnapshotID != 42 || api.request.ExpectedSourceRevision != 3 || api.request.ExpectedDeclarationRevision != 7 ||
		api.request.CandidateSHA256 != strings.Repeat("a", 64) ||
		api.request.RuntimeOverlaySHA256 != strings.Repeat("1", 64) ||
		!strings.Contains(out, "\"declaration_revision\": 8") ||
		!strings.Contains(out, "\"core_validated\": false") ||
		!strings.Contains(out, "\"applied\": false") {
		t.Fatalf("stage CLI: code=%d out=%q stderr=%q", code, out, stderr)
	}
	api.err = errors.New("daemon returned 409 Conflict: https://private.example/?token=SUPER_SECRET")
	code, out, stderr = runProfileStageTest(api, validStageFlags())
	if code != 1 || out != "" || strings.Contains(stderr, "SUPER_SECRET") ||
		!strings.Contains(stderr, "HTTP 409") {
		t.Fatalf("stage error leaked credentials: code=%d out=%q stderr=%q", code, out, stderr)
	}
}
