package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeProfileInitialCLI struct {
	previewCalls int
	stageCalls   int
	profileID    string
	previewReq   apiv1.InitialProfileDeclarationPreviewRequest
	stageReq     apiv1.InitialProfileDeclarationStageRequest
	preview      apiv1.InitialProfileDeclarationPreviewResponse
	staged       apiv1.InitialProfileDeclarationStageResponse
	err          error
}

func (f *fakeProfileInitialCLI) PreviewInitialProfileDeclaration(
	_ context.Context, id string, request apiv1.InitialProfileDeclarationPreviewRequest,
) (apiv1.InitialProfileDeclarationPreviewResponse, error) {
	f.previewCalls++
	f.profileID, f.previewReq = id, request
	return f.preview, f.err
}
func (f *fakeProfileInitialCLI) StageInitialProfileDeclaration(
	_ context.Context, id string, request apiv1.InitialProfileDeclarationStageRequest,
) (apiv1.InitialProfileDeclarationStageResponse, error) {
	f.stageCalls++
	f.profileID, f.stageReq = id, request
	return f.staged, f.err
}
func runInitialCLITest(fake *fakeProfileInitialCLI, args []string) (int, string, string) {
	var out, errOut bytes.Buffer
	status := runProfileInitialCommand(context.Background(), fake, args, &out, &errOut)
	return status, out.String(), errOut.String()
}

func initialPreviewArgs() []string {
	return []string{
		"init-preview", "work", "--snapshot-id=42",
		"--selected-node-id=node-id", "--resolver=127.0.0.1:5300",
	}
}
func initialStageArgs() []string {
	return []string{
		"init-stage", "work", "--snapshot-id=42",
		"--expected-source-revision=3", "--selected-node-id=node-id",
		"--resolver=127.0.0.1:5300",
		"--candidate-sha256=" + strings.Repeat("a", 64),
		"--runtime-overlay-sha256=" + strings.Repeat("b", 64),
		"--acknowledge-proxy-only-no-cn",
	}
}

func TestFirstRunCLIRejectsIncompleteOrUnsafePreviewWithoutRPC(t *testing.T) {
	good := initialPreviewArgs()
	bad := [][]string{
		nil, {"init-preview"}, {"init-preview", "bad/id"},
		{"init-preview", "work"}, good[:len(good)-1],
		append(append([]string{}, good...), "unexpected"),
	}
	for _, key := range []string{"snapshot-id", "selected-node-id", "resolver"} {
		missing := append([]string{}, good[:2]...)
		for _, f := range good[2:] {
			if !strings.HasPrefix(f, "--"+key+"=") {
				missing = append(missing, f)
			}
		}
		bad = append(bad, missing)
	}
	for _, replacement := range []string{
		"--snapshot-id=0", "--snapshot-id=-1",
		"--selected-node-id=bad/node", "--selected-node-id=",
		"--resolver=example.com:53", "--resolver=0.0.0.0:53",
		"--resolver=224.0.0.1:53", "--resolver=127.0.0.1:0",
		"--resolver=[fe80::1%eth0]:53",
	} {
		modified := append([]string{}, good...)
		key := strings.SplitN(replacement, "=", 2)[0]
		for i, f := range modified {
			if strings.HasPrefix(f, key+"=") {
				modified[i] = replacement
			}
		}
		bad = append(bad, modified)
	}
	api := &fakeProfileInitialCLI{}
	for _, args := range bad {
		code, out, _ := runInitialCLITest(api, args)
		if code != 2 || out != "" {
			t.Fatalf("unsafe initial preview arguments accepted: exit=%d output=%q", code, out)
		}
	}
	if api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatalf("invalid preview sent RPC preview=%d stage=%d", api.previewCalls, api.stageCalls)
	}
}

func TestFirstRunCLIRequiresExplicitProxyOnlyAcknowledgement(t *testing.T) {
	good := initialStageArgs()
	bad := [][]string{good[:len(good)-1], append(append([]string{}, good...), "unexpected")}
	for _, key := range []string{
		"snapshot-id", "expected-source-revision", "selected-node-id",
		"resolver", "candidate-sha256", "runtime-overlay-sha256",
	} {
		missing := append([]string{}, good[:2]...)
		for _, f := range good[2:] {
			if !strings.HasPrefix(f, "--"+key+"=") {
				missing = append(missing, f)
			}
		}
		bad = append(bad, missing)
	}
	for _, replacement := range []string{
		"--snapshot-id=0", "--expected-source-revision=0",
		"--selected-node-id=bad/node", "--resolver=dns.example.com:53",
		"--resolver=0.0.0.0:53", "--candidate-sha256=" + strings.Repeat("A", 64),
		"--runtime-overlay-sha256=invalid",
		"--acknowledge-proxy-only-no-cn=false",
	} {
		modified := append([]string{}, good...)
		key := strings.SplitN(replacement, "=", 2)[0]
		for i, f := range modified {
			if f == key || strings.HasPrefix(f, key+"=") {
				modified[i] = replacement
			}
		}
		bad = append(bad, modified)
	}
	api := &fakeProfileInitialCLI{}
	for _, args := range bad {
		code, out, _ := runInitialCLITest(api, args)
		if code != 2 || out != "" {
			t.Fatalf("unsafe initial stage arguments accepted: exit=%d output=%q", code, out)
		}
	}
	if api.previewCalls != 0 || api.stageCalls != 0 {
		t.Fatalf("unsafe initial stage sent RPC preview=%d stage=%d", api.previewCalls, api.stageCalls)
	}
}

func TestFirstRunCLIForwardsOnlyExplicitReceiptAndValidatesResponses(t *testing.T) {
	shaA, shaB := strings.Repeat("a", 64), strings.Repeat("b", 64)
	api := &fakeProfileInitialCLI{preview: apiv1.InitialProfileDeclarationPreviewResponse{
		ProfileID: "work", SnapshotID: 42, SourceRevision: 3,
		BaseDeclarationRevision: 0, EffectiveNodeCount: 1,
		SelectedNodeID: "node-id", ResolverAddress: "127.0.0.1:5300",
		CandidateSHA256: shaA, RuntimeOverlaySHA256: shaB,
		RoutingMode: initialProxyOnlyRoutingMode,
	}, staged: apiv1.InitialProfileDeclarationStageResponse{
		ProfileID: "work", SnapshotID: 42, SourceRevision: 3,
		DeclarationRevision: 1, DeclarationSHA256: shaA,
		RoutingMode: initialProxyOnlyRoutingMode,
	}}
	code, out, stderr := runInitialCLITest(api, initialPreviewArgs())
	if code != 0 || stderr != "" || api.previewCalls != 1 || api.stageCalls != 0 ||
		api.previewReq.SnapshotID != 42 || api.previewReq.SelectedNodeID != "node-id" ||
		api.previewReq.ResolverAddress != "127.0.0.1:5300" ||
		!strings.Contains(out, `"cn_rules_ready": false`) ||
		!strings.Contains(out, `"core_validated": false`) ||
		!strings.Contains(out, `"candidate_sha256"`) {
		t.Fatalf("invalid first-run preview output exit=%d out=%q stderr=%q", code, out, stderr)
	}
	code, out, stderr = runInitialCLITest(api, initialStageArgs())
	if code != 0 || stderr != "" || api.stageCalls != 1 ||
		api.stageReq.SnapshotID != 42 || api.stageReq.ExpectedSourceRevision != 3 ||
		api.stageReq.SelectedNodeID != "node-id" ||
		api.stageReq.ResolverAddress != "127.0.0.1:5300" ||
		api.stageReq.CandidateSHA256 != shaA ||
		api.stageReq.RuntimeOverlaySHA256 != shaB ||
		!api.stageReq.AcknowledgeProxyOnlyNoCN ||
		!strings.Contains(out, `"declaration_revision": 1`) ||
		!strings.Contains(out, `"applied": false`) {
		t.Fatalf("invalid first-run stage output exit=%d out=%q stderr=%q", code, out, stderr)
	}
	api.err = errors.New("daemon returned 409 Conflict: https://subscription/?token=TOP_SECRET")
	code, out, stderr = runInitialCLITest(api, initialStageArgs())
	if code != 1 || out != "" || strings.Contains(stderr, "TOP_SECRET") ||
		!strings.Contains(stderr, "HTTP 409") || !strings.Contains(stderr, "NEVER auto-retry") {
		t.Fatalf("stage error leaked credentials or implied retry: %d %q %q", code, out, stderr)
	}
	api.err = nil
	api.staged.CNRulesReady = true
	code, out, stderr = runInitialCLITest(api, initialStageArgs())
	if code != 1 || out != "" || !strings.Contains(stderr, "inconsistent") {
		t.Fatalf("untruthful CN-ready response accepted: %d %q %q", code, out, stderr)
	}
	api.staged.CNRulesReady = false
	api.preview.Applied = true
	code, out, stderr = runInitialCLITest(api, initialPreviewArgs())
	if code != 1 || out != "" || !strings.Contains(stderr, "inconsistent") {
		t.Fatalf("preview claiming applied accepted: %d %q %q", code, out, stderr)
	}
}
