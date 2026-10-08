package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeProfileCLIClient struct {
	sources     apiv1.ProfileSourceListResponse
	page        apiv1.ProfileNodeListResponse
	update      apiv1.ProfileNodeOverlayResponse
	getErr      error
	putErr      error
	sourceCalls int
	pageCalls   int
	putCalls    int
	lastOffset  int
	lastLimit   int
	lastRequest apiv1.ProfileNodeOverlayPutRequest
}

func (f *fakeProfileCLIClient) ProfileSources(_ context.Context) (apiv1.ProfileSourceListResponse, error) {
	f.sourceCalls++
	return f.sources, f.getErr
}
func (f *fakeProfileCLIClient) ProfileNodes(_ context.Context, _ string, offset, limit int) (apiv1.ProfileNodeListResponse, error) {
	f.pageCalls++
	f.lastOffset = offset
	f.lastLimit = limit
	return f.page, f.getErr
}
func (f *fakeProfileCLIClient) PutProfileNodeOverlay(_ context.Context, _, _ string, request apiv1.ProfileNodeOverlayPutRequest) (apiv1.ProfileNodeOverlayResponse, error) {
	f.putCalls++
	f.lastRequest = request
	return f.update, f.putErr
}
func runProfileTest(args []string, api *fakeProfileCLIClient) (int, string, string) {
	var out, stderr bytes.Buffer
	code := runProfileCommand(context.Background(), api, args, &out, &stderr)
	return code, out.String(), stderr.String()
}

func TestProfilesCLIListRedactsSourceLocations(t *testing.T) {
	secret := "https://example.org/sub?token=SECRET_TOKEN"
	api := &fakeProfileCLIClient{sources: apiv1.ProfileSourceListResponse{
		Profiles: []apiv1.ProfileSourceResponse{
			{ProfileID: "work", Revision: 3, Source: apiv1.ProfileSourceSpec{
				Format: "sing-box", Enabled: true, Location: secret,
			}},
		},
	}}
	code, out, stderr := runProfileTest([]string{"list", "--json"}, api)
	if code != 0 || stderr != "" || !strings.Contains(out, "\"profile_id\": \"work\"") ||
		!strings.Contains(out, "\"revision\": 3") || strings.Contains(out, "SECRET_TOKEN") ||
		strings.Contains(out, "\"location\"") {
		t.Fatalf("safe profile list: code=%d out=%q err=%q", code, out, stderr)
	}
	if api.sourceCalls != 1 {
		t.Fatalf("list calls=%d", api.sourceCalls)
	}
	code, out, stderr = runProfileTest([]string{"list", "extra"}, api)
	if code != 2 || out != "" || api.sourceCalls != 1 {
		t.Fatalf("unexpected positional arg: %d %s %s", code, out, stderr)
	}
}

func TestProfilesCLINodePageBoundsAndOutput(t *testing.T) {
	api := &fakeProfileCLIClient{page: apiv1.ProfileNodeListResponse{
		ProfileID: "test", Total: 1, Offset: 20, Limit: 10,
		Nodes: []apiv1.ProfileNodeSummary{{NodeID: "stable-1", SourceName: "Sample", DisplayName: "Alias", OverlayRevision: 7, Favorite: true}},
	}}
	code, out, stderr := runProfileTest([]string{"nodes", "test", "--offset=20", "--limit=10"}, api)
	if code != 0 || stderr != "" || !strings.Contains(out, "stable-1\tAlias") ||
		api.pageCalls != 1 || api.lastOffset != 20 || api.lastLimit != 10 {
		t.Fatalf("node CLI: %d %q %q %+v", code, out, stderr, api)
	}
	for _, args := range [][]string{
		{"nodes", "test", "--offset=-1"}, {"nodes", "test", "--limit=201"},
		{"nodes", "test", "--limit=0"}, {"nodes"}, {"nodes", "test", "extra"},
	} {
		code, _, _ := runProfileTest(args, api)
		if code != 2 {
			t.Fatalf("invalid flags %q code=%d", args, code)
		}
	}
	if api.pageCalls != 1 {
		t.Fatalf("invalid args accessed daemon: %d", api.pageCalls)
	}
}

func TestProfilesCLIOverlayRequiresCompleteCASReplacement(t *testing.T) {
	api := &fakeProfileCLIClient{update: apiv1.ProfileNodeOverlayResponse{ProfileID: "test", NodeID: "stable-1", Revision: 2}}
	for _, args := range [][]string{
		{"replace-overlay", "test", "stable-1", "--disabled=true", "--favorite=true", "--alias=Pinned", "--sort-rank=3"},
		{"replace-overlay", "test", "stable-1", "--expected-revision=1", "--disabled=true", "--favorite=true", "--alias=Pinned"},
		{"replace-overlay", "test", "stable-1", "--expected-revision=1", "--disabled=true", "--favorite=true", "--alias=Pinned", "--sort-rank=-1"},
		{"replace-overlay", "test", "stable-1", "--expected-revision=1", "--disabled=true", "--favorite=true", "--alias=Pinned", "--sort-rank=not-a-number"},
	} {
		code, _, _ := runProfileTest(args, api)
		if code != 2 {
			t.Fatalf("incomplete replacement %q accepted", args)
		}
	}
	if api.putCalls != 0 {
		t.Fatalf("invalid requests made %d writes", api.putCalls)
	}
	code, out, stderr := runProfileTest([]string{"replace-overlay", "test", "stable-1",
		"--expected-revision=1", "--disabled=true", "--favorite=false", "--alias=Pinned", "--sort-rank=3"}, api)
	if code != 0 || stderr != "" || !strings.Contains(out, "\"revision\": 2") || api.putCalls != 1 ||
		api.lastRequest.ExpectedRevision != 1 || !api.lastRequest.Overlay.Disabled ||
		api.lastRequest.Overlay.Favorite || api.lastRequest.Overlay.Alias != "Pinned" ||
		api.lastRequest.Overlay.SortRank == nil || *api.lastRequest.Overlay.SortRank != 3 {
		t.Fatalf("replace overlay: %d %s %s %+v", code, out, stderr, api.lastRequest)
	}
	code, out, stderr = runProfileTest([]string{"replace-overlay", "test", "stable-1",
		"--expected-revision=2", "--disabled=false", "--favorite=true", "--alias=", "--sort-rank=none"}, api)
	if code != 0 || api.lastRequest.Overlay.SortRank != nil || !api.lastRequest.Overlay.Favorite {
		t.Fatalf("clear rank replacement: %d %s %s %+v", code, out, stderr, api.lastRequest)
	}
	api.putErr = errors.New("revision conflict")
	code, out, stderr = runProfileTest([]string{"replace-overlay", "test", "stable-1",
		"--expected-revision=2", "--disabled=false", "--favorite=true", "--alias=", "--sort-rank=none"}, api)
	if code != 1 || out != "" || !strings.Contains(stderr, "revision conflict") {
		t.Fatalf("CAS error: %d %s %s", code, out, stderr)
	}
}
