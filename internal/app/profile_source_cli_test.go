package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeProfileSourceCLI struct {
	putCalls        int
	refreshCalls    int
	lastID          string
	lastPut         apiv1.ProfileSourcePutRequest
	lastRefresh     apiv1.ProfileRefreshRequest
	putResponse     apiv1.ProfileSourceResponse
	refreshResponse apiv1.ProfileRefreshResponse
	err             error
}

func (f *fakeProfileSourceCLI) PutProfileSource(_ context.Context, id string, request apiv1.ProfileSourcePutRequest) (apiv1.ProfileSourceResponse, error) {
	f.putCalls++
	f.lastID = id
	f.lastPut = request
	return f.putResponse, f.err
}

func (f *fakeProfileSourceCLI) RefreshProfileSource(_ context.Context, id string, request apiv1.ProfileRefreshRequest) (apiv1.ProfileRefreshResponse, error) {
	f.refreshCalls++
	f.lastID = id
	f.lastRefresh = request
	return f.refreshResponse, f.err
}

func runSourceCLITest(api *fakeProfileSourceCLI, args []string, stdin string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := runProfileSourceCommand(context.Background(), api, args, strings.NewReader(stdin), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestProfileSourceCLIPutRedactsCredentialsAndForwardsRevision(t *testing.T) {
	secretURL := "https://example.com/subscription?token=VERY_PRIVATE_TOKEN"
	source := apiv1.ProfileSourceSpec{Format: "sing-box", LocationKind: "url", Location: secretURL,
		Fetch: apiv1.ProfileSourceFetchPolicy{Mode: "direct"}, Enabled: true}
	data, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeProfileSourceCLI{putResponse: apiv1.ProfileSourceResponse{
		ProfileID: "my-profile", Revision: 8, Source: source,
	}}
	code, out, stderr := runSourceCLITest(fake, []string{"put", "my-profile", "--expected-revision=7", "--stdin"}, string(data))
	if code != 0 || stderr != "" || !strings.Contains(out, "\"revision\": 8") ||
		strings.Contains(out, "VERY_PRIVATE_TOKEN") || strings.Contains(out, "location") ||
		fake.putCalls != 1 || fake.lastID != "my-profile" ||
		fake.lastPut.ExpectedRevision != 7 || fake.lastPut.Source.Location != secretURL {
		t.Fatalf("safe put CLI: code=%d out=%q err=%q request=%+v", code, out, stderr, fake.lastPut)
	}
}

func TestProfileSourceCLIPutRequiresExplicitFlagsAndStrictInput(t *testing.T) {
	valid := `{"format":"sing-box","location_kind":"url","location":"https://example.org/sub","fetch":{"mode":"direct"},"enabled":true}`
	for _, item := range []struct {
		args  []string
		input string
	}{
		{[]string{"put", "work", "--stdin"}, valid},
		{[]string{"put", "work", "--expected-revision=0"}, valid},
		{[]string{"put", "work", "--expected-revision=0", "--stdin", "extra"}, valid},
		{[]string{"put", "work", "--expected-revision=0", "--stdin"}, `null`},
		{[]string{"put", "work", "--expected-revision=0", "--stdin"}, valid + ` {}`},
		{[]string{"put", "work", "--expected-revision=0", "--stdin"}, `{"format":"sing-box","unknown":"SECRET_VALUE"}`},
		{[]string{"put", "work", "--expected-revision=0", "--stdin"}, strings.Repeat("x", 16<<10+1)},
	} {
		fake := &fakeProfileSourceCLI{}
		code, out, stderr := runSourceCLITest(fake, item.args, item.input)
		if code != 2 || out != "" || fake.putCalls != 0 || strings.Contains(stderr, "SECRET_VALUE") {
			t.Fatalf("invalid input accepted: code=%d out=%q err=%q", code, out, stderr)
		}
	}
}

func TestProfileSourceCLIRefreshConfirmationAndDiagnosticRedaction(t *testing.T) {
	fake := &fakeProfileSourceCLI{refreshResponse: apiv1.ProfileRefreshResponse{
		ProfileID: "work", SourceRevision: 4, NodeCount: 3,
		Diagnostics: []apiv1.ProfileDiagnosticResponse{
			{Level: "warning", Code: "ignored_by_product_policy", Path: "secret/path?token=TOP_SECRET", Message: "https://secret/?key=TOP_SECRET"},
			{Level: "\x1b[31m", Code: "\x1b[31mPWN"},
		},
	}}
	for _, flags := range [][]string{{"refresh", "work"}, {"refresh", "work", "--expected-revision=0"},
		{"refresh", "work", "--expected-revision=4", "extra"}} {
		code, _, _ := runSourceCLITest(fake, flags, "")
		if code != 2 {
			t.Fatalf("invalid refresh args accepted: %v", flags)
		}
	}
	if fake.refreshCalls != 0 {
		t.Fatalf("unexpected refresh calls: %d", fake.refreshCalls)
	}
	code, out, stderr := runSourceCLITest(fake, []string{"refresh", "work", "--expected-revision=4", "--allow-empty"}, "")
	if code != 0 || stderr != "" || fake.refreshCalls != 1 || fake.lastRefresh.ExpectedSourceRevision != 4 ||
		!fake.lastRefresh.AllowEmpty || !strings.Contains(out, "ignored_by_product_policy") ||
		!strings.Contains(out, `"diagnostic_count": 2`) || strings.Contains(out, "TOP_SECRET") || strings.Contains(out, "PWN") ||
		strings.Contains(out, "secret/path") {
		t.Fatalf("refresh CLI: code=%d out=%q err=%q request=%+v", code, out, stderr, fake.lastRefresh)
	}
}

func TestProfileSourceCLIErrorsSuppressUserProvidedURLs(t *testing.T) {
	fake := &fakeProfileSourceCLI{err: errors.New("daemon returned 422 Unprocessable Entity: invalid https://sub?token=TOP_SECRET")}
	args := []string{"put", "work", "--expected-revision=0", "--stdin"}
	code, out, stderr := runSourceCLITest(fake, args, `{"format":"sing-box"}`)
	if code != 1 || out != "" || strings.Contains(stderr, "TOP_SECRET") || !strings.Contains(stderr, "HTTP 422") {
		t.Fatalf("unsafe source CLI error: %d %q %q", code, out, stderr)
	}
	fake.err = errors.New("fetch failed: https://sub?token=TOP_SECRET")
	code, out, stderr = runSourceCLITest(fake, []string{"refresh", "work", "--expected-revision=1"}, "")
	if code != 1 || out != "" || strings.Contains(stderr, "TOP_SECRET") || !strings.Contains(stderr, "details suppressed") {
		t.Fatalf("unsafe refresh CLI error: %d %q %q", code, out, stderr)
	}
}
