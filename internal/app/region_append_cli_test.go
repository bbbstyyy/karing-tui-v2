package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCNRegionAppendCLIUsesOneFieldPreviewAndExplicitStage(t *testing.T) {
	for _, tc := range []struct {
		layer string
		group string
		flag  string
	}{
		{"geosite", "region:auto-geosite:cn", "false"},
		{"geoip", "region:auto-geoip:cn", "true"},
	} {
		t.Run(tc.layer, func(t *testing.T) {
			api := routeConfigFake()
			private := filepath.Join(t.TempDir(), "region-receipt.json")
			code, out, stderr := routeConfigTest(context.Background(), api,
				"route-preview", "--layer="+tc.layer, "--group="+tc.group,
				"--enabled="+tc.flag, "--out="+private)
			want := tc.flag == "true"
			if code != 0 || stderr != "" || !strings.Contains(out, "receipt saved") ||
				api.previewCalls != 1 || api.stageCalls != 0 ||
				api.previewReq.Layer != domain.RoutingLayer(tc.layer) ||
				api.previewReq.GroupID != tc.group || api.previewReq.Enabled == nil ||
				*api.previewReq.Enabled != want ||
				api.previewReq.Target != nil || api.previewReq.DNSProfileID != nil ||
				api.previewReq.ExpectedDeclarationRevision != 8 ||
				api.previewReq.ExpectedSelectionRevision != 3 {
				t.Fatalf("region preview changed more than one field: out=%q err=%q request=%+v",
					out, stderr, api.previewReq)
			}
			if stat, err := os.Stat(private); err != nil || stat.Mode().Perm() != 0o600 {
				t.Fatalf("region receipt is not private: %+v, %v", stat, err)
			}
			code, _, stderr = routeConfigTest(context.Background(), api,
				"route-stage", "--receipt="+private)
			if code != 2 || api.stageCalls != 0 {
				t.Fatalf("region edit was committed without --confirm: %d, %s", code, stderr)
			}
			code, out, stderr = routeConfigTest(context.Background(), api,
				"route-stage", "--receipt="+private, "--confirm")
			if code != 0 || stderr != "" || api.stageCalls != 1 ||
				api.stageReq.GroupID != tc.group ||
				api.stageReq.Enabled == nil || *api.stageReq.Enabled != want ||
				api.stageReq.Target != nil || api.stageReq.DNSProfileID != nil ||
				!strings.Contains(out, "\"staged\": true") ||
				!strings.Contains(out, "\"applied\": false") {
				t.Fatalf("confirmed region stage was not separate from Core Apply: %d %q %q", code, out, stderr)
			}
		})
	}
}
