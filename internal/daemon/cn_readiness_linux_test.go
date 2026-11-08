//go:build linux

package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/preset"
)

func TestCNReadinessIsReadOnlyAndReportsCompletePinnedInventoryBlockers(t *testing.T) {
	ctx := context.Background()
	store := newDaemonProfileMetadataStore(t, ctx)
	defer store.Close()
	api := httptest.NewServer((&Server{started: time.Now().UTC()}).handler(store, nil))
	defer api.Close()

	initial, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		response, err := http.Get(api.URL + "/v1/cn/resources/readiness")
		if err != nil {
			t.Fatal(err)
		}
		var observed apiv1.CNResourceReadinessResponse
		if err := json.NewDecoder(response.Body).Decode(&observed); err != nil {
			_ = response.Body.Close()
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("read-only CN readiness: HTTP %d", response.StatusCode)
		}
		if observed.Evidence != "pinned_source_inventory_only" ||
			observed.DistributionReady ||
			observed.LicenseStatus != "blocked_unresolved_upstream_data_licenses" ||
			observed.SourceRepository != preset.CNSourceRepository ||
			observed.SourceCommit != preset.CNSourceCommit ||
			observed.SourcePath != preset.CNSourcePath ||
			observed.LogicalResourceRefs != preset.CNResourceExpectedLogicalRefs ||
			observed.FileBackedCandidates != preset.CNResourceExpectedFiles ||
			observed.TotalGroupCount != preset.CNExpectedGroups ||
			observed.DefaultEnabledCount != preset.CNExpectedEnabled ||
			len(observed.Groups) != preset.CNExpectedGroups {
			t.Fatalf("CN baseline was misrepresented: %+v", observed)
		}
		if !reflect.DeepEqual(observed.BlockingCodes, []string{
			"unresolved_upstream_data_licenses", "upstream_resource_absent",
		}) || !reflect.DeepEqual(observed.KnownUpstreamAbsent, []string{"geoip:bing"}) ||
			!reflect.DeepEqual(observed.RegionAppendRefs, []string{"geosite:cn", "geoip:cn"}) {
			t.Fatalf("CN missing resource/licensing blocker not accurately reported: %+v", observed)
		}
		for index, group := range observed.Groups {
			if group.Order != uint32(index+1) || group.ID == "" ||
				group.TargetKind == "" || group.Name == "" {
				t.Fatalf("CN group order/source is incomplete at %d: %+v", index, group)
			}
		}
		if observed.Groups[20].ID != "cn.bing" ||
			!reflect.DeepEqual(observed.Groups[20].RuleSetRefs, []string{"geoip:bing", "geosite:bing"}) {
			t.Fatalf("historical unresolved Bing ref was pruned from read-only evidence: %+v", observed.Groups[20])
		}
	}
	after, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Revision != after.Revision ||
		after.RecoveryRequired || after.ActiveAttemptID != nil ||
		after.AppliedGenerationID != nil ||
		after.LastKnownGoodGenerationID != nil {
		t.Fatalf("read-only baseline report mutated daemon state: %+v", after)
	}

	request, err := http.NewRequest(http.MethodPost, api.URL+"/v1/cn/resources/readiness", nil)
	if err != nil {
		t.Fatal(err)
	}
	post, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("CN read-only endpoint accidentally allowed POST: %d", post.StatusCode)
	}
}
