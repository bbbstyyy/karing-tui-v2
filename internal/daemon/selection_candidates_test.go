package daemon

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestCurrentSelectionCandidatesFollowAppliedNotNewerStagedDeclaration(t *testing.T) {
	store, document, _, handler := appliedSelectionFixture(t)
	defer store.Close()

	get := selectionAPICall(t, handler, http.MethodGet, "/v1/selection/current", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	first := decodeSelectionAPI(t, get)
	wantA := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	wantB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	if len(first.Candidates) != 2 || first.CandidateCount != 2 || first.CandidatesTruncated ||
		first.Candidates[0] != wantA || first.Candidates[1] != wantB {
		t.Fatalf("applied candidates incorrect: %+v", first.Candidates)
	}
	current, err := store.CurrentDeclaration(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	stagedDocument := []byte(strings.ReplaceAll(string(document), "node-b", "node-c"))
	if _, err := store.CommitDeclaration(t.Context(), current.Revision, stagedDocument, "test:staged-candidates"); err != nil {
		t.Fatal(err)
	}
	get = selectionAPICall(t, handler, http.MethodGet, "/v1/selection/current", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET after staging=%d body=%s", get.Code, get.Body.String())
	}
	second := decodeSelectionAPI(t, get)
	if second.CandidateCount != 2 || second.CandidatesTruncated ||
		len(second.Candidates) != 2 || second.Candidates[1] != wantB ||
		second.DeclarationRevision != first.DeclarationRevision ||
		second.DeclarationSHA256 != first.DeclarationSHA256 ||
		second.SelectionRevision != first.SelectionRevision {
		t.Fatalf("newer staged declaration affected applied selector: %+v", second)
	}
}

// The terminal must not silently offer only the first slice of a large
// selector as if the other candidates were absent.
func TestCurrentSelectionCandidateListIsBoundedAndExplicitlyTruncated(t *testing.T) {
	raw := currentSelectionTestDeclaration()
	var doc struct {
		SchemaVersion int `json:"schema_version"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	// Decode to an object so this fixture keeps all unrelated fields.
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	nodes := obj["nodes"].([]any)
	sel := obj["selection"].(map[string]any)
	current := sel["current"].(map[string]any)
	members := current["members"].([]any)
	for i := 0; i < maxCurrentSelectionCandidates; i++ {
		name := "additional-" + strings.Repeat("x", 2) + string(rune('a'+i%26)) + "-" + strings.Repeat("z", i/26)
		nodes = append(nodes, map[string]any{
			"profile_id": "profile-a", "node_id": name, "type": "http",
			"server": "127.0.0.1", "port": 18082 + i, "http": map[string]any{},
		})
		members = append(members, map[string]any{
			"kind": "specific_node", "profile_id": "profile-a", "node_id": name,
		})
	}
	obj["nodes"] = nodes
	current["members"] = members
	document, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	store := openServerTestStore(t, t.Context())
	defer store.Close()
	if _, err := store.CommitDeclaration(t.Context(), 0, document, "test:large-selector"); err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewCurrentSelectionCoordinator(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Get(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if state.CandidateCount != maxCurrentSelectionCandidates+2 ||
		len(state.Candidates) != maxCurrentSelectionCandidates || !state.CandidatesTruncated {
		t.Fatalf("selector list was not capped honestly: count=%d shown=%d truncated=%t",
			state.CandidateCount, len(state.Candidates), state.CandidatesTruncated)
	}
	if state.Candidates[0].NodeID != "node-a" || state.Candidates[1].NodeID != "node-b" {
		t.Fatalf("original member ordering not preserved: %+v", state.Candidates[:2])
	}
	// GET serialization must publish the same explicit truncated flag.
	got := currentSelectionResponse(state)
	if got.CandidateCount != state.CandidateCount || !got.CandidatesTruncated {
		t.Fatalf("API truncated status lost: %+v", got)
	}
}
