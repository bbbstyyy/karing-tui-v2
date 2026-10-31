package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

type fakeCurrentSelectionCore struct {
	snapshot    core.Snapshot
	selected    string
	selectCalls int
	selectErr   error
	readErr     error
}

func (f *fakeCurrentSelectionCore) Snapshot() core.Snapshot {
	return f.snapshot
}

func (f *fakeCurrentSelectionCore) SelectCurrent(_ context.Context, tag string) error {
	f.selectCalls++
	if f.selectErr != nil {
		return f.selectErr
	}
	f.selected = tag
	return nil
}

func (f *fakeCurrentSelectionCore) CurrentSelection(context.Context) (string, error) {
	if f.readErr != nil {
		return "", f.readErr
	}
	return f.selected, nil
}

func TestCurrentSelectionCoordinatorPersistsAndSwitchesRunningCore(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	document := currentSelectionTestDeclaration()
	if _, err := store.CommitDeclaration(ctx, 0, document, "test:selection"); err != nil {
		t.Fatal(err)
	}
	targetA := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	targetB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	tagA, err := declaration.CurrentSelectionRuntimeTag(document, targetA)
	if err != nil {
		t.Fatal(err)
	}
	tagB, err := declaration.CurrentSelectionRuntimeTag(document, targetB)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeCurrentSelectionCore{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 1234},
		selected: tagA,
	}
	coordinator, err := NewCurrentSelectionCoordinator(store, fake)
	if err != nil {
		t.Fatal(err)
	}

	initial, err := coordinator.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Target != targetA || initial.RuntimeTag != tagA || initial.Persisted || !initial.Applied || initial.LiveRuntimeTag != tagA {
		t.Fatalf("initial selection state = %+v", initial)
	}

	updated, err := coordinator.Set(ctx, targetB)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Target != targetB || updated.RuntimeTag != tagB || !updated.Persisted || !updated.Applied || updated.LiveRuntimeTag != tagB {
		t.Fatalf("updated selection state = %+v", updated)
	}
	if fake.selectCalls != 1 || fake.selected != tagB {
		t.Fatalf("live selector calls=%d selected=%q, want %q", fake.selectCalls, fake.selected, tagB)
	}
	intent, ok, err := store.CurrentSelectionIntent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || !strings.Contains(string(intent.TargetJSON), "node-b") {
		t.Fatalf("persisted selection intent = ok:%t %+v", ok, intent)
	}

	invalid := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "missing"}
	if _, err := coordinator.Set(ctx, invalid); !errors.Is(err, ErrCurrentSelectionTarget) {
		t.Fatalf("invalid member error = %v", err)
	}
	intentAfter, ok, err := store.CurrentSelectionIntent(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(intentAfter.TargetJSON) != string(intent.TargetJSON) {
		t.Fatalf("invalid selection overwrote intent: before=%s after=%s", intent.TargetJSON, intentAfter.TargetJSON)
	}
}

func TestCurrentSelectionCoordinatorPersistsWhileCoreStopped(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	document := currentSelectionTestDeclaration()
	if _, err := store.CommitDeclaration(ctx, 0, document, "test:selection-stopped"); err != nil {
		t.Fatal(err)
	}
	target := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	fake := &fakeCurrentSelectionCore{snapshot: core.Snapshot{State: core.StateStopped}}
	coordinator, err := NewCurrentSelectionCoordinator(store, fake)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Set(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if !state.Persisted || state.Applied || state.LiveRuntimeTag != "" || fake.selectCalls != 0 {
		t.Fatalf("stopped-core selection state = %+v calls=%d", state, fake.selectCalls)
	}
}

type fakeSelectionDaemonCore struct {
	fakeCurrentSelectionCore
}

func (f *fakeSelectionDaemonCore) Run(ctx context.Context) error {
	<-ctx.Done()
	return nil
}

func (f *fakeSelectionDaemonCore) WaitReady(context.Context) error {
	return nil
}

func (f *fakeSelectionDaemonCore) Start(context.Context) error {
	f.snapshot.State = core.StateRunning
	return nil
}

func (f *fakeSelectionDaemonCore) Stop(context.Context) error {
	f.snapshot.State = core.StateStopped
	return nil
}

func TestCurrentSelectionAPI(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	document := currentSelectionTestDeclaration()
	if _, err := store.CommitDeclaration(ctx, 0, document, "test:selection-api"); err != nil {
		t.Fatal(err)
	}
	targetA := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-a"}
	targetB := domain.TargetRef{Kind: domain.TargetSpecificNode, ProfileID: "profile-a", NodeID: "node-b"}
	tagA, err := declaration.CurrentSelectionRuntimeTag(document, targetA)
	if err != nil {
		t.Fatal(err)
	}
	fake := &fakeSelectionDaemonCore{fakeCurrentSelectionCore: fakeCurrentSelectionCore{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 4321},
		selected: tagA,
	}}
	runtime := &serverRuntime{core: fake, gate: NewOperationGate()}
	handler := New(runtimepath.Paths{}).handler(store, runtime)

	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/v1/selection/current", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("selection GET status=%d body=%s", get.Code, get.Body.String())
	}
	var initial apiv1.CurrentSelectionResponse
	if err := json.NewDecoder(get.Body).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	if initial.Target != targetA || initial.Persisted || !initial.Applied {
		t.Fatalf("initial API selection = %+v", initial)
	}

	body := `{"target":{"kind":"specific_node","profile_id":"profile-a","node_id":"node-b"}}`
	put := httptest.NewRecorder()
	handler.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/v1/selection/current", strings.NewReader(body)))
	if put.Code != http.StatusOK {
		t.Fatalf("selection PUT status=%d body=%s", put.Code, put.Body.String())
	}
	var updated apiv1.CurrentSelectionResponse
	if err := json.NewDecoder(put.Body).Decode(&updated); err != nil {
		t.Fatal(err)
	}
	if updated.Target != targetB || !updated.Persisted || !updated.Applied || updated.LiveRuntimeTag != updated.RuntimeTag {
		t.Fatalf("updated API selection = %+v", updated)
	}

	bad := httptest.NewRecorder()
	badBody := `{"target":{"kind":"specific_node","profile_id":"profile-a","node_id":"missing"}}`
	handler.ServeHTTP(bad, httptest.NewRequest(http.MethodPut, "/v1/selection/current", strings.NewReader(badBody)))
	if bad.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid selection status=%d body=%s", bad.Code, bad.Body.String())
	}
}

func currentSelectionTestDeclaration() []byte {
	return []byte(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"profile-a",
    "node_id":"node-a",
    "type":"http",
    "server":"127.0.0.1",
    "port":18080,
    "http":{}
  },{
    "profile_id":"profile-a",
    "node_id":"node-b",
    "type":"http",
    "server":"127.0.0.1",
    "port":18081,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{
        "kind":"specific_node",
        "profile_id":"profile-a",
        "node_id":"node-a"
      },{
        "kind":"specific_node",
        "profile_id":"profile-a",
        "node_id":"node-b"
      }],
      "default":{
        "kind":"specific_node",
        "profile_id":"profile-a",
        "node_id":"node-a"
      }
    },
    "custom":[]
  },
  "routing":{
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"current_selected"}
  },
  "dns":{
    "profiles":[{
      "id":"outbound-dns",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":53
    }],
    "outbound_profile_id":"outbound-dns"
  }
}`)
}

func TestCurrentSelectionUsesAppliedDeclarationInsteadOfNewerUnappliedDeclaration(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	appliedDocument := currentSelectionTestDeclaration()
	appliedDeclaration, err := store.CommitDeclaration(ctx, 0, appliedDocument, "test:selection-applied-v1")
	if err != nil {
		t.Fatal(err)
	}
	manifestJSON, err := json.Marshal(compiler.NativeManifest{
		SchemaID:            compiler.NativeSchemaID,
		ConfigSHA256:        strings.Repeat("a", 64),
		DeclarationRevision: appliedDeclaration.Revision,
		DeclarationSHA256:   appliedDeclaration.SHA256,
	})
	if err != nil {
		t.Fatal(err)
	}
	attempt, err := store.PrepareApplyWithMetadata(
		ctx,
		0,
		[]byte(`{}`),
		manifestJSON,
		[]byte(`[]`),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginActivation(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.BeginVerification(ctx, attempt.ID); err != nil {
		t.Fatal(err)
	}
	if err := store.CommitApplied(ctx, attempt.ID, true); err != nil {
		t.Fatal(err)
	}

	newerDocument := []byte(strings.ReplaceAll(
		string(appliedDocument),
		`"node_id":"node-a"`,
		`"node_id":"node-c"`,
	))
	if _, err := store.CommitDeclaration(
		ctx,
		appliedDeclaration.Revision,
		newerDocument,
		"test:selection-unapplied-v2",
	); err != nil {
		t.Fatal(err)
	}

	coordinator, err := NewCurrentSelectionCoordinator(store, nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Get(ctx)
	if err != nil {
		t.Fatal(err)
	}
	wantAppliedDefault := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: "profile-a",
		NodeID:    "node-a",
	}
	if state.Target != wantAppliedDefault {
		t.Fatalf("selection default came from unapplied declaration: got=%+v want=%+v", state.Target, wantAppliedDefault)
	}

	unappliedOnlyTarget := domain.TargetRef{
		Kind:      domain.TargetSpecificNode,
		ProfileID: "profile-a",
		NodeID:    "node-c",
	}
	if _, err := coordinator.Set(ctx, unappliedOnlyTarget); !errors.Is(err, ErrCurrentSelectionTarget) {
		t.Fatalf("unapplied-only target error = %v, want ErrCurrentSelectionTarget", err)
	}
	if _, ok, err := store.CurrentSelectionIntent(ctx); err != nil || ok {
		t.Fatalf("invalid unapplied target persisted selection intent: ok=%t err=%v", ok, err)
	}
}
