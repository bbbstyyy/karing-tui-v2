package daemon

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

const declarationAPITestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestDeclarationAPICommitsAndReadsValidatedV1(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	handler := New(runtimepath.Paths{}).handler(store, nil)

	request := apiv1.DeclarationCommitRequest{
		ExpectedRevision: 0,
		Source:           "test:api",
		Document:         json.RawMessage(declarationAPIMinimalDocument()),
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration", bytes.NewReader(body)))
	if recorder.Code != http.StatusCreated {
		t.Fatalf("commit status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var committed apiv1.DeclarationResponse
	if err := json.NewDecoder(recorder.Body).Decode(&committed); err != nil {
		t.Fatal(err)
	}
	if committed.Revision != 1 || committed.SHA256 == "" || committed.Source != "test:api" || len(committed.Document) == 0 {
		t.Fatalf("unexpected committed declaration: %+v", committed)
	}

	currentRecorder := httptest.NewRecorder()
	handler.ServeHTTP(currentRecorder, httptest.NewRequest(http.MethodGet, "/v1/declaration/current", nil))
	if currentRecorder.Code != http.StatusOK {
		t.Fatalf("current status = %d, body=%s", currentRecorder.Code, currentRecorder.Body.String())
	}
	var current apiv1.DeclarationResponse
	if err := json.NewDecoder(currentRecorder.Body).Decode(&current); err != nil {
		t.Fatal(err)
	}
	if current.Revision != committed.Revision || current.SHA256 != committed.SHA256 || string(current.Document) != string(committed.Document) {
		t.Fatalf("current declaration mismatch: committed=%+v current=%+v", committed, current)
	}
}

func TestDeclarationAPIRejectsInvalidDocumentWithoutAdvancingHead(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	handler := New(runtimepath.Paths{}).handler(store, nil)

	invalid := []byte(`{"schema_version":1,"unexpected":true}`)
	body, err := json.Marshal(apiv1.DeclarationCommitRequest{
		ExpectedRevision: 0,
		Source:           "test:invalid",
		Document:         invalid,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid commit status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 0 {
		t.Fatalf("invalid declaration advanced revision to %d", current.Revision)
	}
}

func TestDeclarationCompilePreviewUsesStoredRevisionAndDoesNotApply(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	stored, err := store.CommitDeclaration(ctx, 0, declarationAPIMinimalDocument(), "test:compile")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  declarationAPITestSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{declarations: coordinator, gate: NewOperationGate()}
	handler := New(runtimepath.Paths{}).handler(store, runtime)

	body, err := json.Marshal(apiv1.DeclarationCompileRequest{Revision: stored.Revision})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration/compile", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("compile status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	var preview apiv1.DeclarationCompileResponse
	if err := json.NewDecoder(recorder.Body).Decode(&preview); err != nil {
		t.Fatal(err)
	}
	if preview.Revision != stored.Revision || preview.DeclarationSHA256 != stored.SHA256 || preview.ConfigSHA256 == "" || preview.NativeSchemaID == "" {
		t.Fatalf("unexpected compile preview: %+v", preview)
	}
	if len(preview.InboundTags) != 3 || preview.RouteEntryCount != 1 || preview.RuleSetCount != 0 {
		t.Fatalf("unexpected compile closure: %+v", preview)
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 0 || snapshot.AppliedGenerationID != nil {
		t.Fatalf("compile preview mutated runtime apply state: %+v", snapshot)
	}
}

func TestDeclarationCompilePreviewRequiresCompilerRuntime(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	handler := New(runtimepath.Paths{}).handler(store, nil)

	body, err := json.Marshal(apiv1.DeclarationCompileRequest{Revision: 1})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration/compile", bytes.NewReader(body)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("compile without runtime status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func declarationAPIMinimalDocument() []byte {
	return []byte(`{
  "schema_version":1,
  "log_level":"warn",
  "nodes":[{
    "profile_id":"p1",
    "node_id":"n1",
    "type":"http",
    "server":"127.0.0.1",
    "port":9,
    "http":{}
  }],
  "selection":{
    "current":{
      "members":[{"kind":"specific_node","profile_id":"p1","node_id":"n1"}],
      "default":{"kind":"specific_node","profile_id":"p1","node_id":"n1"}
    },
    "custom":[]
  },
  "routing":{
    "custom":[],
    "geosite":[],
    "geoip":[],
    "acl":[],
    "final":{"kind":"direct"}
  },
  "dns":{
    "profiles":[{
      "id":"outbound",
      "role":"outbound",
      "transport":"udp",
      "server":"127.0.0.1",
      "port":53
    }],
    "outbound_profile_id":"outbound"
  }
}`)
}
