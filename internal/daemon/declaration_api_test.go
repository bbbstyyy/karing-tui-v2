package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/runtimepath"
)

const declarationAPITestSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestRuleSetUploadEnablesStrictDeclarationCommit(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	resourceStore, err := coreartifact.NewStore(filepath.Join(t.TempDir(), "core"))
	if err != nil {
		t.Fatal(err)
	}
	server := New(runtimepath.Paths{})
	server.ruleSets = resourceStore
	handler := server.handler(store, nil)

	content := []byte(`{"version":4,"rules":[]}`)
	sum := sha256.Sum256(content)
	hash := hex.EncodeToString(sum[:])
	document := declarationAPIWithRuleSet(hash)
	request := apiv1.DeclarationCommitRequest{
		ExpectedRevision: 0,
		Source:           "test:ruleset",
		Document:         json.RawMessage(document),
	}
	body, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}

	missing := httptest.NewRecorder()
	handler.ServeHTTP(missing, httptest.NewRequest(http.MethodPost, "/v1/declaration", bytes.NewReader(body)))
	if missing.Code != http.StatusUnprocessableEntity {
		t.Fatalf("commit before resource upload status = %d, body=%s", missing.Code, missing.Body.String())
	}
	current, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 0 {
		t.Fatalf("missing resource advanced declaration head to %d", current.Revision)
	}

	upload := httptest.NewRecorder()
	handler.ServeHTTP(
		upload,
		httptest.NewRequest(http.MethodPut, "/v1/rule-sets/"+hash+"?format=source", bytes.NewReader(content)),
	)
	if upload.Code != http.StatusCreated {
		t.Fatalf("rule-set upload status = %d, body=%s", upload.Code, upload.Body.String())
	}
	var uploaded apiv1.RuleSetUploadResponse
	if err := json.NewDecoder(upload.Body).Decode(&uploaded); err != nil {
		t.Fatal(err)
	}
	if uploaded.SHA256 != hash || uploaded.Format != "source" || uploaded.Bytes != int64(len(content)) {
		t.Fatalf("unexpected rule-set upload response: %+v", uploaded)
	}

	committed := httptest.NewRecorder()
	handler.ServeHTTP(committed, httptest.NewRequest(http.MethodPost, "/v1/declaration", bytes.NewReader(body)))
	if committed.Code != http.StatusCreated {
		t.Fatalf("commit after resource upload status = %d, body=%s", committed.Code, committed.Body.String())
	}
}

func TestRuleSetUploadRejectsHashMismatch(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	resourceStore, err := coreartifact.NewStore(filepath.Join(t.TempDir(), "core"))
	if err != nil {
		t.Fatal(err)
	}
	server := New(runtimepath.Paths{})
	server.ruleSets = resourceStore
	handler := server.handler(store, nil)

	wrong := strings.Repeat("a", 64)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodPut, "/v1/rule-sets/"+wrong+"?format=binary", bytes.NewReader([]byte("different"))),
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("hash mismatch upload status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

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

func TestDeclarationApplyAPICompilesAndCommitsExplicitRevision(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	stored, err := store.CommitDeclaration(ctx, 0, declarationAPIMinimalDocument(), "test:apply")
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
	declarations, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	core := &fakeApplyCore{}
	apply, err := NewApplyCoordinator(store, core, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{
		apply:        apply,
		declarations: declarations,
		gate:         NewOperationGate(),
	}
	handler := New(runtimepath.Paths{}).handler(store, runtime)

	body, err := json.Marshal(apiv1.DeclarationApplyRequest{
		DeclarationRevision:    stored.Revision,
		ExpectedConfigRevision: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration/apply", bytes.NewReader(body)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("apply status = %d, body=%s", recorder.Code, recorder.Body.String())
	}

	var response apiv1.DeclarationApplyResponse
	if err := json.NewDecoder(recorder.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.DeclarationRevision != stored.Revision ||
		response.DeclarationSHA256 != stored.SHA256 ||
		response.ConfigSHA256 == "" ||
		response.NativeSchemaID == "" ||
		response.AttemptID == 0 ||
		response.GenerationID == 0 ||
		response.BaseConfigRevision != 0 ||
		response.TargetConfigRevision != 1 {
		t.Fatalf("unexpected declaration apply response: %+v", response)
	}
	if got := strings.Join(core.events, ","); got != "check,activate,verify" {
		t.Fatalf("core events = %q", got)
	}

	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 1 ||
		snapshot.AppliedGenerationID == nil ||
		*snapshot.AppliedGenerationID != response.GenerationID {
		t.Fatalf("declaration apply did not commit runtime state: %+v", snapshot)
	}
	artifacts, err := store.GenerationArtifacts(ctx, response.GenerationID)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		DeclarationRevision uint64 `json:"declaration_revision"`
		DeclarationSHA256   string `json:"declaration_sha256"`
		ConfigSHA256        string `json:"config_sha256"`
	}
	if err := json.Unmarshal(artifacts.ManifestJSON, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.DeclarationRevision != stored.Revision ||
		manifest.DeclarationSHA256 != stored.SHA256 ||
		manifest.ConfigSHA256 != response.ConfigSHA256 {
		t.Fatalf("persisted declaration provenance mismatch: %+v", manifest)
	}

	conflict := httptest.NewRecorder()
	handler.ServeHTTP(conflict, httptest.NewRequest(http.MethodPost, "/v1/declaration/apply", bytes.NewReader(body)))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("stale config revision status = %d, body=%s", conflict.Code, conflict.Body.String())
	}
	afterConflict, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if afterConflict.Revision != 1 ||
		afterConflict.AppliedGenerationID == nil ||
		*afterConflict.AppliedGenerationID != response.GenerationID {
		t.Fatalf("stale declaration apply changed committed state: %+v", afterConflict)
	}
}

func TestDeclarationApplyAPIRejectsMissingRevisionWithoutCreatingGeneration(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()

	engine, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:       domain.DefaultInboundSet(),
		ControlAddress: netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:  declarationAPITestSecret,
	})
	if err != nil {
		t.Fatal(err)
	}
	declarations, err := NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	apply, err := NewApplyCoordinator(store, &fakeApplyCore{}, testApplyPolicy())
	if err != nil {
		t.Fatal(err)
	}
	runtime := &serverRuntime{apply: apply, declarations: declarations, gate: NewOperationGate()}
	handler := New(runtimepath.Paths{}).handler(store, runtime)

	body, err := json.Marshal(apiv1.DeclarationApplyRequest{
		DeclarationRevision:    99,
		ExpectedConfigRevision: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration/apply", bytes.NewReader(body)))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("missing declaration status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
	snapshot, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.Revision != 0 || snapshot.AppliedGenerationID != nil || snapshot.ActiveAttemptID != nil {
		t.Fatalf("missing declaration created apply state: %+v", snapshot)
	}
}

func TestDeclarationApplyAPIRequiresApplyRuntime(t *testing.T) {
	ctx := context.Background()
	store := openServerTestStore(t, ctx)
	defer store.Close()
	handler := New(runtimepath.Paths{}).handler(store, nil)

	body, err := json.Marshal(apiv1.DeclarationApplyRequest{
		DeclarationRevision:    1,
		ExpectedConfigRevision: 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/declaration/apply", bytes.NewReader(body)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("apply without runtime status = %d, body=%s", recorder.Code, recorder.Body.String())
	}
}

func declarationAPIWithRuleSet(hash string) []byte {
	document := string(declarationAPIMinimalDocument())
	document = strings.Replace(
		document,
		`"log_level":"warn",`,
		`"log_level":"warn",
  "rule_sets":[{"ref":"geosite:cn","sha256":"`+hash+`","format":"source"}],`,
		1,
	)
	document = strings.Replace(
		document,
		`"routing":{
    "custom":[]`,
		`"routing":{
    "custom":[{"id":"rs","order":1,"enabled":true,"target":{"kind":"direct"},"match":{"op":"atom","predicate":{"kind":"rule_set","value":"geosite:cn"}}}]`,
		1,
	)
	return []byte(document)
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
