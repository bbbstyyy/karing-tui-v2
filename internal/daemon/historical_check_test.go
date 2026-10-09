package daemon

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/declaration"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
	"net/netip"
)

func historicalCoreCheckHarness(t *testing.T) (*storage.Store, *fakeApplyCore, *serverRuntime, int64) {
	t.Helper()
	ctx := context.Background()
	store, core, runtime, handler := checkedApplyHarness(t)
	t.Cleanup(func(){ store.Close() })
	firstReceipt := checkedPreviewTest(t, handler).Receipt
	first := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", firstReceipt)
	if first.Code != http.StatusOK {
		t.Fatalf("first apply: %d %s", first.Code, first.Body.String())
	}
	firstState, err := store.Snapshot(ctx)
	if err != nil || firstState.AppliedGenerationID == nil {
		t.Fatalf("missing first generation: %+v, %v", firstState, err)
	}
	sourceID := *firstState.AppliedGenerationID

	head, err := store.CurrentDeclaration(ctx)
	if err != nil {
		t.Fatal(err)
	}
	document := []byte(strings.Replace(string(head.DocumentJSON),
		`"log_level":"warn"`, `"log_level":"info"`, 1))
	if string(document) == string(head.DocumentJSON) {
		t.Fatal("second fixture did not change the compiled config")
	}
	if _, err := store.CommitDeclaration(ctx, head.Revision, document, "test:historical-check"); err != nil {
		t.Fatal(err)
	}
	secondReceipt := checkedPreviewTest(t, handler).Receipt
	second := routeEditCall(t, handler, http.MethodPost, "/v1/config/apply/confirm", secondReceipt)
	if second.Code != http.StatusOK {
		t.Fatalf("second apply: %d %s", second.Code, second.Body.String())
	}
	return store, core, runtime, sourceID
}

func TestHistoricalCoreCheckPassesWithoutActivationAndLeavesConfirmedState(t *testing.T) {
	store, core, runtime, sourceID := historicalCoreCheckHarness(t)
	ctx := context.Background()
	before, err := store.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	beforeEvents := len(core.events)
	evidence, err := runtime.CheckHistoricalGeneration(ctx, store, "", sourceID)
	if err != nil {
		t.Fatal(err)
	}
	if !evidence.CoreChecked || evidence.RestoreReady || evidence.Applied ||
		evidence.SourceGenerationID != sourceID {
		t.Fatalf("core check misrepresented restore readiness: %+v", evidence)
	}
	if len(core.events) != beforeEvents+1 || core.events[len(core.events)-1] != "check" {
		t.Fatalf("dry run unexpectedly activated the core: %v", core.events)
	}
	after, err := store.Snapshot(ctx)
	if err != nil || after.ActiveAttemptID != nil || after.RecoveryRequired ||
		!sameRecoveryAuditSnapshot(before, after) {
		t.Fatalf("dry run changed confirmed generation state: %+v err=%v", after, err)
	}
	refs, _, err := store.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || len(refs) != 2 {
		t.Fatalf("prepared and aborted candidate became committed history: %+v, %v", refs, err)
	}
}

func TestHistoricalCoreCheckRejectsCompilerControlSecretDriftBeforeCoreIO(t *testing.T) {
	store, core, runtime, sourceID := historicalCoreCheckHarness(t)
	engine, err := declaration.NewNativeCompiler(declaration.NativeCompilerOptions{
		Inbounds:domain.DefaultInboundSet(),
		ControlAddress:netip.MustParseAddrPort("127.0.0.1:3057"),
		ControlSecret:strings.Repeat("b",64),
	})
	if err != nil {
		t.Fatal(err)
	}
	runtime.declarations, err = NewDeclarationCompileCoordinator(store, engine)
	if err != nil {
		t.Fatal(err)
	}
	beforeCalls := len(core.events)
	_, err = runtime.CheckHistoricalGeneration(context.Background(), store, "", sourceID)
	if !errors.Is(err, ErrHistoricalCheckRejected) || len(core.events) != beforeCalls {
		t.Fatalf("stale core control secret accepted: %v events=%v", err, core.events)
	}
	snapshot, err := store.Snapshot(context.Background())
	if err != nil || snapshot.ActiveAttemptID != nil {
		t.Fatalf("rejected check left active journal: %+v err=%v", snapshot, err)
	}
}

func TestHistoricalCoreCheckRejectsStaleSelectorAndFallbackCorruption(t *testing.T) {
	t.Run("selector",func(t *testing.T){
		store, core, runtime, sourceID := historicalCoreCheckHarness(t)
		_, err := store.SetCurrentSelectionIntent(context.Background(),
			[]byte(`{"kind":"specific_node","profile_id":"p1","node_id":"missing"}`))
		if err != nil {t.Fatal(err)}
		before := len(core.events)
		_, err = runtime.CheckHistoricalGeneration(context.Background(), store, "", sourceID)
		if !errors.Is(err, ErrHistoricalCheckRejected) || len(core.events)!=before {
			t.Fatalf("stale selector reached core check: %v, events=%v",err,core.events)
		}
	})
	t.Run("fallback corruption",func(t *testing.T){
		store, core, runtime, sourceID := historicalCoreCheckHarness(t)
		snap, err := store.Snapshot(context.Background())
		if err != nil || snap.AppliedGenerationID == nil {t.Fatal("missing current generation")}
		if err := corruptStoredGenerationManifestHash(store.Path(), *snap.AppliedGenerationID); err != nil {t.Fatal(err)}
		before := len(core.events)
		_, err = runtime.CheckHistoricalGeneration(context.Background(), store, "", sourceID)
		if !errors.Is(err, ErrHistoricalCheckRejected) || len(core.events)!=before {
			t.Fatalf("corrupted fallback reached core check: %v events=%v",err,core.events)
		}
	})
}

func TestHistoricalCoreCheckCoreFailureNeverActivates(t *testing.T) {
	store, core, runtime, sourceID := historicalCoreCheckHarness(t)
	ctx := context.Background()
	previous, _ := store.Snapshot(ctx)
	before := len(core.events)
	core.checkErr = errors.New("native-secret-only-in-test")
	_, err := runtime.CheckHistoricalGeneration(ctx, store, "", sourceID)
	if !errors.Is(err, ErrHistoricalCheckRejected) || strings.Contains(err.Error(), "native-secret-only-in-test") {
		t.Fatalf("core error accepted or leaked: %v", err)
	}
	if len(core.events) != before+1 || core.events[len(core.events)-1] != "check" {
		t.Fatalf("core activated despite check failure: %v", core.events)
	}
	current, _ := store.Snapshot(ctx)
	if !sameRecoveryAuditSnapshot(previous,current) || current.ActiveAttemptID != nil {
		t.Fatalf("core check failure damaged confirmed state: %+v", current)
	}
}

func TestHistoricalCoreCheckRejectsStateChangesDuringCheck(t *testing.T) {
	store, core, runtime, sourceID := historicalCoreCheckHarness(t)
	ctx := context.Background()
	core.checkFn = func(ctx context.Context, _ Generation) error {
		return store.SetRoutingPolicy(ctx, storage.RoutingModeGlobal, true)
	}
	before := len(core.events)
	_, err := runtime.CheckHistoricalGeneration(ctx, store, "", sourceID)
	if !errors.Is(err, ErrHistoricalCheckChanged) || len(core.events)!=before+1 {
		t.Fatalf("routing state changed mid-check but accepted: %v events=%v", err, core.events)
	}
	snap, err := store.Snapshot(ctx)
	if err != nil || snap.ActiveAttemptID != nil || snap.Revision != 2 {
		t.Fatalf("drift leaked active journal: %+v, %v", snap, err)
	}
}

func TestHistoricalCoreCheckOperationGateBlocksConcurrentCoreCheck(t *testing.T) {
	store, core, runtime, sourceID := historicalCoreCheckHarness(t)
	started := make(chan struct{})
	release := make(chan struct{})
	finished := make(chan error, 1)
	go func(){
		finished <- runtime.gate.Do(context.Background(), "test-lock", func(context.Context)error{
			close(started)
			<-release
			return nil
		})
	}()
	<-started
	before := len(core.events)
	ctx,cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := runtime.CheckHistoricalGeneration(ctx, store, "", sourceID)
	close(release)
	if lockErr := <-finished; lockErr != nil {t.Fatal(lockErr)}
	if !errors.Is(err, context.DeadlineExceeded) || len(core.events) != before {
		t.Fatalf("operation gate did not reject queued check: %v events=%v", err, core.events)
	}
	if snap, err := store.Snapshot(context.Background()); err!=nil || snap.ActiveAttemptID !=nil {
		t.Fatalf("queued check mutated state: %+v err=%v",snap,err)
	}
}

func TestHistoricalCoreCheckUnavailableRejectsNilRuntimeAndStore(t *testing.T){
	store,_,runtime,sourceID := historicalCoreCheckHarness(t)
	for _,call := range []func()error{
		func()error{_,err:=(*serverRuntime)(nil).CheckHistoricalGeneration(context.Background(),store,"",sourceID);return err},
		func()error{_,err:=runtime.CheckHistoricalGeneration(context.Background(),nil,"",sourceID);return err},
		func()error{_,err:=runtime.CheckHistoricalGeneration(context.Background(),store,"",0);return err},
	}{
		if err:=call();!errors.Is(err,ErrHistoricalCheckUnavailable){t.Fatalf("unavailable access accepted: %v",err)}
	}
}
