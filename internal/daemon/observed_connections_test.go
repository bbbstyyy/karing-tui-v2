package daemon

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreapi"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

type fakeObservedConnectionsStore struct {
	snapshots []storage.Snapshot
	index     int
}

func (s *fakeObservedConnectionsStore) Snapshot(context.Context) (storage.Snapshot, error) {
	if len(s.snapshots) == 0 {
		return storage.Snapshot{}, nil
	}
	index := s.index
	if index >= len(s.snapshots) {
		index = len(s.snapshots) - 1
	}
	s.index++
	return s.snapshots[index], nil
}

type fakeObservedConnectionsRuntime struct {
	snapshot core.Snapshot
	active   OperationSnapshot
	raw      coreapi.ConnectionsSnapshot
	err      error
	mode     storage.RoutingMode
	modeErr  error
}

func (r *fakeObservedConnectionsRuntime) Snapshot() core.Snapshot {
	return r.snapshot
}

func (r *fakeObservedConnectionsRuntime) Connections(context.Context) (coreapi.ConnectionsSnapshot, error) {
	return r.raw, r.err
}

func (r *fakeObservedConnectionsRuntime) ActiveOperation() OperationSnapshot {
	return r.active
}

func (r *fakeObservedConnectionsRuntime) CurrentRoutingMode(context.Context) (storage.RoutingMode, error) {
	return r.mode, r.modeErr
}

type fakeObservedRouteExplainer struct {
	response apiv1.RouteExplainResponse
	request  apiv1.RouteExplainRequest
	err      error
}

func (e *fakeObservedRouteExplainer) Explain(
	_ context.Context,
	request apiv1.RouteExplainRequest,
) (apiv1.RouteExplainResponse, error) {
	e.request = request
	return e.response, e.err
}

func TestObservedConnectionsKeepsObservedAndSimulatedEvidenceSeparate(t *testing.T) {
	generationID := int64(9)
	store := &fakeObservedConnectionsStore{snapshots: []storage.Snapshot{{
		Revision:            4,
		AppliedGenerationID: &generationID,
	}}}
	runtime := &fakeObservedConnectionsRuntime{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		raw: coreapi.ConnectionsSnapshot{
			DownloadTotal: 12,
			UploadTotal:   34,
			Connections: []coreapi.ConnectionInfo{{
				ID:    "connection-1",
				Start: time.Date(2026, 10, 7, 7, 0, 0, 0, time.UTC),
				Metadata: coreapi.ConnectionMetadata{
					Network:         "tcp",
					Type:            "mixed/in-rule",
					SourceIP:        "127.0.0.1",
					SourcePort:      "40000",
					DestinationIP:   "127.0.0.1",
					DestinationPort: "443",
					Host:            "example.test",
				},
				Chains: []string{"out-direct"},
				Rule:   "final",
			}},
		},
	}
	explainer := &fakeObservedRouteExplainer{response: apiv1.RouteExplainResponse{
		Evidence:       "simulated",
		Decision:       "route",
		ConfigRevision: 4,
		GenerationID:   generationID,
		RuleIndex:      intPtr(3),
		Source:         "source_map",
		Layer:          domain.LayerFinal,
		Final:          true,
		Target:         &domain.TargetRef{Kind: domain.TargetDirect},
	}}
	coordinator, err := NewObservedConnectionsCoordinator(store, runtime, explainer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := coordinator.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if response.Evidence != "observed" || response.GenerationID != generationID ||
		response.ConfigRevision != 4 || len(response.Connections) != 1 {
		t.Fatalf("observed response = %+v", response)
	}
	connection := response.Connections[0]
	if connection.Evidence != "observed" || connection.Rule != "final" ||
		connection.SourceEvidence != "simulated" ||
		connection.SourceLayer != domain.LayerFinal ||
		connection.SourceTarget == nil || connection.SourceTarget.Kind != domain.TargetDirect {
		t.Fatalf("observed connection = %+v", connection)
	}
	if explainer.request.Entry != "rule" || explainer.request.Domain != "example.test" ||
		explainer.request.IP != "127.0.0.1" || explainer.request.Port != 443 ||
		explainer.request.Network != "tcp" {
		t.Fatalf("source simulation request = %+v", explainer.request)
	}
}

func TestObservedConnectionsRejectsGenerationChange(t *testing.T) {
	first := int64(7)
	second := int64(8)
	store := &fakeObservedConnectionsStore{snapshots: []storage.Snapshot{
		{Revision: 3, AppliedGenerationID: &first},
		{Revision: 4, AppliedGenerationID: &second},
	}}
	runtime := &fakeObservedConnectionsRuntime{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		raw:      coreapi.ConnectionsSnapshot{},
	}
	coordinator, err := NewObservedConnectionsCoordinator(store, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.List(context.Background()); err != ErrConnectionGenerationChanged {
		t.Fatalf("generation change error = %v", err)
	}
}

func TestObservedConnectionsRejectsActiveOperation(t *testing.T) {
	generationID := int64(7)
	store := &fakeObservedConnectionsStore{snapshots: []storage.Snapshot{{
		Revision:            3,
		AppliedGenerationID: &generationID,
	}}}
	runtime := &fakeObservedConnectionsRuntime{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		active:   OperationSnapshot{Name: "declaration-apply"},
	}
	coordinator, err := NewObservedConnectionsCoordinator(store, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.List(context.Background()); err == nil {
		t.Fatal("active core transition unexpectedly allowed connection observation")
	}
}

func TestObservedConnectionsDowngradesSourceWhenLiveModeDiffers(t *testing.T) {
	generationID := int64(12)
	store := &fakeObservedConnectionsStore{snapshots: []storage.Snapshot{{
		Revision:            6,
		AppliedGenerationID: &generationID,
		RoutingMode:         storage.RoutingModeGlobal,
	}}}
	runtime := &fakeObservedConnectionsRuntime{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		mode:     storage.RoutingModeRule,
		raw: coreapi.ConnectionsSnapshot{Connections: []coreapi.ConnectionInfo{{
			ID: "connection-mode-mismatch",
			Metadata: coreapi.ConnectionMetadata{
				Network:         "tcp",
				Type:            "mixed/in-rule",
				DestinationIP:   "127.0.0.1",
				DestinationPort: "443",
			},
		}}},
	}
	explainer := &fakeObservedRouteExplainer{response: apiv1.RouteExplainResponse{
		Evidence: "simulated",
		Decision: "route",
	}}
	coordinator, err := NewObservedConnectionsCoordinator(store, runtime, explainer)
	if err != nil {
		t.Fatal(err)
	}
	response, err := coordinator.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Connections) != 1 {
		t.Fatalf("connections = %d", len(response.Connections))
	}
	connection := response.Connections[0]
	if connection.SourceEvidence != "unknown" ||
		len(connection.SourceUnknownConditions) != 1 ||
		connection.SourceUnknownConditions[0] != "routing_mode_mismatch" {
		t.Fatalf("mode-mismatch source attribution = %+v", connection)
	}
	if explainer.request != (apiv1.RouteExplainRequest{}) {
		t.Fatalf("mode-mismatch connection unexpectedly invoked simulator: %+v", explainer.request)
	}
}

func TestObservedConnectionsRejectsRoutingModeChange(t *testing.T) {
	generationID := int64(13)
	store := &fakeObservedConnectionsStore{snapshots: []storage.Snapshot{
		{
			Revision:            7,
			AppliedGenerationID: &generationID,
			RoutingMode:         storage.RoutingModeRule,
		},
		{
			Revision:            7,
			AppliedGenerationID: &generationID,
			RoutingMode:         storage.RoutingModeGlobal,
		},
	}}
	runtime := &fakeObservedConnectionsRuntime{
		snapshot: core.Snapshot{State: core.StateRunning, PID: 123},
		mode:     storage.RoutingModeRule,
		raw:      coreapi.ConnectionsSnapshot{},
	}
	coordinator, err := NewObservedConnectionsCoordinator(store, runtime, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.List(context.Background()); !errors.Is(err, ErrConnectionRoutingModeChanged) {
		t.Fatalf("routing mode change error = %v", err)
	}
}
