package daemon

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreapi"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var (
	ErrConnectionObservationUnavailable = errors.New("connection observation is unavailable")
	ErrConnectionObservationBusy        = errors.New("connection observation is unavailable during a core transition")
	ErrConnectionGenerationChanged      = errors.New("applied generation changed during connection observation")
	ErrConnectionRoutingModeChanged     = errors.New("routing mode changed during connection observation")
)

type observedConnectionsStore interface {
	Snapshot(context.Context) (storage.Snapshot, error)
}

type observedConnectionsRuntime interface {
	Snapshot() core.Snapshot
	Connections(context.Context) (coreapi.ConnectionsSnapshot, error)
	ActiveOperation() OperationSnapshot
}

type routeExplainEngine interface {
	Explain(context.Context, apiv1.RouteExplainRequest) (apiv1.RouteExplainResponse, error)
}

type ObservedConnectionsCoordinator struct {
	store     observedConnectionsStore
	runtime   observedConnectionsRuntime
	explainer routeExplainEngine
}

func NewObservedConnectionsCoordinator(
	store observedConnectionsStore,
	runtime observedConnectionsRuntime,
	explainer routeExplainEngine,
) (*ObservedConnectionsCoordinator, error) {
	if store == nil {
		return nil, errors.New("connection observation store is nil")
	}
	if runtime == nil {
		return nil, errors.New("connection observation runtime is nil")
	}
	return &ObservedConnectionsCoordinator{
		store:     store,
		runtime:   runtime,
		explainer: explainer,
	}, nil
}

func (c *ObservedConnectionsCoordinator) List(
	ctx context.Context,
) (apiv1.ObservedConnectionsResponse, error) {
	if c.runtime.Snapshot().State != core.StateRunning {
		return apiv1.ObservedConnectionsResponse{}, ErrConnectionObservationUnavailable
	}
	if operation := c.runtime.ActiveOperation(); operation.Name != "" {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf(
			"%w: %s",
			ErrConnectionObservationBusy,
			operation.Name,
		)
	}
	before, err := c.store.Snapshot(ctx)
	if err != nil {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf("read state before connection observation: %w", err)
	}
	if before.AppliedGenerationID == nil {
		return apiv1.ObservedConnectionsResponse{}, ErrConnectionObservationUnavailable
	}

	raw, err := c.runtime.Connections(ctx)
	if err != nil {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf("read core connection snapshot: %w", err)
	}
	after, err := c.store.Snapshot(ctx)
	if err != nil {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf("read state after connection observation: %w", err)
	}
	if operation := c.runtime.ActiveOperation(); operation.Name != "" {
		return apiv1.ObservedConnectionsResponse{}, fmt.Errorf(
			"%w: %s",
			ErrConnectionObservationBusy,
			operation.Name,
		)
	}
	if before.Revision != after.Revision ||
		!sameGenerationID(before.AppliedGenerationID, after.AppliedGenerationID) {
		return apiv1.ObservedConnectionsResponse{}, ErrConnectionGenerationChanged
	}
	if before.RoutingMode != after.RoutingMode || before.PrivateDirect != after.PrivateDirect {
		return apiv1.ObservedConnectionsResponse{}, ErrConnectionRoutingModeChanged
	}

	sourceModeAligned := true
	sourceModeReason := ""
	if modeReader, ok := c.runtime.(interface {
		CurrentRoutingPolicy(context.Context) (storage.RoutingMode, bool, error)
	}); ok {
		liveMode, livePrivate, modeErr := modeReader.CurrentRoutingPolicy(ctx)
		if modeErr != nil {
			sourceModeAligned = false
			sourceModeReason = "routing_mode_readback"
		} else if liveMode != before.RoutingMode ||
			(before.RoutingMode != storage.RoutingModeDirect && livePrivate != before.PrivateDirect) {
			sourceModeAligned = false
			sourceModeReason = "routing_mode_mismatch"
		}
	}

	response := apiv1.ObservedConnectionsResponse{
		APIVersion:     apiv1.Version,
		Evidence:       "observed",
		ConfigRevision: before.Revision,
		GenerationID:   *before.AppliedGenerationID,
		DownloadTotal:  raw.DownloadTotal,
		UploadTotal:    raw.UploadTotal,
		Connections:    make([]apiv1.ObservedConnectionResponse, 0, len(raw.Connections)),
	}
	for _, connection := range raw.Connections {
		item := apiv1.ObservedConnectionResponse{
			ID:              connection.ID,
			Evidence:        "observed",
			Start:           connection.Start.UTC().Format("2006-01-02T15:04:05.999999999Z07:00"),
			Network:         connection.Metadata.Network,
			Inbound:         connection.Metadata.Type,
			SourceIP:        connection.Metadata.SourceIP,
			SourcePort:      connection.Metadata.SourcePort,
			DestinationIP:   connection.Metadata.DestinationIP,
			DestinationPort: connection.Metadata.DestinationPort,
			Host:            connection.Metadata.Host,
			ProcessPath:     connection.Metadata.ProcessPath,
			PackageName:     connection.Metadata.PackageName,
			User:            connection.Metadata.User,
			Protocol:        connection.Metadata.Protocol,
			Upload:          connection.Upload,
			Download:        connection.Download,
			Chains:          append([]string(nil), connection.Chains...),
			Rule:            connection.Rule,
			RulePayload:     connection.RulePayload,
			SourceEvidence:  "unknown",
		}
		if sourceModeAligned {
			c.attachSimulatedSource(ctx, before, connection, &item)
		} else {
			item.SourceUnknownConditions = []string{sourceModeReason}
		}
		response.Connections = append(response.Connections, item)
	}
	return response, nil
}

func (c *ObservedConnectionsCoordinator) attachSimulatedSource(
	ctx context.Context,
	snapshot storage.Snapshot,
	connection coreapi.ConnectionInfo,
	item *apiv1.ObservedConnectionResponse,
) {
	if c.explainer == nil || snapshot.AppliedGenerationID == nil {
		return
	}
	request, unknown := observedRouteExplainRequest(connection.Metadata)
	if len(unknown) != 0 {
		item.SourceUnknownConditions = unknown
		return
	}
	explanation, err := c.explainer.Explain(ctx, request)
	if err != nil {
		item.SourceUnknownConditions = []string{"source_explain_error"}
		return
	}
	if explanation.GenerationID != *snapshot.AppliedGenerationID ||
		explanation.ConfigRevision != snapshot.Revision {
		item.SourceUnknownConditions = []string{"source_generation_mismatch"}
		return
	}
	item.SourceEvidence = explanation.Evidence
	item.SourceDecision = explanation.Decision
	item.SourceRuleIndex = explanation.RuleIndex
	item.Source = explanation.Source
	item.SourceLayer = explanation.Layer
	item.SourceGroupID = explanation.GroupID
	item.SourceFinal = explanation.Final
	item.SourceTarget = explanation.Target
	item.SourceDNSProfileID = explanation.DNSProfileID
	item.SourceUnknownConditions = append([]string(nil), explanation.UnknownConditions...)
}

func observedRouteExplainRequest(
	metadata coreapi.ConnectionMetadata,
) (apiv1.RouteExplainRequest, []string) {
	var request apiv1.RouteExplainRequest
	switch {
	case strings.HasSuffix(metadata.Type, "/"+domain.InboundTagRule):
		request.Entry = string(domain.InboundRule)
	case strings.HasSuffix(metadata.Type, "/"+domain.InboundTagDirect):
		request.Entry = string(domain.InboundDirect)
	case strings.HasSuffix(metadata.Type, "/"+domain.InboundTagSelected):
		request.Entry = string(domain.InboundSelected)
	default:
		return apiv1.RouteExplainRequest{}, []string{"inbound"}
	}

	switch metadata.Network {
	case string(domain.NetworkTCP), string(domain.NetworkUDP):
		request.Network = metadata.Network
	default:
		return apiv1.RouteExplainRequest{}, []string{"network"}
	}

	if metadata.DestinationPort != "" {
		port, err := strconv.ParseUint(metadata.DestinationPort, 10, 16)
		if err != nil || port == 0 {
			return apiv1.RouteExplainRequest{}, []string{"destination_port"}
		}
		request.Port = uint16(port)
	}
	if metadata.DestinationIP != "" {
		address, err := netip.ParseAddr(metadata.DestinationIP)
		if err != nil {
			return apiv1.RouteExplainRequest{}, []string{"destination_ip"}
		}
		request.IP = address.Unmap().String()
	}
	if metadata.Host != "" {
		if _, err := netip.ParseAddr(metadata.Host); err != nil {
			request.Domain = metadata.Host
		} else if request.IP == "" {
			request.IP = metadata.Host
		}
	}
	return request, nil
}

func sameGenerationID(left, right *int64) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}
