package apiv1

import (
	"encoding/json"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

const Version = "v1"

type StatusResponse struct {
	APIVersion                string `json:"api_version"`
	DaemonVersion             string `json:"daemon_version"`
	DaemonCommit              string `json:"daemon_commit"`
	PID                       int    `json:"pid"`
	StartedAt                 string `json:"started_at"`
	UptimeSeconds             int64  `json:"uptime_seconds"`
	ConfigRevision            uint64 `json:"config_revision"`
	DeclarationRevision       uint64 `json:"declaration_revision"`
	AppliedGenerationID       *int64 `json:"applied_generation_id,omitempty"`
	LastKnownGoodGenerationID *int64 `json:"last_known_good_generation_id,omitempty"`
	RecoveryRequired          bool   `json:"recovery_required"`
	CoreDesiredState          string `json:"core_desired_state"`
	RoutingMode               string `json:"routing_mode"`
	PrivateDirect             bool   `json:"private_direct"`
	CoreConfigured            bool   `json:"core_configured"`
	CoreState                 string `json:"core_state"`
	CorePID                   int    `json:"core_pid,omitempty"`
	CoreCircuitOpen           bool   `json:"core_circuit_open"`
	CoreConsecutiveFailures   int    `json:"core_consecutive_failures,omitempty"`
	CoreLastError             string `json:"core_last_error,omitempty"`
	ActiveOperation           string `json:"active_operation,omitempty"`
}

type CapabilitiesResponse struct {
	APIVersion   string          `json:"api_version"`
	Capabilities map[string]bool `json:"capabilities"`
}

type HealthResponse struct {
	Status string `json:"status"`
}

type ErrorResponse struct {
	Error string `json:"error"`
}

type DeclarationResponse struct {
	Revision       uint64          `json:"revision"`
	ParentRevision *uint64         `json:"parent_revision,omitempty"`
	SHA256         string          `json:"sha256,omitempty"`
	Source         string          `json:"source,omitempty"`
	CreatedAt      string          `json:"created_at,omitempty"`
	Document       json.RawMessage `json:"document,omitempty"`
}

type DeclarationCommitRequest struct {
	ExpectedRevision uint64          `json:"expected_revision"`
	Source           string          `json:"source"`
	Document         json.RawMessage `json:"document"`
}

type DeclarationCompileRequest struct {
	Revision uint64 `json:"revision"`
}

type DeclarationCompileResponse struct {
	Revision          uint64   `json:"revision"`
	DeclarationSHA256 string   `json:"declaration_sha256"`
	NativeSchemaID    string   `json:"native_schema_id"`
	ConfigSHA256      string   `json:"config_sha256"`
	InboundTags       []string `json:"inbound_tags"`
	OutboundTags      []string `json:"outbound_tags"`
	DNSServerTags     []string `json:"dns_server_tags,omitempty"`
	RouteEntryCount   int      `json:"route_entry_count"`
	RuleSetCount      int      `json:"rule_set_count"`
}

type DeclarationApplyRequest struct {
	DeclarationRevision    uint64 `json:"declaration_revision"`
	ExpectedConfigRevision uint64 `json:"expected_config_revision"`
}

type DeclarationApplyResponse struct {
	DeclarationRevision  uint64 `json:"declaration_revision"`
	DeclarationSHA256    string `json:"declaration_sha256"`
	NativeSchemaID       string `json:"native_schema_id"`
	ConfigSHA256         string `json:"config_sha256"`
	AttemptID            int64  `json:"attempt_id"`
	GenerationID         int64  `json:"generation_id"`
	BaseConfigRevision   uint64 `json:"base_config_revision"`
	TargetConfigRevision uint64 `json:"target_config_revision"`
}

type RuleSetUploadResponse struct {
	SHA256 string `json:"sha256"`
	Format string `json:"format"`
	Bytes  int64  `json:"bytes"`
}

type ProfileMetadataRefreshRequest struct {
	ExpectedSourceRevision uint64 `json:"expected_source_revision"`
}

type ProfileSubscriptionUsageResponse struct {
	UploadBytes   *int64 `json:"upload_bytes,omitempty"`
	DownloadBytes *int64 `json:"download_bytes,omitempty"`
	TotalBytes    *int64 `json:"total_bytes,omitempty"`
	ExpiresAt     string `json:"expires_at,omitempty"`
}

type ProfileMetadataResponse struct {
	ProfileID                  string                            `json:"profile_id"`
	SourceRevision             uint64                            `json:"source_revision"`
	Usage                      *ProfileSubscriptionUsageResponse `json:"usage,omitempty"`
	UsageUpdatedAt             string                            `json:"usage_updated_at,omitempty"`
	MetadataObservedAt         string                            `json:"metadata_observed_at,omitempty"`
	MetadataError              string                            `json:"metadata_error,omitempty"`
	HeaderObserved             bool                              `json:"header_observed"`
	ObservationApplied         bool                              `json:"observation_applied"`
}


type StorageRetentionResponse struct {
	ConfirmedGenerations     int   `json:"confirmed_generations"`
	MaxGenerationBytes       int64 `json:"max_generation_bytes"`
	LiveGenerationCount      int   `json:"live_generation_count"`
	LiveGenerationBytes      int64 `json:"live_generation_bytes"`
	ProtectedGenerationCount int   `json:"protected_generation_count"`
	ActiveAttemptCount       int   `json:"active_attempt_count"`
	ArchivedAttemptCount     int   `json:"archived_attempt_count"`
	ArchivedThisRun          int64 `json:"archived_this_run,omitempty"`
	PrunedGenerationCount    int64 `json:"pruned_generation_count,omitempty"`
	ReclaimedGenerationBytes int64 `json:"reclaimed_generation_bytes,omitempty"`
	OverBudget               bool  `json:"over_budget"`
}

type CurrentSelectionRequest struct {
	Target domain.TargetRef `json:"target"`
}

type CurrentSelectionResponse struct {
	Target         domain.TargetRef `json:"target"`
	RuntimeTag     string           `json:"runtime_tag"`
	Persisted      bool             `json:"persisted"`
	UpdatedAt      string           `json:"updated_at,omitempty"`
	Applied        bool             `json:"applied"`
	LiveRuntimeTag string           `json:"live_runtime_tag,omitempty"`
}

type RouteExplainRequest struct {
	Entry       string `json:"entry,omitempty"`
	Domain      string `json:"domain,omitempty"`
	IP          string `json:"ip,omitempty"`
	Port        uint16 `json:"port,omitempty"`
	Network     string `json:"network,omitempty"`
	ProcessName string `json:"process_name,omitempty"`
}

type RouteExplainStep struct {
	RuleIndex         int                 `json:"rule_index"`
	Result            string              `json:"result"`
	Source            string              `json:"source"`
	ClashMode         string              `json:"clash_mode,omitempty"`
	IPIsPrivate       bool                `json:"ip_is_private,omitempty"`
	Layer             domain.RoutingLayer `json:"layer,omitempty"`
	GroupID           string              `json:"group_id,omitempty"`
	Final             bool                `json:"final,omitempty"`
	Target            *domain.TargetRef   `json:"target,omitempty"`
	Action            string              `json:"action,omitempty"`
	Outbound          string              `json:"outbound,omitempty"`
	Server            string              `json:"server,omitempty"`
	DNSProfileID      string              `json:"dns_profile_id,omitempty"`
	UnknownConditions []string            `json:"unknown_conditions,omitempty"`
}

type RouteExplainResponse struct {
	APIVersion          string              `json:"api_version"`
	Evidence            string              `json:"evidence"`
	Decision            string              `json:"decision"`
	ConfigRevision      uint64              `json:"config_revision"`
	GenerationID        int64               `json:"generation_id"`
	DeclarationRevision uint64              `json:"declaration_revision"`
	RoutingMode         string              `json:"routing_mode"`
	PrivateDirect       bool                `json:"private_direct"`
	Entry               string              `json:"entry"`
	Input               RouteExplainRequest `json:"input"`
	RuleIndex           *int                `json:"rule_index,omitempty"`
	Source              string              `json:"source,omitempty"`
	ClashMode           string              `json:"clash_mode,omitempty"`
	IPIsPrivate         bool                `json:"ip_is_private,omitempty"`
	Layer               domain.RoutingLayer `json:"layer,omitempty"`
	GroupID             string              `json:"group_id,omitempty"`
	Final               bool                `json:"final,omitempty"`
	Target              *domain.TargetRef   `json:"target,omitempty"`
	Action              string              `json:"action,omitempty"`
	Outbound            string              `json:"outbound,omitempty"`
	Server              string              `json:"server,omitempty"`
	DNSProfileID        string              `json:"dns_profile_id,omitempty"`
	UnknownConditions   []string            `json:"unknown_conditions,omitempty"`
	Trace               []RouteExplainStep  `json:"trace"`
}

type ObservedConnectionsResponse struct {
	APIVersion     string                       `json:"api_version"`
	Evidence       string                       `json:"evidence"`
	ConfigRevision uint64                       `json:"config_revision"`
	GenerationID   int64                        `json:"generation_id"`
	DownloadTotal  int64                        `json:"download_total"`
	UploadTotal    int64                        `json:"upload_total"`
	Connections    []ObservedConnectionResponse `json:"connections"`
}

type ObservedConnectionResponse struct {
	ID                      string              `json:"id"`
	Evidence                string              `json:"evidence"`
	Start                   string              `json:"start"`
	Network                 string              `json:"network"`
	Inbound                 string              `json:"inbound"`
	SourceIP                string              `json:"source_ip,omitempty"`
	SourcePort              string              `json:"source_port,omitempty"`
	DestinationIP           string              `json:"destination_ip,omitempty"`
	DestinationPort         string              `json:"destination_port,omitempty"`
	Host                    string              `json:"host,omitempty"`
	ProcessPath             string              `json:"process_path,omitempty"`
	PackageName             string              `json:"package_name,omitempty"`
	User                    string              `json:"user,omitempty"`
	Protocol                string              `json:"protocol,omitempty"`
	Upload                  int64               `json:"upload"`
	Download                int64               `json:"download"`
	Chains                  []string            `json:"chains,omitempty"`
	Rule                    string              `json:"rule,omitempty"`
	RulePayload             string              `json:"rule_payload,omitempty"`
	SourceEvidence          string              `json:"source_evidence"`
	SourceDecision          string              `json:"source_decision,omitempty"`
	SourceRuleIndex         *int                `json:"source_rule_index,omitempty"`
	Source                  string              `json:"source,omitempty"`
	SourceLayer             domain.RoutingLayer `json:"source_layer,omitempty"`
	SourceGroupID           string              `json:"source_group_id,omitempty"`
	SourceFinal             bool                `json:"source_final,omitempty"`
	SourceTarget            *domain.TargetRef   `json:"source_target,omitempty"`
	SourceDNSProfileID      string              `json:"source_dns_profile_id,omitempty"`
	SourceUnknownConditions []string            `json:"source_unknown_conditions,omitempty"`
}

type RoutingModeRequest struct {
	Mode          string `json:"mode,omitempty"`
	PrivateDirect *bool  `json:"private_direct,omitempty"`
}

type RoutingModeResponse struct {
	Mode              string `json:"mode"`
	PrivateDirect     bool   `json:"private_direct"`
	Applied           bool   `json:"applied"`
	LiveMode          string `json:"live_mode,omitempty"`
	LivePrivateDirect *bool  `json:"live_private_direct,omitempty"`
}
