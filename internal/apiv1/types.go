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

// ConfigInspection is a bounded privacy-safe *declaration* projection.
// It does not claim any packet, DNS request or rule match was observed.
// A later staged declaration is compared for semantic drift only.
type ConfigInspectionResponse struct {
	APIVersion                 string                  `json:"api_version"`
	Evidence                   string                  `json:"evidence"`
	ConfigRevision             uint64                  `json:"config_revision"`
	GenerationID               int64                   `json:"generation_id"`
	AppliedDeclarationRevision uint64                  `json:"applied_declaration_revision"`
	CurrentDeclarationRevision uint64                  `json:"current_declaration_revision"`
	StagedUnapplied            bool                    `json:"staged_unapplied"`
	RoutingChanged             bool                    `json:"routing_changed"`
	DNSChanged                 bool                    `json:"dns_changed"`
	RuleSetsChanged            bool                    `json:"rule_sets_changed"`
	CNPreset                   bool                    `json:"cn_preset"`
	RegionAppend               bool                    `json:"region_append"`
	RouteTotal                 int                     `json:"route_total"`
	RouteTruncated             bool                    `json:"route_truncated"`
	Layers                     []ConfigInspectionLayer `json:"layers"`
	DNS                        ConfigInspectionDNS     `json:"dns"`
}

type ConfigInspectionLayer struct {
	Layer       domain.RoutingLayer          `json:"layer"`
	Enabled     bool                         `json:"enabled"`
	GroupCount  int                          `json:"group_count"`
	ActiveCount int                          `json:"active_count"`
	Groups      []ConfigInspectionRouteGroup `json:"groups"`
}

type ConfigInspectionRouteGroup struct {
	ID         string           `json:"id"`
	Order      uint32           `json:"order"`
	Enabled    bool             `json:"enabled"`
	Origin     string           `json:"origin"`
	MatchKinds []string         `json:"match_kinds,omitempty"`
	Target     domain.TargetRef `json:"target"`
	DNSProfile string           `json:"dns_profile_id,omitempty"`
}

type ConfigInspectionDNS struct {
	OutboundProfile string                       `json:"outbound_profile_id"`
	DirectProfile   string                       `json:"direct_profile_id,omitempty"`
	ProxyProfile    string                       `json:"proxy_profile_id,omitempty"`
	FallbackProfile string                       `json:"fallback_profile_id,omitempty"`
	ProfileCount    int                          `json:"profile_count"`
	Truncated       bool                         `json:"truncated"`
	Profiles        []ConfigInspectionDNSProfile `json:"profiles"`
}

type ConfigInspectionDNSProfile struct {
	ID           string              `json:"id"`
	Role         domain.DNSRole      `json:"role"`
	Transport    domain.DNSTransport `json:"transport"`
	Port         uint16              `json:"port"`
	UpstreamKind string              `json:"upstream_kind"`
	BootstrapID  string              `json:"bootstrap_id,omitempty"`
	Detour       *domain.TargetRef   `json:"detour,omitempty"`
}

// RouteEditContext contains non-secret, optimistic bindings needed to form an
// edit proposal. A staged declaration is not evidence of live core behavior.
type RouteEditContext struct {
	APIVersion          string `json:"api_version"`
	DeclarationRevision uint64 `json:"declaration_revision"`
	DeclarationSHA256   string `json:"declaration_sha256"`
	ConfigRevision      uint64 `json:"config_revision"`
	AppliedGenerationID *int64 `json:"applied_generation_id"`
	SelectionRevision   uint64 `json:"selection_revision"`
}

// RouteEditRequest changes precisely one field of an existing route group.
// Missing pointers mean "no edit"; a DNS pointer to "" explicitly clears it.
type RouteEditRequest struct {
	ExpectedDeclarationRevision uint64              `json:"expected_declaration_revision"`
	ExpectedDeclarationSHA256   string              `json:"expected_declaration_sha256"`
	ExpectedConfigRevision      uint64              `json:"expected_config_revision"`
	ExpectedGenerationID        *int64              `json:"expected_generation_id"`
	ExpectedSelectionRevision   uint64              `json:"expected_selection_revision"`
	Layer                       domain.RoutingLayer `json:"layer"`
	GroupID                     string              `json:"group_id"`
	Enabled                     *bool               `json:"enabled,omitempty"`
	Target                      *domain.TargetRef   `json:"target,omitempty"`
	DNSProfileID                *string             `json:"dns_profile_id,omitempty"`
}

// A preview receipt can be handed back as a stage request with both immutable
// digests. The candidate and native JSON are deliberately absent.
type RouteEditPreviewResponse struct {
	APIVersion         string           `json:"api_version"`
	Request            RouteEditRequest `json:"request"`
	Origin             string           `json:"origin"`
	BeforeEnabled      bool             `json:"before_enabled"`
	AfterEnabled       bool             `json:"after_enabled"`
	BeforeTarget       domain.TargetRef `json:"before_target"`
	AfterTarget        domain.TargetRef `json:"after_target"`
	BeforeDNSProfileID string           `json:"before_dns_profile_id"`
	AfterDNSProfileID  string           `json:"after_dns_profile_id"`
	CandidateSHA256    string           `json:"candidate_sha256"`
	NativeConfigSHA256 string           `json:"native_config_sha256"`
	NativeSchemaID     string           `json:"native_schema_id"`
	RouteEntryCount    int              `json:"route_entry_count"`
	DNSServerCount     int              `json:"dns_server_count"`
	RuleSetCount       int              `json:"rule_set_count"`
	CompilerValidated  bool             `json:"compiler_validated"`
	CoreValidated      bool             `json:"core_validated"`
	Staged             bool             `json:"staged"`
	Applied            bool             `json:"applied"`
}

type RouteEditStageRequest struct {
	RouteEditRequest
	CandidateSHA256    string `json:"candidate_sha256"`
	NativeConfigSHA256 string `json:"native_config_sha256"`
}

type RouteEditStageResponse struct {
	DeclarationRevision uint64 `json:"declaration_revision"`
	DeclarationSHA256   string `json:"declaration_sha256"`
	NativeConfigSHA256  string `json:"native_config_sha256"`
	CompilerValidated   bool   `json:"compiler_validated"`
	CoreValidated       bool   `json:"core_validated"`
	Staged              bool   `json:"staged"`
	Applied             bool   `json:"applied"`
}

// A checked apply receipt binds the current unapplied declaration to the
// runtime config, generation, selector revision and compiler-produced bytes.
// It never contains source/native JSON, DNS endpoints or node credentials.
type CheckedApplyReceipt struct {
	DeclarationRevision        uint64 `json:"declaration_revision"`
	DeclarationSHA256          string `json:"declaration_sha256"`
	ExpectedConfigRevision     uint64 `json:"expected_config_revision"`
	ExpectedAppliedGenerationID *int64 `json:"expected_applied_generation_id"`
	ExpectedSelectionRevision  uint64 `json:"expected_selection_revision"`
	NativeConfigSHA256         string `json:"native_config_sha256"`
}

type CheckedApplyPreviewResponse struct {
	APIVersion        string              `json:"api_version"`
	Receipt           CheckedApplyReceipt `json:"receipt"`
	NativeSchemaID    string              `json:"native_schema_id"`
	RouteEntryCount   int                 `json:"route_entry_count"`
	DNSServerCount    int                 `json:"dns_server_count"`
	RuleSetCount      int                 `json:"rule_set_count"`
	CompilerValidated bool                `json:"compiler_validated"`
	CoreValidated     bool                `json:"core_validated"`
	Applied           bool                `json:"applied"`
}

type CheckedApplyResponse struct {
	DeclarationApplyResponse
	CoreChecked bool `json:"core_checked"`
	Verified    bool `json:"verified"`
	Applied     bool `json:"applied"`
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

type ProfileSourceFetchPolicy struct {
	Mode      string `json:"mode"`
	ProfileID string `json:"profile_id,omitempty"`
	NodeID    string `json:"node_id,omitempty"`
}

type ProfileSourceFilter struct {
	Method         string `json:"method,omitempty"`
	KeywordOrRegex string `json:"keyword_or_regex,omitempty"`
	MatchAttribute bool   `json:"match_attribute,omitempty"`
}

type ProfileSourceSpec struct {
	Format                string                   `json:"format"`
	LocationKind          string                   `json:"location_kind"`
	Location              string                   `json:"location"`
	UserAgent             string                   `json:"user_agent,omitempty"`
	Fetch                 ProfileSourceFetchPolicy `json:"fetch"`
	Filter                ProfileSourceFilter      `json:"filter,omitempty"`
	UpdateIntervalSeconds int64                    `json:"update_interval_seconds"`
	Enabled               bool                     `json:"enabled"`
}

type ProfileSourcePutRequest struct {
	ExpectedRevision uint64            `json:"expected_revision"`
	Source           ProfileSourceSpec `json:"source"`
}

type ProfileSourceResponse struct {
	ProfileID             string            `json:"profile_id"`
	Revision              uint64            `json:"revision"`
	Source                ProfileSourceSpec `json:"source"`
	CreatedAt             string            `json:"created_at"`
	UpdatedAt             string            `json:"updated_at"`
	LastAttemptAt         string            `json:"last_attempt_at,omitempty"`
	LastSuccessAt         string            `json:"last_success_at,omitempty"`
	LastError             string            `json:"last_error,omitempty"`
	LastSourceRevision    string            `json:"last_source_revision,omitempty"`
	ETag                  string            `json:"etag,omitempty"`
	LastModified          string            `json:"last_modified,omitempty"`
	ConsecutiveFailures   uint32            `json:"consecutive_failures"`
	RetryAfterAt          string            `json:"retry_after_at,omitempty"`
	ActiveUpdateID        string            `json:"active_update_id,omitempty"`
	ActiveUpdateStartedAt string            `json:"active_update_started_at,omitempty"`
	CurrentSnapshotID     *int64            `json:"current_snapshot_id,omitempty"`
}
type ProfileSourceListResponse struct {
	Profiles []ProfileSourceResponse `json:"profiles"`
}

type ProfileRefreshRequest struct {
	ExpectedSourceRevision uint64 `json:"expected_source_revision"`
	AllowEmpty             bool   `json:"allow_empty,omitempty"`
}

type ProfileDiagnosticResponse struct {
	Level   string `json:"level"`
	Path    string `json:"path,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

type ProfileRefreshResponse struct {
	ProfileID         string                      `json:"profile_id"`
	SourceRevision    uint64                      `json:"source_revision"`
	AcceptedRevision  string                      `json:"accepted_source_revision,omitempty"`
	NotModified       bool                        `json:"not_modified"`
	CurrentSnapshotID *int64                      `json:"current_snapshot_id,omitempty"`
	NodeCount         int                         `json:"node_count,omitempty"`
	Diagnostics       []ProfileDiagnosticResponse `json:"diagnostics,omitempty"`
}

type ProfileRefreshErrorResponse struct {
	Error       string                      `json:"error"`
	Diagnostics []ProfileDiagnosticResponse `json:"diagnostics,omitempty"`
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
	ProfileID          string                            `json:"profile_id"`
	SourceRevision     uint64                            `json:"source_revision"`
	Usage              *ProfileSubscriptionUsageResponse `json:"usage,omitempty"`
	UsageUpdatedAt     string                            `json:"usage_updated_at,omitempty"`
	MetadataObservedAt string                            `json:"metadata_observed_at,omitempty"`
	MetadataError      string                            `json:"metadata_error,omitempty"`
	HeaderObserved     bool                              `json:"header_observed"`
	ObservationApplied bool                              `json:"observation_applied"`
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

// This is a distinct guarded endpoint: legacy unqualified PUT remains
// compatible but never silently upgrades into a checked mutation.
type CurrentSelectionCheckedRequest struct {
	Target                      domain.TargetRef `json:"target"`
	ExpectedSelectionRevision   uint64           `json:"expected_selection_revision"`
	ExpectedConfigRevision      uint64           `json:"expected_config_revision"`
	ExpectedGenerationID        *int64           `json:"expected_generation_id"`
	ExpectedDeclarationRevision uint64           `json:"expected_declaration_revision"`
	ExpectedDeclarationSHA256   string           `json:"expected_declaration_sha256"`
}

type CurrentSelectionResponse struct {
	Target              domain.TargetRef   `json:"target"`
	RuntimeTag          string             `json:"runtime_tag"`
	Persisted           bool               `json:"persisted"`
	UpdatedAt           string             `json:"updated_at,omitempty"`
	Applied             bool               `json:"applied"`
	LiveRuntimeTag      string             `json:"live_runtime_tag,omitempty"`
	SelectionRevision   uint64             `json:"selection_revision"`
	ConfigRevision      uint64             `json:"config_revision"`
	AppliedGenerationID *int64             `json:"applied_generation_id"`
	DeclarationRevision uint64             `json:"declaration_revision"`
	DeclarationSHA256   string             `json:"declaration_sha256"`
	Candidates          []domain.TargetRef `json:"candidates,omitempty"`
	CandidateCount      int                `json:"candidate_count"`
	CandidatesTruncated bool               `json:"candidates_truncated"`
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

type ProfileNodeSummary struct {
	NodeID          string `json:"node_id"`
	SourceName      string `json:"source_name"`
	DisplayName     string `json:"display_name"`
	OverlayRevision uint64 `json:"overlay_revision"`
	Disabled        bool   `json:"disabled"`
	Favorite        bool   `json:"favorite"`
	Alias           string `json:"alias,omitempty"`
	SortRank        *int64 `json:"sort_rank,omitempty"`
}
type ProfileNodeListResponse struct {
	ProfileID  string               `json:"profile_id"`
	SnapshotID *int64               `json:"snapshot_id,omitempty"`
	Total      int                  `json:"total"`
	Offset     int                  `json:"offset"`
	Limit      int                  `json:"limit"`
	Nodes      []ProfileNodeSummary `json:"nodes"`
}
type ProfileNodeOverlaySpec struct {
	Disabled bool   `json:"disabled"`
	Favorite bool   `json:"favorite"`
	Alias    string `json:"alias,omitempty"`
	SortRank *int64 `json:"sort_rank,omitempty"`
}
type ProfileNodeOverlayPutRequest struct {
	ExpectedRevision uint64                 `json:"expected_revision"`
	Overlay          ProfileNodeOverlaySpec `json:"overlay"`
}
type ProfileNodeOverlayResponse struct {
	ProfileID string                 `json:"profile_id"`
	NodeID    string                 `json:"node_id"`
	Revision  uint64                 `json:"revision"`
	UpdatedAt string                 `json:"updated_at"`
	Overlay   ProfileNodeOverlaySpec `json:"overlay"`
}

type ProfileDeclarationPreviewRequest struct {
	SnapshotID                  int64  `json:"snapshot_id"`
	ExpectedDeclarationRevision uint64 `json:"expected_declaration_revision"`
}

type ProfileDeclarationPreviewResponse struct {
	ProfileID               string `json:"profile_id"`
	SnapshotID              int64  `json:"snapshot_id"`
	BaseDeclarationRevision uint64 `json:"base_declaration_revision"`
	SourceRevision          uint64 `json:"source_revision"`
	SnapshotNodeCount       int    `json:"snapshot_node_count"`
	EffectiveNodeCount      int    `json:"effective_node_count"`
	AddedNodeCount          int    `json:"added_node_count"`
	RemovedNodeCount        int    `json:"removed_node_count"`
	RetainedNodeCount       int    `json:"retained_node_count"`
	RuntimeOverlaySHA256    string `json:"runtime_overlay_sha256"`
	CandidateSHA256         string `json:"candidate_sha256"`
	CoreValidated           bool   `json:"core_validated"`
	Applied                 bool   `json:"applied"`
}

type ProfileDeclarationStageRequest struct {
	SnapshotID                  int64  `json:"snapshot_id"`
	ExpectedSourceRevision      uint64 `json:"expected_source_revision"`
	ExpectedDeclarationRevision uint64 `json:"expected_declaration_revision"`
	CandidateSHA256             string `json:"candidate_sha256"`
	RuntimeOverlaySHA256        string `json:"runtime_overlay_sha256"`
}
type ProfileDeclarationStageResponse struct {
	ProfileID           string `json:"profile_id"`
	SourceRevision      uint64 `json:"source_revision"`
	SnapshotID          int64  `json:"snapshot_id"`
	DeclarationRevision uint64 `json:"declaration_revision"`
	DeclarationSHA256   string `json:"declaration_sha256"`
	CoreValidated       bool   `json:"core_validated"`
	Applied             bool   `json:"applied"`
}
