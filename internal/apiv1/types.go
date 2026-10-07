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
