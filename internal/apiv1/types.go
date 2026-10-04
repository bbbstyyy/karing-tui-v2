package apiv1

const Version = "v1"

type StatusResponse struct {
	APIVersion                string `json:"api_version"`
	DaemonVersion             string `json:"daemon_version"`
	DaemonCommit              string `json:"daemon_commit"`
	PID                       int    `json:"pid"`
	StartedAt                 string `json:"started_at"`
	UptimeSeconds             int64  `json:"uptime_seconds"`
	ConfigRevision            uint64 `json:"config_revision"`
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
