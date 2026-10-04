package apiv1

const Version = "v1"

type StatusResponse struct {
	APIVersion     string `json:"api_version"`
	DaemonVersion  string `json:"daemon_version"`
	DaemonCommit   string `json:"daemon_commit"`
	PID            int    `json:"pid"`
	StartedAt      string `json:"started_at"`
	UptimeSeconds  int64  `json:"uptime_seconds"`
	ConfigRevision uint64 `json:"config_revision"`
	CoreState      string `json:"core_state"`
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
