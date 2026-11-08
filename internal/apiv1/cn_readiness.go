package apiv1

// CNResourceReadinessResponse describes the pinned source inventory, not an
// observed Core route or a verified locally installed ruleset. A successful
// GET does not authorize enabling/distributing the CN preset.
type CNResourceReadinessResponse struct {
	Evidence             string                   `json:"evidence"`
	SourceRepository     string                   `json:"source_repository"`
	SourceCommit         string                   `json:"source_commit"`
	SourcePath           string                   `json:"source_path"`
	DistributionReady    bool                     `json:"distribution_ready"`
	LicenseStatus        string                   `json:"license_status"`
	BlockingCodes        []string                 `json:"blocking_codes"`
	KnownUpstreamAbsent  []string                 `json:"known_upstream_absent"`
	LogicalResourceRefs  int                      `json:"logical_resource_refs"`
	FileBackedCandidates int                      `json:"file_backed_candidates"`
	TotalGroupCount      int                      `json:"total_group_count"`
	DefaultEnabledCount  int                      `json:"default_enabled_count"`
	RegionAppendRefs     []string                 `json:"region_append_refs"`
	Groups               []CNPresetReadinessGroup `json:"groups"`
}

type CNPresetReadinessGroup struct {
	ID                      string   `json:"id"`
	Order                   uint32   `json:"order"`
	Name                    string   `json:"name"`
	EnabledByDefault        bool     `json:"enabled_by_default"`
	TargetKind              string   `json:"target_kind"`
	RuleSetRefs             []string `json:"rule_set_refs"`
	DomainSuffixCount       int      `json:"domain_suffix_count"`
	DomainKeywordCount      int      `json:"domain_keyword_count"`
	IPCIDRCount             int      `json:"ip_cidr_count"`
	ProcessNameCount        int      `json:"process_name_count"`
	AndroidOnlyPackageCount int      `json:"android_only_package_count"`
}
