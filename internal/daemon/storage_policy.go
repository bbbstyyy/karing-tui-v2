package daemon

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

const (
	storageKeepConfirmedEnv  = "KARING_TUI_KEEP_CONFIRMED_GENERATIONS"
	storageGenerationQuotaEnv = "KARING_TUI_GENERATION_QUOTA_MIB"
)

func resolveStorageRetentionPolicy() (storage.RetentionPolicy, error) {
	policy := storage.DefaultRetentionPolicy()

	if raw := strings.TrimSpace(os.Getenv(storageKeepConfirmedEnv)); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 2 || value > 1000 {
			return storage.RetentionPolicy{}, fmt.Errorf("%s must be an integer between 2 and 1000", storageKeepConfirmedEnv)
		}
		policy.ConfirmedGenerations = value
	}

	if raw := strings.TrimSpace(os.Getenv(storageGenerationQuotaEnv)); raw != "" {
		value, err := strconv.ParseUint(raw, 10, 63)
		const maxMiB = uint64((1<<63 - 1) / (1 << 20))
		if err != nil || value == 0 || value > maxMiB {
			return storage.RetentionPolicy{}, fmt.Errorf("%s must be a positive MiB integer", storageGenerationQuotaEnv)
		}
		policy.MaxGenerationBytes = int64(value * (1 << 20))
	}

	if err := policy.Validate(); err != nil {
		return storage.RetentionPolicy{}, err
	}
	return policy, nil
}
