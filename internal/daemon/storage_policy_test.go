package daemon

import (
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestResolveStorageRetentionPolicyDefaults(t *testing.T) {
	t.Setenv(storageKeepConfirmedEnv, "")
	t.Setenv(storageGenerationQuotaEnv, "")

	policy, err := resolveStorageRetentionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy != storage.DefaultRetentionPolicy() {
		t.Fatalf("policy = %+v, want %+v", policy, storage.DefaultRetentionPolicy())
	}
}

func TestResolveStorageRetentionPolicyOverrides(t *testing.T) {
	t.Setenv(storageKeepConfirmedEnv, "7")
	t.Setenv(storageGenerationQuotaEnv, "768")

	policy, err := resolveStorageRetentionPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if policy.ConfirmedGenerations != 7 || policy.MaxGenerationBytes != 768<<20 {
		t.Fatalf("unexpected overridden policy: %+v", policy)
	}
}

func TestResolveStorageRetentionPolicyRejectsUnsafeValues(t *testing.T) {
	t.Setenv(storageKeepConfirmedEnv, "1")
	t.Setenv(storageGenerationQuotaEnv, "")
	if _, err := resolveStorageRetentionPolicy(); err == nil {
		t.Fatal("expected unsafe confirmed generation count to fail")
	}

	t.Setenv(storageKeepConfirmedEnv, "")
	t.Setenv(storageGenerationQuotaEnv, "0")
	if _, err := resolveStorageRetentionPolicy(); err == nil {
		t.Fatal("expected zero generation quota to fail")
	}
}
