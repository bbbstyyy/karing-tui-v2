package profile

import (
	"errors"
	"reflect"
	"testing"
)

func TestStableNodeIDIsDeterministicAndProfileScoped(t *testing.T) {
	first, err := StableNodeID("profile-a", "proxy/tag-a")
	if err != nil {
		t.Fatal(err)
	}
	again, err := StableNodeID("profile-a", "proxy/tag-a")
	if err != nil {
		t.Fatal(err)
	}
	otherProfile, err := StableNodeID("profile-b", "proxy/tag-a")
	if err != nil {
		t.Fatal(err)
	}
	if first != again {
		t.Fatalf("stable ID changed: %q != %q", first, again)
	}
	if first == otherProfile {
		t.Fatalf("profile scope did not affect node ID: %q", first)
	}
	if len(first) != len(stableNodeIDPrefix)+64 {
		t.Fatalf("unexpected stable ID length: %q", first)
	}
}

func TestReconcilePreservesPriorNodeIDAndReportsSourceRename(t *testing.T) {
	previous := []NodeIdentity{{
		ProfileID:  "profile-a",
		NodeID:     "legacy-node-id",
		SourceKey:  "provider-key-1",
		SourceName: "Old Name",
	}}
	got, err := ReconcileNodeIdentities("profile-a", previous, []SourceNode{{
		SourceKey:  "provider-key-1",
		SourceName: "New Name",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Current) != 1 || got.Current[0].NodeID != "legacy-node-id" {
		t.Fatalf("prior NodeID was not preserved: %+v", got.Current)
	}
	if len(got.Added) != 0 || len(got.Removed) != 0 {
		t.Fatalf("rename became add/remove: %+v", got)
	}
	wantRename := []NodeRename{{
		NodeID:     "legacy-node-id",
		SourceKey:  "provider-key-1",
		BeforeName: "Old Name",
		AfterName:  "New Name",
	}}
	if !reflect.DeepEqual(got.Renamed, wantRename) {
		t.Fatalf("rename = %+v, want %+v", got.Renamed, wantRename)
	}
}

func TestReconcileNeverRebindsSameNameAcrossChangedSourceKey(t *testing.T) {
	previous := []NodeIdentity{{
		ProfileID:  "profile-a",
		NodeID:     "old-node-id",
		SourceKey:  "old-key",
		SourceName: "Same Display Name",
	}}
	got, err := ReconcileNodeIdentities("profile-a", previous, []SourceNode{{
		SourceKey:  "new-key",
		SourceName: "Same Display Name",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Added) != 1 || len(got.Removed) != 1 || len(got.Renamed) != 0 {
		t.Fatalf("changed source key was heuristically rebound: %+v", got)
	}
	if got.Added[0].NodeID == "old-node-id" {
		t.Fatalf("changed source key reused old node ID: %+v", got.Added[0])
	}
	if got.Removed[0].NodeID != "old-node-id" {
		t.Fatalf("removed identity = %+v", got.Removed)
	}
}

func TestReconcilePreservesIncomingOrderAndReportsRemoval(t *testing.T) {
	idA, err := StableNodeID("profile-a", "a")
	if err != nil {
		t.Fatal(err)
	}
	idB, err := StableNodeID("profile-a", "b")
	if err != nil {
		t.Fatal(err)
	}
	previous := []NodeIdentity{
		{ProfileID: "profile-a", NodeID: idA, SourceKey: "a", SourceName: "A"},
		{ProfileID: "profile-a", NodeID: idB, SourceKey: "b", SourceName: "B"},
	}
	got, err := ReconcileNodeIdentities("profile-a", previous, []SourceNode{
		{SourceKey: "b", SourceName: "B"},
		{SourceKey: "c", SourceName: "C"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Current) != 2 || got.Current[0].SourceKey != "b" || got.Current[1].SourceKey != "c" {
		t.Fatalf("incoming order was not preserved: %+v", got.Current)
	}
	if len(got.Added) != 1 || got.Added[0].SourceKey != "c" {
		t.Fatalf("added = %+v", got.Added)
	}
	if len(got.Removed) != 1 || got.Removed[0].SourceKey != "a" {
		t.Fatalf("removed = %+v", got.Removed)
	}
}

func TestReconcileRejectsDuplicateIncomingSourceKeys(t *testing.T) {
	_, err := ReconcileNodeIdentities("profile-a", nil, []SourceNode{
		{SourceKey: "dup", SourceName: "A"},
		{SourceKey: "dup", SourceName: "B"},
	})
	if !errors.Is(err, ErrDuplicateSourceKey) {
		t.Fatalf("duplicate source key error = %v", err)
	}
}

func TestReconcileRejectsPriorIdentityFromAnotherProfile(t *testing.T) {
	_, err := ReconcileNodeIdentities("profile-a", []NodeIdentity{{
		ProfileID:  "profile-b",
		NodeID:     "node-1",
		SourceKey:  "key",
		SourceName: "Name",
	}}, nil)
	if !errors.Is(err, ErrInvalidPriorIdentity) {
		t.Fatalf("cross-profile prior identity error = %v", err)
	}
}

func TestReconcileRejectsControlCharactersInsteadOfNormalizing(t *testing.T) {
	_, err := ReconcileNodeIdentities("profile-a", nil, []SourceNode{{
		SourceKey:  "bad\nkey",
		SourceName: "Name",
	}})
	if !errors.Is(err, ErrInvalidSourceNode) {
		t.Fatalf("invalid source key error = %v", err)
	}
}
