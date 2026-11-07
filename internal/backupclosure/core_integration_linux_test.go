//go:build linux && integration

package backupclosure

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
)

// This runs only after verify-core-build.sh has generated a real approved
// artifact in managed-core-integration; unit tests never forge lock digests.
func TestApprovedCoreClosureWithRealBinary(t *testing.T) {
	path := os.Getenv("KARING_TUI_TEST_CORE")
	if path == "" {
		t.Skip("approved core binary was not supplied")
	}
	f := newFixture(t)
	f.commit(t, true)
	closure, err := BuildWithApprovedCore(context.Background(), f.store, f.stateRoot, f.parent, path)
	if err != nil {
		t.Fatal(err)
	}
	defer closure.Close()
	core := closure.Inventory.Core
	if core == nil || closure.Inventory.Format != CoreManifestVersion ||
		core.SHA256 != closure.corePin.SHA256() ||
		core.CandidateCommit != coreartifact.CandidateCommit ||
		core.Version != coreartifact.CandidateVersion || core.Size <= 0 ||
		closure.Inventory.RestoreReady {
		t.Fatalf("approved core was not bound to inventory: %+v", core)
	}
	if bytes.Contains(closure.InventoryJSON, []byte(path)) ||
		bytes.Contains(closure.InventoryJSON, []byte(f.stateRoot)) {
		t.Fatal("private executable location disclosed by manifest")
	}
	copyPath, ok := closure.copies.CoreFile()
	if !ok {
		t.Fatal("independent approved core copy is missing")
	}
	original, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	copied, err := os.Stat(copyPath)
	if err != nil || os.SameFile(original, copied) ||
		copied.Mode().Perm() != 0o400 ||
		filepath.Base(copyPath) != "core-"+core.SHA256+".bin" {
		t.Fatalf("approved core copy was not independently protected: %+v err=%v", copied, err)
	}
	if err := closure.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := closure.Close(); err != nil {
		t.Fatal(err)
	}
	requireNoBackupScopes(t, f)
}
