//go:build linux

package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

// Real Go v18 Store creates a fully canonical InertRestoreFence. Mutations
// below happen ONLY to a disposable private SQLite database and never to a
// candidate ciphertext, Core, user state or active restore operation.
func TestGuestAuditRealV18RejectsRehashedInvalidInertFenceAtCapture(t *testing.T) {
	cases := []struct {
		name string
		edit func(InertRestoreFence) ([]byte, error)
	}{
		{
			name: "noncanonical whitespace",
			edit: func(f InertRestoreFence) ([]byte, error) {
				raw, err := json.Marshal(f)
				return append([]byte(" "), raw...), err
			},
		},
		{
			name: "noncanonical unknown field",
			edit: func(f InertRestoreFence) ([]byte, error) {
				raw, err := json.Marshal(f)
				if err != nil {
					return nil, err
				}
				return append(raw[:len(raw)-1], []byte(",\"UnknownField\":1}")...), nil
			},
		},
		{
			name: "invalid config revision",
			edit: func(f InertRestoreFence) ([]byte, error) {
				f.ConfigRevision = 0
				return json.Marshal(f)
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := newGuestBridge(t)
			record := newGuestInertRestoreRecord(t, g)
			canonical, err := json.Marshal(record.Baseline)
			if err != nil {
				t.Fatal(err)
			}
			invalid, err := tc.edit(record.Baseline)
			if err != nil || bytes.Equal(invalid, canonical) {
				t.Fatalf("invalid fixture didn't change original Go JSON: %v", err)
			}
			digest := sha256.Sum256(invalid)
			db, err := sql.Open("sqlite", g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			affected, err := db.ExecContext(context.Background(),
				"UPDATE inert_restore_preparations SET baseline_json=?, baseline_sha256=? WHERE id=?",
				invalid, fmt.Sprintf("%x", digest[:]), record.ID)
			if err != nil {
				t.Fatal(err)
			}
			n, err := affected.RowsAffected()
			if err != nil || n != 1 {
				t.Fatalf("test-only invalid fence replacement failed: %d %v", n, err)
			}
			if err := db.Close(); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			// PRE-CAPTURE refusal: no pinned baseline is needed to
			// detect malformed Go CAS metadata.
			g.run(t, "capture", "", false)
			after, err := os.ReadFile(g.dbPath)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("rejected guest audit wrote SQLite: %v", err)
			}
			store, err := Open(context.Background(), g.dbPath)
			if err != nil {
				t.Fatal(err)
			}
			records, err := store.InspectInertRestoreRecords(context.Background())
			if !errors.Is(err, ErrInertRestorePreparationRefused) || records != nil {
				t.Fatalf("Go v18 scanner accepted malformed canonical fence: %+v %v", records, err)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
