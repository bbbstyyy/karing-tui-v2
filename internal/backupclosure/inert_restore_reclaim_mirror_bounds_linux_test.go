//go:build linux

package backupclosure

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

func TestReclaimProofMirrorAt128RuleBoundaryHasCanonicalFullIntentSet(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("missing test directory inode")
	}
	p := &reclaimRuleScope{
		dirInfo: info,
		receipt: SealedArchiveReceipt{
			ArchiveSHA256:   strings.Repeat("a", 64),
			InventorySHA256: strings.Repeat("b", 64),
		},
	}
	var key [32]byte
	key[0] = 0x21
	rules := make([]reclaimPlannedRule, MaxClosureRuleSets)
	for i := range rules {
		rules[i] = reclaimPlannedRule{
			Name:   fmt.Sprintf("%03d.json", i),
			SHA256: strings.Repeat("c", 64),
			Size:   1,
			Device: st.Dev,
			Inode:  st.Ino,
		}
	}
	plan := reclaimSignedPlan{
		Body: reclaimPlanBody{
			Version:         reclaimPlanVersion,
			ArchiveSHA256:   p.receipt.ArchiveSHA256,
			InventorySHA256: p.receipt.InventorySHA256,
			JournalID:       17,
			DirectoryDevice: st.Dev,
			DirectoryInode:  st.Ino,
			Rules:           rules,
		},
	}
	rawPlan, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	completion := []byte(`{"body":{"test":true},"mac":"signed-completion"}`)
	anchor := []byte(`{"body":{"test":true},"mac":"signed-attestation"}`)
	mirror, total, err := createReclaimEvidenceMirror(p, 17, plan, rawPlan, completion, anchor, key)
	if err != nil || len(mirror) > maxReclaimMirrorBytes || total <= 0 {
		t.Fatalf("valid bounded 128-rule mirror refused: %d %d %v", len(mirror), total, err)
	}
	var signed reclaimSignedMirror
	if err := json.Unmarshal(mirror, &signed); err != nil {
		t.Fatal(err)
	}
	if signed.Body.RuleCount != MaxClosureRuleSets ||
		len(signed.Body.Intents) != MaxClosureRuleSets ||
		signed.Body.AttestationSHA256 != shaHex(anchor) ||
		!bytes.Equal(signed.Body.Plan, rawPlan) ||
		!bytes.Equal(signed.Body.Completion, completion) ||
		!bytes.Equal(signed.Body.Attestation, anchor) {
		t.Fatal("128-rule mirror lost original proof bytes")
	}
	planSHA := shaHex(rawPlan)
	for i, rule := range rules {
		intent := signed.Body.Intents[i]
		if intent.Name != reclaimIntentPrefix+fmtReclaimIndex(i) ||
			intent.MAC != reclaimIntentMAC(key, planSHA, i, rule.Name) {
			t.Fatalf("intent %d missing or reordered", i)
		}
	}
	body, err := json.Marshal(signed.Body)
	if err != nil {
		t.Fatal(err)
	}
	check := hmac.New(sha256.New, key[:])
	_, _ = check.Write([]byte("karing-tui-v2/durable-rule-reclaim/full-proof-mirror-v1\x00"))
	_, _ = check.Write(body)
	got, err := hex.DecodeString(signed.MAC)
	if err != nil || !hmac.Equal(got, check.Sum(nil)) {
		t.Fatal("full mirror body not independently domain-separated HMAC authenticated")
	}
	tooMany := plan
	tooMany.Body.Rules = append(append([]reclaimPlannedRule(nil), rules...), rules[0])
	if out, _, err := createReclaimEvidenceMirror(p, 17, tooMany, rawPlan,
		completion, anchor, key); !errors.Is(err, ErrReclaimEvidenceMirror) || out != nil {
		t.Fatalf("accepted >128 rule mirror: %v", err)
	}
	oversize := bytes.Repeat([]byte("x"), maxReclaimMirrorBytes)
	if out, _, err := createReclaimEvidenceMirror(p, 17, plan, oversize,
		completion, anchor, key); !errors.Is(err, ErrReclaimEvidenceMirror) || out != nil {
		t.Fatalf("accepted >256 KiB untrusted source: %v", err)
	}
	wrongID := plan
	wrongID.Body.JournalID++
	if out, _, err := createReclaimEvidenceMirror(p, 17, wrongID, rawPlan,
		completion, anchor, key); !errors.Is(err, ErrReclaimEvidenceMirror) || out != nil {
		t.Fatalf("accepted stale journal ID: %v", err)
	}
}
