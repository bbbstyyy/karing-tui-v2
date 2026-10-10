package storage

import (
	"context"
	"testing"
)

func TestConfirmedGenerationRefsIncludeArchivedHistoryAndPrunedPayloads(t *testing.T) {
	ctx := context.Background()
	store := openRetentionTestStore(t, ctx, RetentionPolicy{
		ConfirmedGenerations: 2,
		MaxGenerationBytes:   1 << 20,
	})
	defer store.Close()

	attempts := make([]Attempt, 0, 4)
	for i := uint64(0); i < 4; i++ {
		attempts = append(attempts, commitRetentionGeneration(t, ctx, store, i))
	}
	if _, err := store.PruneRetention(ctx); err != nil {
		t.Fatal(err)
	}
	refs, truncated, err := store.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || truncated || len(refs) != 4 {
		t.Fatalf("committed history disappeared after compaction: %+v truncated=%v err=%v", refs, truncated, err)
	}
	for i, ref := range refs {
		expected := attempts[3-i]
		if ref.GenerationID != expected.GenerationID ||
			ref.TargetConfigRevision != expected.TargetRevision ||
			ref.PayloadRetained != (i < 2) {
			t.Fatalf("historical generation %d inconsistent: %+v", i, ref)
		}
	}
	short, truncated, err := store.ConfirmedGenerationRefs(ctx, 2)
	if err != nil || !truncated || len(short) != 2 ||
		short[0].GenerationID != attempts[3].GenerationID ||
		short[1].GenerationID != attempts[2].GenerationID {
		t.Fatalf("bounded sorted result incorrect: %+v, trunc=%v err=%v", short, truncated, err)
	}
	for _, limit := range []int{-1, 0, MaxConfirmedGenerationAudit + 1} {
		if _, _, err := store.ConfirmedGenerationRefs(ctx, limit); err == nil {
			t.Fatalf("unsafe list limit %d accepted", limit)
		}
	}
}

func TestConfirmedGenerationRefsExcludeUnconfirmedCandidate(t *testing.T) {
	ctx := context.Background()
	store := openRetentionTestStore(t, ctx, RetentionPolicy{
		ConfirmedGenerations: 2, MaxGenerationBytes: 1 << 20,
	})
	defer store.Close()
	first := commitRetentionGeneration(t, ctx, store, 0)
	prepared, err := store.PrepareApply(ctx, first.TargetRevision, []byte(`{"unconfirmed":true}`))
	if err != nil {
		t.Fatal(err)
	}
	refs, truncated, err := store.ConfirmedGenerationRefs(ctx, 12)
	if err != nil || truncated || len(refs) != 1 || refs[0].GenerationID != first.GenerationID {
		t.Fatalf("prepared candidate offered as recovery evidence: %+v err=%v", refs, err)
	}
	if refs[0].GenerationID == prepared.GenerationID {
		t.Fatal("unconfirmed payload misclassified as committed")
	}
}
