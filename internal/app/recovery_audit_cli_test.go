package app

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

type fakeRecoveryAuditClient struct {
	result apiv1.RecoveryAuditResponse
	err error
	calls int
}

func (f *fakeRecoveryAuditClient) RecoveryAudit(ctx context.Context) (apiv1.RecoveryAuditResponse, error) {
	f.calls++
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.RecoveryAuditResponse{}, errors.New("missing bounded deadline")
	}
	return f.result, f.err
}

func recoveryAuditFixture() apiv1.RecoveryAuditResponse {
	return apiv1.RecoveryAuditResponse{
		APIVersion: apiv1.Version,
		Evidence: "committed_generation_history_and_retained_storage",
		ConfigRevision: 3, CurrentDeclarationRevision: 6,
		RestoreSupported: false,
		Generations: []apiv1.RecoveryGenerationAudit{
			{
				GenerationID: 12, CommittedConfigRevision: 3, Applied: true,
				PayloadRetained: true, StoredIntegrityVerified: true,
				RuleSetResourcesVerified: true, DeclarationRevision: 6,
				Status: "stored_integrity_verified_only",
			},
			{
				GenerationID: 4, CommittedConfigRevision: 1,
				PayloadRetained: false, Status: "payload_pruned",
			},
		},
	}
}

func TestRecoveryAuditCLIReadOnlyAndNeverOffersRestore(t *testing.T) {
	api := &fakeRecoveryAuditClient{result: recoveryAuditFixture()}
	var out, stderr bytes.Buffer
	exit := runRecoveryAuditCLI(context.Background(), api, nil, &out, &stderr)
	if exit != 0 || stderr.Len() != 0 || api.calls != 1 ||
		!strings.Contains(out.String(), `"stored_integrity_verified_only"`) ||
		!strings.Contains(out.String(), `"restore_supported": false`) ||
		!strings.Contains(out.String(), `"payload_pruned"`) ||
		strings.Contains(out.String(), "runtime_path") ||
		strings.Contains(out.String(), "password") {
		t.Fatalf("bad audit response: exit=%d body=%q stderr=%q", exit, out.String(), stderr.String())
	}
}

func TestRecoveryAuditCLIRejectsMutationsBeforeAnyRPC(t *testing.T) {
	api := &fakeRecoveryAuditClient{result: recoveryAuditFixture()}
	for _, args := range [][]string{
		{"--confirm"}, {"restore", "4"}, {"--target=4"}, {"--json"}, {"--force"},
	} {
		var out, stderr bytes.Buffer
		code := runRecoveryAuditCLI(context.Background(), api, args, &out, &stderr)
		if code != 2 || out.Len() != 0 || !strings.Contains(stderr.String(), "read-only") {
			t.Fatalf("mutation shaped args not refused: %q exit=%d", args, code)
		}
	}
	if api.calls != 0 {
		t.Fatalf("unsafe args triggered %d requests", api.calls)
	}
}

func TestRecoveryAuditCLIRejectsForgedReadyAndUnknownStatus(t *testing.T) {
	cases := []struct {
		name string
		change func(*apiv1.RecoveryAuditResponse)
	}{
		{"restore enabled", func(r *apiv1.RecoveryAuditResponse) {
			r.RestoreSupported = true
		}},
		{"restore ready", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations[0].RestoreReady = true
		}},
		{"unauthorized format", func(r *apiv1.RecoveryAuditResponse) {
			r.APIVersion = "v2"
		}},
		{"unknown status", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations[0].Status = "ready_to_restore"
		}},
		{"resource without stored hash", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations[0].StoredIntegrityVerified = false
		}},
		{"duplicate generation", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations[1].GenerationID = r.Generations[0].GenerationID
		}},
		{"unbounded response", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations = append(r.Generations, make([]apiv1.RecoveryGenerationAudit, 12)...)
		}},
		{"unordered history", func(r *apiv1.RecoveryAuditResponse) {
			r.Generations[1].CommittedConfigRevision = 9
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &fakeRecoveryAuditClient{result: recoveryAuditFixture()}
			tc.change(&api.result)
			var stdout, stderr bytes.Buffer
			code := runRecoveryAuditCLI(context.Background(), api, nil, &stdout, &stderr)
			if code != 1 || stdout.Len() != 0 || api.calls != 1 ||
				!strings.Contains(stderr.String(), "untrusted") {
				t.Fatalf("unsafe %s accepted: code=%d output=%s err=%s", tc.name, code, stdout.String(), stderr.String())
			}
		})
	}
}

func TestRecoveryAuditCLIUnavailableDoesNotExposeSQLitePaths(t *testing.T) {
	api := &fakeRecoveryAuditClient{
		result: recoveryAuditFixture(),
		err: errors.New("sqlite /home/user/secret.db with password=PRIVATE_KEY"),
	}
	var stdout, stderr bytes.Buffer
	if code := runRecoveryAuditCLI(context.Background(), api, nil, &stdout, &stderr); code != 1 ||
		stdout.Len() != 0 || strings.Contains(stderr.String(), "PRIVATE_KEY") ||
		strings.Contains(stderr.String(), "secret.db") {
		t.Fatalf("secret error leaked: %q", stderr.String())
	}
}
