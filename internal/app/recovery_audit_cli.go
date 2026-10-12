package app

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
)

type recoveryAuditClient interface {
	RecoveryAudit(context.Context) (apiv1.RecoveryAuditResponse, error)
}

// No "restore" or "--confirm" variant exists. A successful metadata audit
// does not become a token authorizing a core replacement.
func runRecoveryAuditCLI(ctx context.Context, api recoveryAuditClient, args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "usage: karing-tui config recovery-audit (read-only; no rollback)")
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 29*time.Second)
	defer cancel()
	result, err := api.RecoveryAudit(bounded)
	if err != nil {
		fmt.Fprintln(stderr, "recovery audit unavailable or changed; inspect daemon status and retry the read")
		return 1
	}
	if !validRecoveryAudit(result) {
		fmt.Fprintln(stderr, "invalid or untrusted generation audit response")
		return 1
	}
	return printJSON(stdout, stderr, result)
}

func validRecoveryAudit(result apiv1.RecoveryAuditResponse) bool {
	return apiv1.ValidRecoveryAudit(result)
}

var _ recoveryAuditClient = (*client.Client)(nil)
