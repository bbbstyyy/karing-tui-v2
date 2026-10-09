package tui

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
)

// The ordinary fakeAPI used by all TUI tests remains read-only unless a
// checked-apply-specific fake deliberately implements an apply transaction.
func (f *fakeAPI) CheckedApplyPreview(context.Context) (apiv1.CheckedApplyPreviewResponse, error) {
	return apiv1.CheckedApplyPreviewResponse{}, errors.New("checked apply not configured")
}

func (f *fakeAPI) CheckedApply(context.Context, apiv1.CheckedApplyReceipt) (apiv1.CheckedApplyResponse, error) {
	return apiv1.CheckedApplyResponse{}, errors.New("checked apply not configured")
}

type checkedApplyFakeAPI struct {
	*fakeAPI
	preview       apiv1.CheckedApplyPreviewResponse
	previewErr    error
	applyErr      error
	statusErr     error
	previewCalls  int
	applyCalls    int
	statusCalls   int
	applied       bool
	commitOnError bool
	badAck        bool
	badReadback   bool
	lastReceipt   apiv1.CheckedApplyReceipt
}

func newCheckedApplyFakeAPI() *checkedApplyFakeAPI {
	generation := int64(11)
	base := &fakeAPI{status: apiv1.StatusResponse{
		APIVersion: apiv1.Version, CoreConfigured: true, CoreState: "running",
		ConfigRevision: 4, DeclarationRevision: 8,
		AppliedGenerationID: &generation,
		CoreLastError: "Bearer PASSWORD=NEVER_KEEP",
	}}
	return &checkedApplyFakeAPI{
		fakeAPI: base,
		preview: apiv1.CheckedApplyPreviewResponse{
			APIVersion: apiv1.Version,
			Receipt: apiv1.CheckedApplyReceipt{
				DeclarationRevision: 8, DeclarationSHA256: strings.Repeat("a", 64),
				ExpectedConfigRevision: 4, ExpectedAppliedGenerationID: &generation,
				ExpectedSelectionRevision: 7, NativeConfigSHA256: strings.Repeat("b", 64),
			},
			NativeSchemaID: "sing-box-compatible",
			RouteEntryCount: 32, DNSServerCount: 5, RuleSetCount: 2,
			CompilerValidated: true,
		},
	}
}

func (f *checkedApplyFakeAPI) CheckedApplyPreview(ctx context.Context) (apiv1.CheckedApplyPreviewResponse, error) {
	f.previewCalls++
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.CheckedApplyPreviewResponse{}, errors.New("preview has no deadline")
	}
	return f.preview, f.previewErr
}

func (f *checkedApplyFakeAPI) CheckedApply(ctx context.Context, receipt apiv1.CheckedApplyReceipt) (apiv1.CheckedApplyResponse, error) {
	f.applyCalls++
	f.lastReceipt = receipt
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.CheckedApplyResponse{}, errors.New("write has no deadline")
	}
	if f.applyErr != nil {
		if f.commitOnError {
			f.applied = true
		}
		return apiv1.CheckedApplyResponse{}, f.applyErr
	}
	f.applied = true
	result := apiv1.CheckedApplyResponse{
		DeclarationApplyResponse: apiv1.DeclarationApplyResponse{
			DeclarationRevision: receipt.DeclarationRevision,
			DeclarationSHA256: receipt.DeclarationSHA256,
			ConfigSHA256: receipt.NativeConfigSHA256,
			NativeSchemaID: f.preview.NativeSchemaID,
			AttemptID: 17, GenerationID: 19,
			BaseConfigRevision: receipt.ExpectedConfigRevision,
			TargetConfigRevision: receipt.ExpectedConfigRevision + 1,
		},
		CoreChecked: true, Verified: true, Applied: true,
	}
	if f.badAck {
		result.ConfigSHA256 = strings.Repeat("f", 64)
	}
	return result, nil
}

func (f *checkedApplyFakeAPI) Status(ctx context.Context) (apiv1.StatusResponse, error) {
	f.statusCalls++
	if _, ok := ctx.Deadline(); !ok {
		return apiv1.StatusResponse{}, errors.New("status readback has no deadline")
	}
	if f.statusErr != nil {
		return apiv1.StatusResponse{}, f.statusErr
	}
	value := f.fakeAPI.status
	if f.applied {
		generation := int64(19)
		value.AppliedGenerationID = &generation
		value.ConfigRevision++
	}
	if f.badReadback {
		generation := int64(9)
		value.AppliedGenerationID = &generation
	}
	return value, nil
}

func checkedApplyKey(t *testing.T, m Model, key rune) (Model, tea.Cmd) {
	t.Helper()
	return updated(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{key}})
}

func checkedApplyDashboard(t *testing.T, api *checkedApplyFakeAPI) Model {
	t.Helper()
	m := NewModel(context.Background(), api)
	m, _ = updated(t, m, statusLoaded{request: m.statusRequest, value: api.fakeAPI.status})
	if !m.statusReady || m.page != dashboardPage {
		t.Fatal("dashboard fixture did not load")
	}
	return m
}

func TestTUICheckedApplyRequiresPreviewRiskAndConfirmation(t *testing.T) {
	api := newCheckedApplyFakeAPI()
	m := checkedApplyDashboard(t, api)
	m, previewCmd := checkedApplyKey(t, m, 'a')
	if previewCmd == nil || !m.checkedApply.previewing || api.previewCalls != 0 || api.applyCalls != 0 {
		t.Fatal("a did not schedule a compiler-only preview")
	}
	m, _ = updated(t, m, previewCmd())
	if api.previewCalls != 1 || api.applyCalls != 0 || m.checkedApply.pending == nil {
		t.Fatal("compiler preview was not accepted without a write")
	}
	for _, phrase := range []string{
		"Declaration revision 8", "config revision 4", "selection revision 7",
		"Core check has NOT run", "INTERRUPT EXISTING CONNECTIONS",
		"y: APPLY NOW", "Compiled SHA256",
	} {
		if !strings.Contains(m.View(), phrase) {
			t.Fatalf("preview modal missing %q: %q", phrase, m.View())
		}
	}
	m, blocked := checkedApplyKey(t, m, '2')
	if blocked != nil || m.page != dashboardPage || m.checkedApply.pending == nil {
		t.Fatal("pending confirmation navigated away")
	}
	m, applyCmd := checkedApplyKey(t, m, 'y')
	if applyCmd == nil || !m.checkedApply.writing || m.checkedApply.pending != nil ||
		api.applyCalls != 0 || m.statusReady {
		t.Fatal("explicit confirmation did not schedule exactly one write")
	}
	m, blocked = checkedApplyKey(t, m, 'y')
	if blocked != nil || api.applyCalls != 0 {
		t.Fatal("duplicate confirmation escaped the in-flight guard")
	}
	m, blocked = checkedApplyKey(t, m, 'r')
	if blocked != nil || m.page != dashboardPage {
		t.Fatal("refresh crossed in-flight apply")
	}
	m, _ = updated(t, m, applyCmd())
	if api.applyCalls != 1 || api.statusCalls != 1 ||
		!m.statusReady || m.checkedApply.writing ||
		m.status.ConfigRevision != 5 || m.status.AppliedGenerationID == nil ||
		*m.status.AppliedGenerationID != 19 ||
		m.status.CoreLastError != "" ||
		!strings.Contains(m.View(), "Applied and verified") ||
		strings.Contains(m.View(), "NEVER_KEEP") {
		t.Fatalf("apply did not verify persisted generation safely: %s", m.View())
	}
	if api.lastReceipt.DeclarationSHA256 != strings.Repeat("a", 64) ||
		api.lastReceipt.NativeConfigSHA256 != strings.Repeat("b", 64) {
		t.Fatal("apply request not bound to preview hashes")
	}
}

func TestTUICheckedApplyCancelQuitAndStalePreviewNeverWrite(t *testing.T) {
	api := newCheckedApplyFakeAPI()
	m := checkedApplyDashboard(t, api)
	m, late := checkedApplyKey(t, m, 'a')
	m, _ = checkedApplyKey(t, m, 'r')
	m, _ = updated(t, m, late())
	if m.checkedApply.pending != nil || m.checkedApply.previewing || api.applyCalls != 0 {
		t.Fatal("old compiler preview survived status refresh")
	}
	m, preview := checkedApplyKey(t, m, 'a')
	m, _ = updated(t, m, preview())
	m, _ = checkedApplyKey(t, m, 'q')
	if !m.quitting || api.applyCalls != 0 {
		t.Fatal("quit stage sent an unconfirmed core apply")
	}

	m = checkedApplyDashboard(t, api)
	m, preview = checkedApplyKey(t, m, 'a')
	m, _ = updated(t, m, preview())
	m, _ = updated(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.checkedApply.pending != nil || api.applyCalls != 0 ||
		!strings.Contains(m.View(), "cancelled") {
		t.Fatal("Esc did not discard pending receipt")
	}
	m, cmd := checkedApplyKey(t, m, 'y')
	if cmd != nil || api.applyCalls != 0 {
		t.Fatal("stale y sent write after cancellation")
	}

	m, late = checkedApplyKey(t, m, 'a')
	m, _ = checkedApplyKey(t, m, '2')
	m, _ = updated(t, m, late())
	if m.page != profilesPage || m.checkedApply.pending != nil {
		t.Fatal("late preview crossed page boundary")
	}
}

func TestTUICheckedApplyRejectsUnsafeOrDriftedReceipts(t *testing.T) {
	for _, tc := range []struct{
		name string
		mutate func(*checkedApplyFakeAPI)
	}{
		{"wrong config revision", func(f *checkedApplyFakeAPI) {
			f.preview.Receipt.ExpectedConfigRevision++
		}},
		{"wrong generation", func(f *checkedApplyFakeAPI) {
			v := int64(99)
			f.preview.Receipt.ExpectedAppliedGenerationID = &v
		}},
		{"invalid native SHA", func(f *checkedApplyFakeAPI) {
			f.preview.Receipt.NativeConfigSHA256 = "SECRET=DO_NOT_SHOW"
		}},
		{"fake core validation", func(f *checkedApplyFakeAPI) {
			f.preview.CoreValidated = true
		}},
		{"fake applied", func(f *checkedApplyFakeAPI) {
			f.preview.Applied = true
		}},
		{"unsafe schema", func(f *checkedApplyFakeAPI) {
			f.preview.NativeSchemaID = "https://node.invalid?token=SECRET"
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := newCheckedApplyFakeAPI()
			tc.mutate(api)
			m := checkedApplyDashboard(t, api)
			m, preview := checkedApplyKey(t, m, 'a')
			m, _ = updated(t, m, preview())
			if m.checkedApply.pending != nil || api.applyCalls != 0 ||
				strings.Contains(m.View(), "DO_NOT_SHOW") {
				t.Fatal("unsafe preview became actionable or leaked")
			}
		})
	}
}

func TestTUICheckedApplyRespectsTerminalRiskVisibilityAndStatus(t *testing.T) {
	api := newCheckedApplyFakeAPI()
	m := checkedApplyDashboard(t, api)
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 52, Height: 12})
	m, cmd := checkedApplyKey(t, m, 'a')
	if cmd != nil || api.previewCalls != 0 {
		t.Fatal("small terminal opened apply preview")
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 64, Height: 16})
	m, preview := checkedApplyKey(t, m, 'a')
	m, _ = updated(t, m, preview())
	view := m.View()
	for _, text := range []string{"APPLY MAY RESTART CORE", "y: APPLY NOW"} {
		if !strings.Contains(view, text) {
			t.Fatalf("safety warning out of viewport: %s", view)
		}
	}
	lines := strings.Split(strings.TrimSuffix(view, "\n"), "\n")
	if len(lines) > 16 {
		t.Fatal("confirmation view exceeds terminal height")
	}
	for _, line := range lines {
		if runeWidthOfLine(line) > 64 {
			t.Fatalf("terminal confirmation overflow: %q", line)
		}
	}
	m, _ = updated(t, m, tea.WindowSizeMsg{Width: 32, Height: 7})
	if m.checkedApply.pending != nil {
		t.Fatal("unsafe resized modal remained actionable")
	}
	m, cmd = checkedApplyKey(t, m, 'y')
	if cmd != nil || api.applyCalls != 0 {
		t.Fatal("blind y after shrinking triggered apply")
	}
	api = newCheckedApplyFakeAPI()
	api.status.RecoveryRequired = true
	m = checkedApplyDashboard(t, api)
	m, cmd = checkedApplyKey(t, m, 'a')
	if cmd != nil {
		t.Fatal("recovery-required status permitted apply")
	}
}

func TestTUICheckedApplyUncertainResponseAndReadbackNeverAutoRetry(t *testing.T) {
	for _, mode := range []string{"transport uncertain", "spoofed ack", "readback mismatch", "status failure"} {
		t.Run(mode, func(t *testing.T) {
			api := newCheckedApplyFakeAPI()
			switch mode {
			case "transport uncertain":
				api.applyErr = errors.New("password=SECRET_CORE")
				api.commitOnError = true
			case "spoofed ack":
				api.badAck = true
			case "readback mismatch":
				api.badReadback = true
			case "status failure":
				api.statusErr = errors.New("token=VERY_PRIVATE")
			}
			m := checkedApplyDashboard(t, api)
			m, preview := checkedApplyKey(t, m, 'a')
			m, _ = updated(t, m, preview())
			m, write := checkedApplyKey(t, m, 'y')
			m, _ = updated(t, m, write())
			if api.applyCalls != 1 || api.statusCalls != 1 ||
				m.checkedApply.writing || m.checkedApply.pending != nil ||
				!strings.Contains(m.View(), "NEVER auto-retry") ||
				strings.Contains(m.View(), "SECRET_CORE") ||
				strings.Contains(m.View(), "VERY_PRIVATE") {
				t.Fatalf("%s: unsafe uncertain state %s", mode, m.View())
			}
		})
	}
}

func TestTUICheckedApplyRejectsChangedStatusBeforeConfirmation(t *testing.T) {
	api := newCheckedApplyFakeAPI()
	m := checkedApplyDashboard(t, api)
	m, preview := checkedApplyKey(t, m, 'a')
	m, _ = updated(t, m, preview())
	m.status.ConfigRevision++
	m, cmd := checkedApplyKey(t, m, 'y')
	if cmd != nil || api.applyCalls != 0 || m.checkedApply.pending != nil {
		t.Fatalf("concurrent status mutation accepted: %s", m.View())
	}
}

func TestTUICheckedApplyMalformedAckDoesNotReportSuccess(t *testing.T) {
	// This test also ensures that the API can be implemented without an
	// implicit method on the daemon: the TUI only sees typed client messages.
	api := newCheckedApplyFakeAPI()
	api.badAck = true
	m := checkedApplyDashboard(t, api)
	m, cmd := checkedApplyKey(t, m, 'a')
	m, _ = updated(t, m, cmd())
	m, cmd = checkedApplyKey(t, m, 'y')
	m, _ = updated(t, m, cmd())
	if strings.Contains(m.checkedApply.notice, "Applied and verified") {
		t.Fatal(fmt.Sprintf("invalid core response accepted: %s", m.checkedApply.notice))
	}
}
