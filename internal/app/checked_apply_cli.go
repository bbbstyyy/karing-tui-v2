package app

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"syscall"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/apiv1"
	"github.com/bbbstyyy/karing-tui-v2/internal/client"
)

type checkedApplyCLIClient interface {
	CheckedApplyPreview(context.Context) (apiv1.CheckedApplyPreviewResponse, error)
	CheckedApply(context.Context, apiv1.CheckedApplyReceipt) (apiv1.CheckedApplyResponse, error)
	Status(context.Context) (apiv1.StatusResponse, error)
}

func runCheckedApplyCLI(ctx context.Context, api checkedApplyCLIClient, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		checkedApplyUsage(stderr)
		return 2
	}
	switch args[0] {
	case "apply-preview":
		return runCheckedApplyPreviewCLI(ctx, api, args[1:], stdout, stderr)
	case "apply":
		return runCheckedApplyConfirmCLI(ctx, api, args[1:], stdout, stderr)
	default:
		checkedApplyUsage(stderr)
		return 2
	}
}

func checkedApplyUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: karing-tui config apply-preview [--out=PRIVATE_NEW_FILE]")
	fmt.Fprintln(w, "       karing-tui config apply --receipt=PRIVATE_FILE --confirm")
	fmt.Fprintln(w, "Preview is compiler-only. Confirm may restart/replace the live core. On uncertain outcome inspect status; do not auto-retry.")
}

func checkedApplyPreviewValid(preview apiv1.CheckedApplyPreviewResponse) bool {
	r := preview.Receipt
	return preview.APIVersion == apiv1.Version &&
		preview.CompilerValidated && !preview.CoreValidated && !preview.Applied &&
		preview.NativeSchemaID != "" && preview.RouteEntryCount >= 0 &&
		preview.DNSServerCount >= 0 && preview.RuleSetCount >= 0 &&
		r.DeclarationRevision > 0 && r.DeclarationRevision < 1<<63-1 &&
		validStageSHA256(r.DeclarationSHA256) && validStageSHA256(r.NativeConfigSHA256) &&
		(r.ExpectedAppliedGenerationID == nil || *r.ExpectedAppliedGenerationID > 0) &&
		r.ExpectedConfigRevision < 1<<63-1
}

func runCheckedApplyPreviewCLI(ctx context.Context, api checkedApplyCLIClient, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config apply-preview", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "create a private new 0600 receipt file")
	if err := fs.Parse(args); err != nil { return 2 }
	if len(fs.Args()) != 0 || (flagWasSet(fs, "out") && *out == "") {
		checkedApplyUsage(stderr)
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	preview, err := api.CheckedApplyPreview(bounded)
	if err != nil {
		fmt.Fprintf(stderr, "checked apply preview unavailable: %s\n", safeSourceCLIError(err))
		return 1
	}
	if !checkedApplyPreviewValid(preview) {
		fmt.Fprintln(stderr, "inconsistent compiler preview; no receipt accepted")
		return 1
	}
	if !flagWasSet(fs, "out") {
		return printJSON(stdout, stderr, preview)
	}
	if err := writeNewPrivateReceipt(*out, preview); err != nil {
		fmt.Fprintln(stderr, "cannot create private apply receipt; no existing file overwritten")
		return 1
	}
	fmt.Fprintln(stdout, "compiler-only apply receipt saved (0600); core NOT checked/applied; inspect file before explicit config apply --receipt=FILE --confirm")
	return 0
}

func flagWasSet(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) { if f.Name == name { found = true } })
	return found
}

func readPrivateCheckedApplyReceipt(path string) (apiv1.CheckedApplyPreviewResponse, error) {
	if path == "" { return apiv1.CheckedApplyPreviewResponse{}, errors.New("empty receipt path") }
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil { return apiv1.CheckedApplyPreviewResponse{}, err }
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Mode().Perm()&0o077 != 0 ||
		stat.Size() > 8192 || stat.Size() == 0 {
		return apiv1.CheckedApplyPreviewResponse{}, errors.New("unsafe receipt file")
	}
	meta, ok := stat.Sys().(*syscall.Stat_t)
	if !ok || meta.Uid != uint32(os.Geteuid()) {
		return apiv1.CheckedApplyPreviewResponse{}, errors.New("invalid receipt owner")
	}
	decoder := json.NewDecoder(io.LimitReader(file, 8193))
	decoder.DisallowUnknownFields()
	var preview apiv1.CheckedApplyPreviewResponse
	if err := decoder.Decode(&preview); err != nil { return apiv1.CheckedApplyPreviewResponse{}, err }
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return apiv1.CheckedApplyPreviewResponse{}, errors.New("trailing or invalid receipt contents")
	}
	return preview, nil
}

func runCheckedApplyConfirmCLI(ctx context.Context, api checkedApplyCLIClient, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("config apply", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("receipt", "", "private receipt from apply-preview")
	confirm := fs.Bool("confirm", false, "authorize core check and possibly disruptive activation")
	if err := fs.Parse(args); err != nil { return 2 }
	if len(fs.Args()) != 0 || !flagWasSet(fs, "receipt") || *path == "" ||
		!flagWasSet(fs, "confirm") || !*confirm {
		checkedApplyUsage(stderr)
		return 2
	}
	preview, err := readPrivateCheckedApplyReceipt(*path)
	if err != nil || !checkedApplyPreviewValid(preview) {
		fmt.Fprintln(stderr, "invalid or unsafe private apply receipt; no apply sent")
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 95*time.Second)
	defer cancel()
	result, err := api.CheckedApply(bounded, preview.Receipt)
	if err != nil {
		fmt.Fprintf(stderr, "apply rejected or outcome uncertain: %s; inspect daemon status and recovery before further action, NEVER auto-retry\n",
			safeSourceCLIError(err))
		return 1
	}
	if result.DeclarationRevision != preview.Receipt.DeclarationRevision ||
		result.DeclarationSHA256 != preview.Receipt.DeclarationSHA256 ||
		result.ConfigSHA256 != preview.Receipt.NativeConfigSHA256 ||
		result.NativeSchemaID != preview.NativeSchemaID ||
		result.BaseConfigRevision != preview.Receipt.ExpectedConfigRevision ||
		result.TargetConfigRevision != preview.Receipt.ExpectedConfigRevision+1 ||
		result.GenerationID <= 0 || result.AttemptID <= 0 ||
		!result.CoreChecked || !result.Verified || !result.Applied {
		fmt.Fprintln(stderr, "inconsistent apply acknowledgement; inspect durable status before further action")
		return 1
	}
	// A successful HTTP acknowledgement is not enough: read durable revision
	// and generation once. No second apply is ever issued by the client.
	checkCtx, checkCancel := context.WithTimeout(ctx, 5*time.Second)
	defer checkCancel()
	status, err := api.Status(checkCtx)
	if err != nil || status.ConfigRevision != result.TargetConfigRevision ||
		status.AppliedGenerationID == nil || *status.AppliedGenerationID != result.GenerationID ||
		status.RecoveryRequired {
		fmt.Fprintln(stderr, "apply acknowledged but durable readback unavailable/mismatched; inspect status (no retry)")
		return 1
	}
	return printJSON(stdout, stderr, struct {
		Apply           apiv1.CheckedApplyResponse `json:"apply"`
		ReadbackConfigRevision uint64 `json:"readback_config_revision"`
		ReadbackGenerationID int64 `json:"readback_generation_id"`
		CurrentDeclarationRevision uint64 `json:"current_declaration_revision"`
		HeadAdvanced bool `json:"head_advanced_since_preview"`
		CoreState string `json:"core_state"`
	}{
		Apply: result, ReadbackConfigRevision: status.ConfigRevision,
		ReadbackGenerationID: *status.AppliedGenerationID,
		CurrentDeclarationRevision: status.DeclarationRevision,
		HeadAdvanced: status.DeclarationRevision != result.DeclarationRevision,
		CoreState: status.CoreState,
	})
}

var _ checkedApplyCLIClient = (*client.Client)(nil)
