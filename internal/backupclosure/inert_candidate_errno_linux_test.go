//go:build linux

package backupclosure

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"
)

func TestInertCandidateFailureClassificationNeverExposesErrorText(t *testing.T) {
	for _, test := range []struct {
		name string
		err error
		want string
	}{
		{"no_space", syscall.ENOSPC, "storage_capacity"},
		{"quota", syscall.EDQUOT, "storage_capacity"},
		{"process_fds", syscall.EMFILE, "descriptor_pressure"},
		{"system_fds", syscall.ENFILE, "descriptor_pressure"},
		{"already_locked", syscall.EWOULDBLOCK, "lock_contention"},
		{"interrupted", syscall.EINTR, "interrupted"},
		{"permissions", syscall.EACCES, "permission"},
		{"privilege", syscall.EPERM, "permission"},
		{"not_found", syscall.ENOENT, "missing_path"},
		{"symbolic_link", syscall.ELOOP, "symlink"},
		{"disk_io", syscall.EIO, "io_error"},
		{"unknown", errors.New("secret path /private/archive-123"), "other"},
		{"wrapped", fmt.Errorf("secret path /private/%w", syscall.ENOSPC), "storage_capacity"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := inertCandidateErrnoClass(test.err)
			if got != test.want {
				t.Fatalf("classification=%q, want %q", got, test.want)
			}
			if strings.Contains(got, "/") || strings.Contains(got, "secret") ||
				strings.Contains(got, "archive") {
				t.Fatalf("diagnostic leaked arbitrary error content: %q", got)
			}
		})
	}
}

func TestInertCandidateFailureProbeReportsOnlyFixedClasses(t *testing.T) {
	for _, test := range []struct {
		operation string
		err error
		want string
	}{
		{"scope_mkdir", syscall.ENOSPC, "scope_mkdir_failed_storage_capacity"},
		{"scope_child_open", syscall.EMFILE, "scope_child_open_failed_descriptor_pressure"},
		{"scope_child_flock", syscall.EWOULDBLOCK, "scope_child_flock_failed_lock_contention"},
		{"scope_child_open", errors.New("sensitive /path/and/key"), "scope_child_open_failed_other"},
	} {
		var phases []string
		recordInertCandidateSyscallFailure(func(s string) bool {
			phases = append(phases, s)
			return false
		}, test.operation, test.err)
		if len(phases) != 1 || phases[0] != test.want {
			t.Fatalf("operation=%q produced %q, want %q", test.operation, phases, test.want)
		}
	}
	// Production does not pass a probe and never receives any new labels.
	recordInertCandidateSyscallFailure(nil, "scope_mkdir", syscall.ENOSPC)
}
