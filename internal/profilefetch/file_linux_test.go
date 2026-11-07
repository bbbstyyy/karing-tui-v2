//go:build linux

package profilefetch

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

func TestReadFileSourceReadsRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscription.json")
	if err := os.WriteFile(path, []byte("profile-data"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := ReadFileSource(context.Background(), testFileSource(path), 1024)
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Body) != "profile-data" || result.NotModified {
		t.Fatalf("file result = %+v", result)
	}
}

func TestReadFileSourceRejectsFinalSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("profile-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "subscription.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := ReadFileSource(context.Background(), testFileSource(link), 1024)
	if !errors.Is(err, ErrUnsafeSourceFile) {
		t.Fatalf("symlink error = %v", err)
	}
	if strings.Contains(err.Error(), link) {
		t.Fatalf("file error leaked source path: %q", err.Error())
	}
}

func TestReadFileSourceRejectsFIFOWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscription.pipe")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := ReadFileSource(context.Background(), testFileSource(path), 1024)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnsafeSourceFile) {
			t.Fatalf("FIFO error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO source blocked before regular-file validation")
	}
}

func TestReadFileSourceRejectsDirectoryAndOversizedFile(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadFileSource(context.Background(), testFileSource(dir), 1024); !errors.Is(err, ErrUnsafeSourceFile) {
		t.Fatalf("directory error = %v", err)
	}

	path := filepath.Join(dir, "large.json")
	if err := os.WriteFile(path, []byte("0123456789"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFileSource(context.Background(), testFileSource(path), 4); !errors.Is(err, ErrFetchTooLarge) {
		t.Fatalf("oversized file error = %v", err)
	}
}

func TestReadFileSourceHonorsPreCanceledContext(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subscription.json")
	if err := os.WriteFile(path, []byte("profile-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := ReadFileSource(ctx, testFileSource(path), 1024)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled file read error = %v", err)
	}
}

func testFileSource(path string) profile.SourceSpec {
	return profile.SourceSpec{
		ProfileID:    "profile-a",
		Format:       profile.SourceFormatSingBox,
		LocationKind: profile.SourceLocationFile,
		Location:     path,
		Fetch:        profile.FetchPolicy{Mode: profile.FetchDirect},
		Enabled:      true,
	}
}
