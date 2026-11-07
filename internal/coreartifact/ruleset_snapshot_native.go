package coreartifact

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// StageNativeCheckConfig writes a separately hashed, rebound *check-only*
// native JSON next to the independently copied rules. It must never reuse
// a real generation ID, state journal payload or live core binding. The
// private scope remains locked until Close; crashed copies use the existing
// bounded SHA256.json orphan scavenger.
func (s *RuleSetSnapshot) StageNativeCheckConfig(
	ctx context.Context, config []byte,
) (path, sha string, err error) {
	if err := ctx.Err(); err != nil {
		return "", "", err
	}
	if s == nil || s.closed || s.dir == "" || s.nativeConfigStaged ||
		len(config) == 0 || int64(len(config)) > MaxRuleSetUploadBytes ||
		!json.Valid(config) || len(s.files) >= MaxRuleSetSnapshotFiles {
		return "", "", ErrUnsafeRuleSetSnapshot
	}
	if err := s.Verify(ctx); err != nil {
		return "", "", ErrUnsafeRuleSetSnapshot
	}
	remaining := MaxRuleSetSnapshotBytes
	for _, item := range s.files {
		if item.size < 0 || item.size > remaining {
			return "", "", ErrRuleSetTooLarge
		}
		remaining -= item.size
	}
	if int64(len(config)) > remaining {
		return "", "", ErrRuleSetTooLarge
	}
	digest := sha256.Sum256(config)
	sha = hex.EncodeToString(digest[:])
	name := sha + ".json"
	for _, item := range s.files {
		if item.name == name {
			return "", "", ErrUnsafeRuleSetSnapshot
		}
	}
	path = filepath.Join(s.dir, name)
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", "", fmt.Errorf("%w: create isolated native config", ErrUnsafeRuleSetSnapshot)
	}
	info, infoErr := file.Stat()
	if infoErr != nil {
		_ = file.Close()
		return "", "", infoErr
	}
	// Keep the inode in the exact ownership list even if Write/Sync fails;
	// the daemon's deferred Close will remove only this recognized file.
	s.files = append(s.files, snapshotFile{
		name: name, hash: sha, size: int64(len(config)), identity: info,
	})
	s.nativeConfigStaged = true
	_, writeErr := file.Write(config)
	if writeErr == nil {
		writeErr = file.Chmod(0o400)
	}
	if writeErr == nil {
		writeErr = file.Sync()
	}
	writeErr = errors.Join(writeErr, file.Close())
	if writeErr != nil {
		return "", "", fmt.Errorf("%w: write isolated native config", ErrUnsafeRuleSetSnapshot)
	}
	if err := VerifyRuleSet(path, sha); err != nil {
		return "", "", ErrUnsafeRuleSetSnapshot
	}
	if err := syncDir(s.dir); err != nil {
		return "", "", err
	}
	if err := s.Verify(ctx); err != nil {
		return "", "", ErrUnsafeRuleSetSnapshot
	}
	return path, sha, nil
}
