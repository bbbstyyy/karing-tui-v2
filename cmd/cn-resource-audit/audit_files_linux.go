//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Narrow disposable release-audit budgets, not runtime CN rule-set quotas.
// The pinned upstream tree has a largest .srs file under 1 MiB; leave room
// for format expansion while refusing unbounded disk/CPU consumption.
const (
	maxCNAssetBytes int64 = 8 << 20
	maxCNTotalBytes int64 = 64 << 20
)

func openCNAssetRoot(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	return fd, nil
}

func closeCNAssetRoot(fd int) {
	_ = unix.Close(fd)
}

func cnAssetRelativePath(relative string) (string, string, error) {
	fields := strings.Split(relative, "/")
	if len(fields) != 2 || fields[1] == "" || fields[1] == "." ||
		fields[1] == ".." || strings.Contains(fields[1], "\\") ||
		strings.ContainsRune(fields[1], 0) || !strings.HasSuffix(fields[1], ".srs") {
		return "", "", errors.New("CN audit path is not a single safe relative asset")
	}
	switch fields[0] {
	case "geosite", "geoip", "acl":
		return fields[0], fields[1], nil
	default:
		return "", "", errors.New("CN audit path is outside allowed resource families")
	}
}

func sameCNFile(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino &&
		a.Mode == b.Mode && a.Nlink == b.Nlink &&
		a.Size == b.Size && a.Mtim == b.Mtim && a.Ctim == b.Ctim
}

func cnAssetDirectory(rootFD int, family string) (int, error) {
	fd, err := unix.Openat(rootFD, family,
		unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	if err := assertCNAssetDirectory(rootFD, family, fd); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func assertCNAssetDirectory(rootFD int, family string, fd int) error {
	var opened, named unix.Stat_t
	if err := unix.Fstat(fd, &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(rootFD, family, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Mode&unix.S_IFMT != unix.S_IFDIR || !sameCNFile(opened, named) {
		return errors.New("CN asset directory changed or became a symlink")
	}
	return nil
}

func cnAssetExistsAt(rootFD int, relative string) (bool, error) {
	family, leaf, err := cnAssetRelativePath(relative)
	if err != nil {
		return false, err
	}
	dirFD, err := cnAssetDirectory(rootFD, family)
	if err != nil {
		return false, err
	}
	defer unix.Close(dirFD)

	var info unix.Stat_t
	err = unix.Fstatat(dirFD, leaf, &info, unix.AT_SYMLINK_NOFOLLOW)
	if err != nil && !errors.Is(err, unix.ENOENT) {
		return false, err
	}
	if err := assertCNAssetDirectory(rootFD, family, dirFD); err != nil {
		return false, err
	}
	return err == nil, nil
}

func hashCNAssetAt(rootFD int, relative string) (int64, string, error) {
	family, leaf, err := cnAssetRelativePath(relative)
	if err != nil {
		return 0, "", err
	}
	dirFD, err := cnAssetDirectory(rootFD, family)
	if err != nil {
		return 0, "", err
	}
	defer unix.Close(dirFD)

	// O_NONBLOCK also avoids hangs if an adversary replaces a regular file
	// with a FIFO before opening. O_NOFOLLOW rejects the final symlink.
	fd, err := unix.Openat(dirFD, leaf,
		unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, "", err
	}
	file := os.NewFile(uintptr(fd), "bounded-CN-asset")
	defer file.Close()

	var before, named, after, namedAfter unix.Stat_t
	if err := unix.Fstat(fd, &before); err != nil {
		return 0, "", err
	}
	if err := unix.Fstatat(dirFD, leaf, &named, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, "", err
	}
	if before.Mode&unix.S_IFMT != unix.S_IFREG || before.Nlink != 1 ||
		before.Size <= 0 || before.Size > maxCNAssetBytes || !sameCNFile(before, named) {
		return 0, "", errors.New("CN resource is nonregular, hardlinked, oversized or replaced")
	}
	hasher := sha256.New()
	size, err := io.Copy(hasher, io.LimitReader(file, maxCNAssetBytes+1))
	if err != nil {
		return 0, "", err
	}
	if err := unix.Fstat(fd, &after); err != nil {
		return 0, "", err
	}
	if err := unix.Fstatat(dirFD, leaf, &namedAfter, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return 0, "", err
	}
	if size != before.Size || !sameCNFile(before, after) ||
		!sameCNFile(after, namedAfter) {
		return 0, "", fmt.Errorf("CN asset content or path changed during bounded read")
	}
	if err := assertCNAssetDirectory(rootFD, family, dirFD); err != nil {
		return 0, "", err
	}
	return size, hex.EncodeToString(hasher.Sum(nil)), nil
}
