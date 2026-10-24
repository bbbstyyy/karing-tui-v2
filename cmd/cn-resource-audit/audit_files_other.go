//go:build !linux

package main

import "errors"

const maxCNTotalBytes int64 = 64 << 20

func openCNAssetRoot(string) (int, error) {
	return -1, errors.New("CN resource audit requires Linux O_NOFOLLOW/openat")
}

func closeCNAssetRoot(int) {}

func cnAssetExistsAt(int, string) (bool, error) {
	return false, errors.New("CN resource audit requires Linux")
}

func hashCNAssetAt(int, string) (int64, string, error) {
	return 0, "", errors.New("CN resource audit requires Linux")
}
