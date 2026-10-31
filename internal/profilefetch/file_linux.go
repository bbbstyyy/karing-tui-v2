//go:build linux

package profilefetch

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

var (
	ErrUnsafeSourceFile = errors.New("profile source file is not a safe regular file")
	ErrSourceFileRead   = errors.New("profile source file could not be read")
)

func ReadFileSource(
	ctx context.Context,
	spec profile.SourceSpec,
	maxBytes int64,
) (Result, error) {
	if err := spec.Validate(); err != nil {
		return Result{}, err
	}
	if spec.LocationKind != profile.SourceLocationFile {
		return Result{}, ErrUnsupportedSourceLocation
	}
	if maxBytes <= 0 {
		return Result{}, errors.New("profile file body limit must be positive")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}

	fd, err := syscall.Open(
		spec.Location,
		syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_NONBLOCK,
		0,
	)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return Result{}, ErrUnsafeSourceFile
		}
		return Result{}, ErrSourceFileRead
	}
	file := os.NewFile(uintptr(fd), "profile-source")
	if file == nil {
		_ = syscall.Close(fd)
		return Result{}, ErrSourceFileRead
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Result{}, ErrSourceFileRead
	}
	if !info.Mode().IsRegular() {
		return Result{}, ErrUnsafeSourceFile
	}
	if info.Size() > maxBytes {
		return Result{}, fmt.Errorf("%w: limit %d bytes", ErrFetchTooLarge, maxBytes)
	}

	body, err := readBoundedBody(io.Reader(file), maxBytes)
	if err != nil {
		return Result{}, err
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	return Result{Body: body}, nil
}
