//go:build linux

package profilefetch

import (
	"context"
	"errors"

	"github.com/bbbstyyy/karing-tui-v2/internal/profile"
)

type SourceFetcher struct {
	http         *HTTPFetcher
	maxFileBytes int64
}

func NewSourceFetcher(options HTTPOptions) (*SourceFetcher, error) {
	httpFetcher, err := NewHTTPFetcher(options)
	if err != nil {
		return nil, err
	}
	return &SourceFetcher{
		http:         httpFetcher,
		maxFileBytes: options.MaxBodyBytes,
	}, nil
}

func (f *SourceFetcher) Fetch(
	ctx context.Context,
	spec profile.SourceSpec,
	conditional ConditionalRequest,
) (Result, error) {
	if f == nil || f.http == nil {
		return Result{}, errors.New("profile source fetcher is nil")
	}
	switch spec.LocationKind {
	case profile.SourceLocationURL:
		return f.http.Fetch(ctx, spec, conditional)
	case profile.SourceLocationFile:
		return ReadFileSource(ctx, spec, f.maxFileBytes)
	default:
		return Result{}, ErrUnsupportedSourceLocation
	}
}
