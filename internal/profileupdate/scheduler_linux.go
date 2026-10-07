//go:build linux

package profileupdate

import (
	"context"
	"errors"

	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func NewSourceRefreshScheduler(
	store *storage.Store,
	fetcher Fetcher,
	refreshOptions Options,
	schedulerOptions SchedulerOptions,
) (*RefreshScheduler, error) {
	if fetcher == nil {
		return nil, errors.New("profile scheduler fetcher is nil")
	}
	return NewRefreshScheduler(
		store,
		func(
			ctx context.Context,
			profileID string,
			sourceRevision uint64,
			updateID string,
		) error {
			_, err := RefreshProfileSource(
				ctx,
				store,
				fetcher,
				profileID,
				sourceRevision,
				updateID,
				refreshOptions,
			)
			return err
		},
		schedulerOptions,
	)
}
