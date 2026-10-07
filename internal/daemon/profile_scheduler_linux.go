//go:build linux

package daemon

import (
	"errors"

	"github.com/bbbstyyy/karing-tui-v2/internal/profilefetch"
	"github.com/bbbstyyy/karing-tui-v2/internal/profileupdate"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func profileFetchOptions(runtime *serverRuntime) profilefetch.HTTPOptions {
	options := profilefetch.DefaultHTTPOptions()
	if runtime == nil {
		return options
	}
	if selected, ok := runtime.SelectedInbound(); ok {
		options.SelectedProxy = selected
	}
	return options
}

func buildProfileRefreshScheduler(
	store *storage.Store,
	runtime *serverRuntime,
) (*profileupdate.RefreshScheduler, error) {
	if store == nil {
		return nil, errors.New("profile refresh scheduler store is nil")
	}
	fetcher, err := profilefetch.NewSourceFetcher(profileFetchOptions(runtime))
	if err != nil {
		return nil, err
	}
	return profileupdate.NewSourceRefreshScheduler(
		store,
		fetcher,
		profileupdate.Options{},
		profileupdate.DefaultSchedulerOptions(),
	)
}
