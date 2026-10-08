package profile

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const (
	MaxNodeAliasBytes = 512
	MaxNodeSortRank    = int64(1<<62 - 1)
)

var ErrInvalidNodeOverlay = errors.New("invalid profile node overlay")

type NodeOverlay struct {
	ProfileID string
	NodeID    string
	Disabled  bool
	Favorite  bool
	Alias     string
	SortRank  *int64
}

func (o NodeOverlay) Validate() error {
	if err := ValidateProfileID(o.ProfileID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNodeOverlay, err)
	}
	if err := ValidateNodeID(o.NodeID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidNodeOverlay, err)
	}
	if len(o.Alias) > MaxNodeAliasBytes {
		return fmt.Errorf("%w: alias exceeds %d bytes", ErrInvalidNodeOverlay, MaxNodeAliasBytes)
	}
	if strings.TrimSpace(o.Alias) != o.Alias {
		return fmt.Errorf("%w: alias must not have leading or trailing whitespace", ErrInvalidNodeOverlay)
	}
	if !utf8.ValidString(o.Alias) {
		return fmt.Errorf("%w: alias is not valid UTF-8", ErrInvalidNodeOverlay)
	}
	for _, r := range o.Alias {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: alias contains a control character", ErrInvalidNodeOverlay)
		}
	}
	if o.SortRank != nil {
		if *o.SortRank < 0 || *o.SortRank > MaxNodeSortRank {
			return fmt.Errorf("%w: sort rank is outside supported range", ErrInvalidNodeOverlay)
		}
	}
	return nil
}

func (o NodeOverlay) IsDefault() bool {
	return !o.Disabled && !o.Favorite && o.Alias == "" && o.SortRank == nil
}
