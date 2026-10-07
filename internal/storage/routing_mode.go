package storage

import (
	"context"
	"errors"
	"fmt"
)

type RoutingMode string

const (
	RoutingModeRule   RoutingMode = "rule"
	RoutingModeGlobal RoutingMode = "global"
	RoutingModeDirect RoutingMode = "direct"
)

var ErrInvalidRoutingMode = errors.New("invalid routing mode")

func (m RoutingMode) Validate() error {
	switch m {
	case RoutingModeRule, RoutingModeGlobal, RoutingModeDirect:
		return nil
	default:
		return fmt.Errorf("%w: %q", ErrInvalidRoutingMode, m)
	}
}

func (s *Store) SetRoutingMode(ctx context.Context, mode RoutingMode) error {
	if err := mode.Validate(); err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `
		UPDATE daemon_state
		SET routing_mode = ?
		WHERE singleton = 1
	`, mode)
	if err != nil {
		return fmt.Errorf("persist routing mode: %w", err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("read routing mode update result: %w", err)
	}
	if affected != 1 {
		return fmt.Errorf("persist routing mode: updated %d daemon_state rows", affected)
	}
	return nil
}
