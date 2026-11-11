package daemon

import (
	"context"
	"errors"
	"sync"
	"time"
)

var ErrOperationNameRequired = errors.New("operation name is required")

type OperationSnapshot struct {
	Name      string
	StartedAt time.Time
}

type OperationGate struct {
	token chan struct{}

	mu     sync.RWMutex
	active OperationSnapshot
}

func NewOperationGate() *OperationGate {
	gate := &OperationGate{token: make(chan struct{}, 1)}
	gate.token <- struct{}{}
	return gate
}

func (g *OperationGate) Do(ctx context.Context, name string, operation func(context.Context) error) error {
	if name == "" {
		return ErrOperationNameRequired
	}
	if operation == nil {
		return errors.New("operation callback is nil")
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-g.token:
	}

	g.mu.Lock()
	g.active = OperationSnapshot{Name: name, StartedAt: time.Now().UTC()}
	g.mu.Unlock()

	defer func() {
		g.mu.Lock()
		g.active = OperationSnapshot{}
		g.mu.Unlock()
		g.token <- struct{}{}
	}()

	return operation(ctx)
}

func (g *OperationGate) Snapshot() OperationSnapshot {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.active
}
