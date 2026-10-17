package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestOperationGateSerializesMutations(t *testing.T) {
	gate := NewOperationGate()
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	secondEntered := make(chan struct{})
	var concurrent atomic.Int32

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- gate.Do(context.Background(), "apply", func(context.Context) error {
			if got := concurrent.Add(1); got != 1 {
				t.Errorf("first concurrent count = %d", got)
			}
			close(firstEntered)
			<-releaseFirst
			concurrent.Add(-1)
			return nil
		})
	}()

	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first operation did not enter")
	}

	snapshot := gate.Snapshot()
	if snapshot.Name != "apply" || snapshot.StartedAt.IsZero() {
		t.Fatalf("unexpected active operation: %+v", snapshot)
	}

	secondDone := make(chan error, 1)
	go func() {
		secondDone <- gate.Do(context.Background(), "core-stop", func(context.Context) error {
			if got := concurrent.Add(1); got != 1 {
				t.Errorf("second concurrent count = %d", got)
			}
			close(secondEntered)
			concurrent.Add(-1)
			return nil
		})
	}()

	select {
	case <-secondEntered:
		t.Fatal("second operation entered before first completed")
	case <-time.After(30 * time.Millisecond):
	}

	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second operation did not enter after first completed")
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
	if snapshot := gate.Snapshot(); snapshot.Name != "" || !snapshot.StartedAt.IsZero() {
		t.Fatalf("operation did not clear: %+v", snapshot)
	}
}

func TestOperationGateWaitingCanBeCanceled(t *testing.T) {
	gate := NewOperationGate()
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- gate.Do(context.Background(), "apply", func(context.Context) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	called := false
	err := gate.Do(ctx, "core-start", func(context.Context) error {
		called = true
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("wait error = %v, want deadline exceeded", err)
	}
	if called {
		t.Fatal("canceled waiting operation callback was called")
	}
	if snapshot := gate.Snapshot(); snapshot.Name != "apply" {
		t.Fatalf("active operation changed after canceled waiter: %+v", snapshot)
	}

	close(release)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestOperationGateReleasesAfterFailure(t *testing.T) {
	gate := NewOperationGate()
	want := errors.New("boom")
	if err := gate.Do(context.Background(), "apply", func(context.Context) error { return want }); !errors.Is(err, want) {
		t.Fatalf("operation error = %v", err)
	}
	if err := gate.Do(context.Background(), "core-stop", func(context.Context) error { return nil }); err != nil {
		t.Fatalf("gate remained locked after failure: %v", err)
	}
}

func TestOperationGateValidatesInputs(t *testing.T) {
	gate := NewOperationGate()
	if err := gate.Do(context.Background(), "", func(context.Context) error { return nil }); !errors.Is(err, ErrOperationNameRequired) {
		t.Fatalf("empty name error = %v", err)
	}
	if err := gate.Do(context.Background(), "apply", nil); err == nil {
		t.Fatal("expected nil callback error")
	}
}
