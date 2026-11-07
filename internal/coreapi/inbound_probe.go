package coreapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/bbbstyyy/karing-tui-v2/internal/core"
	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

type MixedInboundProbe struct {
	inbounds []domain.MixedInbound
}

func NewMixedInboundProbe(set domain.InboundSet) (*MixedInboundProbe, error) {
	inbounds, err := set.Ordered()
	if err != nil {
		return nil, err
	}
	return &MixedInboundProbe{inbounds: inbounds}, nil
}

func (p *MixedInboundProbe) Ready(ctx context.Context, _ core.Process) error {
	for _, inbound := range p.inbounds {
		if err := probeSOCKS5Greeting(ctx, inbound); err != nil {
			return err
		}
	}
	return nil
}

func probeSOCKS5Greeting(ctx context.Context, inbound domain.MixedInbound) error {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", inbound.Address.String())
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return transientReadiness(fmt.Errorf("%s mixed inbound %s is unavailable: %w", inbound.Role, inbound.Address, err))
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set %s mixed inbound deadline: %w", inbound.Role, err)
		}
	} else {
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return fmt.Errorf("set %s mixed inbound fallback deadline: %w", inbound.Role, err)
		}
	}

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return transientReadiness(fmt.Errorf("write %s mixed inbound SOCKS5 greeting: %w", inbound.Role, err))
	}

	var response [2]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return transientReadiness(fmt.Errorf("read %s mixed inbound SOCKS5 greeting: %w", inbound.Role, err))
	}
	if response[0] != 0x05 || response[1] != 0x00 {
		return fmt.Errorf("%s listener %s did not answer as an unauthenticated SOCKS5 mixed inbound", inbound.Role, inbound.Address)
	}
	return nil
}

const localHealthPollInterval = 25 * time.Millisecond

type LocalHealthProbe struct {
	control *ClashVersionProbe
	mixed   *MixedInboundProbe
}

func NewLocalHealthProbe(controlEndpoint, secret string, inbounds domain.InboundSet) (*LocalHealthProbe, error) {
	control, err := NewClashVersionProbe(controlEndpoint, secret)
	if err != nil {
		return nil, err
	}
	mixed, err := NewMixedInboundProbe(inbounds)
	if err != nil {
		return nil, err
	}
	return &LocalHealthProbe{control: control, mixed: mixed}, nil
}

func (p *LocalHealthProbe) Ready(ctx context.Context, process core.Process) error {
	if p.control == nil || p.mixed == nil {
		return errors.New("local core health probe is incomplete")
	}

	check := func() error {
		if err := p.control.Ready(ctx, process); err != nil {
			return err
		}
		if err := p.mixed.Ready(ctx, process); err != nil {
			return err
		}
		return nil
	}

	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		return check()
	}

	var lastTransient error
	for {
		err := check()
		if err == nil {
			return nil
		}
		if !isTransientReadiness(err) {
			return err
		}
		lastTransient = err

		timer := time.NewTimer(localHealthPollInterval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return fmt.Errorf("local core readiness deadline after transient failure %v: %w", lastTransient, ctx.Err())
		case <-timer.C:
		}
	}
}
