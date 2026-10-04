package domain

import (
	"errors"
	"fmt"
	"net/netip"
)

type InboundRole string

const (
	InboundRule     InboundRole = "rule"
	InboundDirect   InboundRole = "direct"
	InboundSelected InboundRole = "selected"
)

type InboundSet struct {
	Listen       netip.Addr
	RulePort     uint16
	DirectPort   uint16
	SelectedPort uint16
}

type MixedInbound struct {
	Role    InboundRole
	Address netip.AddrPort
}

func DefaultInboundSet() InboundSet {
	return InboundSet{
		Listen:       netip.MustParseAddr("127.0.0.1"),
		RulePort:     2080,
		DirectPort:   2081,
		SelectedPort: 2082,
	}
}

func (s InboundSet) Validate() error {
	if !s.Listen.IsValid() || !s.Listen.IsLoopback() {
		return errors.New("proxy inbounds must listen on a loopback IP address")
	}
	if s.RulePort == 0 || s.DirectPort == 0 || s.SelectedPort == 0 {
		return errors.New("proxy inbound ports must be non-zero")
	}
	if s.RulePort == s.DirectPort || s.RulePort == s.SelectedPort || s.DirectPort == s.SelectedPort {
		return errors.New("proxy inbound ports must be distinct")
	}
	return nil
}

func (s InboundSet) Ordered() ([]MixedInbound, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return []MixedInbound{
		{Role: InboundRule, Address: netip.AddrPortFrom(s.Listen, s.RulePort)},
		{Role: InboundDirect, Address: netip.AddrPortFrom(s.Listen, s.DirectPort)},
		{Role: InboundSelected, Address: netip.AddrPortFrom(s.Listen, s.SelectedPort)},
	}, nil
}

func (s InboundSet) Address(role InboundRole) (netip.AddrPort, error) {
	if err := s.Validate(); err != nil {
		return netip.AddrPort{}, err
	}
	switch role {
	case InboundRule:
		return netip.AddrPortFrom(s.Listen, s.RulePort), nil
	case InboundDirect:
		return netip.AddrPortFrom(s.Listen, s.DirectPort), nil
	case InboundSelected:
		return netip.AddrPortFrom(s.Listen, s.SelectedPort), nil
	default:
		return netip.AddrPort{}, fmt.Errorf("unknown proxy inbound role %q", role)
	}
}
