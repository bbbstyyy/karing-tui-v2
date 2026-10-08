package profile

import (
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"
)

type SourceFormat string

const (
	SourceFormatSingBox SourceFormat = "sing-box"
	SourceFormatURIList SourceFormat = "uri-list"

	DefaultUpdateInterval = 12 * time.Hour
	MinUpdateInterval     = 5 * time.Minute
	MaxUpdateInterval     = 365 * 24 * time.Hour
)

type SourceLocationKind string

const (
	SourceLocationURL  SourceLocationKind = "url"
	SourceLocationFile SourceLocationKind = "file"
)

type FetchMode string

const (
	FetchDirect       FetchMode = "direct"
	FetchSelected     FetchMode = "selected"
	FetchSpecificNode FetchMode = "specific_node"
)

var ErrInvalidProfileSource = errors.New("invalid profile source")

type FetchPolicy struct {
	Mode      FetchMode
	ProfileID string
	NodeID    string
}

type SourceSpec struct {
	ProfileID      string
	Format         SourceFormat
	LocationKind   SourceLocationKind
	Location       string
	UserAgent      string
	Fetch          FetchPolicy
	Filter         NodeFilterSpec
	UpdateInterval time.Duration
	Enabled        bool
}

func (s SourceSpec) Validate() error {
	if err := ValidateProfileID(s.ProfileID); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProfileSource, err)
	}
	switch s.Format {
	case SourceFormatSingBox, SourceFormatURIList:
	default:
		return fmt.Errorf("%w: unsupported source format %q", ErrInvalidProfileSource, s.Format)
	}
	if err := validateSourceLocation(s.LocationKind, s.Location); err != nil {
		return err
	}
	if err := validateOptionalText("user agent", s.UserAgent, 1024); err != nil {
		return err
	}
	if err := s.Fetch.Validate(); err != nil {
		return err
	}
	if err := s.Filter.Validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidProfileSource, err)
	}
	if s.UpdateInterval != 0 {
		if s.LocationKind != SourceLocationURL {
			return fmt.Errorf("%w: automatic updates require a remote URL source", ErrInvalidProfileSource)
		}
		if s.UpdateInterval < MinUpdateInterval || s.UpdateInterval > MaxUpdateInterval {
			return fmt.Errorf(
				"%w: update interval must be between %s and %s",
				ErrInvalidProfileSource,
				MinUpdateInterval,
				MaxUpdateInterval,
			)
		}
		if s.UpdateInterval%time.Second != 0 {
			return fmt.Errorf("%w: update interval must use whole seconds", ErrInvalidProfileSource)
		}
	}
	if s.LocationKind == SourceLocationFile && s.Fetch.Mode != FetchDirect {
		return fmt.Errorf("%w: local file sources must use direct fetch mode", ErrInvalidProfileSource)
	}
	return nil
}

func (p FetchPolicy) Validate() error {
	switch p.Mode {
	case FetchDirect, FetchSelected:
		if p.ProfileID != "" || p.NodeID != "" {
			return fmt.Errorf("%w: fetch mode %q must not carry a node reference", ErrInvalidProfileSource, p.Mode)
		}
	case FetchSpecificNode:
		if err := ValidateProfileID(p.ProfileID); err != nil {
			return fmt.Errorf("%w: fixed fetch profile: %v", ErrInvalidProfileSource, err)
		}
		if err := validateStableID(p.NodeID); err != nil {
			return fmt.Errorf("%w: fixed fetch node ID: %v", ErrInvalidProfileSource, err)
		}
	default:
		return fmt.Errorf("%w: unsupported fetch mode %q", ErrInvalidProfileSource, p.Mode)
	}
	return nil
}

func validateSourceLocation(kind SourceLocationKind, value string) error {
	if value == "" {
		return fmt.Errorf("%w: source location must not be empty", ErrInvalidProfileSource)
	}
	if len(value) > 8192 {
		return fmt.Errorf("%w: source location exceeds 8192 bytes", ErrInvalidProfileSource)
	}
	if !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return fmt.Errorf("%w: source location must be trimmed valid UTF-8", ErrInvalidProfileSource)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: source location contains a control character", ErrInvalidProfileSource)
		}
	}
	switch kind {
	case SourceLocationURL:
		parsed, err := url.Parse(value)
		if err != nil {
			return fmt.Errorf("%w: parse source URL: %v", ErrInvalidProfileSource, err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("%w: source URL must use http or https", ErrInvalidProfileSource)
		}
		if parsed.Host == "" {
			return fmt.Errorf("%w: source URL must have a host", ErrInvalidProfileSource)
		}
		if parsed.User != nil {
			return fmt.Errorf("%w: source URL must not contain userinfo", ErrInvalidProfileSource)
		}
	case SourceLocationFile:
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%w: source file path must be absolute", ErrInvalidProfileSource)
		}
		if filepath.Clean(value) != value {
			return fmt.Errorf("%w: source file path must be clean", ErrInvalidProfileSource)
		}
	default:
		return fmt.Errorf("%w: unsupported source location kind %q", ErrInvalidProfileSource, kind)
	}
	return nil
}

func validateOptionalText(label, value string, limit int) error {
	if len(value) > limit {
		return fmt.Errorf("%w: %s exceeds %d bytes", ErrInvalidProfileSource, label, limit)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%w: %s is not valid UTF-8", ErrInvalidProfileSource, label)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: %s contains a control character", ErrInvalidProfileSource, label)
		}
	}
	return nil
}
