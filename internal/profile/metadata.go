package profile

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const MaxSubscriptionUserinfoBytes = 4096

var ErrInvalidSubscriptionUserinfo = errors.New("invalid Subscription-Userinfo metadata")

type SubscriptionUsage struct {
	UploadBytes   *int64
	DownloadBytes *int64
	TotalBytes    *int64
	ExpiresAt     *time.Time
}

func (u SubscriptionUsage) Validate() error {
	for label, value := range map[string]*int64{
		"upload":   u.UploadBytes,
		"download": u.DownloadBytes,
		"total":    u.TotalBytes,
	} {
		if value != nil && *value < 0 {
			return fmt.Errorf("%w: %s bytes must not be negative", ErrInvalidSubscriptionUserinfo, label)
		}
	}
	if u.ExpiresAt != nil {
		value := u.ExpiresAt.UTC()
		if value.Year() < 1970 || value.Year() > 9999 {
			return fmt.Errorf("%w: expire timestamp is outside supported range", ErrInvalidSubscriptionUserinfo)
		}
	}
	return nil
}

func ParseSubscriptionUserinfo(value string) (*SubscriptionUsage, bool, error) {
	if value == "" {
		return nil, false, nil
	}
	if len(value) > MaxSubscriptionUserinfoBytes || !utf8.ValidString(value) {
		return nil, true, fmt.Errorf("%w: header length or encoding is invalid", ErrInvalidSubscriptionUserinfo)
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return nil, true, fmt.Errorf("%w: header contains a control character", ErrInvalidSubscriptionUserinfo)
		}
	}

	usage := &SubscriptionUsage{}
	seen := make(map[string]struct{}, 4)
	recognized := 0
	for _, field := range strings.Split(value, ";") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		key, raw, ok := strings.Cut(field, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		raw = strings.TrimSpace(raw)
		switch key {
		case "upload", "download", "total", "expire":
		default:
			continue
		}
		if _, duplicate := seen[key]; duplicate {
			return nil, true, fmt.Errorf("%w: duplicate %s field", ErrInvalidSubscriptionUserinfo, key)
		}
		seen[key] = struct{}{}
		recognized++
		if raw == "" {
			return nil, true, fmt.Errorf("%w: %s field is empty", ErrInvalidSubscriptionUserinfo, key)
		}

		number, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || number < 0 {
			return nil, true, fmt.Errorf("%w: %s field must be a non-negative decimal integer", ErrInvalidSubscriptionUserinfo, key)
		}
		switch key {
		case "upload":
			usage.UploadBytes = int64Ptr(number)
		case "download":
			usage.DownloadBytes = int64Ptr(number)
		case "total":
			usage.TotalBytes = int64Ptr(number)
		case "expire":
			if number == 0 {
				usage.ExpiresAt = nil
				continue
			}
			expires := time.Unix(number, 0).UTC()
			if expires.Year() < 1970 || expires.Year() > 9999 {
				return nil, true, fmt.Errorf("%w: expire field is outside supported range", ErrInvalidSubscriptionUserinfo)
			}
			usage.ExpiresAt = &expires
		}
	}
	if recognized == 0 {
		return nil, true, fmt.Errorf("%w: header has no recognized fields", ErrInvalidSubscriptionUserinfo)
	}
	if err := usage.Validate(); err != nil {
		return nil, true, err
	}
	return usage, true, nil
}

func int64Ptr(value int64) *int64 {
	result := value
	return &result
}
