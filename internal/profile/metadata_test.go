package profile

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseSubscriptionUserinfoValid(t *testing.T) {
	usage, present, err := ParseSubscriptionUserinfo(
		"upload=1024; download=2048; total=4096; expire=1798761600; reset_day=1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if !present || usage == nil {
		t.Fatalf("usage present=%v value=%+v", present, usage)
	}
	if usage.UploadBytes == nil || *usage.UploadBytes != 1024 ||
		usage.DownloadBytes == nil || *usage.DownloadBytes != 2048 ||
		usage.TotalBytes == nil || *usage.TotalBytes != 4096 {
		t.Fatalf("usage bytes = %+v", usage)
	}
	wantExpiry := time.Unix(1798761600, 0).UTC()
	if usage.ExpiresAt == nil || !usage.ExpiresAt.Equal(wantExpiry) {
		t.Fatalf("expiry = %v, want %v", usage.ExpiresAt, wantExpiry)
	}
}

func TestParseSubscriptionUserinfoAbsent(t *testing.T) {
	usage, present, err := ParseSubscriptionUserinfo("")
	if err != nil {
		t.Fatal(err)
	}
	if present || usage != nil {
		t.Fatalf("absent header parsed as present=%v usage=%+v", present, usage)
	}
}

func TestParseSubscriptionUserinfoAllowsZeroExpiry(t *testing.T) {
	usage, present, err := ParseSubscriptionUserinfo("total=0; expire=0")
	if err != nil {
		t.Fatal(err)
	}
	if !present || usage == nil ||
		usage.TotalBytes == nil || *usage.TotalBytes != 0 ||
		usage.ExpiresAt != nil {
		t.Fatalf("zero-expiry usage = %+v present=%v", usage, present)
	}
}

func TestParseSubscriptionUserinfoRejectsMalformedRecognizedFields(t *testing.T) {
	cases := []string{
		"upload=-1",
		"download=abc",
		"total=",
		"expire=999999999999999999",
		"upload=1; upload=2",
		"feature=true",
		"upload=1\nexpire=2",
		strings.Repeat("x", MaxSubscriptionUserinfoBytes+1),
	}
	for _, value := range cases {
		usage, present, err := ParseSubscriptionUserinfo(value)
		if !present {
			t.Fatalf("header %q was not marked present", value)
		}
		if usage != nil {
			t.Fatalf("header %q produced usage %+v", value, usage)
		}
		if !errors.Is(err, ErrInvalidSubscriptionUserinfo) {
			t.Fatalf("header %q error = %v", value, err)
		}
	}
}

func TestSubscriptionUsageValidateRejectsInvalidValues(t *testing.T) {
	negative := int64(-1)
	if err := (SubscriptionUsage{UploadBytes: &negative}).Validate(); !errors.Is(err, ErrInvalidSubscriptionUserinfo) {
		t.Fatalf("negative usage error = %v", err)
	}
	tooLate := time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := (SubscriptionUsage{ExpiresAt: &tooLate}).Validate(); !errors.Is(err, ErrInvalidSubscriptionUserinfo) {
		t.Fatalf("out-of-range expiry error = %v", err)
	}
}
