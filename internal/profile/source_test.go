package profile

import (
	"errors"
	"testing"
	"time"
)

func TestSourceSpecAcceptsHTTPSDirect(t *testing.T) {
	spec := SourceSpec{
		ProfileID:    "profile-a",
		Format:       SourceFormatSingBox,
		LocationKind: SourceLocationURL,
		Location:     "https://example.com/subscription?token=secret",
		UserAgent:    "karing-tui-v2/test",
		Fetch:        FetchPolicy{Mode: FetchDirect},
		Enabled:      true,
	}
	if err := spec.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestSourceSpecAcceptsURIListSources(t *testing.T) {
	for _, location := range []struct {
		kind  SourceLocationKind
		value string
	}{
		{kind: SourceLocationURL, value: "https://example.com/subscription.txt"},
		{kind: SourceLocationFile, value: "/home/user/subscription.txt"},
	} {
		spec := SourceSpec{
			ProfileID:    "profile-uri",
			Format:       SourceFormatURIList,
			LocationKind: location.kind,
			Location:     location.value,
			Fetch:        FetchPolicy{Mode: FetchDirect},
			Enabled:      true,
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("URI-list source %+v: %v", location, err)
		}
	}
}

func TestSourceSpecAcceptsExplicitBase64URIList(t *testing.T) {
	for _, kind := range []SourceLocationKind{SourceLocationURL, SourceLocationFile} {
		location := "https://example.com/v2ray-subscription"
		if kind == SourceLocationFile {
			location = "/home/user/subscription.base64"
		}
		spec := SourceSpec{
			ProfileID:    "profile-b64",
			Format:       SourceFormatBase64URIList,
			LocationKind: kind,
			Location:     location,
			Fetch:        FetchPolicy{Mode: FetchDirect},
			Enabled:      true,
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("base64 URI-list source %q: %v", kind, err)
		}
	}
}

func TestSourceSpecAcceptsSelectedAndFixedFetch(t *testing.T) {
	for _, fetch := range []FetchPolicy{
		{Mode: FetchSelected},
		{Mode: FetchSpecificNode, ProfileID: "bootstrap-profile", NodeID: "node-1"},
	} {
		spec := SourceSpec{
			ProfileID:    "profile-a",
			Format:       SourceFormatSingBox,
			LocationKind: SourceLocationURL,
			Location:     "https://example.com/subscription",
			Fetch:        fetch,
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("fetch %+v: %v", fetch, err)
		}
	}
}

func TestSourceSpecRejectsURLUserinfoAndUnsupportedScheme(t *testing.T) {
	cases := []string{
		"https://user:pass@example.com/sub",
		"file:///tmp/sub.json",
		"ftp://example.com/sub",
	}
	for _, location := range cases {
		spec := SourceSpec{
			ProfileID:    "profile-a",
			Format:       SourceFormatSingBox,
			LocationKind: SourceLocationURL,
			Location:     location,
			Fetch:        FetchPolicy{Mode: FetchDirect},
		}
		if err := spec.Validate(); !errors.Is(err, ErrInvalidProfileSource) {
			t.Fatalf("location %q error = %v", location, err)
		}
	}
}

func TestSourceSpecRequiresAbsoluteCleanFileAndDirectMode(t *testing.T) {
	valid := SourceSpec{
		ProfileID:    "profile-a",
		Format:       SourceFormatSingBox,
		LocationKind: SourceLocationFile,
		Location:     "/home/user/sub.json",
		Fetch:        FetchPolicy{Mode: FetchDirect},
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	for _, spec := range []SourceSpec{
		{
			ProfileID:    "profile-a",
			Format:       SourceFormatSingBox,
			LocationKind: SourceLocationFile,
			Location:     "relative/sub.json",
			Fetch:        FetchPolicy{Mode: FetchDirect},
		},
		{
			ProfileID:    "profile-a",
			Format:       SourceFormatSingBox,
			LocationKind: SourceLocationFile,
			Location:     "/home/user/../user/sub.json",
			Fetch:        FetchPolicy{Mode: FetchDirect},
		},
		{
			ProfileID:    "profile-a",
			Format:       SourceFormatSingBox,
			LocationKind: SourceLocationFile,
			Location:     "/home/user/sub.json",
			Fetch:        FetchPolicy{Mode: FetchSelected},
		},
	} {
		if err := spec.Validate(); !errors.Is(err, ErrInvalidProfileSource) {
			t.Fatalf("spec %+v error = %v", spec, err)
		}
	}
}

func TestFetchPolicyRejectsAmbiguousReferences(t *testing.T) {
	cases := []FetchPolicy{
		{Mode: FetchDirect, ProfileID: "p", NodeID: "n"},
		{Mode: FetchSelected, ProfileID: "p", NodeID: "n"},
		{Mode: FetchSpecificNode},
		{Mode: FetchSpecificNode, ProfileID: "p"},
		{Mode: "unknown"},
	}
	for _, policy := range cases {
		if err := policy.Validate(); !errors.Is(err, ErrInvalidProfileSource) {
			t.Fatalf("policy %+v error = %v", policy, err)
		}
	}
}

func TestSourceSpecUpdateIntervalMatchesConfirmedKaringBounds(t *testing.T) {
	valid := []time.Duration{
		0,
		MinUpdateInterval,
		DefaultUpdateInterval,
		MaxUpdateInterval,
	}
	for _, interval := range valid {
		spec := SourceSpec{
			ProfileID:      "profile-a",
			Format:         SourceFormatSingBox,
			LocationKind:   SourceLocationURL,
			Location:       "https://example.com/subscription",
			Fetch:          FetchPolicy{Mode: FetchDirect},
			UpdateInterval: interval,
			Enabled:        true,
		}
		if err := spec.Validate(); err != nil {
			t.Fatalf("interval %s: %v", interval, err)
		}
	}

	invalid := []time.Duration{
		MinUpdateInterval - time.Second,
		MaxUpdateInterval + time.Second,
		MinUpdateInterval + time.Nanosecond,
	}
	for _, interval := range invalid {
		spec := SourceSpec{
			ProfileID:      "profile-a",
			Format:         SourceFormatSingBox,
			LocationKind:   SourceLocationURL,
			Location:       "https://example.com/subscription",
			Fetch:          FetchPolicy{Mode: FetchDirect},
			UpdateInterval: interval,
			Enabled:        true,
		}
		if err := spec.Validate(); !errors.Is(err, ErrInvalidProfileSource) {
			t.Fatalf("invalid interval %s error = %v", interval, err)
		}
	}
}

func TestSourceSpecRejectsAutomaticPollingForLocalFile(t *testing.T) {
	spec := SourceSpec{
		ProfileID:      "profile-a",
		Format:         SourceFormatSingBox,
		LocationKind:   SourceLocationFile,
		Location:       "/home/user/sub.json",
		Fetch:          FetchPolicy{Mode: FetchDirect},
		UpdateInterval: DefaultUpdateInterval,
		Enabled:        true,
	}
	if err := spec.Validate(); !errors.Is(err, ErrInvalidProfileSource) {
		t.Fatalf("scheduled local file error = %v", err)
	}
}
