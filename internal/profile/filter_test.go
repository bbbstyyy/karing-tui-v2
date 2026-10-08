package profile

import (
	"errors"
	"strings"
	"testing"
)

func TestNodeFilterSpecAcceptsPersistedKaringFields(t *testing.T) {
	for _, filter := range []NodeFilterSpec{
		{},
		{Method: NodeFilterAll, KeywordOrRegex: "hk|jp", MatchAttribute: true},
		{Method: NodeFilterInclude, KeywordOrRegex: "HK|Hong Kong"},
		{Method: NodeFilterExclude, KeywordOrRegex: "expired|traffic", MatchAttribute: true},
	} {
		if err := filter.Validate(); err != nil {
			t.Fatalf("filter %+v: %v", filter, err)
		}
	}
}

func TestNodeFilterSpecRejectsUnsafeOrUnknownState(t *testing.T) {
	cases := []NodeFilterSpec{
		{Method: NodeFilterMethod("regex")},
		{Method: NodeFilterInclude, KeywordOrRegex: " padded "},
		{Method: NodeFilterExclude, KeywordOrRegex: "bad\nfilter"},
		{Method: NodeFilterInclude, KeywordOrRegex: strings.Repeat("x", MaxNodeFilterExpressionBytes+1)},
	}
	for i, filter := range cases {
		if err := filter.Validate(); !errors.Is(err, ErrInvalidNodeFilter) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}
