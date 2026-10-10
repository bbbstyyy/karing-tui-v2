package profile

import (
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

const MaxNodeFilterExpressionBytes = 4096

type NodeFilterMethod string

const (
	NodeFilterAll     NodeFilterMethod = ""
	NodeFilterInclude NodeFilterMethod = "include"
	NodeFilterExclude NodeFilterMethod = "exclude"
)

var ErrInvalidNodeFilter = errors.New("invalid profile node filter")

type NodeFilterSpec struct {
	Method         NodeFilterMethod
	KeywordOrRegex string
	MatchAttribute bool
}

func (f NodeFilterSpec) Validate() error {
	switch f.Method {
	case NodeFilterAll, NodeFilterInclude, NodeFilterExclude:
	default:
		return fmt.Errorf("%w: unsupported method %q", ErrInvalidNodeFilter, f.Method)
	}
	if len(f.KeywordOrRegex) > MaxNodeFilterExpressionBytes {
		return fmt.Errorf(
			"%w: expression exceeds %d bytes",
			ErrInvalidNodeFilter,
			MaxNodeFilterExpressionBytes,
		)
	}
	if !utf8.ValidString(f.KeywordOrRegex) {
		return fmt.Errorf("%w: expression is not valid UTF-8", ErrInvalidNodeFilter)
	}
	if strings.TrimSpace(f.KeywordOrRegex) != f.KeywordOrRegex {
		return fmt.Errorf("%w: expression must not have leading or trailing whitespace", ErrInvalidNodeFilter)
	}
	for _, r := range f.KeywordOrRegex {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: expression contains a control character", ErrInvalidNodeFilter)
		}
	}
	return nil
}
