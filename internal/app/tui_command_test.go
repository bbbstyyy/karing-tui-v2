package app

import (
	"bytes"
	"strings"
	"testing"
)

func TestTUICommandRejectsExtraArgsWithoutLaunchingTerminal(t *testing.T) {
	var out, errs bytes.Buffer
	code := Run([]string{"tui", "unexpected"}, &out, &errs)
	if code != 2 || out.Len() != 0 || !strings.Contains(errs.String(), "usage: karing-tui tui") {
		t.Fatalf("tui command validation: code=%d stdout=%q stderr=%q", code, out.String(), errs.String())
	}
}
