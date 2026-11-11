package declaration

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func replacementHTTPNode(id string) domain.Node {
	return domain.Node{
		ProfileID: "p1", NodeID: id, Kind: domain.NodeHTTP,
		Server: "127.0.0.1", Port: 8080,
		HTTP: &domain.HTTPNodeOptions{},
	}
}

func simpleRebindDocument(t *testing.T) []byte {
	t.Helper()
	doc, err := BuildInitialProxyOnlyV1(
		[]domain.Node{replacementHTTPNode("n1")}, "n1", netip.MustParseAddrPort("127.0.0.1:53"),
	)
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestExplicitSelectionRebindRequiresChosenAcceptedNode(t *testing.T) {
	base := simpleRebindDocument(t)
	nodes := []domain.Node{replacementHTTPNode("n2")}
	if _, err := ReplaceProfileNodesV1(base, "p1", nodes); !errors.Is(err, ErrProfileNodeReplacementInvalid) {
		t.Fatalf("removed selected node silently replaced: %v", err)
	}
	replaced, err := ReplaceProfileNodesWithExplicitSelectionV1(base, "p1", nodes, "n2")
	if err != nil {
		t.Fatal(err)
	}
	if len(replaced.Impact.AddedNodeIDs) != 1 || replaced.Impact.AddedNodeIDs[0] != "n2" ||
		len(replaced.Impact.RemovedNodeIDs) != 1 || replaced.Impact.RemovedNodeIDs[0] != "n1" {
		t.Fatalf("incorrect accepted source diff: %+v", replaced.Impact)
	}
	model, err := ParseV1(replaced.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Selection.Current.Members) != 1 ||
		model.Selection.Current.Members[0].NodeID != "n2" ||
		model.Selection.Current.Default.NodeID != "n2" ||
		model.Routing.Final.Kind != domain.TargetCurrentSelected {
		t.Fatalf("explicit selection was not rebound: %+v", model.Selection.Current)
	}
	for _, invalid := range []string{"", "n1", "missing"} {
		if _, err := ReplaceProfileNodesWithExplicitSelectionV1(base, "p1", nodes, invalid); err == nil {
			t.Fatalf("invalid replacement %q accepted", invalid)
		}
	}
}

func TestExplicitSelectionRebindRejectsCrossProfileOrRichSelection(t *testing.T) {
	base := simpleRebindDocument(t)
	bad := replacementHTTPNode("n2")
	bad.ProfileID = "p2"
	if _, err := ReplaceProfileNodesWithExplicitSelectionV1(base, "p1", []domain.Node{bad}, "n2"); err == nil {
		t.Fatal("cross-profile replacement accepted")
	}
	richer, err := ReplaceProfileNodesV1(base, "p2", []domain.Node{{
		ProfileID: "p2", NodeID: "z1", Kind: domain.NodeHTTP,
		Server: "127.0.0.1", Port: 9090, HTTP: &domain.HTTPNodeOptions{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ReplaceProfileNodesWithExplicitSelectionV1(richer.Document, "p1", []domain.Node{replacementHTTPNode("n2")}, "n2"); !errors.Is(err, ErrProfileNodeReplacementInvalid) {
		t.Fatalf("multi-profile declaration should be refused: %v", err)
	}
}
