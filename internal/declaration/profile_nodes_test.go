package declaration

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestReplaceProfileNodesV1PreservesStableReferenceAndUpdatesPayload(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p1", []domain.Node{{
		ProfileID: "p1",
		NodeID:    "n1",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{Username: "u", Password: "p"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := replacement.Impact.RetainedNodeIDs, []string{"n1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retained nodes = %#v, want %#v", got, want)
	}
	if len(replacement.Impact.AddedNodeIDs) != 0 || len(replacement.Impact.RemovedNodeIDs) != 0 {
		t.Fatalf("unexpected replacement impact: %+v", replacement.Impact)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 1 || model.Nodes[0].Port != 8080 ||
		model.Nodes[0].HTTP == nil ||
		model.Nodes[0].HTTP.Username != "u" ||
		model.Selection.Current.Default.NodeID != "n1" {
		t.Fatalf("replacement model = %+v", model)
	}
}

func TestReplaceProfileNodesV1ReportsRemovedReferenceAndFailsClosed(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p1", []domain.Node{{
		ProfileID: "p1",
		NodeID:    "n2",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}})
	if !errors.Is(err, ErrProfileNodeReplacementInvalid) {
		t.Fatalf("removed referenced node error = %v", err)
	}
	if len(replacement.Document) == 0 {
		t.Fatal("failed replacement did not return inspectable candidate document")
	}
	if got, want := replacement.Impact.AddedNodeIDs, []string{"n2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("added nodes = %#v, want %#v", got, want)
	}
	if got, want := replacement.Impact.RemovedNodeIDs, []string{"n1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed nodes = %#v, want %#v", got, want)
	}
	if len(replacement.Impact.RetainedNodeIDs) != 0 {
		t.Fatalf("retained nodes = %#v", replacement.Impact.RetainedNodeIDs)
	}
}

func TestReplaceProfileNodesV1AppendsNewProfileWithoutChangingExistingOrder(t *testing.T) {
	replacement, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "n2",
		Kind:      domain.NodeSOCKS,
		Server:    "127.0.0.1",
		Port:      1080,
		SOCKS: &domain.SOCKSNodeOptions{
			Version: domain.SOCKS5,
			Network: domain.ProxyNetworkBoth,
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := ParseV1(replacement.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 2 ||
		model.Nodes[0].ProfileID != "p1" ||
		model.Nodes[0].NodeID != "n1" ||
		model.Nodes[1].ProfileID != "p2" ||
		model.Nodes[1].NodeID != "n2" {
		t.Fatalf("node order = %+v", model.Nodes)
	}
	if got, want := replacement.Impact.AddedNodeIDs, []string{"n2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("impact = %+v", replacement.Impact)
	}
}

func TestReplaceProfileNodesV1RejectsCrossProfileReplacement(t *testing.T) {
	_, err := ReplaceProfileNodesV1(minimalDeclaration(), "p1", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "n2",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}})
	if err == nil {
		t.Fatal("cross-profile replacement was accepted")
	}
}

func TestReplaceProfileNodesV1CanRemoveUnreferencedProfile(t *testing.T) {
	withP2, err := ReplaceProfileNodesV1(minimalDeclaration(), "p2", []domain.Node{{
		ProfileID: "p2",
		NodeID:    "n2",
		Kind:      domain.NodeHTTP,
		Server:    "127.0.0.1",
		Port:      8080,
		HTTP:      &domain.HTTPNodeOptions{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	removed, err := ReplaceProfileNodesV1(withP2.Document, "p2", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := removed.Impact.RemovedNodeIDs, []string{"n2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("removed impact = %+v", removed.Impact)
	}
	model, err := ParseV1(removed.Document)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Nodes) != 1 || model.Nodes[0].ProfileID != "p1" {
		t.Fatalf("unreferenced profile removal changed other nodes: %+v", model.Nodes)
	}
}
