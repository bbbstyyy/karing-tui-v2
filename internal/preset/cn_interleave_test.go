package preset

import (
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestMergeCNCustomRoutingInterleavesWithoutChangingOrdinaryRelativeOrder(t *testing.T) {
	custom := []domain.RouteGroup{
		testCNCustomGroup("user.first", 10, "first.invalid"),
		testCNCustomGroup("user.second", 20, "second.invalid"),
	}
	cn := []domain.RouteGroup{
		testCNCustomGroup("cn.one", 1, "cn-one.invalid"),
		testCNCustomGroup("cn.two", 2, "cn-two.invalid"),
	}

	got, err := MergeCNCustomRouting(custom, cn, []CNCustomOrderEntry{
		{Kind: CNCustomOrderPreset, GroupID: "cn.two"},
		{Kind: CNCustomOrderUser, GroupID: "user.first"},
		{Kind: CNCustomOrderPreset, GroupID: "cn.one"},
		{Kind: CNCustomOrderUser, GroupID: "user.second"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gotIDs := make([]string, 0, len(got))
	gotOrders := make([]uint32, 0, len(got))
	for _, group := range got {
		gotIDs = append(gotIDs, group.ID)
		gotOrders = append(gotOrders, group.Order)
	}
	if want := []string{"cn.two", "user.first", "cn.one", "user.second"}; !reflect.DeepEqual(gotIDs, want) {
		t.Fatalf("merged IDs = %#v, want %#v", gotIDs, want)
	}
	if want := []uint32{1, 2, 3, 4}; !reflect.DeepEqual(gotOrders, want) {
		t.Fatalf("merged orders = %#v, want %#v", gotOrders, want)
	}

	got[1].Match.Predicate.Value = "mutated.invalid"
	if custom[0].Match.Predicate.Value != "first.invalid" {
		t.Fatal("merged ordinary custom matcher aliases input")
	}
	got[0].Match.Predicate.Value = "mutated-cn.invalid"
	if cn[1].Match.Predicate.Value != "cn-two.invalid" {
		t.Fatal("merged CN matcher aliases input")
	}
}

func TestMergeCNCustomRoutingUsesSnapshotOrderWhenCNIsOnlyCustomSource(t *testing.T) {
	cn := []domain.RouteGroup{
		testCNCustomGroup("cn.one", 4, "one.invalid"),
		testCNCustomGroup("cn.two", 9, "two.invalid"),
	}
	got, err := MergeCNCustomRouting(nil, cn, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got[0].ID != "cn.one" || got[0].Order != 1 ||
		got[1].ID != "cn.two" || got[1].Order != 2 {
		t.Fatalf("implicit CN-only order = %+v", got)
	}
}

func TestMergeCNCustomRoutingRequiresExplicitOrderWhenSourcesCoexist(t *testing.T) {
	_, err := MergeCNCustomRouting(
		[]domain.RouteGroup{testCNCustomGroup("user.one", 1, "user.invalid")},
		[]domain.RouteGroup{testCNCustomGroup("cn.one", 1, "cn.invalid")},
		nil,
	)
	if !errors.Is(err, ErrInvalidCNCustomOrder) {
		t.Fatalf("coexisting-source error = %v", err)
	}
}

func TestMergeCNCustomRoutingRejectsInvalidCoverageAndProjection(t *testing.T) {
	custom := []domain.RouteGroup{
		testCNCustomGroup("user.first", 10, "first.invalid"),
		testCNCustomGroup("user.second", 20, "second.invalid"),
	}
	cn := []domain.RouteGroup{
		testCNCustomGroup("cn.one", 1, "cn-one.invalid"),
		testCNCustomGroup("cn.two", 2, "cn-two.invalid"),
	}
	cases := [][]CNCustomOrderEntry{
		{
			{Kind: CNCustomOrderPreset, GroupID: "cn.one"},
		},
		{
			{Kind: CNCustomOrderPreset, GroupID: "cn.one"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.one"},
			{Kind: CNCustomOrderUser, GroupID: "user.first"},
			{Kind: CNCustomOrderUser, GroupID: "user.second"},
		},
		{
			{Kind: CNCustomOrderUser, GroupID: "user.second"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.one"},
			{Kind: CNCustomOrderUser, GroupID: "user.first"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.two"},
		},
		{
			{Kind: CNCustomOrderUser, GroupID: "user.first"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.unknown"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.two"},
			{Kind: CNCustomOrderUser, GroupID: "user.second"},
		},
		{
			{Kind: CNCustomOrderKind("future"), GroupID: "cn.one"},
			{Kind: CNCustomOrderUser, GroupID: "user.first"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.two"},
			{Kind: CNCustomOrderUser, GroupID: "user.second"},
		},
	}
	for i, order := range cases {
		if _, err := MergeCNCustomRouting(custom, cn, order); !errors.Is(err, ErrInvalidCNCustomOrder) {
			t.Fatalf("case %d error = %v", i, err)
		}
	}
}

func TestMergeCNCustomRoutingRejectsIDCollision(t *testing.T) {
	_, err := MergeCNCustomRouting(
		[]domain.RouteGroup{testCNCustomGroup("cn.one", 1, "user.invalid")},
		[]domain.RouteGroup{testCNCustomGroup("cn.one", 1, "cn.invalid")},
		[]CNCustomOrderEntry{
			{Kind: CNCustomOrderUser, GroupID: "cn.one"},
			{Kind: CNCustomOrderPreset, GroupID: "cn.one"},
		},
	)
	if !errors.Is(err, ErrInvalidCNCustomOrder) {
		t.Fatalf("ID collision error = %v", err)
	}
}

func testCNCustomGroup(id string, order uint32, domainName string) domain.RouteGroup {
	match := domain.Atom(domain.Predicate{Kind: domain.PredicateDomain, Value: domainName})
	return domain.RouteGroup{
		ID:    id,
		Layer: domain.LayerCustom,
		Order: order,
		Match: &match,
		Binding: domain.RouteBinding{
			Enabled: true,
			Target:  domain.TargetRef{Kind: domain.TargetDirect},
		},
	}
}
