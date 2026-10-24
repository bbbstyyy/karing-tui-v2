package profileupdate

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

func TestCommitBasicSingBoxProfilePreservesNodeIDAcrossPayloadUpdate(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)

	firstData := []byte(`{
  "outbounds":[
    {"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}
  ],
  "route":{"rules":[{"domain_suffix":["example.com"],"outbound":"proxy-a"}]}
}`)
	first, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "etag-1", firstData, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Nodes) != 1 || first.Nodes[0].Port != 8080 {
		t.Fatalf("first nodes = %+v", first.Nodes)
	}
	firstNodeID := first.Nodes[0].NodeID
	if firstNodeID == "" {
		t.Fatal("first node ID is empty")
	}

	secondData := []byte(`{
  "outbounds":[
    {"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":9090}
  ]
}`)
	second, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "etag-2", secondData, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Nodes) != 1 || second.Nodes[0].Port != 9090 {
		t.Fatalf("second nodes = %+v", second.Nodes)
	}
	if second.Nodes[0].NodeID != firstNodeID {
		t.Fatalf("payload update changed stable NodeID: first=%q second=%q", firstNodeID, second.Nodes[0].NodeID)
	}

	previous, ok, err := store.PreviousProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || previous.ID != first.Commit.Snapshot.ID {
		t.Fatalf("previous snapshot = %+v ok=%v", previous, ok)
	}
	previousNodes, err := MaterializeBasicSingBoxSnapshot(previous)
	if err != nil {
		t.Fatal(err)
	}
	if len(previousNodes) != 1 || previousNodes[0].Port != 8080 || previousNodes[0].NodeID != firstNodeID {
		t.Fatalf("previous materialized nodes = %+v", previousNodes)
	}

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	current, ok, err := reopened.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("current profile snapshot disappeared after reopen")
	}
	reloadedNodes, err := MaterializeBasicSingBoxSnapshot(current)
	if err != nil {
		t.Fatal(err)
	}
	if len(reloadedNodes) != 1 || reloadedNodes[0].Port != 9090 || reloadedNodes[0].NodeID != firstNodeID {
		t.Fatalf("reloaded nodes = %+v", reloadedNodes)
	}
}

func TestCommitBasicSingBoxProfilePersistsShadowsocksAcrossReopen(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)

	result, err := CommitBasicSingBoxProfile(ctx, store, "profile-ss", "v1", []byte(`{
  "outbounds":[{
    "type":"shadowsocks",
    "tag":"ss-a",
    "server":"ss.example.com",
    "server_port":8388,
    "method":"aes-256-gcm",
    "password":"secret",
    "plugin":"obfs-local",
    "plugin_opts":"obfs=http",
    "network":"tcp"
  }]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 ||
		result.Nodes[0].Kind != domain.NodeShadowsocks ||
		result.Nodes[0].Shadowsocks == nil ||
		result.Nodes[0].Shadowsocks.PluginOptions != "obfs=http" {
		t.Fatalf("committed Shadowsocks nodes = %+v", result.Nodes)
	}
	nodeID := result.Nodes[0].NodeID
	snapshotID := result.Commit.Snapshot.ID

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	snapshot, err := reopened.ProfileSnapshotByID(ctx, "profile-ss", snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := MaterializeBasicSingBoxSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 ||
		nodes[0].NodeID != nodeID ||
		nodes[0].Kind != domain.NodeShadowsocks ||
		nodes[0].Shadowsocks == nil ||
		nodes[0].Shadowsocks.Method != "aes-256-gcm" ||
		nodes[0].Shadowsocks.Password != "secret" ||
		nodes[0].Shadowsocks.Plugin != "obfs-local" ||
		nodes[0].Shadowsocks.PluginOptions != "obfs=http" ||
		nodes[0].Shadowsocks.Network != domain.ProxyNetworkTCP {
		t.Fatalf("reopened Shadowsocks nodes = %+v", nodes)
	}
}

func TestCommitBasicSingBoxProfilePersistsVMessAcrossReopen(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)

	result, err := CommitBasicSingBoxProfile(ctx, store, "profile-vmess", "v1", []byte(`{
  "outbounds":[{
    "type":"vmess",
    "tag":"vmess-a",
    "server":"vmess.example.com",
    "server_port":10086,
    "uuid":"11111111-2222-3333-4444-555555555555",
    "security":"aes-128-gcm",
    "alter_id":1,
    "global_padding":true,
    "authenticated_length":true,
    "network":"udp",
    "packet_encoding":"xudp"
  }]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 ||
		result.Nodes[0].Kind != domain.NodeVMess ||
		result.Nodes[0].VMess == nil ||
		result.Nodes[0].VMess.PacketEncoding != "xudp" {
		t.Fatalf("committed VMess nodes = %+v", result.Nodes)
	}
	nodeID := result.Nodes[0].NodeID
	snapshotID := result.Commit.Snapshot.ID

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	snapshot, err := reopened.ProfileSnapshotByID(ctx, "profile-vmess", snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := MaterializeBasicSingBoxSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 ||
		nodes[0].NodeID != nodeID ||
		nodes[0].Kind != domain.NodeVMess ||
		nodes[0].VMess == nil ||
		nodes[0].VMess.UUID != "11111111-2222-3333-4444-555555555555" ||
		nodes[0].VMess.Security != "aes-128-gcm" ||
		nodes[0].VMess.AlterID != 1 ||
		!nodes[0].VMess.GlobalPadding ||
		!nodes[0].VMess.AuthenticatedLength ||
		nodes[0].VMess.Network != domain.ProxyNetworkUDP ||
		nodes[0].VMess.PacketEncoding != "xudp" {
		t.Fatalf("reopened VMess nodes = %+v", nodes)
	}
}

func TestCommitBasicSingBoxProfilePersistsVLESSPacketEncodingAcrossReopen(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)

	result, err := CommitBasicSingBoxProfile(ctx, store, "profile-vless", "v1", []byte(`{
  "outbounds":[{
    "type":"vless",
    "tag":"vless-a",
    "server":"vless.example.com",
    "server_port":443,
    "uuid":"11111111-2222-3333-4444-555555555555",
    "encryption":"none",
    "network":"udp",
    "packet_encoding":"",
    "tls":{"enabled":true,"server_name":"edge.example.com","insecure":true}
  }]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 ||
		result.Nodes[0].Kind != domain.NodeVLESS ||
		result.Nodes[0].VLESS == nil ||
		result.Nodes[0].VLESS.PacketEncoding == nil ||
		*result.Nodes[0].VLESS.PacketEncoding != "" ||
		result.Nodes[0].TLS == nil ||
		!result.Nodes[0].TLS.Enabled ||
		result.Nodes[0].TLS.ServerName != "edge.example.com" ||
		!result.Nodes[0].TLS.Insecure {
		t.Fatalf("committed VLESS nodes = %+v", result.Nodes)
	}
	nodeID := result.Nodes[0].NodeID
	snapshotID := result.Commit.Snapshot.ID

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	snapshot, err := reopened.ProfileSnapshotByID(ctx, "profile-vless", snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := MaterializeBasicSingBoxSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 ||
		nodes[0].NodeID != nodeID ||
		nodes[0].Kind != domain.NodeVLESS ||
		nodes[0].VLESS == nil ||
		nodes[0].VLESS.UUID != "11111111-2222-3333-4444-555555555555" ||
		nodes[0].VLESS.Encryption != "none" ||
		nodes[0].VLESS.Network != domain.ProxyNetworkUDP ||
		nodes[0].VLESS.PacketEncoding == nil ||
		*nodes[0].VLESS.PacketEncoding != "" ||
		nodes[0].TLS == nil ||
		!nodes[0].TLS.Enabled ||
		nodes[0].TLS.ServerName != "edge.example.com" ||
		!nodes[0].TLS.Insecure {
		t.Fatalf("reopened VLESS nodes = %+v", nodes)
	}
}

func TestCommitBasicSingBoxProfilePersistsTrojanAcrossReopen(t *testing.T) {
	ctx := context.Background()
	store, path := newProfileUpdateStore(t, ctx)

	result, err := CommitBasicSingBoxProfile(ctx, store, "profile-trojan", "v1", []byte(`{
  "outbounds":[{
    "type":"trojan",
    "tag":"trojan-a",
    "server":"trojan.example.com",
    "server_port":443,
    "password":"secret",
    "network":"tcp"
  }]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 1 ||
		result.Nodes[0].Kind != domain.NodeTrojan ||
		result.Nodes[0].Trojan == nil ||
		result.Nodes[0].Trojan.Password != "secret" ||
		result.Nodes[0].Trojan.Network != domain.ProxyNetworkTCP {
		t.Fatalf("committed Trojan nodes = %+v", result.Nodes)
	}
	nodeID := result.Nodes[0].NodeID
	snapshotID := result.Commit.Snapshot.ID

	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	snapshot, err := reopened.ProfileSnapshotByID(ctx, "profile-trojan", snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := MaterializeBasicSingBoxSnapshot(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 ||
		nodes[0].NodeID != nodeID ||
		nodes[0].Kind != domain.NodeTrojan ||
		nodes[0].Trojan == nil ||
		nodes[0].Trojan.Password != "secret" ||
		nodes[0].Trojan.Network != domain.ProxyNetworkTCP {
		t.Fatalf("reopened Trojan nodes = %+v", nodes)
	}
}

func TestCommitBasicSingBoxProfileBlocksUnsupportedProtocolWithoutAdvancingSnapshot(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	valid, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "v1", []byte(`{
  "outbounds":[{"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":8080}]
}`), Options{})
	if err != nil {
		t.Fatal(err)
	}

	blocked, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "v2", []byte(`{
  "outbounds":[
    {"type":"http","tag":"proxy-a","server":"127.0.0.1","server_port":9090},
    {"type":"hysteria2","tag":"unsupported","server":"example.com","server_port":443,"password":"secret"}
  ]
}`), Options{})
	if !errors.Is(err, ErrImportBlocked) {
		t.Fatalf("blocked import error = %v", err)
	}
	if !blocked.Analysis.HasBlockingDiagnostics() {
		t.Fatalf("blocked import lost diagnostics: %+v", blocked.Analysis.Diagnostics)
	}

	current, ok, err := store.CurrentProfileSnapshot(ctx, "profile-a")
	if err != nil {
		t.Fatal(err)
	}
	if !ok || current.ID != valid.Commit.Snapshot.ID || current.SourceRevision != "v1" {
		t.Fatalf("blocked import advanced snapshot: %+v ok=%v", current, ok)
	}
}

func TestCommitBasicSingBoxProfileRequiresExplicitEmptyConfirmation(t *testing.T) {
	ctx := context.Background()
	store, _ := newProfileUpdateStore(t, ctx)
	defer store.Close()

	data := []byte(`{
  "outbounds":[{"type":"direct","tag":"direct"}]
}`)
	_, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "empty-1", data, Options{})
	if !errors.Is(err, storage.ErrEmptyProfileSnapshot) {
		t.Fatalf("implicit empty import error = %v", err)
	}
	result, err := CommitBasicSingBoxProfile(ctx, store, "profile-a", "empty-2", data, Options{AllowEmpty: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Nodes) != 0 || len(result.Commit.Snapshot.Nodes) != 0 {
		t.Fatalf("explicit empty snapshot unexpectedly materialized nodes: %+v", result)
	}
}

func newProfileUpdateStore(t *testing.T, ctx context.Context) (*storage.Store, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	store, err := storage.Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return store, path
}
