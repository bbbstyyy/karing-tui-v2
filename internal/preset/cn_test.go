package preset

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/bbbstyyy/karing-tui-v2/internal/domain"
)

func TestLoadCNPreservesUpstream28GroupSnapshot(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SourceRepository != CNSourceRepository ||
		snapshot.SourceCommit != CNSourceCommit ||
		snapshot.SourcePath != CNSourcePath {
		t.Fatalf("unexpected source identity: %+v", snapshot)
	}
	if len(snapshot.Groups) != 28 {
		t.Fatalf("groups = %d, want 28", len(snapshot.Groups))
	}

	wantNames := []string{
		"🛑 广告拦截",
		"🍃 应用净化",
		"🛑 恶意软件",
		"📢 苹果推送通知",
		"🍎 苹果服务",
		"📹 油管视频",
		"♊️ Google Gemini",
		"🌏 Google Play",
		"📢 Google FCM",
		"🌏 Google",
		"📲 Facebook",
		"📲 X",
		"🎧 TikTok",
		"📸 Instagram",
		"🎥 奈飞视频",
		"📲 WhatsApp",
		"📲 电报消息",
		"💬 Claude",
		"💬 OpenAI",
		"🐱 GitHub",
		"Ⓜ️ 微软Bing",
		"Ⓜ️ 微软云盘",
		"Ⓜ️ 微软服务",
		"🎮 游戏平台",
		"📺 哔哩哔哩",
		"🎶 网易音乐",
		"🎯 国内直连",
		"🌏 国外穿墙",
	}
	gotNames := make([]string, len(snapshot.Groups))
	for i, group := range snapshot.Groups {
		if group.ID != cnExpectedID(i) {
			t.Fatalf("group %d ID = %q, want %q", i+1, group.ID, cnExpectedID(i))
		}
		if group.Order != uint32(i+1) {
			t.Fatalf("group %d order = %d", i+1, group.Order)
		}
		gotNames[i] = group.DisplayName
	}
	if !reflect.DeepEqual(gotNames, wantNames) {
		t.Fatalf("CN group order changed:\n%#v\nwant\n%#v", gotNames, wantNames)
	}
}

func TestLoadCNPreservesDefaultEnableAndTargets(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	var enabled []string
	for _, group := range snapshot.Groups {
		if group.Enabled {
			enabled = append(enabled, group.DisplayName)
		}
	}
	wantEnabled := []string{
		"🍎 苹果服务",
		"🌏 Google Play",
		"🌏 Google",
		"📺 哔哩哔哩",
		"🎯 国内直连",
		"🌏 国外穿墙",
	}
	if !reflect.DeepEqual(enabled, wantEnabled) {
		t.Fatalf("enabled groups = %#v, want %#v", enabled, wantEnabled)
	}

	cases := map[int]domain.TargetKind{
		1:  domain.TargetBlock,
		5:  domain.TargetDirect,
		8:  domain.TargetCurrentSelected,
		25: domain.TargetDirect,
		27: domain.TargetDirect,
		28: domain.TargetCurrentSelected,
	}
	for ordinal, want := range cases {
		if got := snapshot.Groups[ordinal-1].Target.Kind; got != want {
			t.Fatalf("group %d target = %q, want %q", ordinal, got, want)
		}
	}
}

func TestLoadCNPreservesRawConditionsWithoutLayerReclassification(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}

	push := snapshot.Groups[3].Source
	if got, want := push.DomainSuffix, []string{"push.apple.com", "akadns.net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Apple push suffixes = %#v, want %#v", got, want)
	}
	if got, want := push.DomainKeyword, []string{"apple.com.edgekey.net"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Apple push keywords = %#v, want %#v", got, want)
	}
	if len(push.IPCIDR) != 9 {
		t.Fatalf("Apple push CIDRs = %d, want 9", len(push.IPCIDR))
	}

	googlePlay := snapshot.Groups[7].Source
	if got, want := googlePlay.RuleSetBuildIn, []string{"geosite:google-play"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Google Play rule sets = %#v, want %#v", got, want)
	}
	if got, want := googlePlay.Package, []string{"com.android.vending"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("Google Play package = %#v, want %#v", got, want)
	}

	domestic := snapshot.Groups[26].Source
	if got, want := domestic.RuleSetBuildIn, []string{
		"acl:ChinaIp",
		"acl:ChinaDomain",
		"acl:ChinaCompanyIp",
		"acl:UnBan",
		"acl:SteamCN",
		"acl:Download",
		"acl:ChinaMedia",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("domestic rule sets = %#v, want %#v", got, want)
	}

	foreign := snapshot.Groups[27].Source
	if got, want := foreign.RuleSetBuildIn, []string{
		"geosite:geolocation-!cn",
		"geosite:google",
		"geoip:google",
		"acl:ProxyGFWlist",
		"acl:ProxyMedia",
	}; !reflect.DeepEqual(got, want) {
		t.Fatalf("foreign rule sets = %#v, want %#v", got, want)
	}
}

func TestCNSourceConditionsAreDeepCopied(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	first := snapshot.Groups[0].Source.RuleSetBuildIn[0]
	snapshot.Groups[0].Source.RuleSetBuildIn[0] = "mutated"

	reloaded, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Groups[0].Source.RuleSetBuildIn[0] != first {
		t.Fatal("mutating a loaded snapshot changed the embedded source")
	}
}

func TestParseCNRejectsUnknownFieldsAndSnapshotDrift(t *testing.T) {
	raw, err := cnFS.ReadFile("cn.json")
	if err != nil {
		t.Fatal(err)
	}

	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	rules := document["rules"].([]any)

	first := rules[0].(map[string]any)
	first["unknown_future_field"] = true
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCN(mutated); !errors.Is(err, ErrInvalidCNPreset) {
		t.Fatalf("unknown field error = %v", err)
	}

	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	rules = document["rules"].([]any)
	document["rules"] = rules[:27]
	mutated, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCN(mutated); !errors.Is(err, ErrInvalidCNPreset) {
		t.Fatalf("group count drift error = %v", err)
	}
}

func TestParseCNRejectsUnsupportedTarget(t *testing.T) {
	raw, err := cnFS.ReadFile("cn.json")
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	rules := document["rules"].([]any)
	rules[0].(map[string]any)["outbound"] = "mystery"
	mutated, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseCN(mutated); !errors.Is(err, ErrInvalidCNPreset) {
		t.Fatalf("unsupported target error = %v", err)
	}
}

func cnExpectedID(index int) string {
	return []string{
		"cn.ad-block",
		"cn.app-cleanup",
		"cn.malware",
		"cn.apple-push",
		"cn.apple-services",
		"cn.youtube",
		"cn.google-gemini",
		"cn.google-play",
		"cn.google-fcm",
		"cn.google",
		"cn.facebook",
		"cn.x",
		"cn.tiktok",
		"cn.instagram",
		"cn.netflix",
		"cn.whatsapp",
		"cn.telegram",
		"cn.claude",
		"cn.openai",
		"cn.github",
		"cn.bing",
		"cn.onedrive",
		"cn.microsoft",
		"cn.gaming",
		"cn.bilibili",
		"cn.netease-music",
		"cn.domestic-direct",
		"cn.foreign-proxy",
	}[index]
}

func TestCNRuleSetClosurePreservesFirstUseAcrossAllGroups(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	all := snapshot.RuleSetRefs(false)
	if len(all) != 66 {
		t.Fatalf("full rule-set closure = %d, want 66", len(all))
	}
	wantPrefix := []string{
		"acl:BanAD",
		"geosite:category-ads",
		"acl:BanProgramAD",
		"acl:BanADCompany",
		"geosite:malware",
		"geoip:malware",
	}
	if !reflect.DeepEqual(all[:len(wantPrefix)], wantPrefix) {
		t.Fatalf("rule-set closure prefix = %#v, want %#v", all[:len(wantPrefix)], wantPrefix)
	}
	wantSuffix := []string{
		"geosite:geolocation-!cn",
		"acl:ProxyGFWlist",
		"acl:ProxyMedia",
	}
	if !reflect.DeepEqual(all[len(all)-len(wantSuffix):], wantSuffix) {
		t.Fatalf("rule-set closure suffix = %#v, want %#v", all[len(all)-len(wantSuffix):], wantSuffix)
	}
}

func TestCNActiveRuleSetClosureUsesOnlySixDefaultEnabledGroups(t *testing.T) {
	snapshot, err := LoadCN()
	if err != nil {
		t.Fatal(err)
	}
	got := snapshot.RuleSetRefs(true)
	want := []string{
		"geosite:apple",
		"geosite:apple@ads",
		"geosite:apple-dev",
		"geosite:apple-pki",
		"geosite:apple-update",
		"geosite:google-play",
		"geosite:google",
		"geoip:google",
		"acl:BilibiliHMT",
		"acl:Bilibili",
		"acl:ChinaIp",
		"acl:ChinaDomain",
		"acl:ChinaCompanyIp",
		"acl:UnBan",
		"acl:SteamCN",
		"acl:Download",
		"acl:ChinaMedia",
		"geosite:geolocation-!cn",
		"acl:ProxyGFWlist",
		"acl:ProxyMedia",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("active rule-set closure = %#v, want %#v", got, want)
	}
}
