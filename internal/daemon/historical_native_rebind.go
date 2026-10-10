package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/bbbstyyy/karing-tui-v2/internal/compiler"
	"github.com/bbbstyyy/karing-tui-v2/internal/coreartifact"
	"github.com/bbbstyyy/karing-tui-v2/internal/storage"
)

var ErrHistoricalPathRebind = errors.New("historical rule-set path rebind rejected")

// rebindHistoricalCheckJSON changes ONLY route.rule_set[].path in a verified,
// compiler-owned historical native config. The original generation bytes,
// manifest and source-map are never modified. This result is non-activatable
// ephemeral Check input; its SHA deliberately differs from the stored one.
func rebindHistoricalCheckJSON(
	ctx context.Context, original []byte, manifest compiler.NativeManifest,
	snapshot *coreartifact.RuleSetSnapshot,
) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if snapshot == nil || len(manifest.RuleSets) == 0 ||
		len(manifest.RuleSets) > coreartifact.MaxRuleSetSnapshotFiles ||
		len(original) == 0 || len(original) > storage.MaxGenerationConfigBytes ||
		!json.Valid(original) {
		return nil, ErrHistoricalPathRebind
	}
	sum := sha256.Sum256(original)
	if hex.EncodeToString(sum[:]) != manifest.ConfigSHA256 {
		return nil, ErrHistoricalPathRebind
	}
	if err := snapshot.Verify(ctx); err != nil {
		return nil, ErrHistoricalPathRebind
	}

	// Use RawMessage instead of a generic untyped map for everything except
	// the exact compiler-emitted local rule-set nodes. DNS, routing rules,
	// outbounds, selectors, control secret and all other fields are untouched.
	var root map[string]json.RawMessage
	if err := json.Unmarshal(original, &root); err != nil {
		return nil, ErrHistoricalPathRebind
	}
	var route map[string]json.RawMessage
	if err := json.Unmarshal(root["route"], &route); err != nil || route == nil {
		return nil, ErrHistoricalPathRebind
	}
	var rules []json.RawMessage
	if err := json.Unmarshal(route["rule_set"], &rules); err != nil ||
		len(rules) != len(manifest.RuleSets) {
		return nil, ErrHistoricalPathRebind
	}
	expected := make(map[string]compiler.NativeRuleSetManifest, len(manifest.RuleSets))
	for _, rule := range manifest.RuleSets {
		if rule.Ref == "" || rule.RuntimeTag == "" || rule.RuntimePath == "" {
			return nil, ErrHistoricalPathRebind
		}
		if _, duplicate := expected[rule.RuntimeTag]; duplicate {
			return nil, ErrHistoricalPathRebind
		}
		if rule.Format != compiler.RuleSetFormatSource &&
			rule.Format != compiler.RuleSetFormatBinary {
			return nil, ErrHistoricalPathRebind
		}
		expected[rule.RuntimeTag] = rule
	}
	for i, raw := range rules {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
			return nil, ErrHistoricalPathRebind
		}
		var local struct {
			Type   string                 `json:"type"`
			Tag    string                 `json:"tag"`
			Format compiler.RuleSetFormat `json:"format"`
			Path   string                 `json:"path"`
		}
		if err := json.Unmarshal(raw, &local); err != nil || local.Type != "local" {
			return nil, ErrHistoricalPathRebind
		}
		source, ok := expected[local.Tag]
		if !ok || local.Format != source.Format ||
			local.Path != source.RuntimePath {
			return nil, ErrHistoricalPathRebind
		}
		copyPath, exists := snapshot.FileFor(source.RuntimePath)
		if !exists {
			return nil, ErrHistoricalPathRebind
		}
		copyJSON, err := json.Marshal(copyPath)
		if err != nil {
			return nil, fmt.Errorf("%w: encode isolated path", ErrHistoricalPathRebind)
		}
		fields["path"] = copyJSON
		rules[i], err = json.Marshal(fields)
		if err != nil {
			return nil, ErrHistoricalPathRebind
		}
		delete(expected, local.Tag)
	}
	if len(expected) != 0 {
		return nil, ErrHistoricalPathRebind
	}
	ruleSetJSON, err := json.Marshal(rules)
	if err != nil {
		return nil, ErrHistoricalPathRebind
	}
	route["rule_set"] = ruleSetJSON
	routeJSON, err := json.Marshal(route)
	if err != nil {
		return nil, ErrHistoricalPathRebind
	}
	root["route"] = routeJSON
	result, err := json.Marshal(root)
	if err != nil || len(result) > storage.MaxGenerationConfigBytes {
		return nil, ErrHistoricalPathRebind
	}
	// Confirm no accidental re-use of the archived native hash.
	newSum := sha256.Sum256(result)
	if newSum == sum {
		return nil, ErrHistoricalPathRebind
	}
	return result, nil
}
