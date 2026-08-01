//go:build linux

package netpolicy

import (
	"net/netip"
	"strings"
	"testing"
)

func TestRulesUsePortOnlyTProxySyntax(t *testing.T) {
	policy, err := New([]netip.Prefix{netip.MustParsePrefix("fd12::/16")}, "[::]:15001", "[::]:15002")
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.rules()
	for _, expected := range []string{
		"ip6 daddr fd12::/16 meta l4proto tcp tproxy to :15001",
		"ip6 daddr fd12::/16 meta l4proto udp tproxy to :15002",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("rules do not contain %q:\n%s", expected, rules)
		}
	}
	if strings.Contains(rules, "tproxy ip6 to :") {
		t.Fatalf("rules contain invalid address-family syntax:\n%s", rules)
	}
}
