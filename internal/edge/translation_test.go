//go:build linux

package edge

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/paperkeel/tailscale-railway-quic-bridge/internal/config"
)

func TestTranslateAddressPreservesLower112Bits(t *testing.T) {
	virtual := netip.MustParsePrefix("fd2a::/16")
	real := netip.MustParsePrefix("fd12::/16")
	address := netip.MustParseAddr("fd2a:3456:789a:bcde:f012:3456:789a:bcde")
	want := netip.MustParseAddr("fd12:3456:789a:bcde:f012:3456:789a:bcde")
	got, err := translateAddress(address, virtual, real)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("translateAddress() = %s, want %s", got, want)
	}
	reversed, err := translateAddress(got, real, virtual)
	if err != nil {
		t.Fatal(err)
	}
	if reversed != address {
		t.Fatalf("reverse translation = %s, want %s", reversed, address)
	}
}

func TestRouteSelectsConnectorAndTranslatesDestination(t *testing.T) {
	server := testServer(1)
	server.routes = nil
	server.registry = make(map[string]*connectorEntry)
	for _, target := range []config.ConnectorTarget{
		{ConnectorID: "first", Slot: 0, VirtualPrefix: netip.MustParsePrefix("fd20::/16"), RealPrefix: netip.MustParsePrefix("fd12::/16")},
		{ConnectorID: "second", Slot: 1, VirtualPrefix: netip.MustParsePrefix("fd21::/16"), RealPrefix: netip.MustParsePrefix("fd12::/16")},
	} {
		entry := &connectorEntry{target: target}
		entry.active.Store(&session{id: target.ConnectorID, connectorID: target.ConnectorID, routes: []netip.Prefix{target.RealPrefix}})
		server.registry[target.ConnectorID] = entry
		server.routes = append(server.routes, entry)
	}

	active, destination, ok := server.route(netip.MustParseAddrPort("[fd21:3456::80]:443"))
	if !ok {
		t.Fatal("route() rejected a configured virtual destination")
	}
	if active.connectorID != "second" {
		t.Fatalf("route() selected connector %q, want second", active.connectorID)
	}
	if want := netip.MustParseAddrPort("[fd12:3456::80]:443"); destination != want {
		t.Fatalf("route() destination = %s, want %s", destination, want)
	}
	if _, _, ok := server.route(netip.MustParseAddrPort("[fd22::1]:443")); ok {
		t.Fatal("route() accepted an unconfigured virtual prefix")
	}
	server.session.Store(&session{id: "compatibility", routes: []netip.Prefix{netip.MustParsePrefix("fd22::/16")}})
	if _, _, ok := server.route(netip.MustParseAddrPort("[fd22::1]:443")); ok {
		t.Fatal("route() used the compatibility session for an unconfigured virtual prefix")
	}
}

func TestTranslateAddrPortPreservesPort(t *testing.T) {
	got, err := translateAddrPort(
		netip.MustParseAddrPort("[fd20::53]:5353"),
		netip.MustParsePrefix("fd20::/16"),
		netip.MustParsePrefix("fd12::/16"),
	)
	if err != nil {
		t.Fatal(err)
	}
	if want := netip.MustParseAddrPort("[fd12::53]:5353"); got != want {
		t.Fatalf("translateAddrPort() = %s, want %s", got, want)
	}
}

func TestTranslateAddressRejectsInvalidInputs(t *testing.T) {
	tests := []struct {
		name    string
		address string
		from    string
		to      string
		want    error
	}{
		{name: "outside prefix", address: "fd21::1", from: "fd20::/16", to: "fd12::/16", want: errAddressOutsidePrefix},
		{name: "IPv4", address: "192.0.2.1", from: "192.0.0.0/16", to: "198.51.0.0/16"},
		{name: "narrow source", address: "fd20::1", from: "fd20::/32", to: "fd12::/16"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := translateAddress(netip.MustParseAddr(test.address), netip.MustParsePrefix(test.from), netip.MustParsePrefix(test.to))
			if err == nil {
				t.Fatal("translateAddress() accepted invalid input")
			}
			if test.want != nil && !errors.Is(err, test.want) {
				t.Fatalf("translateAddress() error = %v, want %v", err, test.want)
			}
		})
	}
}
