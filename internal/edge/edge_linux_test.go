//go:build linux

package edge

import (
	"net/netip"
	"os"
	"testing"
)

func TestTransparentUDPListeners(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("transparent sockets require root")
	}
	listener, err := transparentUDPListener("[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = listener.Close()
	for _, address := range []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.1:0"),
		netip.MustParseAddrPort("[::1]:0"),
	} {
		response, err := transparentUDPResponse(address)
		if err != nil {
			t.Fatalf("create response socket for %s: %v", address, err)
		}
		_ = response.Close()
	}
}
