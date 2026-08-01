package protocol

import (
	"net/netip"
	"testing"
)

func TestUDPDatagramRoundTrip(t *testing.T) {
	want := UDPDatagram{
		FlowID:      9,
		Source:      netip.MustParseAddrPort("[fd7a::1]:1234"),
		Destination: netip.MustParseAddrPort("[fd12::10]:53"),
		Payload:     []byte("dns"),
	}
	encoded, err := EncodeUDP(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeUDP(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if got.FlowID != want.FlowID || got.Source != want.Source || got.Destination != want.Destination || string(got.Payload) != string(want.Payload) {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func FuzzDecodeUDP(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeUDP(data) })
}
