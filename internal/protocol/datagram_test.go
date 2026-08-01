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

func TestUDPDatagramResponseRoundTrip(t *testing.T) {
	want := UDPDatagram{
		FlowID:      10,
		Response:    true,
		Source:      netip.MustParseAddrPort("192.0.2.1:53"),
		Destination: netip.MustParseAddrPort("192.0.2.2:1234"),
		Payload:     []byte("response"),
	}
	encoded, err := EncodeUDP(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeUDP(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Response {
		t.Fatal("expected the response flag")
	}
}

func TestDecodeUDPRejectsUnknownFlags(t *testing.T) {
	packet := UDPDatagram{
		Source:      netip.MustParseAddrPort("192.0.2.1:53"),
		Destination: netip.MustParseAddrPort("192.0.2.2:1234"),
	}
	encoded, err := EncodeUDP(packet)
	if err != nil {
		t.Fatal(err)
	}
	encoded[1] = 2
	if _, err := DecodeUDP(encoded); err == nil {
		t.Fatal("expected an unknown flag to fail")
	}
}

func TestDecodeUDPRejectsProtocolBoundaries(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{name: "short header", data: make([]byte, 11)},
		{name: "unknown version", data: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1}},
		{name: "empty source", data: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0}},
		{name: "truncated addresses", data: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16, 16}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := DecodeUDP(test.data); err == nil {
				t.Fatal("expected the invalid datagram to fail")
			}
		})
	}
}

func FuzzDecodeUDP(f *testing.F) {
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) { _, _ = DecodeUDP(data) })
}
