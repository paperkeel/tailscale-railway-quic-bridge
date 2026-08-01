//go:build linux

package edge

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
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

func TestOriginalUDPDestination(t *testing.T) {
	tests := []struct {
		name  string
		level int32
		type_ int32
		data  []byte
		want  netip.AddrPort
	}{
		{
			name:  "IPv4",
			level: unix.SOL_IP,
			type_: unix.IP_ORIGDSTADDR,
			data:  originalIPv4Data(netip.MustParseAddrPort("192.0.2.10:5353")),
			want:  netip.MustParseAddrPort("192.0.2.10:5353"),
		},
		{
			name:  "IPv6",
			level: unix.SOL_IPV6,
			type_: unix.IPV6_ORIGDSTADDR,
			data:  originalIPv6Data(netip.MustParseAddrPort("[2001:db8::10]:5353")),
			want:  netip.MustParseAddrPort("[2001:db8::10]:5353"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := originalUDPDestination(controlMessage(test.level, test.type_, test.data))
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("got destination %s, want %s", got, test.want)
			}
		})
	}
}

func TestOriginalUDPDestinationRejectsMissingMessage(t *testing.T) {
	data := make([]byte, 8)
	if _, err := originalUDPDestination(controlMessage(unix.SOL_SOCKET, unix.SCM_RIGHTS, data)); err == nil {
		t.Fatal("expected a missing original destination to fail")
	}
}

func originalIPv4Data(address netip.AddrPort) []byte {
	data := make([]byte, 16)
	binary.BigEndian.PutUint16(data[2:4], address.Port())
	value := address.Addr().As4()
	copy(data[4:8], value[:])
	return data
}

func originalIPv6Data(address netip.AddrPort) []byte {
	data := make([]byte, 28)
	binary.BigEndian.PutUint16(data[2:4], address.Port())
	value := address.Addr().As16()
	copy(data[8:24], value[:])
	return data
}

func controlMessage(level, messageType int32, data []byte) []byte {
	message := make([]byte, unix.CmsgSpace(len(data)))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&message[0]))
	header.Level = level
	header.Type = messageType
	header.SetLen(unix.CmsgLen(len(data)))
	copy(message[unix.CmsgLen(0):], data)
	return message
}
