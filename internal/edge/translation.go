//go:build linux

package edge

import (
	"errors"
	"net/netip"
)

var errAddressOutsidePrefix = errors.New("address is outside the translation prefix")

func translateAddress(address netip.Addr, from, to netip.Prefix) (netip.Addr, error) {
	address = address.Unmap()
	from = from.Masked()
	to = to.Masked()
	if !address.Is6() || !from.Addr().Is6() || !to.Addr().Is6() || from.Bits() != 16 || to.Bits() != 16 {
		return netip.Addr{}, errors.New("translation requires IPv6 /16 prefixes")
	}
	if !from.Contains(address) {
		return netip.Addr{}, errAddressOutsidePrefix
	}
	translated := address.As16()
	prefix := to.Addr().As16()
	translated[0] = prefix[0]
	translated[1] = prefix[1]
	return netip.AddrFrom16(translated), nil
}

func translateAddrPort(address netip.AddrPort, from, to netip.Prefix) (netip.AddrPort, error) {
	translated, err := translateAddress(address.Addr(), from, to)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return netip.AddrPortFrom(translated, address.Port()), nil
}
