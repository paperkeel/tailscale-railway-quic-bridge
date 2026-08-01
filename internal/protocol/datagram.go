package protocol

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const datagramVersion byte = 1

type UDPDatagram struct {
	FlowID      uint64
	Response    bool
	Source      netip.AddrPort
	Destination netip.AddrPort
	Payload     []byte
}

func EncodeUDP(packet UDPDatagram) ([]byte, error) {
	source, err := packet.Source.MarshalBinary()
	if err != nil {
		return nil, err
	}
	destination, err := packet.Destination.MarshalBinary()
	if err != nil {
		return nil, err
	}
	if len(source) > 255 || len(destination) > 255 {
		return nil, errors.New("address encoding exceeds limit")
	}
	result := make([]byte, 12+len(source)+len(destination)+len(packet.Payload))
	result[0] = datagramVersion
	if packet.Response {
		result[1] = 1
	}
	binary.BigEndian.PutUint64(result[2:10], packet.FlowID)
	result[10] = byte(len(source))
	result[11] = byte(len(destination))
	copy(result[12:], source)
	copy(result[12+len(source):], destination)
	copy(result[12+len(source)+len(destination):], packet.Payload)
	return result, nil
}

func DecodeUDP(data []byte) (UDPDatagram, error) {
	if len(data) < 12 || data[0] != datagramVersion {
		return UDPDatagram{}, errors.New("The UDP datagram is not valid.")
	}
	if data[1]&^byte(1) != 0 {
		return UDPDatagram{}, errors.New("The UDP datagram flags are not valid.")
	}
	sourceLength, destinationLength := int(data[10]), int(data[11])
	headerLength := 12 + sourceLength + destinationLength
	if sourceLength == 0 || destinationLength == 0 || headerLength > len(data) {
		return UDPDatagram{}, errors.New("The UDP address lengths are not valid.")
	}
	var source, destination netip.AddrPort
	if err := source.UnmarshalBinary(data[12 : 12+sourceLength]); err != nil {
		return UDPDatagram{}, err
	}
	if err := destination.UnmarshalBinary(data[12+sourceLength : headerLength]); err != nil {
		return UDPDatagram{}, err
	}
	return UDPDatagram{
		FlowID:      binary.BigEndian.Uint64(data[2:10]),
		Response:    data[1]&1 == 1,
		Source:      source,
		Destination: destination,
		Payload:     append([]byte(nil), data[headerLength:]...),
	}, nil
}
