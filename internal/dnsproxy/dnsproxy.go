package dnsproxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	railwaySuffix   = "railway.internal."
	tcpDrainTimeout = 250 * time.Millisecond
)

type Rewriter struct {
	realPrefix    netip.Prefix
	virtualPrefix netip.Prefix
	suffix        string
}

func New(realPrefix, virtualPrefix netip.Prefix, suffix string) (*Rewriter, error) {
	realPrefix = realPrefix.Masked()
	virtualPrefix = virtualPrefix.Masked()
	if !realPrefix.Addr().Is6() || realPrefix.Bits() != 16 {
		return nil, errors.New("the real DNS prefix must be an IPv6 /16")
	}
	if !virtualPrefix.Addr().Is6() || virtualPrefix.Bits() != 16 {
		return nil, errors.New("the virtual DNS prefix must be an IPv6 /16")
	}
	suffix = strings.ToLower(dns.Fqdn(strings.TrimSpace(suffix)))
	if _, ok := dns.IsDomainName(suffix); !ok || suffix == railwaySuffix || !strings.HasSuffix(suffix, "."+railwaySuffix) {
		return nil, errors.New("the DNS suffix must be a subdomain of railway.internal")
	}
	return &Rewriter{realPrefix: realPrefix, virtualPrefix: virtualPrefix, suffix: suffix}, nil
}

func (r *Rewriter) Query(payload []byte) ([]byte, error) {
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return nil, fmt.Errorf("decode DNS query: %w", err)
	}
	if err := r.rewriteQuery(message); err != nil {
		return nil, err
	}
	return message.Pack()
}

func (r *Rewriter) Response(payload []byte) ([]byte, error) {
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return nil, fmt.Errorf("decode DNS response: %w", err)
	}
	r.rewriteResponse(message)
	return message.Pack()
}

func (r *Rewriter) rewriteQuery(message *dns.Msg) error {
	if len(message.Question) == 0 {
		return errors.New("the DNS query has no questions")
	}
	for index := range message.Question {
		name, ok := replaceSuffix(message.Question[index].Name, r.suffix, railwaySuffix)
		if !ok {
			return fmt.Errorf("DNS query name %q is outside %s", message.Question[index].Name, r.suffix)
		}
		message.Question[index].Name = name
	}
	return nil
}

func (r *Rewriter) rewriteResponse(message *dns.Msg) {
	for index := range message.Question {
		if name, ok := replaceSuffix(message.Question[index].Name, railwaySuffix, r.suffix); ok {
			message.Question[index].Name = name
		}
	}
	message.Answer = r.rewriteRecords(message.Answer)
	message.Ns = r.rewriteRecords(message.Ns)
	message.Extra = r.rewriteRecords(message.Extra)
}

func (r *Rewriter) rewriteRecords(records []dns.RR) []dns.RR {
	result := records[:0]
	for _, record := range records {
		if _, remove := record.(*dns.A); remove {
			continue
		}
		header := record.Header()
		if name, ok := replaceSuffix(header.Name, railwaySuffix, r.suffix); ok {
			header.Name = name
		}
		r.rewriteRecord(record)
		result = append(result, record)
	}
	return result
}

func (r *Rewriter) rewriteRecord(record dns.RR) {
	switch value := record.(type) {
	case *dns.AAAA:
		address, ok := netip.AddrFromSlice(value.AAAA)
		if !ok || !r.realPrefix.Contains(address) {
			return
		}
		bytes := address.As16()
		virtual := r.virtualPrefix.Addr().As16()
		bytes[0], bytes[1] = virtual[0], virtual[1]
		value.AAAA = net.IP(bytes[:])
	case *dns.CNAME:
		value.Target = r.responseName(value.Target)
	case *dns.DNAME:
		value.Target = r.responseName(value.Target)
	case *dns.MX:
		value.Mx = r.responseName(value.Mx)
	case *dns.NS:
		value.Ns = r.responseName(value.Ns)
	case *dns.PTR:
		value.Ptr = r.responseName(value.Ptr)
	case *dns.SOA:
		value.Ns = r.responseName(value.Ns)
		value.Mbox = r.responseName(value.Mbox)
	case *dns.SRV:
		value.Target = r.responseName(value.Target)
	case *dns.NAPTR:
		value.Replacement = r.responseName(value.Replacement)
	case *dns.SVCB:
		value.Target = r.responseName(value.Target)
		value.Value = r.rewriteSVCBValues(value.Value)
	case *dns.HTTPS:
		value.Target = r.responseName(value.Target)
		value.Value = r.rewriteSVCBValues(value.Value)
	}
}

func (r *Rewriter) rewriteSVCBValues(values []dns.SVCBKeyValue) []dns.SVCBKeyValue {
	result := values[:0]
	for _, value := range values {
		switch hint := value.(type) {
		case *dns.SVCBIPv4Hint:
			continue
		case *dns.SVCBIPv6Hint:
			for index, address := range hint.Hint {
				parsed, ok := netip.AddrFromSlice(address)
				if !ok || !r.realPrefix.Contains(parsed) {
					continue
				}
				bytes := parsed.As16()
				virtual := r.virtualPrefix.Addr().As16()
				bytes[0], bytes[1] = virtual[0], virtual[1]
				hint.Hint[index] = net.IP(bytes[:])
			}
		}
		result = append(result, value)
	}
	return result
}

func (r *Rewriter) responseName(name string) string {
	result, ok := replaceSuffix(name, railwaySuffix, r.suffix)
	if !ok {
		return name
	}
	return result
}

func replaceSuffix(name, from, to string) (string, bool) {
	name = dns.Fqdn(name)
	lower := strings.ToLower(name)
	from = strings.ToLower(dns.Fqdn(from))
	to = dns.Fqdn(to)
	if lower == from {
		return to, true
	}
	boundary := "." + from
	if !strings.HasSuffix(lower, boundary) {
		return name, false
	}
	return name[:len(name)-len(from)] + to, true
}

func (r *Rewriter) ForwardTCP(client io.ReadWriteCloser, upstream net.Conn) (int64, int64, error) {
	type result struct {
		query bool
		bytes int64
		err   error
	}
	results := make(chan result, 2)
	go func() {
		count, err := r.forwardQueries(client, upstream)
		closeWrite(upstream)
		results <- result{query: true, bytes: count, err: err}
	}()
	go func() {
		count, err := r.forwardResponses(upstream, client)
		closeWrite(client)
		results <- result{bytes: count, err: err}
	}()
	first := <-results
	if transferError(first.err) != nil || !first.query {
		_ = upstream.Close()
		_ = client.Close()
	} else {
		_ = upstream.SetReadDeadline(time.Now().Add(tcpDrainTimeout))
	}
	second := <-results
	_ = upstream.Close()
	_ = client.Close()
	var sent, received int64
	if first.query {
		sent, received = first.bytes, second.bytes
	} else {
		sent, received = second.bytes, first.bytes
	}
	return sent, received, errors.Join(transferError(first.err), transferError(second.err))
}

func closeWrite(connection any) {
	if writer, ok := connection.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
}

func transferError(err error) error {
	if errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	var networkError net.Error
	if errors.As(err, &networkError) && networkError.Timeout() {
		return nil
	}
	return err
}

func (r *Rewriter) forwardQueries(source io.Reader, destination io.Writer) (int64, error) {
	var count int64
	for {
		message, err := readTCPMessage(source)
		if err != nil {
			return count, err
		}
		if err := r.rewriteQuery(message); err != nil {
			return count, err
		}
		payload, err := message.Pack()
		if err != nil {
			return count, err
		}
		if err := writeTCPMessage(destination, payload); err != nil {
			return count, err
		}
		count += int64(len(payload) + 2)
	}
}

func (r *Rewriter) forwardResponses(source io.Reader, destination io.Writer) (int64, error) {
	var count int64
	for {
		message, err := readTCPMessage(source)
		if err != nil {
			return count, err
		}
		r.rewriteResponse(message)
		payload, err := message.Pack()
		if err != nil {
			return count, err
		}
		if err := writeTCPMessage(destination, payload); err != nil {
			return count, err
		}
		count += int64(len(payload) + 2)
	}
}

func readTCPMessage(reader io.Reader) (*dns.Msg, error) {
	var header [2]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(header[:])
	if size == 0 {
		return nil, errors.New("the DNS-over-TCP message is empty")
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, err
	}
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		return nil, err
	}
	return message, nil
}

func writeTCPMessage(writer io.Writer, payload []byte) error {
	if len(payload) == 0 || len(payload) > int(^uint16(0)) {
		return errors.New("the DNS-over-TCP message size is not valid")
	}
	var header [2]byte
	binary.BigEndian.PutUint16(header[:], uint16(len(payload)))
	if err := writeAll(writer, header[:]); err != nil {
		return err
	}
	return writeAll(writer, payload)
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		payload = payload[written:]
	}
	return nil
}
