package dnsproxy

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestQueryRewritesOnlyTheConfiguredSuffix(t *testing.T) {
	rewriter := testRewriter(t)
	query := new(dns.Msg)
	query.SetQuestion("api.project.railway.internal.", dns.TypeAAAA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := rewriter.Query(payload)
	if err != nil {
		t.Fatal(err)
	}
	message := unpack(t, rewritten)
	if got := message.Question[0].Name; got != "api.railway.internal." {
		t.Fatalf("query name = %q, want api.railway.internal.", got)
	}

	query.SetQuestion("api.other.railway.internal.", dns.TypeAAAA)
	payload, err = query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rewriter.Query(payload); err == nil {
		t.Fatal("Query() accepted a name outside the configured suffix")
	}
}

func TestForwardTCPRewritesQueriesAndResponses(t *testing.T) {
	rewriter := testRewriter(t)
	client, proxyClient := net.Pipe()
	proxyUpstream, upstream := net.Pipe()
	t.Cleanup(func() { _ = client.Close() })
	done := make(chan error, 1)
	go func() {
		_, _, err := rewriter.ForwardTCP(proxyClient, proxyUpstream)
		done <- err
	}()
	go func() {
		defer func() { _ = upstream.Close() }()
		request, err := readTCPMessage(upstream)
		if err != nil {
			return
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 44},
			AAAA: net.ParseIP("fd12::55"),
		}}
		payload, err := response.Pack()
		if err == nil {
			err = writeTCPMessage(upstream, payload)
		}
		_ = err
	}()
	query := new(dns.Msg)
	query.SetQuestion("api.project.railway.internal.", dns.TypeAAAA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTCPMessage(client, payload); err != nil {
		t.Fatal(err)
	}
	response, err := readTCPMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if response.Question[0].Name != "api.project.railway.internal." {
		t.Fatalf("question name = %q", response.Question[0].Name)
	}
	aaaa := response.Answer[0].(*dns.AAAA)
	if aaaa.AAAA.String() != "fd20::55" || aaaa.Hdr.Ttl != 44 {
		t.Fatalf("AAAA answer = %+v", aaaa)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ForwardTCP() did not stop after the client closed")
	}
}

func TestResponseRestoresNamesTranslatesAAAAAndFiltersA(t *testing.T) {
	rewriter := testRewriter(t)
	message := new(dns.Msg)
	message.SetQuestion("api.railway.internal.", dns.TypeAAAA)
	message.Rcode = dns.RcodeNameError
	message.Answer = []dns.RR{
		&dns.AAAA{Hdr: dns.RR_Header{Name: "api.railway.internal.", Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 73}, AAAA: net.ParseIP("fd12:3456::42")},
		&dns.A{Hdr: dns.RR_Header{Name: "api.railway.internal.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 31}, A: net.ParseIP("192.0.2.1")},
		&dns.CNAME{Hdr: dns.RR_Header{Name: "alias.railway.internal.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 19}, Target: "api.railway.internal."},
	}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := rewriter.Response(payload)
	if err != nil {
		t.Fatal(err)
	}
	response := unpack(t, rewritten)
	if response.Rcode != dns.RcodeNameError {
		t.Fatalf("rcode = %d, want %d", response.Rcode, dns.RcodeNameError)
	}
	if got := response.Question[0].Name; got != "api.project.railway.internal." {
		t.Fatalf("question name = %q", got)
	}
	if len(response.Answer) != 2 {
		t.Fatalf("answer count = %d, want 2", len(response.Answer))
	}
	aaaa, ok := response.Answer[0].(*dns.AAAA)
	if !ok {
		t.Fatalf("first answer type = %T, want AAAA", response.Answer[0])
	}
	if got := aaaa.AAAA.String(); got != "fd20:3456::42" {
		t.Fatalf("AAAA = %s, want fd20:3456::42", got)
	}
	if aaaa.Hdr.Ttl != 73 || aaaa.Hdr.Name != "api.project.railway.internal." {
		t.Fatalf("AAAA metadata = %+v", aaaa.Hdr)
	}
	cname, ok := response.Answer[1].(*dns.CNAME)
	if !ok || cname.Hdr.Name != "alias.project.railway.internal." || cname.Target != "api.project.railway.internal." {
		t.Fatalf("CNAME = %+v", response.Answer[1])
	}
}

func TestResponseRewritesServiceBindingAddressHints(t *testing.T) {
	rewriter := testRewriter(t)
	message := new(dns.Msg)
	message.SetQuestion("api.railway.internal.", dns.TypeHTTPS)
	message.Answer = []dns.RR{&dns.HTTPS{SVCB: dns.SVCB{
		Hdr:      dns.RR_Header{Name: "api.railway.internal.", Rrtype: dns.TypeHTTPS, Class: dns.ClassINET},
		Priority: 1,
		Target:   "target.railway.internal.",
		Value: []dns.SVCBKeyValue{
			&dns.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP("192.0.2.1")}},
			&dns.SVCBIPv6Hint{Hint: []net.IP{net.ParseIP("fd12:3456::42"), net.ParseIP("2001:db8::1")}},
		},
	}}}
	payload, err := message.Pack()
	if err != nil {
		t.Fatal(err)
	}
	rewritten, err := rewriter.Response(payload)
	if err != nil {
		t.Fatal(err)
	}
	https := unpack(t, rewritten).Answer[0].(*dns.HTTPS)
	if https.Target != "target.project.railway.internal." {
		t.Fatalf("target = %q", https.Target)
	}
	if len(https.Value) != 1 {
		t.Fatalf("service binding values = %v, want only IPv6 hints", https.Value)
	}
	hints := https.Value[0].(*dns.SVCBIPv6Hint).Hint
	if len(hints) != 1 || hints[0].String() != "fd20:3456::42" {
		t.Fatalf("IPv6 hints = %v", hints)
	}
}

func TestForwardTCPPreservesResponseAfterClientHalfClose(t *testing.T) {
	rewriter := testRewriter(t)
	clientListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = clientListener.Close() }()
	upstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = upstreamListener.Close() }()

	done := make(chan error, 1)
	go func() {
		proxyClient, acceptErr := clientListener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		var dialer net.Dialer
		proxyUpstream, dialErr := dialer.DialContext(
			t.Context(),
			"tcp",
			upstreamListener.Addr().String(),
		)
		if dialErr != nil {
			done <- dialErr
			return
		}
		_, _, forwardErr := rewriter.ForwardTCP(proxyClient, proxyUpstream)
		done <- forwardErr
	}()
	go func() {
		upstream, acceptErr := upstreamListener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = upstream.Close() }()
		request, readErr := readTCPMessage(upstream)
		if readErr != nil {
			return
		}
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET}, AAAA: net.ParseIP("fd12::55")}}
		time.Sleep(300 * time.Millisecond)
		payload, packErr := response.Pack()
		if packErr == nil {
			_ = writeTCPMessage(upstream, payload)
		}
	}()

	connection, err := net.DialTCP("tcp", nil, clientListener.Addr().(*net.TCPAddr))
	if err != nil {
		t.Fatal(err)
	}
	query := new(dns.Msg)
	query.SetQuestion("api.project.railway.internal.", dns.TypeAAAA)
	payload, err := query.Pack()
	if err != nil {
		t.Fatal(err)
	}
	if err := writeTCPMessage(connection, payload); err != nil {
		t.Fatal(err)
	}
	if err := connection.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	response, err := readTCPMessage(connection)
	if err != nil {
		t.Fatal(err)
	}
	if got := response.Answer[0].(*dns.AAAA).AAAA.String(); got != "fd20::55" {
		t.Fatalf("AAAA = %s, want fd20::55", got)
	}
	_ = connection.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("ForwardTCP() did not stop")
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	real := netip.MustParsePrefix("fd12::/16")
	virtual := netip.MustParsePrefix("fd20::/16")
	for _, test := range []struct {
		name    string
		real    netip.Prefix
		virtual netip.Prefix
		suffix  string
	}{
		{name: "real IPv4", real: netip.MustParsePrefix("10.0.0.0/16"), virtual: virtual, suffix: "project.railway.internal"},
		{name: "virtual width", real: real, virtual: netip.MustParsePrefix("fd20::/32"), suffix: "project.railway.internal"},
		{name: "base suffix", real: real, virtual: virtual, suffix: "railway.internal"},
		{name: "outside suffix", real: real, virtual: virtual, suffix: "example.com"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := New(test.real, test.virtual, test.suffix); err == nil {
				t.Fatal("New() accepted invalid configuration")
			}
		})
	}
}

func testRewriter(t *testing.T) *Rewriter {
	t.Helper()
	rewriter, err := New(netip.MustParsePrefix("fd12::/16"), netip.MustParsePrefix("fd20::/16"), "project.railway.internal")
	if err != nil {
		t.Fatal(err)
	}
	return rewriter
}

func unpack(t *testing.T, payload []byte) *dns.Msg {
	t.Helper()
	message := new(dns.Msg)
	if err := message.Unpack(payload); err != nil {
		t.Fatal(err)
	}
	return message
}
