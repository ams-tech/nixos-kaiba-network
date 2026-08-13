package dnswriter

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestRFC2136AtomicAddressReplacement(t *testing.T) {
	t.Parallel()
	const (
		keyName = "publisher-update."
		secret  = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
	)
	received := make(chan *dns.Msg, 1)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		Listener:   listener,
		TsigSecret: map[string]string{keyName: secret},
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction {
			return dns.MsgAccept
		},
		Handler: dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
			if err := response.TsigStatus(); err != nil {
				t.Errorf("TSIG verification failed: %v", err)
			}
			received <- request.Copy()
			reply := new(dns.Msg)
			reply.SetReply(request)
			if signature := request.IsTsig(); signature != nil {
				reply.SetTsig(signature.Hdr.Name, signature.Algorithm, 300, time.Now().Unix())
			}
			_ = response.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	writer := RFC2136{
		Server: listener.Addr().String(), Zone: "kaiba.network", TSIGName: keyName,
		TSIGSecret: secret, Algorithm: dns.HmacSHA256, Timeout: 2 * time.Second,
	}
	addresses := []netip.Addr{netip.MustParseAddr("203.0.113.42"), netip.MustParseAddr("2001:db8::42")}
	if err := writer.ReplaceAddressRRsets(context.Background(), "pi-001.kaiba.network", addresses, 300); err != nil {
		t.Fatal(err)
	}
	select {
	case message := <-received:
		if message.Opcode != dns.OpcodeUpdate || len(message.Question) != 1 || message.Question[0].Name != "kaiba.network." {
			t.Fatalf("unexpected update header: %+v", message)
		}
		deletes := map[uint16]bool{}
		inserts := map[uint16]bool{}
		for _, record := range message.Ns {
			header := record.Header()
			if header.Name != "pi-001.kaiba.network." {
				t.Fatalf("update contains unauthorized owner %q", header.Name)
			}
			switch header.Class {
			case dns.ClassANY:
				deletes[header.Rrtype] = true
			case dns.ClassINET:
				if header.Ttl != 300 {
					t.Fatalf("insert TTL = %d", header.Ttl)
				}
				inserts[header.Rrtype] = true
			}
		}
		if !deletes[dns.TypeA] || !deletes[dns.TypeAAAA] || !inserts[dns.TypeA] || !inserts[dns.TypeAAAA] {
			t.Fatalf("update was not an atomic A/AAAA replacement: deletes=%v inserts=%v", deletes, inserts)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DNS server did not receive update")
	}
}

func TestRFC2136RejectsOutOfZoneName(t *testing.T) {
	t.Parallel()
	writer := RFC2136{Server: "127.0.0.1", Zone: "kaiba.network", TSIGName: "key.", TSIGSecret: "secret"}
	if err := writer.ReplaceAddressRRsets(context.Background(), "victim.example", nil, 300); err == nil {
		t.Fatal("out-of-zone update was accepted")
	}
}

func TestRFC2136RejectsUnsignedSuccessResponse(t *testing.T) {
	t.Parallel()
	const (
		keyName = "publisher-update."
		secret  = "MTIzNDU2Nzg5MDEyMzQ1Ng=="
	)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		Listener:   listener,
		TsigSecret: map[string]string{keyName: secret},
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction {
			return dns.MsgAccept
		},
		Handler: dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
			reply := new(dns.Msg)
			reply.SetReply(request)
			// Deliberately omit TSIG from this otherwise successful response.
			_ = response.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })
	writer := RFC2136{
		Server: listener.Addr().String(), Zone: "kaiba.network", TSIGName: keyName,
		TSIGSecret: secret, Algorithm: dns.HmacSHA256, Timeout: 2 * time.Second,
	}
	if err := writer.ReplaceAddressRRsets(context.Background(), "pi-001.kaiba.network", []netip.Addr{netip.MustParseAddr("203.0.113.42")}, 300); err == nil {
		t.Fatal("unsigned success response was accepted")
	}
}

func TestDNSObserverRequiresExactAuthoritativeAnswers(t *testing.T) {
	t.Parallel()
	answers := []netip.Addr{netip.MustParseAddr("203.0.113.42"), netip.MustParseAddr("2001:db8::42")}
	serverAddress, shutdown := startObservationServer(t, answers, true)
	defer shutdown()
	observer := DNSObserver{Servers: []string{serverAddress}, Timeout: 2 * time.Second}
	observed, err := observer.ObserveAddressRRsets(context.Background(), "pi-001.kaiba.network", answers)
	if err != nil || !observed {
		t.Fatalf("expected observation, got %t, %v", observed, err)
	}
	observed, err = observer.ObserveAddressRRsets(context.Background(), "pi-001.kaiba.network", []netip.Addr{answers[0]})
	if err != nil || observed {
		t.Fatalf("mismatched answer observed=%t, err=%v", observed, err)
	}
	nonAuthoritative, stop := startObservationServer(t, answers, false)
	defer stop()
	observer.Servers = []string{serverAddress, nonAuthoritative}
	observed, err = observer.ObserveAddressRRsets(context.Background(), "pi-001.kaiba.network", answers)
	if err != nil || observed {
		t.Fatalf("non-authoritative answer observed=%t, err=%v", observed, err)
	}
}

func TestDNSObserverRetriesTruncatedUDPResponseOverTCP(t *testing.T) {
	t.Parallel()
	address := netip.MustParseAddr("203.0.113.42")
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	packet, err := net.ListenPacket("udp", tcpListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
		reply := new(dns.Msg)
		reply.SetReply(request)
		reply.Authoritative = true
		if response.LocalAddr().Network() == "udp" || response.LocalAddr().Network() == "udp4" {
			reply.Truncated = true
			_ = response.WriteMsg(reply)
			return
		}
		if request.Question[0].Qtype == dns.TypeA {
			reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IP(address.AsSlice())})
		}
		_ = response.WriteMsg(reply)
	})
	udpServer := &dns.Server{PacketConn: packet, Handler: handler}
	tcpServer := &dns.Server{Listener: tcpListener, Handler: handler}
	go func() { _ = udpServer.ActivateAndServe() }()
	go func() { _ = tcpServer.ActivateAndServe() }()
	t.Cleanup(func() {
		_ = udpServer.Shutdown()
		_ = tcpServer.Shutdown()
	})
	observer := DNSObserver{Servers: []string{tcpListener.Addr().String()}, Timeout: 2 * time.Second}
	observed, err := observer.ObserveAddressRRsets(context.Background(), "pi-001.kaiba.network", []netip.Addr{address})
	if err != nil || !observed {
		t.Fatalf("truncated observation did not fall back to TCP: observed=%t err=%v", observed, err)
	}
}

func startObservationServer(t *testing.T, addresses []netip.Addr, authoritative bool) (string, func()) {
	t.Helper()
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &dns.Server{
		PacketConn: packet,
		Handler: dns.HandlerFunc(func(response dns.ResponseWriter, request *dns.Msg) {
			reply := new(dns.Msg)
			reply.SetReply(request)
			reply.Authoritative = authoritative
			for _, addr := range addresses {
				if request.Question[0].Qtype == dns.TypeA && addr.Is4() {
					reply.Answer = append(reply.Answer, &dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300}, A: net.IP(addr.AsSlice())})
				}
				if request.Question[0].Qtype == dns.TypeAAAA && addr.Is6() {
					reply.Answer = append(reply.Answer, &dns.AAAA{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300}, AAAA: net.IP(addr.AsSlice())})
				}
			}
			_ = response.WriteMsg(reply)
		}),
	}
	go func() { _ = server.ActivateAndServe() }()
	return packet.LocalAddr().String(), func() { _ = server.Shutdown() }
}
