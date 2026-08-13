package dnswriter

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// Writer is the replaceable desired-state-to-DNS projection boundary.
type Writer interface {
	ReplaceAddressRRsets(context.Context, string, []netip.Addr, uint32) error
}

// Observer verifies that a projection has reached every configured public
// authoritative server.
type Observer interface {
	ObserveAddressRRsets(context.Context, string, []netip.Addr) (bool, error)
}

type RFC2136 struct {
	Server     string
	Zone       string
	TSIGName   string
	TSIGSecret string
	Algorithm  string
	Timeout    time.Duration
}

func (w RFC2136) ReplaceAddressRRsets(ctx context.Context, hostname string, addresses []netip.Addr, ttl uint32) error {
	zone := dns.Fqdn(strings.ToLower(w.Zone))
	name := dns.Fqdn(strings.ToLower(hostname))
	if !dns.IsSubDomain(zone, name) || name == zone {
		return fmt.Errorf("hostname %q is outside update zone %q", hostname, w.Zone)
	}
	if w.Server == "" || w.TSIGName == "" || w.TSIGSecret == "" {
		return errors.New("DNS server and TSIG credentials are required")
	}
	algorithm := dns.Fqdn(strings.ToLower(w.Algorithm))
	if algorithm == "." {
		algorithm = dns.HmacSHA256
	}
	keyName := dns.Fqdn(w.TSIGName)
	message := new(dns.Msg)
	message.SetUpdate(zone)
	message.RemoveRRset([]dns.RR{
		&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassANY}},
		&dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassANY}},
	})
	for _, addr := range addresses {
		addr = addr.Unmap()
		if addr.Is4() {
			message.Insert([]dns.RR{&dns.A{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}, A: net.IP(addr.AsSlice())}})
		} else if addr.Is6() {
			message.Insert([]dns.RR{&dns.AAAA{Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}, AAAA: net.IP(addr.AsSlice())}})
		} else {
			return fmt.Errorf("invalid address %q", addr)
		}
	}
	message.SetTsig(keyName, algorithm, 300, time.Now().Unix())
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	client := &dns.Client{Net: "tcp", Timeout: timeout, TsigSecret: map[string]string{keyName: strings.TrimSpace(w.TSIGSecret)}}
	response, _, err := client.ExchangeContext(ctx, message, withDNSPort(w.Server))
	if err != nil {
		return fmt.Errorf("RFC 2136 update: %w", err)
	}
	if response == nil {
		return errors.New("RFC 2136 update returned no response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("RFC 2136 update refused: %s", dns.RcodeToString[response.Rcode])
	}
	if response.IsTsig() == nil {
		return errors.New("RFC 2136 success response was not authenticated with TSIG")
	}
	if !response.Response || response.Opcode != dns.OpcodeUpdate || len(response.Question) != 1 || response.Question[0].Name != zone {
		return errors.New("RFC 2136 success response did not match the update request")
	}
	return nil
}

type DNSObserver struct {
	Servers []string
	Timeout time.Duration
}

func (o DNSObserver) ObserveAddressRRsets(ctx context.Context, hostname string, expected []netip.Addr) (bool, error) {
	if len(o.Servers) == 0 {
		return false, errors.New("at least one observation server is required")
	}
	expectedValues := addressStrings(expected)
	for _, server := range o.Servers {
		observed, authoritative, err := o.query(ctx, server, hostname)
		if err != nil {
			return false, err
		}
		if !authoritative || !equalStrings(observed, expectedValues) {
			return false, nil
		}
	}
	return true, nil
}

func (o DNSObserver) query(ctx context.Context, server, hostname string) ([]string, bool, error) {
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	client := &dns.Client{Timeout: timeout}
	var values []string
	authoritative := true
	for _, recordType := range []uint16{dns.TypeA, dns.TypeAAAA} {
		message := new(dns.Msg)
		message.SetQuestion(dns.Fqdn(hostname), recordType)
		message.RecursionDesired = false
		message.SetEdns0(1232, false)
		response, _, err := client.ExchangeContext(ctx, message, withDNSPort(server))
		if err != nil {
			return nil, false, fmt.Errorf("observe %s at %s: %w", hostname, server, err)
		}
		if response.Truncated {
			tcpClient := &dns.Client{Net: "tcp", Timeout: timeout}
			response, _, err = tcpClient.ExchangeContext(ctx, message, withDNSPort(server))
			if err != nil {
				return nil, false, fmt.Errorf("observe truncated %s answer at %s over TCP: %w", hostname, server, err)
			}
			if response.Truncated {
				return nil, false, fmt.Errorf("observe %s at %s: TCP answer is truncated", hostname, server)
			}
		}
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			return nil, false, fmt.Errorf("observe %s at %s: %s", hostname, server, dns.RcodeToString[response.Rcode])
		}
		authoritative = authoritative && response.Authoritative
		for _, answer := range response.Answer {
			if answer.Header().Name != dns.Fqdn(hostname) {
				authoritative = false
				continue
			}
			switch record := answer.(type) {
			case *dns.A:
				if addr, ok := netip.AddrFromSlice(record.A); ok {
					values = append(values, addr.Unmap().String())
				}
			case *dns.AAAA:
				if addr, ok := netip.AddrFromSlice(record.AAAA); ok {
					values = append(values, addr.String())
				}
			}
		}
	}
	sort.Strings(values)
	return values, authoritative, nil
}

func addressStrings(addresses []netip.Addr) []string {
	values := make([]string, 0, len(addresses))
	for _, addr := range addresses {
		values = append(values, addr.Unmap().String())
	}
	sort.Strings(values)
	return values
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func withDNSPort(server string) string {
	if _, _, err := net.SplitHostPort(server); err == nil {
		return server
	}
	if addr, err := netip.ParseAddr(strings.Trim(server, "[]")); err == nil {
		return net.JoinHostPort(addr.String(), "53")
	}
	return net.JoinHostPort(server, "53")
}
