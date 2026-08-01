//go:build linux

package netpolicy

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

const (
	tableName  = "tailbridge"
	routeTable = "100"
	packetMark = "0x6a1"
)

type Policy struct {
	routes  []netip.Prefix
	tcpPort string
	udpPort string
}

func New(routes []netip.Prefix, tcpAddress, udpAddress string) (*Policy, error) {
	tcpPort, err := port(tcpAddress)
	if err != nil {
		return nil, fmt.Errorf("TCP listener: %w", err)
	}
	udpPort, err := port(udpAddress)
	if err != nil {
		return nil, fmt.Errorf("UDP listener: %w", err)
	}
	return &Policy{routes: routes, tcpPort: tcpPort, udpPort: udpPort}, nil
}

func (p *Policy) Apply(ctx context.Context) error {
	_ = command(ctx, "nft", "delete", "table", "inet", tableName)
	rules := p.rules()
	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(rules)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("apply nftables rules: %w: %s", err, bytes.TrimSpace(output))
	}
	for _, family := range []string{"-4", "-6"} {
		_ = command(ctx, "ip", family, "rule", "del", "fwmark", packetMark, "lookup", routeTable)
		if err := command(ctx, "ip", family, "rule", "add", "fwmark", packetMark, "lookup", routeTable); err != nil {
			return err
		}
		prefix := "0.0.0.0/0"
		if family == "-6" {
			prefix = "::/0"
		}
		if err := command(ctx, "ip", family, "route", "replace", "local", prefix, "dev", "lo", "table", routeTable); err != nil {
			return err
		}
	}
	return nil
}

func (p *Policy) rules() string {
	var rules strings.Builder
	rules.WriteString("table inet " + tableName + " {\nchain prerouting { type filter hook prerouting priority mangle; policy accept;\n")
	for _, route := range p.routes {
		family := "ip"
		if route.Addr().Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&rules, "iifname \"tailscale0\" %s daddr %s meta l4proto tcp tproxy to :%s meta mark set %s accept\n", family, route, p.tcpPort, packetMark)
		fmt.Fprintf(&rules, "iifname \"tailscale0\" %s daddr %s meta l4proto udp tproxy to :%s meta mark set %s accept\n", family, route, p.udpPort, packetMark)
	}
	rules.WriteString("}\n}\n")
	return rules.String()
}

func (p *Policy) Close(ctx context.Context) {
	_ = command(ctx, "nft", "delete", "table", "inet", tableName)
	for _, family := range []string{"-4", "-6"} {
		_ = command(ctx, "ip", family, "rule", "del", "fwmark", packetMark, "lookup", routeTable)
	}
}

func WaitForTailscale(ctx context.Context) error {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := net.InterfaceByName("tailscale0"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func command(ctx context.Context, name string, args ...string) error {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, bytes.TrimSpace(output))
	}
	return nil
}

func port(address string) (string, error) {
	_, raw, err := net.SplitHostPort(address)
	if err != nil {
		return "", err
	}
	value, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || value == 0 {
		return "", fmt.Errorf("invalid port %q", raw)
	}
	return raw, nil
}
