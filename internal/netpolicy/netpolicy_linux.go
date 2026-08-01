//go:build linux

package netpolicy

import (
	"bytes"
	"context"
	"errors"
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

	cleanupTimeout = 5 * time.Second
)

type commandRunner func(context.Context, string, []string, string) error

type Policy struct {
	routes  []netip.Prefix
	tcpPort string
	udpPort string
	run     commandRunner
}

func New(routes []netip.Prefix, tcpAddress, udpAddress string) (*Policy, error) {
	tcpPort, err := port(tcpAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid TCP listener address: %w", err)
	}
	udpPort, err := port(udpAddress)
	if err != nil {
		return nil, fmt.Errorf("invalid UDP listener address: %w", err)
	}
	return &Policy{routes: routes, tcpPort: tcpPort, udpPort: udpPort, run: runCommand}, nil
}

func (p *Policy) Apply(ctx context.Context) error {
	_ = p.cleanup(ctx)
	if err := p.run(ctx, "nft", []string{"-f", "-"}, p.rules()); err != nil {
		return p.rollback(ctx, fmt.Errorf("apply nftables rules: %w", err))
	}
	for _, family := range []string{"-4", "-6"} {
		if err := p.run(ctx, "ip", []string{family, "rule", "add", "fwmark", packetMark, "lookup", routeTable}, ""); err != nil {
			return p.rollback(ctx, fmt.Errorf("add the %s policy rule: %w", family, err))
		}
		prefix := "0.0.0.0/0"
		if family == "-6" {
			prefix = "::/0"
		}
		if err := p.run(ctx, "ip", []string{family, "route", "replace", "local", prefix, "dev", "lo", "table", routeTable}, ""); err != nil {
			return p.rollback(ctx, fmt.Errorf("add the %s local route: %w", family, err))
		}
	}
	return nil
}

func (p *Policy) rollback(ctx context.Context, applyErr error) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if cleanupErr := p.cleanup(cleanupContext); cleanupErr != nil {
		return errors.Join(applyErr, fmt.Errorf("clean the network policy: %w", cleanupErr))
	}
	return applyErr
}

func (p *Policy) cleanup(ctx context.Context) error {
	var cleanupErrors []error
	for _, family := range []string{"-6", "-4"} {
		if err := p.run(ctx, "ip", []string{family, "route", "flush", "table", routeTable}, ""); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
		if err := p.run(ctx, "ip", []string{family, "rule", "del", "fwmark", packetMark, "lookup", routeTable}, ""); err != nil {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if err := p.run(ctx, "nft", []string{"delete", "table", "inet", tableName}, ""); err != nil {
		cleanupErrors = append(cleanupErrors, err)
	}
	return errors.Join(cleanupErrors...)
}

func (p *Policy) rules() string {
	var rules strings.Builder
	rules.WriteString("table inet " + tableName + " {\nchain prerouting { type filter hook prerouting priority mangle; policy accept;\n")
	for _, route := range p.routes {
		family := "ip"
		if route.Addr().Is6() {
			family = "ip6"
		}
		fmt.Fprintf(&rules, "iifname \"tailscale0\" %s daddr %s meta l4proto tcp tproxy %s to :%s meta mark set %s accept\n", family, route, family, p.tcpPort, packetMark)
		fmt.Fprintf(&rules, "iifname \"tailscale0\" %s daddr %s meta l4proto udp tproxy %s to :%s meta mark set %s accept\n", family, route, family, p.udpPort, packetMark)
	}
	rules.WriteString("}\n}\n")
	return rules.String()
}

func (p *Policy) Close(ctx context.Context) error {
	cleanupContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), cleanupTimeout)
	defer cancel()
	if err := p.cleanup(cleanupContext); err != nil {
		return fmt.Errorf("clean the network policy: %w", err)
	}
	return nil
}

func WaitForTailscale(ctx context.Context) error {
	return waitForTailscale(ctx, net.InterfaceByName, 250*time.Millisecond)
}

func waitForTailscale(ctx context.Context, interfaceByName func(string) (*net.Interface, error), interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if _, err := interfaceByName("tailscale0"); err == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func runCommand(ctx context.Context, name string, args []string, stdin string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s command failed: %w: %s", name, err, bytes.TrimSpace(output))
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
		return "", fmt.Errorf("Use a valid port instead of %q.", raw)
	}
	return raw, nil
}
