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
	"sync"
	"time"
)

const (
	tableName  = "tailbridge"
	routeTable = "100"
	packetMark = "0x6a1"

	cleanupTimeout = 5 * time.Second
)

type commandRunner func(context.Context, string, []string, string) error

type commandError struct {
	name   string
	err    error
	output string
}

func (e *commandError) Error() string {
	if e.output == "" {
		return fmt.Sprintf("%s command failed: %v", e.name, e.err)
	}
	return fmt.Sprintf("%s command failed: %v: %s", e.name, e.err, e.output)
}

func (e *commandError) Unwrap() error {
	return e.err
}

type Policy struct {
	mu      sync.Mutex
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
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.cleanup(ctx); err != nil {
		return fmt.Errorf("clean the existing network policy: %w", err)
	}
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

// Replace atomically changes the nftables interception prefixes. The policy
// routing rules do not change, so an unsuccessful replacement keeps the prior
// nftables generation active.
func (p *Policy) Replace(ctx context.Context, routes []netip.Prefix) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.routes
	p.routes = routes
	rules := "delete table inet " + tableName + "\n" + p.rules()
	if err := p.run(ctx, "nft", []string{"-f", "-"}, rules); err != nil {
		p.routes = previous
		return fmt.Errorf("replace nftables rules: %w", err)
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
		if err := p.run(ctx, "ip", []string{family, "route", "flush", "table", routeTable}, ""); err != nil && !policyObjectAbsent(err) {
			cleanupErrors = append(cleanupErrors, err)
		}
		if err := p.run(ctx, "ip", []string{family, "rule", "del", "fwmark", packetMark, "lookup", routeTable}, ""); err != nil && !policyObjectAbsent(err) {
			cleanupErrors = append(cleanupErrors, err)
		}
	}
	if err := p.run(ctx, "nft", []string{"delete", "table", "inet", tableName}, ""); err != nil && !policyObjectAbsent(err) {
		cleanupErrors = append(cleanupErrors, err)
	}
	return errors.Join(cleanupErrors...)
}

func policyObjectAbsent(err error) bool {
	var commandErr *commandError
	if !errors.As(err, &commandErr) {
		return false
	}
	output := strings.ToLower(commandErr.output)
	return strings.Contains(output, "no such file or directory") || strings.Contains(output, "fib table does not exist")
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
	p.mu.Lock()
	defer p.mu.Unlock()
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
		return &commandError{name: name, err: err, output: string(bytes.TrimSpace(output))}
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
