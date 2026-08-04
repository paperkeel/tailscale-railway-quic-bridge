//go:build linux

package netpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"
)

type commandCall struct {
	name  string
	args  []string
	stdin string
}

func TestRulesUseAddressFamilyTProxySyntax(t *testing.T) {
	policy, err := New(
		[]netip.Prefix{
			netip.MustParsePrefix("100.64.0.0/10"),
			netip.MustParsePrefix("fd12::/16"),
		},
		"[::]:15001",
		"[::]:15002",
	)
	if err != nil {
		t.Fatal(err)
	}
	rules := policy.rules()
	for _, expected := range []string{
		"ip daddr 100.64.0.0/10 meta l4proto tcp tproxy ip to :15001",
		"ip daddr 100.64.0.0/10 meta l4proto udp tproxy ip to :15002",
		"ip6 daddr fd12::/16 meta l4proto tcp tproxy ip6 to :15001",
		"ip6 daddr fd12::/16 meta l4proto udp tproxy ip6 to :15002",
	} {
		if !strings.Contains(rules, expected) {
			t.Fatalf("The rules do not contain %q.\n%s", expected, rules)
		}
	}
}

func TestNewRejectsInvalidPorts(t *testing.T) {
	tests := []struct {
		name       string
		tcpAddress string
		udpAddress string
		want       string
	}{
		{name: "TCP address", tcpAddress: "missing-port", udpAddress: ":2", want: "invalid TCP listener address"},
		{name: "TCP zero", tcpAddress: ":0", udpAddress: ":2", want: `Use a valid port instead of "0".`},
		{name: "UDP too large", tcpAddress: ":1", udpAddress: ":65536", want: `invalid UDP listener address: Use a valid port instead of "65536".`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := New(nil, test.tcpAddress, test.udpAddress)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("New() error = %v, want an error that contains %q", err, test.want)
			}
		})
	}
}

func TestApplyReplacesPolicy(t *testing.T) {
	policy := testPolicy(t)
	var calls []commandCall
	policy.run = func(_ context.Context, name string, args []string, stdin string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...), stdin: stdin})
		return nil
	}

	if err := policy.Apply(context.Background()); err != nil {
		t.Fatal(err)
	}

	want := append(cleanupCalls(),
		commandCall{name: "nft", args: []string{"-f", "-"}, stdin: policy.rules()},
		commandCall{name: "ip", args: []string{"-4", "rule", "add", "fwmark", packetMark, "lookup", routeTable}},
		commandCall{name: "ip", args: []string{"-4", "route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", routeTable}},
		commandCall{name: "ip", args: []string{"-6", "rule", "add", "fwmark", packetMark, "lookup", routeTable}},
		commandCall{name: "ip", args: []string{"-6", "route", "replace", "local", "::/0", "dev", "lo", "table", routeTable}},
	)
	if !reflect.DeepEqual(calls, want) {
		t.Fatalf("Apply() calls = %#v, want %#v", calls, want)
	}
}

func TestApplyRollsBackInReverseOrder(t *testing.T) {
	policy := testPolicy(t)
	applyErr := errors.New("route failed")
	var calls []commandCall
	policy.run = func(_ context.Context, name string, args []string, stdin string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...), stdin: stdin})
		if reflect.DeepEqual(args, []string{"-6", "route", "replace", "local", "::/0", "dev", "lo", "table", routeTable}) {
			return applyErr
		}
		return nil
	}

	err := policy.Apply(context.Background())
	if !errors.Is(err, applyErr) {
		t.Fatalf("Apply() error = %v, want %v", err, applyErr)
	}
	wantRollback := cleanupCalls()
	if got := calls[len(calls)-len(wantRollback):]; !reflect.DeepEqual(got, wantRollback) {
		t.Fatalf("rollback calls = %#v, want %#v", got, wantRollback)
	}
}

func TestApplyReturnsCleanupErrorsAndDetachesRollback(t *testing.T) {
	policy := testPolicy(t)
	ctx, cancel := context.WithCancel(context.Background())
	applyErr := errors.New("apply failed")
	cleanupErr := errors.New("cleanup failed")
	callCount := 0
	policy.run = func(ctx context.Context, _ string, args []string, _ string) error {
		callCount++
		if callCount == len(cleanupCalls())+1 {
			cancel()
			return applyErr
		}
		if callCount > len(cleanupCalls())+1 {
			if ctx.Err() != nil {
				t.Fatalf("rollback used the canceled Apply context: %v", ctx.Err())
			}
			if reflect.DeepEqual(args, []string{"-6", "route", "flush", "table", routeTable}) {
				return cleanupErr
			}
		}
		return nil
	}

	err := policy.Apply(ctx)
	if !errors.Is(err, applyErr) || !errors.Is(err, cleanupErr) {
		t.Fatalf("Apply() error = %v, want both Apply and cleanup errors", err)
	}
	if callCount != 2*len(cleanupCalls())+1 {
		t.Fatalf("Apply() made %d calls, want %d", callCount, 2*len(cleanupCalls())+1)
	}
}

func TestCloseCleansAllPolicyStateAndReturnsErrors(t *testing.T) {
	policy := testPolicy(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cleanupErr := errors.New("cannot flush route")
	var calls []commandCall
	policy.run = func(ctx context.Context, name string, args []string, stdin string) error {
		if ctx.Err() != nil {
			t.Fatalf("Close() used the canceled context: %v", ctx.Err())
		}
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...), stdin: stdin})
		if len(calls) == 1 {
			return cleanupErr
		}
		return nil
	}

	err := policy.Close(ctx)
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("Close() error = %v, want %v", err, cleanupErr)
	}
	if want := cleanupCalls(); !reflect.DeepEqual(calls, want) {
		t.Fatalf("Close() calls = %#v, want %#v", calls, want)
	}
}

func TestCleanupIgnoresAbsentPolicyObjects(t *testing.T) {
	policy := testPolicy(t)
	var calls []commandCall
	policy.run = func(_ context.Context, name string, args []string, stdin string) error {
		calls = append(calls, commandCall{name: name, args: append([]string(nil), args...), stdin: stdin})
		output := "RTNETLINK answers: No such file or directory"
		if len(args) > 1 && args[1] == "route" {
			output = "Error: ipv4: FIB table does not exist."
		}
		return &commandError{name: name, err: errors.New("exit status 2"), output: output}
	}

	if err := policy.Close(context.Background()); err != nil {
		t.Fatalf("Close() error = %v, want nil", err)
	}
	if want := cleanupCalls(); !reflect.DeepEqual(calls, want) {
		t.Fatalf("Close() calls = %#v, want %#v", calls, want)
	}
}

func TestApplyReturnsGenuinePreCleanErrors(t *testing.T) {
	policy := testPolicy(t)
	cleanupErr := errors.New("permission denied")
	callCount := 0
	policy.run = func(context.Context, string, []string, string) error {
		callCount++
		if callCount == 1 {
			return cleanupErr
		}
		return nil
	}

	err := policy.Apply(context.Background())
	if !errors.Is(err, cleanupErr) {
		t.Fatalf("Apply() error = %v, want %v", err, cleanupErr)
	}
	if callCount != len(cleanupCalls()) {
		t.Fatalf("Apply() made %d calls, want %d cleanup calls", callCount, len(cleanupCalls()))
	}
}

func TestReplaceKeepsPreviousRoutesOnFailure(t *testing.T) {
	policy := testPolicy(t)
	original := append([]netip.Prefix(nil), policy.routes...)
	want := []netip.Prefix{netip.MustParsePrefix("fd40::/16")}
	var script string
	policy.run = func(_ context.Context, name string, arguments []string, stdin string) error {
		if name != "nft" || !reflect.DeepEqual(arguments, []string{"-f", "-"}) {
			t.Fatalf("Replace() command = %s %v", name, arguments)
		}
		script = stdin
		return nil
	}
	if err := policy.Replace(context.Background(), want); err != nil || !reflect.DeepEqual(policy.routes, want) || !strings.Contains(script, "delete table inet tailbridge") {
		t.Fatalf("Replace() routes=%v script=%q err=%v", policy.routes, script, err)
	}
	policy.run = func(context.Context, string, []string, string) error { return errors.New("failed") }
	if err := policy.Replace(context.Background(), original); err == nil || !reflect.DeepEqual(policy.routes, want) {
		t.Fatalf("failed Replace() routes=%v err=%v", policy.routes, err)
	}
}

func TestWaitForTailscale(t *testing.T) {
	calls := 0
	err := waitForTailscale(context.Background(), func(name string) (*net.Interface, error) {
		calls++
		if name != "tailscale0" {
			t.Fatalf("interface name = %q, want tailscale0", name)
		}
		if calls < 2 {
			return nil, errors.New("not ready")
		}
		return &net.Interface{Name: name}, nil
	}, time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("interface lookup count = %d, want 2", calls)
	}
}

func TestWaitForTailscaleReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := waitForTailscale(ctx, func(string) (*net.Interface, error) {
		return nil, fmt.Errorf("not ready")
	}, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForTailscale() error = %v, want %v", err, context.Canceled)
	}
}

func testPolicy(t *testing.T) *Policy {
	t.Helper()
	policy, err := New([]netip.Prefix{netip.MustParsePrefix("100.64.0.0/10")}, ":15001", ":15002")
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func cleanupCalls() []commandCall {
	return []commandCall{
		{name: "ip", args: []string{"-6", "route", "flush", "table", routeTable}},
		{name: "ip", args: []string{"-6", "rule", "del", "fwmark", packetMark, "lookup", routeTable}},
		{name: "ip", args: []string{"-4", "route", "flush", "table", routeTable}},
		{name: "ip", args: []string{"-4", "rule", "del", "fwmark", packetMark, "lookup", routeTable}},
		{name: "nft", args: []string{"delete", "table", "inet", tableName}},
	}
}
