package protocol

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	want := OpenTCP{FlowID: 42, Source: "[fd7a::1]:1234", Destination: "[fd12::10]:53"}
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, want); err != nil {
		t.Fatal(err)
	}
	var got OpenTCP
	if err := ReadFrame(&buffer, &got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}

func TestProtocolConstantsRemainStable(t *testing.T) {
	if ALPN != "tailbridge/2" {
		t.Fatalf("got ALPN %q", ALPN)
	}
	if ProtocolVersion != "2.0" {
		t.Fatalf("got protocol version %q", ProtocolVersion)
	}
}

func TestProtocolJSONFieldsRemainStable(t *testing.T) {
	tests := []struct {
		name  string
		value any
		keys  []string
	}{
		{
			name:  "connector hello",
			value: ConnectorHello{},
			keys:  []string{"connector_id", "environment", "protocol_version", "routes", "software_version", "started_unix_nano"},
		},
		{
			name:  "connector accepted",
			value: ConnectorAccepted{},
			keys:  []string{"accepted_routes", "connector_id", "max_tcp_flows", "real_prefix", "session_id", "slot", "virtual_prefix"},
		},
		{
			name:  "open TCP",
			value: OpenTCP{TraceParent: "trace", TraceState: "state"},
			keys:  []string{"deadline_unix_ms", "destination", "flow_id", "source", "traceparent", "tracestate"},
		},
		{
			name:  "open TCP result",
			value: OpenTCPResult{Code: "DENIED"},
			keys:  []string{"accepted", "error_code"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload, err := json.Marshal(test.value)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err := json.Unmarshal(payload, &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range test.keys {
				if _, ok := fields[key]; !ok {
					t.Fatalf("field %q is missing from %s", key, payload)
				}
			}
		})
	}
}

func TestWriteFrameRejectsOversizedPayload(t *testing.T) {
	if err := WriteFrame(&bytes.Buffer{}, strings.Repeat("x", MaxControlFrame)); err == nil {
		t.Fatal("expected an oversized frame to fail")
	}
}

func TestReadFrameRejectsInvalidSizes(t *testing.T) {
	for _, size := range []uint32{0, MaxControlFrame + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			var header [4]byte
			binary.BigEndian.PutUint32(header[:], size)
			if err := ReadFrame(bytes.NewReader(header[:]), &map[string]any{}); err == nil {
				t.Fatalf("expected frame size %d to fail", size)
			}
		})
	}
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) { return 0, nil }

func TestControlFrameIOFailures(t *testing.T) {
	if err := WriteFrame(&bytes.Buffer{}, make(chan int)); err == nil {
		t.Fatal("WriteFrame() accepted a value that JSON cannot encode")
	}
	if err := writeAll(zeroWriter{}, []byte("data")); err == nil {
		t.Fatal("writeAll() accepted a zero-length write")
	}
	var truncated bytes.Buffer
	_ = binary.Write(&truncated, binary.BigEndian, uint32(4))
	truncated.WriteString("{")
	if err := ReadFrame(&truncated, &map[string]any{}); err == nil {
		t.Fatal("ReadFrame() accepted a truncated payload")
	}
	var invalid bytes.Buffer
	_ = binary.Write(&invalid, binary.BigEndian, uint32(1))
	invalid.WriteByte('{')
	if err := ReadFrame(&invalid, &map[string]any{}); err == nil {
		t.Fatal("ReadFrame() accepted invalid JSON")
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value map[string]any
		_ = ReadFrame(bytes.NewReader(data), &value)
	})
}
