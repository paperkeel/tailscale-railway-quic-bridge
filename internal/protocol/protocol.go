package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ALPN            = "tailbridge/1"
	MaxControlFrame = 64 * 1024
	ProtocolVersion = "1.0"
)

type ConnectorHello struct {
	ProtocolVersion string   `json:"protocol_version"`
	ConnectorID     string   `json:"connector_id"`
	Environment     string   `json:"environment"`
	Routes          []string `json:"routes"`
	SoftwareVersion string   `json:"software_version"`
	StartedUnixNano int64    `json:"started_unix_nano"`
}

type ConnectorAccepted struct {
	SessionID   string   `json:"session_id"`
	Routes      []string `json:"accepted_routes"`
	MaxTCPFlows int64    `json:"max_tcp_flows"`
}

type OpenTCP struct {
	FlowID         uint64 `json:"flow_id"`
	Source         string `json:"source"`
	Destination    string `json:"destination"`
	DeadlineUnixMS int64  `json:"deadline_unix_ms"`
	TraceParent    string `json:"traceparent,omitempty"`
	TraceState     string `json:"tracestate,omitempty"`
}

type OpenTCPResult struct {
	Accepted bool   `json:"accepted"`
	Code     string `json:"error_code,omitempty"`
}

func WriteFrame(w io.Writer, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > MaxControlFrame {
		return errors.New("control frame exceeds size limit")
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if err := writeAll(w, header[:]); err != nil {
		return err
	}
	return writeAll(w, payload)
}

func writeAll(w io.Writer, payload []byte) error {
	for len(payload) > 0 {
		written, err := w.Write(payload)
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

func ReadFrame(r io.Reader, value any) error {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return err
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > MaxControlFrame {
		return fmt.Errorf("The control frame size %d is not valid.", size)
	}
	payload := make([]byte, size)
	if _, err := io.ReadFull(r, payload); err != nil {
		return err
	}
	return json.Unmarshal(payload, value)
}
