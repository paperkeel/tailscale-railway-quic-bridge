package protocol

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	ALPN              = "tailbridge/2"
	ALPNV3            = "tailbridge/3"
	RegistrationALPN  = "tailbridge-register/1"
	MaxControlFrame   = 64 * 1024
	ProtocolVersion   = "2.0"
	ProtocolVersionV3 = "3.0"
)

type RegistrationRequest struct {
	RequestID        string `json:"request_id"`
	Kind             string `json:"kind"`
	ProjectID        string `json:"project_id"`
	EnvironmentID    string `json:"environment_id"`
	EnvironmentName  string `json:"environment_name"`
	DeploymentID     string `json:"deployment_id"`
	ProjectAlias     string `json:"project_alias"`
	EnvironmentAlias string `json:"environment_alias"`
	IdentityKey      []byte `json:"identity_key"`
	TransportKey     []byte `json:"transport_key"`
	Proof            []byte `json:"proof"`
}

type RegistrationResponse struct {
	RequestID      string `json:"request_id"`
	State          string `json:"state"`
	ErrorCode      string `json:"error_code,omitempty"`
	RetryAfterMS   int64  `json:"retry_after_ms,omitempty"`
	VirtualPrefix  string `json:"virtual_prefix,omitempty"`
	RealPrefix     string `json:"real_prefix,omitempty"`
	DNSSuffix      string `json:"dns_suffix,omitempty"`
	CertificatePEM []byte `json:"certificate_pem,omitempty"`
	CertificateEnd int64  `json:"certificate_end,omitempty"`
	LeaseExpiresAt int64  `json:"lease_expires_at,omitempty"`
}

type ConnectorHelloV3 struct {
	ProtocolVersion string   `json:"protocol_version"`
	ProjectID       string   `json:"project_id"`
	EnvironmentID   string   `json:"environment_id"`
	IdentityKeyID   string   `json:"identity_key_id"`
	Routes          []string `json:"routes"`
	SoftwareVersion string   `json:"software_version"`
	StartedUnixNano int64    `json:"started_unix_nano"`
}

type ConnectorHello struct {
	ProtocolVersion string   `json:"protocol_version"`
	ConnectorID     string   `json:"connector_id"`
	Environment     string   `json:"environment"`
	Routes          []string `json:"routes"`
	SoftwareVersion string   `json:"software_version"`
	StartedUnixNano int64    `json:"started_unix_nano"`
}

type ConnectorAccepted struct {
	SessionID     string   `json:"session_id"`
	ConnectorID   string   `json:"connector_id"`
	Slot          int      `json:"slot"`
	VirtualPrefix string   `json:"virtual_prefix"`
	RealPrefix    string   `json:"real_prefix"`
	Routes        []string `json:"accepted_routes"`
	MaxTCPFlows   int64    `json:"max_tcp_flows"`
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
