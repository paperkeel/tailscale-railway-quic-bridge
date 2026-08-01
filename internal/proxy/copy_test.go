package proxy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

type testConnection struct {
	reader      io.Reader
	written     bytes.Buffer
	closed      bool
	writeClosed bool
	local       net.Addr
	remote      net.Addr
}

func (c *testConnection) Read(p []byte) (int, error)       { return c.reader.Read(p) }
func (c *testConnection) Write(p []byte) (int, error)      { return c.written.Write(p) }
func (c *testConnection) Close() error                     { c.closed = true; return nil }
func (c *testConnection) CloseWrite() error                { c.writeClosed = true; return nil }
func (c *testConnection) LocalAddr() net.Addr              { return c.local }
func (c *testConnection) RemoteAddr() net.Addr             { return c.remote }
func (c *testConnection) SetDeadline(time.Time) error      { return nil }
func (c *testConnection) SetReadDeadline(time.Time) error  { return nil }
func (c *testConnection) SetWriteDeadline(time.Time) error { return nil }

func TestBidirectionalCopiesBytesAndHalfCloses(t *testing.T) {
	left := &testConnection{reader: bytes.NewBufferString("from-left")}
	right := &testConnection{reader: bytes.NewBufferString("from-right")}

	sent, received, err := Bidirectional(left, right)
	if err != nil {
		t.Fatal(err)
	}

	if sent != int64(len("from-left")) || received != int64(len("from-right")) {
		t.Fatalf("byte counts = (%d, %d), want (%d, %d)", sent, received, len("from-left"), len("from-right"))
	}
	if got := right.written.String(); got != "from-left" {
		t.Errorf("right received %q", got)
	}
	if got := left.written.String(); got != "from-right" {
		t.Errorf("left received %q", got)
	}
	if !left.writeClosed || !right.writeClosed {
		t.Error("Bidirectional did not close both write halves")
	}
	if !left.closed || !right.closed {
		t.Error("Bidirectional did not close both connections")
	}
}

type errorConnection struct {
	closed atomic.Bool
}

func (c *errorConnection) Read([]byte) (int, error)  { return 0, errors.New("read failed") }
func (c *errorConnection) Write([]byte) (int, error) { return 0, errors.New("write failed") }
func (c *errorConnection) Close() error              { c.closed.Store(true); return errors.New("close failed") }

func TestBidirectionalClosesConnectionsAfterCopyErrors(t *testing.T) {
	left := &errorConnection{}
	right := &errorConnection{}

	sent, received, err := Bidirectional(left, right)
	if err == nil {
		t.Fatal("Bidirectional() did not report the copy failures")
	}

	if sent != 0 || received != 0 {
		t.Fatalf("byte counts = (%d, %d), want (0, 0)", sent, received)
	}
	if !left.closed.Load() || !right.closed.Load() {
		t.Error("Bidirectional did not close both connections")
	}
}

type blockingConnection struct {
	closed chan struct{}
	once   sync.Once
}

func (c *blockingConnection) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *blockingConnection) Write(data []byte) (int, error) { return len(data), nil }
func (c *blockingConnection) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

func TestBidirectionalUnblocksTheOtherCopyAfterAnError(t *testing.T) {
	done := make(chan error, 1)
	go func() {
		_, _, err := Bidirectional(&errorConnection{}, &blockingConnection{closed: make(chan struct{})})
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Bidirectional() did not report the copy error")
		}
	case <-time.After(time.Second):
		t.Fatal("Bidirectional() remained blocked after a copy error")
	}
}

type cancelableBlockingConnection struct {
	blockingConnection
	readCanceled  atomic.Bool
	writeCanceled atomic.Bool
}

func (c *cancelableBlockingConnection) Close() error { return nil }
func (c *cancelableBlockingConnection) CancelRead(quic.StreamErrorCode) {
	c.readCanceled.Store(true)
	c.once.Do(func() { close(c.closed) })
}
func (c *cancelableBlockingConnection) CancelWrite(quic.StreamErrorCode) {
	c.writeCanceled.Store(true)
}

func TestBidirectionalCancelsAQUICStyleStreamAfterAnError(t *testing.T) {
	blocked := &cancelableBlockingConnection{blockingConnection: blockingConnection{closed: make(chan struct{})}}
	done := make(chan error, 1)
	go func() {
		_, _, err := Bidirectional(&errorConnection{}, blocked)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Bidirectional() did not report the copy error")
		}
	case <-time.After(time.Second):
		t.Fatal("Bidirectional() did not cancel the blocked stream")
	}
	if !blocked.readCanceled.Load() || !blocked.writeCanceled.Load() {
		t.Fatal("Bidirectional() did not cancel both stream directions")
	}
}

func TestAddress(t *testing.T) {
	connection := &testConnection{
		reader: bytes.NewReader(nil),
		local:  testAddress("[fd00::2]:443"),
		remote: testAddress("[fd00::1]:1234"),
	}
	source, destination := Address(connection)
	if source != "[fd00::1]:1234" || destination != "[fd00::2]:443" {
		t.Fatalf("Address() = (%q, %q)", source, destination)
	}

	connection.local = nil
	connection.remote = nil
	source, destination = Address(connection)
	if source != "" || destination != "" {
		t.Fatalf("Address() with nil addresses = (%q, %q)", source, destination)
	}
}

type testAddress string

func (a testAddress) Network() string { return "test" }
func (a testAddress) String() string  { return string(a) }
