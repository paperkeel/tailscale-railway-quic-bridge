package transport

import (
	"testing"
	"time"
)

func TestQUICConfig(t *testing.T) {
	configuration := QUICConfig(4096)
	if !configuration.EnableDatagrams {
		t.Fatal("expected QUIC datagrams to be enabled")
	}
	if configuration.KeepAlivePeriod != 10*time.Second {
		t.Fatalf("got keepalive period %s", configuration.KeepAlivePeriod)
	}
	if configuration.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("got idle timeout %s", configuration.MaxIdleTimeout)
	}
	if configuration.InitialStreamReceiveWindow != 1<<20 || configuration.MaxStreamReceiveWindow != 16<<20 {
		t.Fatal("got unexpected stream receive windows")
	}
	if configuration.InitialConnectionReceiveWindow != 4<<20 || configuration.MaxConnectionReceiveWindow != 128<<20 {
		t.Fatal("got unexpected connection receive windows")
	}
	if configuration.MaxIncomingStreams != 4096 {
		t.Fatalf("got incoming stream limit %d", configuration.MaxIncomingStreams)
	}
	if configuration.MaxIncomingUniStreams != -1 {
		t.Fatalf("got incoming unidirectional stream limit %d", configuration.MaxIncomingUniStreams)
	}
}
