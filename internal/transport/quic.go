package transport

import (
	"time"

	"github.com/quic-go/quic-go"
)

func QUICConfig(maxIncomingStreams int64) *quic.Config {
	return &quic.Config{
		EnableDatagrams:                true,
		KeepAlivePeriod:                10 * time.Second,
		MaxIdleTimeout:                 30 * time.Second,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         16 << 20,
		InitialConnectionReceiveWindow: 4 << 20,
		MaxConnectionReceiveWindow:     128 << 20,
		MaxIncomingStreams:             maxIncomingStreams,
		MaxIncomingUniStreams:          -1,
	}
}
