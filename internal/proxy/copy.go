package proxy

import (
	"io"
	"net"
	"sync"
)

type closeWriter interface{ CloseWrite() error }

func Bidirectional(left, right io.ReadWriteCloser) (sent, received int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		sent, _ = io.Copy(right, left)
		closeSend(right)
	}()
	go func() {
		defer wg.Done()
		received, _ = io.Copy(left, right)
		closeSend(left)
	}()
	wg.Wait()
	_ = left.Close()
	_ = right.Close()
	return sent, received
}

func closeSend(connection io.ReadWriteCloser) {
	if closer, ok := connection.(closeWriter); ok {
		_ = closer.CloseWrite()
		return
	}
	_ = connection.Close()
}

func Address(conn net.Conn) (source, destination string) {
	if conn.RemoteAddr() != nil {
		source = conn.RemoteAddr().String()
	}
	if conn.LocalAddr() != nil {
		destination = conn.LocalAddr().String()
	}
	return source, destination
}
