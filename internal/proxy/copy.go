package proxy

import (
	"errors"
	"io"
	"net"
)

type closeWriter interface{ CloseWrite() error }

func Bidirectional(left, right io.ReadWriteCloser) (sent, received int64, copyErr error) {
	type result struct {
		sent  bool
		bytes int64
		err   error
	}
	results := make(chan result, 2)
	go func() {
		count, err := io.Copy(right, left)
		err = errors.Join(normalizeCopyError(err), normalizeCopyError(closeSend(right)))
		results <- result{sent: true, bytes: count, err: err}
	}()
	go func() {
		count, err := io.Copy(left, right)
		err = errors.Join(normalizeCopyError(err), normalizeCopyError(closeSend(left)))
		results <- result{bytes: count, err: err}
	}()
	first := <-results
	if first.err != nil {
		_ = left.Close()
		_ = right.Close()
	}
	second := <-results
	_ = left.Close()
	_ = right.Close()
	for _, result := range []result{first, second} {
		if result.sent {
			sent = result.bytes
		} else {
			received = result.bytes
		}
	}
	return sent, received, errors.Join(first.err, second.err)
}

func closeSend(connection io.ReadWriteCloser) error {
	if closer, ok := connection.(closeWriter); ok {
		return closer.CloseWrite()
	}
	return connection.Close()
}

func normalizeCopyError(err error) error {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return nil
	}
	return err
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
