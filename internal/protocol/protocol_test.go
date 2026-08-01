package protocol

import (
	"bytes"
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

func FuzzReadFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 2, '{', '}'})
	f.Fuzz(func(t *testing.T, data []byte) {
		var value map[string]any
		_ = ReadFrame(bytes.NewReader(data), &value)
	})
}
