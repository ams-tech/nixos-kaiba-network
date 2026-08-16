package yubikeysigner

import (
	"bytes"
	"testing"
)

func TestBoundedBufferDrainsButRecordsOverflow(t *testing.T) {
	buffer := newBoundedBuffer(8)
	payload := bytes.Repeat([]byte{'x'}, 32)
	if written, err := buffer.Write(payload); err != nil || written != len(payload) {
		t.Fatalf("Write = %d, %v", written, err)
	}
	if !buffer.Overflowed() || !bytes.Equal(buffer.Bytes(), payload[:8]) {
		t.Fatalf("overflow/data = %v/%q", buffer.Overflowed(), buffer.Bytes())
	}
}
