package physicalrpi5

import (
	"context"
	"errors"
	"reflect"
	"syscall"
	"testing"
)

type fakeUARTDevice struct {
	events   []string
	original syscall.Termios
	set      []syscall.Termios
	flushed  bool
	flushErr error
	fresh    []byte
}

func (device *fakeUARTDevice) Open(string) (int, error) {
	device.events = append(device.events, "open")
	return 7, nil
}

func (device *fakeUARTDevice) Close(int) error {
	device.events = append(device.events, "close")
	return nil
}

func (device *fakeUARTDevice) Read(int, []byte) (int, error) {
	device.events = append(device.events, "read")
	return 0, syscall.EAGAIN
}

func (device *fakeUARTDevice) GetTermios(int) (syscall.Termios, error) {
	device.events = append(device.events, "get")
	return device.original, nil
}

func (device *fakeUARTDevice) SetTermios(_ int, settings syscall.Termios) error {
	device.events = append(device.events, "set")
	device.set = append(device.set, settings)
	return nil
}

func (device *fakeUARTDevice) FlushInput(int) error {
	device.events = append(device.events, "flush")
	if device.flushErr != nil {
		return device.flushErr
	}
	device.flushed = true
	return nil
}

type evidenceUARTDevice struct{ fakeUARTDevice }

func (device *evidenceUARTDevice) Read(_ int, buffer []byte) (int, error) {
	device.events = append(device.events, "read")
	if !device.flushed {
		return copy(buffer, []byte("STALE_PROOF\n")), nil
	}
	return copy(buffer, device.fresh), nil
}

func TestFileUARTConfiguresFlushesAndRestoresAroundTrigger(t *testing.T) {
	original := syscall.Termios{
		Iflag:  syscall.ICRNL | syscall.IXON | syscall.IXOFF,
		Oflag:  syscall.OPOST,
		Cflag:  syscall.CS7 | syscall.PARENB | syscall.CSTOPB | syscall.B9600 | linuxCRTSCTS,
		Lflag:  syscall.ECHO | syscall.ICANON | syscall.ISIG,
		Ispeed: syscall.B9600,
		Ospeed: syscall.B9600,
	}
	device := &evidenceUARTDevice{fakeUARTDevice: fakeUARTDevice{
		original: original,
		fresh:    []byte("FRESH_PROOF\n"),
	}}
	uart := FileUART{device: device}
	evidence, err := uart.Capture(context.Background(), "/dev/serial/by-id/test", []byte("FRESH_PROOF"), 4096, func() error {
		device.events = append(device.events, "trigger")
		return nil
	})
	if err != nil || string(evidence) != "FRESH_PROOF\n" {
		t.Fatalf("capture = %q, %v", evidence, err)
	}
	wantEvents := []string{"open", "get", "set", "flush", "trigger", "read", "set", "close"}
	if !reflect.DeepEqual(device.events, wantEvents) {
		t.Fatalf("UART event order = %v, want %v", device.events, wantEvents)
	}
	if len(device.set) != 2 || device.set[1] != original {
		t.Fatalf("UART settings were not restored: %#v", device.set)
	}
	configured := device.set[0]
	if configured.Ispeed != syscall.B115200 || configured.Ospeed != syscall.B115200 ||
		configured.Cflag&linuxCBAUD != syscall.B115200 || configured.Cflag&syscall.CSIZE != syscall.CS8 ||
		configured.Cflag&(syscall.PARENB|syscall.CSTOPB|linuxCRTSCTS) != 0 ||
		configured.Cflag&(syscall.CREAD|syscall.CLOCAL) != syscall.CREAD|syscall.CLOCAL ||
		configured.Iflag&(syscall.ICRNL|syscall.IXON|syscall.IXOFF) != 0 ||
		configured.Oflag&syscall.OPOST != 0 || configured.Lflag&(syscall.ECHO|syscall.ICANON|syscall.ISIG) != 0 {
		t.Fatalf("UART was not configured as 115200 8N1 raw: %#v", configured)
	}
}

func TestFileUARTFailsClosedWhenStaleInputCannotBeFlushed(t *testing.T) {
	device := &fakeUARTDevice{flushErr: errors.New("flush failed")}
	triggered := false
	_, err := (FileUART{device: device}).Capture(context.Background(), "/dev/serial/by-id/test", []byte("PROOF"), 4096, func() error {
		triggered = true
		return nil
	})
	if err == nil || triggered {
		t.Fatalf("flush failure = %v, triggered = %t", err, triggered)
	}
	wantEvents := []string{"open", "get", "set", "flush", "set", "close"}
	if !reflect.DeepEqual(device.events, wantEvents) {
		t.Fatalf("UART failure event order = %v, want %v", device.events, wantEvents)
	}
}
