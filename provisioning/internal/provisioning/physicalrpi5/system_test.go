package physicalrpi5

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

func TestOSFileSystemPinDetectsSamePathReplacement(t *testing.T) {
	root := t.TempDir()
	first := filepath.Join(root, "first")
	second := filepath.Join(root, "second")
	path := filepath.Join(root, "1-1")
	if err := os.Mkdir(first, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(second, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(first, path); err != nil {
		t.Fatal(err)
	}
	pin, err := (OSFileSystem{}).PinUSBInstance(path)
	if err != nil {
		t.Fatal(err)
	}
	defer pin.Close()
	if err := pin.Verify(); err != nil {
		t.Fatalf("initial pin verification: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(second, path); err != nil {
		t.Fatal(err)
	}
	if err := pin.Verify(); err == nil {
		t.Fatal("same-path replacement matched the held sysfs instance")
	}
}

func TestExecGPIOReleaseDrivesLogicalInactive(t *testing.T) {
	tests := []struct {
		name      string
		activeLow bool
	}{
		{name: "active high"},
		{name: "active low", activeLow: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary, invocationLog := writeFakeGPIOSet(t, 0, 0)
			descriptor := laneguard.GPIODescriptor{
				ChipPath:  "/dev/gpiochip-kaiba-rp1",
				Offset:    22,
				ActiveLow: test.activeLow,
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
			if err != nil {
				t.Fatalf("acquire power: %v", err)
			}
			t.Cleanup(func() { _ = lease.Release() })
			if err := lease.Release(); err != nil {
				t.Fatalf("release power: %v", err)
			}

			activeArguments := []string{
				"--banner", "--chip", descriptor.ChipPath,
				"--consumer", gpioActiveConsumer,
			}
			inactiveArguments := []string{
				"--chip", descriptor.ChipPath,
				"--consumer", gpioInactiveConsumer,
			}
			if test.activeLow {
				activeArguments = append(activeArguments, "--active-low")
				inactiveArguments = append(inactiveArguments, "--active-low")
			}
			activeArguments = append(activeArguments, "22=1")
			inactiveArguments = append(inactiveArguments,
				"--hold-period", gpioInactiveHoldPeriod,
				"--toggle", "0",
				"22=0",
			)
			want := [][]string{activeArguments, inactiveArguments}
			if got := readFakeGPIOSetInvocations(t, invocationLog); !reflect.DeepEqual(got, want) {
				t.Fatalf("gpioset invocations = %#v, want %#v", got, want)
			}
		})
	}
}

func TestExecGPIOReleaseAttemptsInactiveAfterHolderFailure(t *testing.T) {
	binary, invocationLog := writeFakeGPIOSet(t, 17, 23)
	descriptor := laneguard.GPIODescriptor{
		ChipPath: "/dev/gpiochip-kaiba-rp1",
		Offset:   22,
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
	if err != nil {
		t.Fatalf("acquire power: %v", err)
	}
	execLease := lease.(*execPowerLease)
	waitForZombie(t, execLease.command.Process.Pid)

	err = lease.Release()
	if err == nil {
		t.Fatal("release unexpectedly accepted failed holder and inactive processes")
	}
	for _, fragment := range []string{
		"persistent gpioset exited unexpectedly",
		"exit status 17",
		"drive GPIO line explicitly inactive",
		"exit status 23",
	} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("release error %q does not contain %q", err, fragment)
		}
	}
	retryErr := lease.Release()
	if retryErr == nil || !strings.Contains(retryErr.Error(), "exit status 17") {
		t.Fatalf("retry did not preserve abnormal-holder error: %v", retryErr)
	}
	if strings.Contains(retryErr.Error(), "exit status 23") {
		t.Fatalf("successful inactive retry retained its prior transient error: %v", retryErr)
	}
	if finalErr := lease.Release(); finalErr == nil || finalErr.Error() != retryErr.Error() {
		t.Fatalf("completed release did not remain idempotently conservative: %v, want %v", finalErr, retryErr)
	}

	invocations := readFakeGPIOSetInvocations(t, invocationLog)
	if len(invocations) != 3 {
		t.Fatalf("gpioset invocation count = %d, want 3: %#v", len(invocations), invocations)
	}
	wantInactive := []string{
		"--chip", descriptor.ChipPath,
		"--consumer", gpioInactiveConsumer,
		"--hold-period", gpioInactiveHoldPeriod,
		"--toggle", "0",
		"22=0",
	}
	for index, invocation := range invocations[1:] {
		if !reflect.DeepEqual(invocation, wantInactive) {
			t.Fatalf("inactive gpioset invocation %d = %#v, want %#v", index+1, invocation, wantInactive)
		}
	}
}

func TestExecGPIOReleaseRejectsHolderExitZeroAndDrivesInactive(t *testing.T) {
	binary, invocationLog := writeExitZeroGPIOSet(t)
	descriptor := laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip-kaiba-rp1", Offset: 22}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
	if err != nil {
		t.Fatalf("acquire power: %v", err)
	}
	execLease := lease.(*execPowerLease)
	waitForZombie(t, execLease.command.Process.Pid)

	err = lease.Release()
	if err == nil || !strings.Contains(err.Error(), "exited unexpectedly with status 0") {
		t.Fatalf("status-zero holder release = %v", err)
	}
	invocations := readFakeGPIOSetInvocations(t, invocationLog)
	if len(invocations) != 2 || invocations[1][len(invocations[1])-1] != "22=0" {
		t.Fatalf("status-zero holder cleanup invocations = %#v", invocations)
	}
}

func TestExecGPIOReleaseIsIdempotent(t *testing.T) {
	binary, invocationLog := writeFakeGPIOSet(t, 0, 0)
	descriptor := laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip-kaiba-rp1", Offset: 22}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
	if err != nil {
		t.Fatalf("acquire power: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("first release: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
	if invocations := readFakeGPIOSetInvocations(t, invocationLog); len(invocations) != 2 {
		t.Fatalf("idempotent release ran gpioset %d times, want 2 total: %#v", len(invocations), invocations)
	}
}

func TestExecGPIOReleaseRetriesInactiveFailure(t *testing.T) {
	binary, invocationLog := writeFakeGPIOSet(t, 0, 23)
	descriptor := laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip-kaiba-rp1", Offset: 22}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
	if err != nil {
		t.Fatalf("acquire power: %v", err)
	}
	if err := lease.Release(); err == nil || !strings.Contains(err.Error(), "exit status 23") {
		t.Fatalf("first inactive release failure = %v, want exit status 23", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("retry inactive release: %v", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatalf("idempotent release after inactive retry: %v", err)
	}
	if invocations := readFakeGPIOSetInvocations(t, invocationLog); len(invocations) != 3 {
		t.Fatalf("inactive retry ran gpioset %d times, want 3 total: %#v", len(invocations), invocations)
	}
}

func TestExecGPIOAcquireReportsInactiveCleanupFailure(t *testing.T) {
	binary := writeFailedAcquireGPIOSet(t, 23)
	descriptor := laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip-kaiba-rp1", Offset: 22}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
	if err == nil {
		t.Fatal("missing acquisition acknowledgement and inactive cleanup failure were accepted")
	}
	if lease == nil {
		t.Fatal("inactive cleanup failure did not return its retryable lease")
	}
	for _, fragment := range []string{
		"persistent gpioset did not acknowledge line acquisition",
		"GPIO cleanup after acquisition failure",
		"drive GPIO line explicitly inactive",
		"exit status 23",
	} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("acquisition error %q does not contain %q", err, fragment)
		}
	}
	retryErr := lease.Release()
	if retryErr == nil || !strings.Contains(retryErr.Error(), "exit status 17") {
		t.Fatalf("cleanup retry did not preserve abnormal-holder evidence: %v", retryErr)
	}
	if strings.Contains(retryErr.Error(), "exit status 23") {
		t.Fatalf("cleanup retry retained prior inactive failure: %v", retryErr)
	}
	if lease.(*execPowerLease).cleanupPending() {
		t.Fatal("successful inactive retry remained cleanup-pending")
	}
}

func TestExecGPIOAcquireDoesNotReturnLeaseAfterSuccessfulCleanup(t *testing.T) {
	binary := writeFailedAcquireGPIOSet(t, 0)
	descriptor := laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip-kaiba-rp1", Offset: 22}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := (ExecGPIO{Binary: binary}).AcquirePower(ctx, descriptor)
	if err == nil {
		t.Fatal("missing acquisition acknowledgement was accepted")
	}
	if lease != nil {
		t.Fatal("fully inactive acquisition cleanup returned a pending lease")
	}
	if !strings.Contains(err.Error(), "GPIO cleanup after acquisition failure") ||
		strings.Contains(err.Error(), "drive GPIO line explicitly inactive") {
		t.Fatalf("successful cleanup error attribution = %v", err)
	}
}

func TestExecGPIOReleaseCompletesPersistentWaitOnRetry(t *testing.T) {
	binary, invocationLog := writeFakeGPIOSet(t, 0, 0)
	waited := make(chan error, 1)
	waited <- nil
	priorErr := errors.New("prior holder reap timed out")
	lease := &execPowerLease{
		binary:              binary,
		descriptor:          laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip-kaiba-rp1", Offset: 22},
		command:             &exec.Cmd{},
		holderWait:          waited,
		holderWaitStarted:   true,
		holderStopAttempted: true,
		holderErr:           priorErr,
	}

	err := lease.Release()
	if !errors.Is(err, priorErr) {
		t.Fatalf("retry did not preserve prior reap failure: %v", err)
	}
	if !lease.holderDone || !lease.released || lease.cleanupPending() {
		t.Fatalf("retry state holderDone=%t released=%t pending=%t",
			lease.holderDone, lease.released, lease.cleanupPending())
	}
	invocations := readFakeGPIOSetInvocations(t, invocationLog)
	if len(invocations) != 1 || invocations[0][len(invocations[0])-1] != "22=0" {
		t.Fatalf("persistent-wait retry invocations = %#v", invocations)
	}
}

func writeFailedAcquireGPIOSet(t *testing.T, firstInactiveExit int) string {
	t.Helper()
	directory := t.TempDir()
	inactiveFailureMarker := filepath.Join(directory, "inactive-failed")
	binary := filepath.Join(directory, "gpioset")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
last=
for argument do
  last="$argument"
done
case "$last" in
  *=1) exit 17 ;;
  *=0)
    if test %d -ne 0 && test ! -e %s; then
      : > %s
      exit %d
    fi
    exit 0
    ;;
  *) exit 64 ;;
esac
`, firstInactiveExit, shellSingleQuote(inactiveFailureMarker),
		shellSingleQuote(inactiveFailureMarker), firstInactiveExit)
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatalf("write failed-acquire gpioset: %v", err)
	}
	return binary
}

func writeExitZeroGPIOSet(t *testing.T) (string, string) {
	t.Helper()
	directory := t.TempDir()
	invocationLog := filepath.Join(directory, "invocations")
	binary := filepath.Join(directory, "gpioset")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
{
  printf 'BEGIN\n'
  for argument do
    printf 'ARG:%%s\n' "$argument"
  done
  printf 'END\n'
} >> %s
last=
for argument do
  last="$argument"
done
case "$last" in
  *=1) printf 'acquired\n'; exit 0 ;;
  *=0) exit 0 ;;
  *) exit 64 ;;
esac
`, shellSingleQuote(invocationLog))
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatalf("write status-zero gpioset: %v", err)
	}
	return binary, invocationLog
}

func writeFakeGPIOSet(t *testing.T, holderExit, firstInactiveExit int) (string, string) {
	t.Helper()
	directory := t.TempDir()
	invocationLog := filepath.Join(directory, "invocations")
	inactiveFailureMarker := filepath.Join(directory, "inactive-failed")
	binary := filepath.Join(directory, "gpioset")
	script := fmt.Sprintf(`#!/bin/sh
set -eu
{
  printf 'BEGIN\n'
  for argument do
    printf 'ARG:%%s\n' "$argument"
  done
  printf 'END\n'
} >> %s
last=
for argument do
  last="$argument"
done
case "$last" in
  *=1)
    printf 'acquired\n'
    if test %d -ne 0; then
      exit %d
    fi
    while :; do
      sleep 0.01
    done
    ;;
  *=0)
    if test %d -ne 0 && test ! -e %s; then
      : > %s
      exit %d
    fi
    exit 0
    ;;
  *)
    exit 64
    ;;
esac
`, shellSingleQuote(invocationLog), holderExit, holderExit, firstInactiveExit,
		shellSingleQuote(inactiveFailureMarker), shellSingleQuote(inactiveFailureMarker), firstInactiveExit)
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatalf("write fake gpioset: %v", err)
	}
	return binary, invocationLog
}

func readFakeGPIOSetInvocations(t *testing.T, path string) [][]string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fake gpioset invocations: %v", err)
	}
	var invocations [][]string
	var current []string
	for _, line := range strings.Split(strings.TrimSpace(string(content)), "\n") {
		switch {
		case line == "BEGIN":
			if current != nil {
				t.Fatalf("nested fake gpioset invocation in %q", content)
			}
			current = []string{}
		case strings.HasPrefix(line, "ARG:"):
			if current == nil {
				t.Fatalf("argument outside fake gpioset invocation in %q", content)
			}
			current = append(current, strings.TrimPrefix(line, "ARG:"))
		case line == "END":
			if current == nil {
				t.Fatalf("end outside fake gpioset invocation in %q", content)
			}
			invocations = append(invocations, current)
			current = nil
		default:
			t.Fatalf("invalid fake gpioset invocation record %q", line)
		}
	}
	if current != nil {
		t.Fatalf("incomplete fake gpioset invocation in %q", content)
	}
	return invocations
}

func waitForZombie(t *testing.T, pid int) {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/stat", pid)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status, err := os.ReadFile(path)
		if err == nil {
			closingParenthesis := strings.LastIndexByte(string(status), ')')
			if closingParenthesis >= 0 && len(status) > closingParenthesis+2 && status[closingParenthesis+2] == 'Z' {
				return
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("fake gpioset process %d did not become a zombie", pid)
}

func shellSingleQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

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
	evidence, err := uart.Capture(context.Background(), "/dev/serial/by-id/test", []byte("FRESH_PROOF"), 4096, time.Second, func() error {
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
	_, err := (FileUART{device: device}).Capture(context.Background(), "/dev/serial/by-id/test", []byte("PROOF"), 4096, time.Second, func() error {
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

func TestFileUARTCaptureTimeoutStartsAfterTrigger(t *testing.T) {
	device := &fakeUARTDevice{}
	uart := FileUART{PollInterval: time.Millisecond, device: device}
	triggerDelay := 40 * time.Millisecond
	captureTimeout := 30 * time.Millisecond
	started := time.Now()
	_, err := uart.Capture(context.Background(), "/dev/serial/by-id/test", []byte("PROOF"), 4096, captureTimeout, func() error {
		time.Sleep(triggerDelay)
		return nil
	})
	elapsed := time.Since(started)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("capture error = %v, want deadline exceeded", err)
	}
	if elapsed < triggerDelay+captureTimeout-(5*time.Millisecond) {
		t.Fatalf("capture timeout was consumed before trigger completed: elapsed %s", elapsed)
	}
}
