package physicalrpi5

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

type Runner interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

// GuardedRunner places one final identity check at the process-start boundary.
// The check narrows the physically exclusive lane's re-identification window;
// it is not an atomic hot-swap-resistant USB transaction.
type GuardedRunner interface {
	RunGuarded(context.Context, string, []string, func() error, io.Writer, io.Writer) error
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, arguments []string, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	return command.Run()
}

func (ExecRunner) RunGuarded(ctx context.Context, executable string, arguments []string, beforeStart func() error, stdout, stderr io.Writer) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Stdout = stdout
	command.Stderr = stderr
	if beforeStart == nil {
		return errors.New("guarded runner requires a process-start identity check")
	}
	if err := beforeStart(); err != nil {
		return fmt.Errorf("process-start identity check: %w", err)
	}
	return command.Run()
}

type FileSystem interface {
	ReadDir(string) ([]fs.DirEntry, error)
	ReadFile(string) ([]byte, error)
}

// USBInstancePin holds the opened sysfs target object across multiple rpiboot
// invocations. Verify compares the current fixed path with that still-open
// kernel object, detecting removal and replacement at the same path.
type USBInstancePin interface {
	Verify() error
	Close() error
}

type USBInstancePinner interface {
	PinUSBInstance(string) (USBInstancePin, error)
}

type OSFileSystem struct{}

func (OSFileSystem) ReadDir(path string) ([]fs.DirEntry, error) { return os.ReadDir(path) }
func (OSFileSystem) ReadFile(path string) ([]byte, error)       { return os.ReadFile(path) }

func (OSFileSystem) PinUSBInstance(path string) (USBInstancePin, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixed USB sysfs target: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("stat opened USB sysfs target: %w", err)
	}
	if !info.IsDir() {
		_ = file.Close()
		return nil, errors.New("fixed USB sysfs target does not resolve to a directory")
	}
	return &osUSBInstancePin{path: path, file: file, initial: info}, nil
}

type osUSBInstancePin struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	initial os.FileInfo
}

func (pin *osUSBInstancePin) Verify() error {
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin.file == nil {
		return errors.New("USB sysfs instance pin is closed")
	}
	held, err := pin.file.Stat()
	if err != nil {
		return fmt.Errorf("stat held USB sysfs instance: %w", err)
	}
	current, err := os.Stat(pin.path)
	if err != nil {
		return fmt.Errorf("stat current fixed USB sysfs target: %w", err)
	}
	if !os.SameFile(pin.initial, held) || !os.SameFile(pin.initial, current) {
		return errors.New("fixed USB sysfs target no longer names the pinned device instance")
	}
	return nil
}

func (pin *osUSBInstancePin) Close() error {
	pin.mu.Lock()
	defer pin.mu.Unlock()
	if pin.file == nil {
		return nil
	}
	file := pin.file
	pin.file = nil
	return file.Close()
}

type GPIO interface {
	AcquirePower(context.Context, laneguard.GPIODescriptor) (PowerLease, error)
}

// PowerLease may be returned together with an AcquirePower error when the
// acquisition failed and explicit inactive cleanup still requires a retry.
type PowerLease interface {
	Release() error
}

// ExecGPIO starts one build-pinned libgpiod 2.x gpioset process. By default
// gpioset holds the requested line until it exits. --banner provides a bounded
// acquisition acknowledgement; Pdeathsig bounds the asserted holder's lifetime
// if its parent dies. A normal Release explicitly drives logical inactive.
type ExecGPIO struct {
	Binary string
}

const (
	gpioHolderStopTimeout  = 2 * time.Second
	gpioInactiveRunTimeout = 2 * time.Second
	gpioInactiveHoldPeriod = "100ms"
	gpioActiveConsumer     = "kaiba-provision-lane-guard"
	gpioInactiveConsumer   = "kaiba-provision-lane-guard-inactive"
)

func (gpio ExecGPIO) AcquirePower(ctx context.Context, descriptor laneguard.GPIODescriptor) (PowerLease, error) {
	arguments := []string{"--banner", "--chip", descriptor.ChipPath, "--consumer", gpioActiveConsumer}
	if descriptor.ActiveLow {
		arguments = append(arguments, "--active-low")
	}
	arguments = append(arguments, strconv.FormatUint(uint64(descriptor.Offset), 10)+"=1")
	command := exec.Command(gpio.Binary, arguments...)
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("open gpioset acknowledgement: %w", err)
	}
	stderr := &boundedDiagnostic{maximum: 4096}
	command.Stderr = stderr
	if err := command.Start(); err != nil {
		return nil, fmt.Errorf("start persistent gpioset: %w", err)
	}
	lease := &execPowerLease{
		binary:     gpio.Binary,
		descriptor: descriptor,
		command:    command,
	}
	acknowledgement := make(chan error, 1)
	go func() {
		line, readErr := bufio.NewReader(io.LimitReader(stdout, 4097)).ReadString('\n')
		if readErr != nil {
			acknowledgement <- readErr
			return
		}
		if len(line) == 0 || len(line) > 4096 {
			acknowledgement <- errors.New("gpioset acknowledgement is invalid")
			return
		}
		acknowledgement <- nil
	}()
	select {
	case err := <-acknowledgement:
		if err != nil {
			return finishFailedGPIOAcquire(lease,
				fmt.Errorf("persistent gpioset did not acknowledge line acquisition: %w", err))
		}
		return lease, nil
	case <-ctx.Done():
		return finishFailedGPIOAcquire(lease,
			fmt.Errorf("wait for persistent gpioset line acquisition: %w", ctx.Err()))
	}
}

func finishFailedGPIOAcquire(lease *execPowerLease, acquireErr error) (PowerLease, error) {
	cleanupErr := lease.Release()
	var pending PowerLease
	if lease.cleanupPending() {
		pending = lease
	}
	return pending, errors.Join(acquireErr, wrapGPIOCleanupError(cleanupErr))
}

func wrapGPIOCleanupError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("GPIO cleanup after acquisition failure: %w", err)
}

type execPowerLease struct {
	mu                  sync.Mutex
	binary              string
	descriptor          laneguard.GPIODescriptor
	command             *exec.Cmd
	holderWait          chan error
	holderWaitStarted   bool
	holderStopAttempted bool
	holderTermSignaled  bool
	holderKillSignaled  bool
	holderDone          bool
	holderErr           error
	released            bool
}

func (lease *execPowerLease) Release() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.released {
		return lease.holderErr
	}
	if !lease.holderDone {
		reaped, holderErr := lease.stopAndReapHolder()
		lease.holderErr = errors.Join(lease.holderErr, holderErr)
		lease.holderDone = reaped
	}
	inactiveErr := lease.driveInactive()
	if lease.holderDone && inactiveErr == nil {
		lease.released = true
	}
	return errors.Join(lease.holderErr, inactiveErr)
}

func (lease *execPowerLease) cleanupPending() bool {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	return !lease.released
}

func (lease *execPowerLease) ensureHolderWaiter() {
	if lease.holderWaitStarted {
		return
	}
	lease.holderWait = make(chan error, 1)
	lease.holderWaitStarted = true
	go func() { lease.holderWait <- lease.command.Wait() }()
}

func (lease *execPowerLease) stopAndReapHolder() (bool, error) {
	lease.ensureHolderWaiter()
	if lease.holderStopAttempted {
		if waitErr, ready := lease.pollHolderWait(); ready {
			return true, lease.classifyHolderWait(waitErr)
		}
	}
	lease.holderStopAttempted = true

	var holderErrors []error
	var signalErr error
	if lease.command.Process != nil {
		signalErr = lease.command.Process.Signal(syscall.SIGTERM)
	} else {
		signalErr = errors.New("persistent gpioset has no process")
	}
	if signalErr == nil {
		lease.holderTermSignaled = true
	} else if !lease.expectedProcessDone(signalErr) {
		holderErrors = append(holderErrors,
			fmt.Errorf("persistent gpioset exited before requested release: %w", signalErr))
	}

	if waitErr, reaped := lease.awaitHolderWait(gpioHolderStopTimeout); reaped {
		return true, errors.Join(errors.Join(holderErrors...), lease.classifyHolderWait(waitErr))
	}
	holderErrors = append(holderErrors,
		errors.New("persistent gpioset ignored SIGTERM and required SIGKILL"))

	if lease.command.Process != nil {
		killErr := lease.command.Process.Kill()
		if killErr == nil {
			lease.holderKillSignaled = true
		} else if !lease.expectedProcessDone(killErr) {
			holderErrors = append(holderErrors, fmt.Errorf("kill persistent gpioset: %w", killErr))
		}
	}
	if waitErr, reaped := lease.awaitHolderWait(gpioHolderStopTimeout); reaped {
		return true, errors.Join(errors.Join(holderErrors...), lease.classifyHolderWait(waitErr))
	}
	holderErrors = append(holderErrors,
		errors.New("timed out reaping persistent gpioset after SIGKILL"))
	return false, errors.Join(holderErrors...)
}

func (lease *execPowerLease) expectedProcessDone(err error) bool {
	return errors.Is(err, os.ErrProcessDone) && (lease.holderTermSignaled || lease.holderKillSignaled)
}

func (lease *execPowerLease) pollHolderWait() (error, bool) {
	select {
	case waitErr := <-lease.holderWait:
		return waitErr, true
	default:
		return nil, false
	}
}

func (lease *execPowerLease) awaitHolderWait(timeout time.Duration) (error, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case waitErr := <-lease.holderWait:
		return waitErr, true
	case <-timer.C:
		return nil, false
	}
}

func (lease *execPowerLease) classifyHolderWait(waitErr error) error {
	if waitErr == nil {
		// Pinned gpioset 2.2.4 has no SIGTERM handler; requested termination
		// therefore reports a signaled WaitStatus. Status zero means the holder
		// stopped independently and continuity was lost before release.
		return errors.New("persistent gpioset exited unexpectedly with status 0")
	}
	var exitError *exec.ExitError
	if !errors.As(waitErr, &exitError) || exitError.ProcessState == nil {
		return fmt.Errorf("reap persistent gpioset: %w", waitErr)
	}
	status, ok := exitError.ProcessState.Sys().(syscall.WaitStatus)
	normalTermination := ok && status.Signaled() && status.Signal() == syscall.SIGTERM && lease.holderTermSignaled
	forcedTermination := ok && status.Signaled() && status.Signal() == syscall.SIGKILL && lease.holderKillSignaled
	if !normalTermination && !forcedTermination {
		return fmt.Errorf("persistent gpioset exited unexpectedly: %w", waitErr)
	}
	return nil
}

func (lease *execPowerLease) driveInactive() error {
	arguments := []string{
		"--chip", lease.descriptor.ChipPath,
		"--consumer", gpioInactiveConsumer,
	}
	if lease.descriptor.ActiveLow {
		arguments = append(arguments, "--active-low")
	}
	// libgpiod 2.2.4 treats a sole zero toggle period as an instruction to
	// exit without toggling. The hold period therefore keeps the line at its
	// initial logical inactive value for a bounded interval before release.
	arguments = append(arguments,
		"--hold-period", gpioInactiveHoldPeriod,
		"--toggle", "0",
		strconv.FormatUint(uint64(lease.descriptor.Offset), 10)+"=0",
	)

	ctx, cancel := context.WithTimeout(context.Background(), gpioInactiveRunTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, lease.binary, arguments...)
	stderr := &boundedDiagnostic{maximum: 4096}
	command.Stderr = stderr
	err := command.Run()
	if ctxErr := ctx.Err(); ctxErr != nil {
		timeoutErr := fmt.Errorf("drive GPIO line explicitly inactive: %w", ctxErr)
		if err != nil {
			return errors.Join(timeoutErr, fmt.Errorf("inactive gpioset process: %w", err))
		}
		return timeoutErr
	}
	if err != nil {
		return fmt.Errorf("drive GPIO line explicitly inactive: %w", err)
	}
	return nil
}

type boundedDiagnostic struct {
	mu      sync.Mutex
	bytes   []byte
	maximum int
}

func (diagnostic *boundedDiagnostic) Write(value []byte) (int, error) {
	diagnostic.mu.Lock()
	defer diagnostic.mu.Unlock()
	remaining := diagnostic.maximum - len(diagnostic.bytes)
	if remaining > 0 {
		if len(value) < remaining {
			remaining = len(value)
		}
		diagnostic.bytes = append(diagnostic.bytes, value[:remaining]...)
	}
	return len(value), nil
}

// UART captures a bounded byte stream after opening the fixed adapter and
// before Trigger powers or boots the target.
type UART interface {
	Capture(context.Context, string, []byte, int, func() error) ([]byte, error)
}

// FileUART owns the serial settings for the duration of one capture. It fixes
// the target console at 115200 8N1 raw mode, flushes bytes queued before the
// operation trigger, and restores the prior settings before closing the port.
type FileUART struct {
	PollInterval time.Duration
	device       uartDevice
}

type uartDevice interface {
	Open(string) (int, error)
	Close(int) error
	Read(int, []byte) (int, error)
	GetTermios(int) (syscall.Termios, error)
	SetTermios(int, syscall.Termios) error
	FlushInput(int) error
}

type linuxUARTDevice struct{}

func (linuxUARTDevice) Open(path string) (int, error) {
	return syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY, 0)
}

func (linuxUARTDevice) Close(fd int) error { return syscall.Close(fd) }

func (linuxUARTDevice) Read(fd int, buffer []byte) (int, error) { return syscall.Read(fd, buffer) }

func (linuxUARTDevice) GetTermios(fd int) (syscall.Termios, error) {
	var settings syscall.Termios
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&settings)))
	if errno != 0 {
		return syscall.Termios{}, errno
	}
	return settings, nil
}

func (linuxUARTDevice) SetTermios(fd int, settings syscall.Termios) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&settings)))
	if errno != 0 {
		return errno
	}
	return nil
}

// TCFLSH and CBAUD are stable across the supported x86_64 and aarch64 Linux
// station platforms but are not exported consistently by package syscall.
const (
	linuxTCFLSH  = 0x540b
	linuxCBAUD   = 0x100f
	linuxCRTSCTS = 0x80000000
)

func (linuxUARTDevice) FlushInput(fd int) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), linuxTCFLSH, uintptr(syscall.TCIFLUSH))
	if errno != 0 {
		return errno
	}
	return nil
}

func raw115200(settings syscall.Termios) syscall.Termios {
	settings.Iflag &^= syscall.IGNBRK | syscall.BRKINT | syscall.PARMRK | syscall.ISTRIP |
		syscall.INLCR | syscall.IGNCR | syscall.ICRNL | syscall.IXON | syscall.IXOFF
	settings.Oflag &^= syscall.OPOST
	settings.Lflag &^= syscall.ECHO | syscall.ECHONL | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	settings.Cflag &^= syscall.CSIZE | syscall.PARENB | syscall.PARODD | syscall.CSTOPB | linuxCBAUD | linuxCRTSCTS
	settings.Cflag |= syscall.CS8 | syscall.CREAD | syscall.CLOCAL | syscall.B115200
	settings.Ispeed = syscall.B115200
	settings.Ospeed = syscall.B115200
	settings.Cc[syscall.VMIN] = 0
	settings.Cc[syscall.VTIME] = 0
	return settings
}

func (uart FileUART) Capture(ctx context.Context, path string, marker []byte, maximum int, trigger func() error) (result []byte, resultErr error) {
	device := uart.device
	if device == nil {
		device = linuxUARTDevice{}
	}
	fd, err := device.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open fixed UART: %w", err)
	}
	defer func() {
		if err := device.Close(fd); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("close fixed UART: %w", err))
		}
	}()
	original, err := device.GetTermios(fd)
	if err != nil {
		return nil, fmt.Errorf("read fixed UART settings: %w", err)
	}
	defer func() {
		if err := device.SetTermios(fd, original); err != nil {
			resultErr = errors.Join(resultErr, fmt.Errorf("restore fixed UART settings: %w", err))
		}
	}()
	if err := device.SetTermios(fd, raw115200(original)); err != nil {
		return nil, fmt.Errorf("configure fixed UART for 115200 8N1 raw capture: %w", err)
	}
	if err := device.FlushInput(fd); err != nil {
		return nil, fmt.Errorf("discard stale fixed UART input before trigger: %w", err)
	}
	if err := trigger(); err != nil {
		return nil, err
	}
	interval := uart.PollInterval
	if interval <= 0 {
		interval = 10 * time.Millisecond
	}
	result = make([]byte, 0, 4096)
	buffer := make([]byte, 4096)
	for {
		count, readErr := device.Read(fd, buffer)
		if count > 0 {
			if len(result)+count > maximum {
				return nil, fmt.Errorf("UART evidence exceeds %d bytes", maximum)
			}
			result = append(result, buffer[:count]...)
			if completeMarkerLine(result, marker) {
				return result, nil
			}
		}
		if readErr != nil && !errors.Is(readErr, syscall.EAGAIN) && !errors.Is(readErr, syscall.EWOULDBLOCK) && !errors.Is(readErr, syscall.EINTR) {
			return nil, fmt.Errorf("read fixed UART: %w", readErr)
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func completeMarkerLine(result, marker []byte) bool {
	markerIndex := bytes.Index(result, marker)
	if markerIndex < 0 {
		return false
	}
	return bytes.IndexByte(result[markerIndex+len(marker):], '\n') >= 0
}

type Sleeper interface {
	Sleep(context.Context, time.Duration) error
}

type TimerSleeper struct{}

func (TimerSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
