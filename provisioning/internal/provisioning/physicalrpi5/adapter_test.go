package physicalrpi5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

const (
	expectedKey    = "1111111111111111111111111111111111111111111111111111111111111111"
	expectedEEPROM = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	expectedBoot   = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

type runnerCall struct {
	executable string
	arguments  []string
}

type fakeRunner struct {
	mu      sync.Mutex
	outputs map[string]string
	errors  map[string]error
	calls   []runnerCall
}

func (runner *fakeRunner) Run(_ context.Context, executable string, arguments []string, stdout, _ io.Writer) error {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	copyArguments := append([]string(nil), arguments...)
	runner.calls = append(runner.calls, runnerCall{executable, copyArguments})
	key := executable
	if len(arguments) > 0 {
		key = arguments[len(arguments)-1]
	}
	_, _ = io.WriteString(stdout, runner.outputs[key])
	return runner.errors[key]
}

type fakeFS struct {
	mu      sync.Mutex
	devices map[string][2]string
}

func (filesystem *fakeFS) ReadDir(string) ([]fs.DirEntry, error) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	names := make([]string, 0, len(filesystem.devices))
	for name := range filesystem.devices {
		names = append(names, name)
	}
	sort.Strings(names)
	entries := make([]fs.DirEntry, 0, len(names))
	for _, name := range names {
		entries = append(entries, fakeDirEntry(name))
	}
	return entries, nil
}

func (filesystem *fakeFS) ReadFile(path string) ([]byte, error) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil, fs.ErrNotExist
	}
	device := filesystem.devices[parts[len(parts)-2]]
	switch parts[len(parts)-1] {
	case "idVendor":
		return []byte(device[0]), nil
	case "idProduct":
		return []byte(device[1]), nil
	default:
		return nil, fs.ErrNotExist
	}
}

func (filesystem *fakeFS) clear() {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	filesystem.devices = map[string][2]string{}
}

func (filesystem *fakeFS) set(name string, device [2]string) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	filesystem.devices = map[string][2]string{name: device}
}

type fakeDirEntry string

func (entry fakeDirEntry) Name() string         { return string(entry) }
func (fakeDirEntry) IsDir() bool                { return true }
func (fakeDirEntry) Type() fs.FileMode          { return fs.ModeDir }
func (fakeDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

type fakeGPIO struct {
	calls []bool
	on    func()
	off   func()
}

func (gpio *fakeGPIO) AcquirePower(context.Context, laneguard.GPIODescriptor) (PowerLease, error) {
	gpio.calls = append(gpio.calls, true)
	if gpio.on != nil {
		gpio.on()
	}
	return &fakePowerLease{gpio: gpio}, nil
}

type fakePowerLease struct {
	gpio     *fakeGPIO
	released bool
}

func (lease *fakePowerLease) Release() error {
	if lease.released {
		return nil
	}
	lease.released = true
	lease.gpio.calls = append(lease.gpio.calls, false)
	if lease.gpio.off != nil {
		lease.gpio.off()
	}
	return nil
}

type fakeUART struct {
	paths    []string
	markers  [][]byte
	err      error
	evidence []byte
}

func (uart *fakeUART) Capture(_ context.Context, path string, marker []byte, _ int, trigger func() error) ([]byte, error) {
	uart.paths = append(uart.paths, path)
	uart.markers = append(uart.markers, append([]byte(nil), marker...))
	if err := trigger(); err != nil {
		return nil, err
	}
	if uart.err != nil {
		return nil, uart.err
	}
	if uart.evidence != nil {
		return append([]byte(nil), uart.evidence...), nil
	}
	if string(marker) == signedBootMarker {
		return []byte("UART log\n" + signedEvidence("00000008", expectedBoot)), nil
	}
	return append(append([]byte("UART log\n"), marker...), '\n'), nil
}

type fakeSleeper struct{ durations []time.Duration }

func (sleeper *fakeSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	sleeper.durations = append(sleeper.durations, duration)
	return ctx.Err()
}

func TestObserveUsesFixedFreshReadbackAndExactUSBPath(t *testing.T) {
	adapter, runner, _, _, _, lane := fixture(t, ModeFresh)
	observation, err := adapter.Observe(context.Background(), lane)
	if err != nil {
		t.Fatal(err)
	}
	if observation.EligibleTargets != 1 || observation.RPIBootSysfsPath != lane.RPIBootSysfsPath || observation.State.SecurityState != "fresh" || observation.State.CustomerKeyHash != "sha256:"+zeroCustomerKey {
		t.Fatalf("observation = %#v", observation)
	}
	if len(runner.calls) != 1 || runner.calls[0].executable != "/immutable/rpiboot" || strings.Join(runner.calls[0].arguments, " ") != "-p 1-1 -d /immutable/fresh-readback" {
		t.Fatalf("runner calls = %#v", runner.calls)
	}
}

func TestConfigRequiresCanonicalPrefixedBootImageDigest(t *testing.T) {
	paths := ImmutablePaths{
		RPIBootBinary: "/immutable/rpiboot", GPIOSetBinary: "/immutable/gpioset",
		FreshReadbackBundle: "/immutable/fresh-readback", FreshCommitBundle: "/immutable/fresh-commit",
		OwnedReadbackBundle: "/immutable/owned-readback", OwnedRecoveryBundle: "/immutable/owned-recovery",
		NegativeBootBundle: "/immutable/negative", RootIntegrityBundle: "/immutable/root-integrity",
	}
	_, err := New(Config{
		Paths: paths, InitialMode: ModeFresh, ExpectedCustomerKeyHash: expectedKey,
		ExpectedEEPROMHash: expectedEEPROM, ExpectedBootImageDigest: strings.TrimPrefix(expectedBoot, "sha256:"),
	}, Dependencies{})
	if err == nil || !strings.Contains(err.Error(), "canonical sha256:") {
		t.Fatalf("error = %v", err)
	}
}

func TestPreflightRejectsAbsentAmbiguousAndWrongPathTargets(t *testing.T) {
	for _, test := range []struct {
		name    string
		devices map[string][2]string
		want    error
	}{
		{"absent", map[string][2]string{}, ErrNoRPIBootTarget},
		{"ambiguous", map[string][2]string{"1-1": {broadcomVendorID, bcm2712ProductID}, "1-2": {broadcomVendorID, bcm2712ProductID}}, ErrAmbiguousTargets},
		{"wrong path", map[string][2]string{"1-2": {broadcomVendorID, bcm2712ProductID}}, ErrUnexpectedTarget},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, _, filesystem, gpio, _, lane := fixture(t, ModeFresh)
			adapter.config.USBReappearTimeout = 2 * time.Millisecond
			adapter.sleeper = TimerSleeper{}
			gpio.on = nil
			filesystem.devices = test.devices
			_, err := adapter.Observe(context.Background(), lane)
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestCommitRequiresCompleteAuthoritativeMetadata(t *testing.T) {
	adapter, runner, _, _, _, lane := fixture(t, ModeFresh)
	if _, err := adapter.Observe(context.Background(), lane); err != nil {
		t.Fatal(err)
	}
	// A command-level error after complete success metadata is not ambiguous:
	// the direct metadata postcondition is authoritative.
	runner.errors["/immutable/fresh-commit"] = errors.New("late USB close error")
	result, err := adapter.Execute(context.Background(), lane, laneguard.OperationProgramCustomerKeyAndEEPROM)
	if err != nil || result.OutputDigest == "" {
		t.Fatalf("commit = %#v, %v", result, err)
	}
	observation, err := adapter.Observe(context.Background(), lane)
	if err != nil || observation.State.CustomerKeyHash != "sha256:"+expectedKey || observation.State.EEPROMHash != "sha256:"+expectedEEPROM || observation.State.SecurityState != "owned" {
		t.Fatalf("owned observation = %#v, %v", observation, err)
	}
	if len(runner.calls) != 3 || runner.calls[2].arguments[len(runner.calls[2].arguments)-1] != "/immutable/owned-readback" {
		t.Fatalf("postcondition was not directly re-observed: %#v", runner.calls)
	}
}

func TestObserveRequiresTargetDisappearanceAfterPowerRelease(t *testing.T) {
	adapter, _, _, gpio, _, lane := fixture(t, ModeFresh)
	adapter.config.USBDisappearTimeout = 2 * time.Millisecond
	adapter.sleeper = TimerSleeper{}
	gpio.off = nil
	_, err := adapter.Observe(context.Background(), lane)
	if err == nil || !strings.Contains(err.Error(), "confirm target disappearance") {
		t.Fatalf("stuck-powered target was accepted: %v", err)
	}
}

func TestCommitRejectsEveryRequiredMetadataMismatch(t *testing.T) {
	for _, test := range []struct {
		name   string
		output string
	}{
		{"key", metadata(strings.Repeat("2", 64), expectedEEPROM, true, "A7EB274C")},
		{"EEPROM", metadata(expectedKey, strings.Repeat("d", 64), true, "A7EB274C")},
		{"EEPROM update", strings.Replace(metadata(expectedKey, expectedEEPROM, true, "A7EB274C"), `"EEPROM_UPDATE":"success"`, `"EEPROM_UPDATE":"failed"`, 1)},
		{"secure boot", strings.Replace(metadata(expectedKey, expectedEEPROM, true, "A7EB274C"), `"SECURE_BOOT_PROVISION":"success"`, `"SECURE_BOOT_PROVISION":"failed"`, 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, runner, _, _, _, lane := fixture(t, ModeFresh)
			if _, err := adapter.Observe(context.Background(), lane); err != nil {
				t.Fatal(err)
			}
			runner.outputs["/immutable/fresh-commit"] = test.output
			if _, err := adapter.Execute(context.Background(), lane, laneguard.OperationProgramCustomerKeyAndEEPROM); !errors.Is(err, ErrMetadataMismatch) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestColdPowerCycleRequiresDisappearanceColdIntervalAndUART(t *testing.T) {
	adapter, _, filesystem, gpio, uart, lane := fixture(t, ModeOwned)
	sleeper := &fakeSleeper{}
	adapter.sleeper = sleeper
	gpio.off = filesystem.clear
	if _, err := adapter.Observe(context.Background(), lane); err != nil {
		t.Fatal(err)
	}
	gpio.calls = nil
	result, err := adapter.Execute(context.Background(), lane, laneguard.OperationColdPowerCycle)
	if err != nil {
		t.Fatalf("cold power cycle: %v", err)
	}
	if strings.Join(boolStrings(gpio.calls), ",") != "true,false" {
		t.Fatalf("GPIO calls = %v", gpio.calls)
	}
	if len(sleeper.durations) != 1 || sleeper.durations[0] != adapter.config.MinimumColdInterval {
		t.Fatalf("sleep durations = %v", sleeper.durations)
	}
	if len(uart.paths) != 1 || uart.paths[0] != lane.UARTPath || string(uart.markers[0]) != signedBootMarker || result.OutputDigest == "" {
		t.Fatalf("UART evidence = paths %v markers %q result %#v", uart.paths, uart.markers, result)
	}
	observation, err := adapter.Observe(context.Background(), lane)
	if err != nil || observation.State.PowerState != "powered_off" {
		t.Fatalf("cold observation = %#v, %v", observation, err)
	}
}

func TestColdPowerCycleFailsIfUSBNeverDisappears(t *testing.T) {
	adapter, _, filesystem, gpio, _, lane := fixture(t, ModeOwned)
	adapter.config.USBDisappearTimeout = 2 * time.Millisecond
	adapter.config.USBPollInterval = time.Millisecond
	adapter.sleeper = TimerSleeper{}
	if _, err := adapter.Observe(context.Background(), lane); err != nil {
		t.Fatal(err)
	}
	gpio.off = nil
	filesystem.set("1-1", [2]string{broadcomVendorID, bcm2712ProductID})
	_, err := adapter.Execute(context.Background(), lane, laneguard.OperationColdPowerCycle)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "disappearance") {
		t.Fatalf("error = %v", err)
	}
}

func TestWaitForDisappearanceContextErrorHasPhase(t *testing.T) {
	adapter, _, _, _, _, lane := fixture(t, ModeOwned)
	ctx, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	err := adapter.waitForDisappearance(ctx, lane.RPIBootSysfsPath)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "disappearance") {
		t.Fatalf("error = %v", err)
	}
}

func TestColdPowerCycleRejectsNonCanonicalOrMismatchedBootEvidence(t *testing.T) {
	for _, test := range []struct {
		name   string
		signed string
		digest string
	}{
		{name: "wrong digest", signed: "00000008", digest: "sha256:" + strings.Repeat("c", 64)},
		{name: "unprefixed digest", signed: "00000008", digest: strings.Repeat("b", 64)},
		{name: "OTP bit clear", signed: "00000000", digest: expectedBoot},
	} {
		t.Run(test.name, func(t *testing.T) {
			adapter, _, filesystem, gpio, uart, lane := fixture(t, ModeOwned)
			gpio.off = filesystem.clear
			uart.evidence = []byte(signedEvidence(test.signed, test.digest))
			if _, err := adapter.Observe(context.Background(), lane); err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Execute(context.Background(), lane, laneguard.OperationColdPowerCycle); !errors.Is(err, ErrBootEvidence) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOwnedReadbackRejectsTargetReplacement(t *testing.T) {
	adapter, runner, _, _, _, lane := fixture(t, ModeOwned)
	if _, err := adapter.Observe(context.Background(), lane); err != nil {
		t.Fatal(err)
	}
	runner.outputs["/immutable/owned-readback"] = metadata(expectedKey, expectedEEPROM, false, "A7EB274D")
	if _, err := adapter.Execute(context.Background(), lane, laneguard.OperationOwnedReadback); !errors.Is(err, laneguard.ErrTargetContinuity) {
		t.Fatalf("replacement error = %v", err)
	}
}

func TestBoundedOutputAndUARTTests(t *testing.T) {
	t.Run("bounded rpiboot", func(t *testing.T) {
		adapter, runner, _, _, _, lane := fixture(t, ModeFresh)
		adapter.config.MaximumOutputBytes = 1024
		runner.outputs["/immutable/fresh-readback"] = strings.Repeat("x", 1025)
		if _, err := adapter.Observe(context.Background(), lane); err == nil || !strings.Contains(err.Error(), "exceeds") {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("negative and root markers", func(t *testing.T) {
		for operation, marker := range map[laneguard.Operation]string{
			laneguard.OperationTestNegativeBoot:  negativeBootProof,
			laneguard.OperationTestRootIntegrity: rootIntegrityProof,
		} {
			adapter, _, _, _, uart, lane := fixture(t, ModeOwned)
			if _, err := adapter.Observe(context.Background(), lane); err != nil {
				t.Fatal(err)
			}
			if _, err := adapter.Execute(context.Background(), lane, operation); err != nil {
				t.Fatalf("%s: %v", operation, err)
			}
			if len(uart.markers) != 1 || string(uart.markers[0]) != marker {
				t.Fatalf("%s marker = %q", operation, uart.markers)
			}
		}
	})
	t.Run("marker must be an exact record", func(t *testing.T) {
		adapter, _, _, _, uart, lane := fixture(t, ModeOwned)
		if _, err := adapter.Observe(context.Background(), lane); err != nil {
			t.Fatal(err)
		}
		uart.evidence = []byte("prefix " + negativeBootProof + " suffix\n")
		if _, err := adapter.Execute(context.Background(), lane, laneguard.OperationTestNegativeBoot); !errors.Is(err, ErrUARTTestEvidence) {
			t.Fatalf("non-exact marker error = %v", err)
		}
	})
}

func fixture(t *testing.T, mode string) (*Adapter, *fakeRunner, *fakeFS, *fakeGPIO, *fakeUART, laneguard.Config) {
	t.Helper()
	paths := ImmutablePaths{
		RPIBootBinary: "/immutable/rpiboot", GPIOSetBinary: "/immutable/gpioset",
		FreshReadbackBundle: "/immutable/fresh-readback", FreshCommitBundle: "/immutable/fresh-commit",
		OwnedReadbackBundle: "/immutable/owned-readback", OwnedRecoveryBundle: "/immutable/owned-recovery",
		NegativeBootBundle: "/immutable/negative", RootIntegrityBundle: "/immutable/root-integrity",
	}
	runner := &fakeRunner{outputs: map[string]string{
		paths.FreshReadbackBundle: metadata(zeroCustomerKey, strings.Repeat("f", 64), false, "A7EB274C"),
		paths.FreshCommitBundle:   metadata(expectedKey, expectedEEPROM, true, "A7EB274C"),
		paths.OwnedReadbackBundle: metadata(expectedKey, expectedEEPROM, false, "A7EB274C"),
		paths.OwnedRecoveryBundle: metadata(expectedKey, expectedEEPROM, false, "A7EB274C"),
	}, errors: make(map[string]error)}
	filesystem := &fakeFS{devices: map[string][2]string{"1-1": {broadcomVendorID, bcm2712ProductID}}}
	gpio := &fakeGPIO{
		on: func() {
			filesystem.set("1-1", [2]string{broadcomVendorID, bcm2712ProductID})
		},
		off: filesystem.clear,
	}
	uart := &fakeUART{}
	adapter, err := New(Config{
		Paths: paths, InitialMode: mode, ExpectedCustomerKeyHash: expectedKey,
		ExpectedEEPROMHash: expectedEEPROM, ExpectedBootImageDigest: expectedBoot,
		CommandTimeout: time.Second, UARTTimeout: time.Second, USBDisappearTimeout: time.Second,
		USBReappearTimeout: time.Second, USBPollInterval: time.Millisecond,
		MinimumColdInterval: 5 * time.Millisecond, MaximumOutputBytes: 4096,
	}, Dependencies{Runner: runner, FS: filesystem, GPIO: gpio, UART: uart, Sleeper: &fakeSleeper{}})
	if err != nil {
		t.Fatal(err)
	}
	lane := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: "station-1", LaneID: "lane-1",
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/kaiba-uart",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17}, LeaseSafetyMargin: time.Second,
	}
	return adapter, runner, filesystem, gpio, uart, lane
}

func metadata(customerKey, eeprom string, commit bool, serial string) string {
	operationFields := ""
	if commit {
		operationFields = `,"EEPROM_UPDATE":"success","SECURE_BOOT_PROVISION":"success"`
	}
	return fmt.Sprintf(`{"USER_SERIAL_NUM":%q,"MAC_ADDR":"2C:CF:67:70:76:F3","EEPROM_HASH":%q,"CUSTOMER_KEY_HASH":%q,"BOOT_ROM":"0000000A","BOARD_ATTR":"00000000","USER_BOARDREV":"B04170","JTAG_LOCKED":"0","SIGNATURE_MODE":"0","MAC_WIFI_ADDR":"2C:CF:67:70:76:F4","MAC_BT_ADDR":"2C:CF:67:70:76:F5","FACTORY_UUID":"001000911006186073"%s}`, serial, eeprom, customerKey, operationFields)
}

func boolStrings(values []bool) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = fmt.Sprint(value)
	}
	return result
}

func signedEvidence(signed, digest string) string {
	return "KAIBA_SECURE_BOOT_EVIDENCE=pass signed=" + signed + " boot_img_sha256=" + digest +
		" root=/dev/mapper/root rollback=unimplemented enrollment_ready=false\n"
}
