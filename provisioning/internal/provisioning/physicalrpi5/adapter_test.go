package physicalrpi5

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5"
)

const (
	expectedKey         = "1111111111111111111111111111111111111111111111111111111111111111"
	expectedEEPROM      = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	expectedBoot        = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	expectedSerial      = "A7EB274C"
	expectedFingerprint = "sha256:710f24d5142c15afc9b42b4c835b6c4791ce403984f7fa70a0b9748a8edf729b"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *fakeClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *fakeClock) advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration)
	clock.mu.Unlock()
}

type fakeSleeper struct {
	clock        *fakeClock
	pollInterval time.Duration
	mu           sync.Mutex
	durations    []time.Duration
}

func (sleeper *fakeSleeper) Sleep(ctx context.Context, duration time.Duration) error {
	sleeper.mu.Lock()
	sleeper.durations = append(sleeper.durations, duration)
	sleeper.mu.Unlock()
	if duration != sleeper.pollInterval {
		sleeper.clock.advance(duration)
		return ctx.Err()
	}
	<-ctx.Done()
	return ctx.Err()
}

type fakeFS struct {
	mu          sync.Mutex
	devices     map[string][2]string
	readErrors  map[string]error
	generations map[string]uint64
	next        uint64
	reads       int
}

func (filesystem *fakeFS) ReadDir(string) ([]fs.DirEntry, error) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	filesystem.reads++
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
	if err := filesystem.readErrors[path]; err != nil {
		return nil, err
	}
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		return nil, fs.ErrNotExist
	}
	device, ok := filesystem.devices[parts[len(parts)-2]]
	if !ok {
		return nil, fs.ErrNotExist
	}
	switch parts[len(parts)-1] {
	case "idVendor":
		return []byte(device[0]), nil
	case "idProduct":
		return []byte(device[1]), nil
	default:
		return nil, fs.ErrNotExist
	}
}

func (filesystem *fakeFS) set(devices map[string][2]string) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	if filesystem.generations == nil {
		filesystem.generations = make(map[string]uint64)
	}
	copyDevices := make(map[string][2]string, len(devices))
	for name, device := range devices {
		copyDevices[name] = device
		if previous, exists := filesystem.devices[name]; !exists || previous != device {
			filesystem.next++
			filesystem.generations[name] = filesystem.next
		}
	}
	filesystem.devices = copyDevices
	if len(devices) == 0 {
		filesystem.readErrors = nil
	}
}

func (filesystem *fakeFS) replace(name string, device [2]string) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	if filesystem.generations == nil {
		filesystem.generations = make(map[string]uint64)
	}
	filesystem.next++
	filesystem.generations[name] = filesystem.next
	filesystem.devices[name] = device
}

func (filesystem *fakeFS) failRead(path string, err error) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	if filesystem.readErrors == nil {
		filesystem.readErrors = make(map[string]error)
	}
	filesystem.readErrors[path] = err
}

func (filesystem *fakeFS) PinUSBInstance(path string) (USBInstancePin, error) {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	name := filepath.Base(path)
	if _, exists := filesystem.devices[name]; !exists {
		return nil, fs.ErrNotExist
	}
	if filesystem.generations == nil {
		filesystem.generations = make(map[string]uint64)
	}
	generation := filesystem.generations[name]
	if generation == 0 {
		filesystem.next++
		generation = filesystem.next
		filesystem.generations[name] = generation
	}
	return &fakeUSBInstancePin{filesystem: filesystem, name: name, generation: generation}, nil
}

type fakeUSBInstancePin struct {
	filesystem *fakeFS
	name       string
	generation uint64
	closed     bool
}

func (pin *fakeUSBInstancePin) Verify() error {
	pin.filesystem.mu.Lock()
	defer pin.filesystem.mu.Unlock()
	if pin.closed {
		return errors.New("fake USB instance pin is closed")
	}
	if _, exists := pin.filesystem.devices[pin.name]; !exists || pin.filesystem.generations[pin.name] != pin.generation {
		return errors.New("fake USB instance was replaced")
	}
	return nil
}

func (pin *fakeUSBInstancePin) Close() error {
	pin.filesystem.mu.Lock()
	defer pin.filesystem.mu.Unlock()
	pin.closed = true
	return nil
}

func (filesystem *fakeFS) readCount() int {
	filesystem.mu.Lock()
	defer filesystem.mu.Unlock()
	return filesystem.reads
}

type fakeDirEntry string

func (entry fakeDirEntry) Name() string         { return string(entry) }
func (fakeDirEntry) IsDir() bool                { return true }
func (fakeDirEntry) Type() fs.FileMode          { return fs.ModeDir }
func (fakeDirEntry) Info() (fs.FileInfo, error) { return nil, errors.New("unused") }

type fakeGPIO struct {
	mu         sync.Mutex
	acquired   int
	released   int
	powered    bool
	on         func()
	off        func()
	releaseErr error
}

func (gpio *fakeGPIO) AcquirePower(context.Context, laneguard.GPIODescriptor) (PowerLease, error) {
	gpio.mu.Lock()
	gpio.acquired++
	gpio.powered = true
	gpio.mu.Unlock()
	if gpio.on != nil {
		gpio.on()
	}
	return &fakePowerLease{gpio: gpio}, nil
}

func (gpio *fakeGPIO) state() (int, int, bool) {
	gpio.mu.Lock()
	defer gpio.mu.Unlock()
	return gpio.acquired, gpio.released, gpio.powered
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
	lease.gpio.mu.Lock()
	lease.gpio.released++
	lease.gpio.powered = false
	err := lease.gpio.releaseErr
	lease.gpio.mu.Unlock()
	if lease.gpio.off != nil {
		lease.gpio.off()
	}
	return err
}

type runnerCall struct {
	executable string
	arguments  []string
}

type fakeRunner struct {
	mu      sync.Mutex
	outputs map[string]string
	errors  map[string]error
	calls   []runnerCall
	before  func(context.Context, string)
}

func (runner *fakeRunner) Run(ctx context.Context, executable string, arguments []string, stdout, _ io.Writer) error {
	return runner.run(ctx, executable, arguments, nil, stdout)
}

func (runner *fakeRunner) RunGuarded(ctx context.Context, executable string, arguments []string, beforeStart func() error, stdout, _ io.Writer) error {
	return runner.run(ctx, executable, arguments, beforeStart, stdout)
}

func (runner *fakeRunner) run(ctx context.Context, executable string, arguments []string, beforeStart func() error, stdout io.Writer) error {
	key := executable
	if len(arguments) > 0 {
		key = arguments[len(arguments)-1]
	}
	if runner.before != nil {
		runner.before(ctx, key)
	}
	if beforeStart != nil {
		if err := beforeStart(); err != nil {
			return err
		}
	}
	runner.mu.Lock()
	defer runner.mu.Unlock()
	runner.calls = append(runner.calls, runnerCall{executable: executable, arguments: append([]string(nil), arguments...)})
	_, _ = io.WriteString(stdout, runner.outputs[key])
	return runner.errors[key]
}

type fakeUART struct {
	filesystem    *fakeFS
	ready         bool
	baselineReads int
	evidence      []byte
	err           error
}

func (uart *fakeUART) Capture(_ context.Context, _ string, marker []byte, _ int, trigger func() error) ([]byte, error) {
	uart.ready = true
	uart.baselineReads = uart.filesystem.readCount()
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

type fakePrompter struct {
	clock   *fakeClock
	mu      sync.Mutex
	prompts []operatorprompt.Prompt
	errors  map[operatorprompt.Kind]error
	before  func(operatorprompt.Prompt)
}

func (prompter *fakePrompter) Present(_ context.Context, prompt operatorprompt.Prompt) (operatorprompt.Acknowledgement, error) {
	prompter.mu.Lock()
	prompter.prompts = append(prompter.prompts, prompt)
	err := prompter.errors[prompt.Kind]
	prompter.mu.Unlock()
	if prompter.before != nil {
		prompter.before(prompt)
	}
	if err != nil {
		return operatorprompt.Acknowledgement{}, err
	}
	return operatorprompt.Acknowledgement{
		SchemaVersion: operatorprompt.AcknowledgementSchemaVersion,
		PromptID:      prompt.ID, PromptDigest: prompt.Digest,
		Peer:           laneguard.OperatorPeer{UID: 1000, GID: 1000, PID: 2000},
		AcknowledgedAt: prompter.clock.Now(),
	}, nil
}

func (prompter *fakePrompter) kinds() []operatorprompt.Kind {
	prompter.mu.Lock()
	defer prompter.mu.Unlock()
	result := make([]operatorprompt.Kind, len(prompter.prompts))
	for index, prompt := range prompter.prompts {
		result[index] = prompt.Kind
	}
	return result
}

type recordingJournal struct {
	store                 *laneguard.MemoryStore
	mu                    sync.Mutex
	failStatus            laneguard.BootTransitionStatus
	failed                bool
	persistThenFailStatus laneguard.BootTransitionStatus
	persistThenFailed     bool
	normalize             func(laneguard.BootTransition) (laneguard.BootTransition, error)
}

func (journal *recordingJournal) Get(key string) (laneguard.Attempt, bool, error) {
	return journal.store.Get(key)
}

func (journal *recordingJournal) Put(attempt laneguard.Attempt) error {
	return journal.store.Put(attempt)
}

func (journal *recordingJournal) BeginBootTransition(request laneguard.BeginBootTransitionRequest) (laneguard.BootTransition, error) {
	return journal.store.BeginBootTransition(request)
}

func (journal *recordingJournal) GetBootTransition(key string) (laneguard.BootTransition, bool, error) {
	return journal.store.GetBootTransition(key)
}

func (journal *recordingJournal) PutBootTransition(transition laneguard.BootTransition) error {
	journal.mu.Lock()
	if !journal.failed && journal.failStatus != "" && transition.Status == journal.failStatus {
		journal.failed = true
		journal.mu.Unlock()
		return errors.New("injected journal write failure")
	}
	normalize := journal.normalize
	persistThenFail := !journal.persistThenFailed && journal.persistThenFailStatus != "" &&
		transition.Status == journal.persistThenFailStatus
	if persistThenFail {
		journal.persistThenFailed = true
	}
	journal.mu.Unlock()
	if normalize != nil {
		var err error
		transition, err = normalize(transition)
		if err != nil {
			return err
		}
	}
	if err := journal.store.PutBootTransition(transition); err != nil {
		return err
	}
	if persistThenFail {
		return errors.New("injected post-persistence journal failure")
	}
	return nil
}

func (journal *recordingJournal) IncompleteBootTransitions() ([]laneguard.BootTransition, error) {
	return journal.store.IncompleteBootTransitions()
}

func (journal *recordingJournal) HasQuarantinedBootTransition() (bool, error) {
	return journal.store.HasQuarantinedBootTransition()
}

type testEnvironment struct {
	adapter    *Adapter
	runner     *fakeRunner
	filesystem *fakeFS
	gpio       *fakeGPIO
	uart       *fakeUART
	sleeper    *fakeSleeper
	journal    *recordingJournal
	prompter   *fakePrompter
	clock      *fakeClock
	lane       laneguard.Config
}

func TestRPIBootTransitionPersistsBeforePromptsAndReturnsJournalOutcome(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	environment.gpio.on = func() {
		incomplete, err := environment.journal.IncompleteBootTransitions()
		if err != nil || len(incomplete) != 1 || incomplete[0].Status != laneguard.BootTransitionOperatorAcknowledged {
			t.Errorf("power applied before durable acknowledgement: %#v, %v", incomplete, err)
		}
		environment.filesystem.set(exactTarget())
	}
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	environment.prompter.before = func(prompt operatorprompt.Prompt) {
		incomplete, err := environment.journal.IncompleteBootTransitions()
		if err != nil || len(incomplete) != 1 {
			t.Errorf("prompt without one durable transition: %#v, %v", incomplete, err)
			return
		}
		want := laneguard.BootTransitionAwaitingOperator
		if prompt.Kind == operatorprompt.KindReleaseBOOTSEL {
			want = laneguard.BootTransitionModeObserved
		}
		if incomplete[0].Status != want || incomplete[0].PromptDigest == "" {
			t.Errorf("prompt %s durable status = %s", prompt.Kind, incomplete[0].Status)
		}
	}
	environment.runner.before = func(_ context.Context, _ string) {
		incomplete, _ := environment.journal.IncompleteBootTransitions()
		if len(incomplete) != 1 || incomplete[0].Status != laneguard.BootTransitionOperatorReleased {
			t.Errorf("payload ran before durable BOOTSEL release: %#v", incomplete)
		}
	}

	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err != nil {
		t.Fatal(err)
	}
	if observation.State.SecurityState != "fresh" || observation.TargetFingerprint != expectedFingerprint {
		t.Fatalf("observation = %#v", observation)
	}
	if got := environment.prompter.kinds(); fmt.Sprint(got) != fmt.Sprint([]operatorprompt.Kind{operatorprompt.KindHoldBOOTSEL, operatorprompt.KindReleaseBOOTSEL}) {
		t.Fatalf("prompt order = %v", got)
	}
	assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
	acquired, released, powered := environment.gpio.state()
	if acquired != 1 || released != 1 || powered {
		t.Fatalf("relay state acquired=%d released=%d powered=%t", acquired, released, powered)
	}
}

func TestRPIBootReadbackReportsEEPROMHashAvailability(t *testing.T) {
	t.Run("fresh metadata omits EEPROM hash", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.runner.outputs[environment.adapter.config.Paths.FreshReadbackBundle] =
			metadataWithoutEEPROM(zeroCustomerKey, false, expectedSerial)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }

		observation, err := environment.adapter.Observe(
			context.Background(),
			environment.lane,
			testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM),
		)
		if err != nil {
			t.Fatal(err)
		}
		if observation.State.EEPROMHashStatus != laneguard.EEPROMHashUnavailable || observation.State.EEPROMHash != "" {
			t.Fatalf("fresh omitted EEPROM state = %#v, want unavailable with an empty hash", observation.State)
		}
		if strings.HasPrefix(observation.State.EEPROMHash, "sha256:") {
			t.Fatalf("fresh omitted EEPROM hash was synthesized: %q", observation.State.EEPROMHash)
		}
	})

	t.Run("fresh metadata observes EEPROM hash", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }

		observation, err := environment.adapter.Observe(
			context.Background(),
			environment.lane,
			testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM),
		)
		if err != nil {
			t.Fatal(err)
		}
		if observation.State.EEPROMHashStatus != laneguard.EEPROMHashObserved || observation.State.EEPROMHash != "sha256:"+strings.Repeat("f", 64) {
			t.Fatalf("fresh observed EEPROM state = %#v", observation.State)
		}
	})

	t.Run("owned metadata omits EEPROM hash", func(t *testing.T) {
		environment := newEnvironment(t, ModeOwned)
		environment.runner.outputs[environment.adapter.config.Paths.OwnedReadbackBundle] =
			metadataWithoutEEPROM(expectedKey, false, expectedSerial)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }

		result, err := environment.adapter.Execute(
			context.Background(),
			environment.lane,
			testAction(laneguard.HardwarePhaseExecute, laneguard.OperationOwnedReadback),
		)
		if err != nil {
			t.Fatalf("owned omitted EEPROM readback: %v", err)
		}
		if result.BootTransition.Reference.Status != laneguard.BootTransitionCompleted {
			t.Fatalf("owned omitted EEPROM outcome = %#v", result.BootTransition.Reference)
		}
		if environment.adapter.directState.EEPROMHashStatus != laneguard.EEPROMHashUnavailable ||
			environment.adapter.directState.EEPROMHash != "" {
			t.Fatalf("owned omitted EEPROM state = %#v", environment.adapter.directState)
		}
	})
}

func TestUnavailableMetadataCommitCanReachSignedColdBoot(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.runner.outputs[environment.adapter.config.Paths.FreshReadbackBundle] =
		metadataWithoutEEPROM(zeroCustomerKey, false, expectedSerial)
	environment.runner.outputs[environment.adapter.config.Paths.OwnedReadbackBundle] =
		metadataWithoutEEPROM(expectedKey, false, expectedSerial)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }

	preCommit, err := environment.adapter.Observe(
		context.Background(), environment.lane,
		testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM),
	)
	if err != nil || preCommit.State.EEPROMHashStatus != laneguard.EEPROMHashUnavailable {
		t.Fatalf("fresh pre-observation = %#v, %v", preCommit, err)
	}
	commit, err := environment.adapter.Execute(
		context.Background(), environment.lane,
		testAction(laneguard.HardwarePhaseExecute, laneguard.OperationProgramCustomerKeyAndEEPROM),
	)
	if err != nil || commit.CommitAttestation.IsZero() {
		t.Fatalf("fresh commit = %#v, %v", commit, err)
	}
	postCommit, err := environment.adapter.Observe(
		context.Background(), environment.lane,
		testAction(laneguard.HardwarePhasePostObservation, laneguard.OperationProgramCustomerKeyAndEEPROM),
	)
	if err != nil || postCommit.State.CustomerKeyHash != "sha256:"+expectedKey ||
		postCommit.State.EEPROMHashStatus != laneguard.EEPROMHashUnavailable {
		t.Fatalf("owned post-commit observation = %#v, %v", postCommit, err)
	}

	preBoot, err := environment.adapter.Observe(
		context.Background(), environment.lane,
		testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationColdPowerCycle),
	)
	if err != nil || preBoot.State.EEPROMHashStatus != laneguard.EEPROMHashUnavailable {
		t.Fatalf("signed-boot pre-observation = %#v, %v", preBoot, err)
	}
	environment.gpio.on = func() { environment.filesystem.set(map[string][2]string{}) }
	boot, err := environment.adapter.Execute(
		context.Background(), environment.lane,
		testAction(laneguard.HardwarePhaseExecute, laneguard.OperationColdPowerCycle),
	)
	if err != nil || boot.BootTransition.Reference.Status != laneguard.BootTransitionCompleted {
		t.Fatalf("signed cold boot = %#v, %v", boot, err)
	}
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	postBoot, err := environment.adapter.Observe(
		context.Background(), environment.lane,
		testAction(laneguard.HardwarePhasePostObservation, laneguard.OperationColdPowerCycle),
	)
	if err != nil || postBoot.State.EEPROMHashStatus != laneguard.EEPROMHashUnavailable {
		t.Fatalf("signed-boot post-observation = %#v, %v", postBoot, err)
	}
}

func TestNormalTransitionArmsUARTAndWatcherBeforePower(t *testing.T) {
	environment := newEnvironment(t, ModeOwned)
	target := targetObservation()
	environment.adapter.target = &target
	environment.adapter.directState = directState(targetObservation(), "powered_off")
	action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationColdPowerCycle)
	environment.gpio.on = func() {
		if !environment.uart.ready {
			t.Error("power applied before UART was opened/configured/flushed")
		}
		if environment.filesystem.readCount() <= environment.uart.baselineReads {
			t.Error("power applied before the BCM2712 watcher completed its arming poll")
		}
	}
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }

	result, err := environment.adapter.Execute(context.Background(), environment.lane, action)
	if err != nil {
		t.Fatal(err)
	}
	if got := environment.prompter.kinds(); fmt.Sprint(got) != fmt.Sprint([]operatorprompt.Kind{operatorprompt.KindNormalNoAction}) {
		t.Fatalf("normal prompt sequence = %v", got)
	}
	outcome := result.BootTransition
	if outcome.Evidence.ObservedMode != laneguard.BootModeNormal || outcome.Evidence.RPIBootEligibleTargets != 0 ||
		outcome.Evidence.RPIBootNotObservedThrough.Before(outcome.Evidence.ModeObservedAt) || outcome.Evidence.UARTOutputDigest == "" {
		t.Fatalf("normal evidence = %#v", outcome.Evidence)
	}
	assertOutcomeEqualsJournal(t, environment.journal, outcome, action)
}

func TestWrongBootModeFailsClosedInBothDirections(t *testing.T) {
	t.Run("RPIBOOT requested but absent", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.gpio.on = func() {}
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
		observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
		if err == nil || observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureWrongMode {
			t.Fatalf("wrong RPIBOOT direction = %#v, %v", observation.BootTransition, err)
		}
		assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
	})
	t.Run("normal requested but RPIBOOT appears", func(t *testing.T) {
		environment := newEnvironment(t, ModeOwned)
		target := targetObservation()
		environment.adapter.target = &target
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationColdPowerCycle)
		result, err := environment.adapter.Execute(context.Background(), environment.lane, action)
		if err == nil || result.BootTransition.Reference.Failure != laneguard.BootTransitionFailureWrongMode {
			t.Fatalf("wrong normal direction = %#v, %v", result.BootTransition, err)
		}
		assertOutcomeEqualsJournal(t, environment.journal, result.BootTransition, action)
	})
}

func TestOperatorTimeoutAndRejectionAreDurableSafeAborts(t *testing.T) {
	for _, test := range []struct {
		name    string
		err     error
		failure laneguard.BootTransitionFailure
	}{
		{name: "timeout", err: operatorprompt.ErrPromptExpired, failure: laneguard.BootTransitionFailureOperatorTimeout},
		{name: "rejected", err: errors.New("operator rejected prompt"), failure: laneguard.BootTransitionFailureOperatorRejected},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newEnvironment(t, ModeFresh)
			environment.prompter.errors[operatorprompt.KindHoldBOOTSEL] = test.err
			action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
			observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
			if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff ||
				observation.BootTransition.Reference.Failure != test.failure {
				t.Fatalf("terminal outcome = %#v, %v", observation.BootTransition, err)
			}
			acquired, _, powered := environment.gpio.state()
			if acquired != 0 || powered {
				t.Fatalf("operator failure applied power: acquired=%d powered=%t", acquired, powered)
			}
			assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
		})
	}
}

func TestReleasePromptRejectionReleasesPowerAndPersistsAbort(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	environment.prompter.errors[operatorprompt.KindReleaseBOOTSEL] = errors.New("release rejected")
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff ||
		observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureOperatorRejected {
		t.Fatalf("release rejection = %#v, %v", observation.BootTransition, err)
	}
	acquired, released, powered := environment.gpio.state()
	if acquired != 1 || released != 1 || powered {
		t.Fatalf("release rejection relay acquired=%d released=%d powered=%t", acquired, released, powered)
	}
	assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
}

func TestReleaseRecheckRejectsExtraOrMovedTargets(t *testing.T) {
	for _, test := range []struct {
		name    string
		devices map[string][2]string
	}{
		{name: "extra", devices: map[string][2]string{"1-1": {broadcomVendorID, bcm2712ProductID}, "1-2": {broadcomVendorID, bcm2712ProductID}}},
		{name: "moved", devices: map[string][2]string{"1-2": {broadcomVendorID, bcm2712ProductID}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newEnvironment(t, ModeFresh)
			environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
			environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
			environment.prompter.before = func(prompt operatorprompt.Prompt) {
				if prompt.Kind == operatorprompt.KindReleaseBOOTSEL {
					environment.filesystem.set(test.devices)
				}
			}
			action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
			observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
			if err == nil || observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureTargetContinuity {
				t.Fatalf("target recheck = %#v, %v", observation.BootTransition, err)
			}
		})
	}
}

func TestMetadataReplacementReturnsDurableContinuityFailure(t *testing.T) {
	environment := newEnvironment(t, ModeOwned)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	environment.runner.outputs[environment.adapter.config.Paths.OwnedReadbackBundle] = metadata(expectedKey, expectedEEPROM, false, "A7EB274D")
	action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationOwnedReadback)
	result, err := environment.adapter.Execute(context.Background(), environment.lane, action)
	if err == nil || result.BootTransition.Reference.Failure != laneguard.BootTransitionFailureTargetContinuity {
		t.Fatalf("replacement outcome = %#v, %v", result.BootTransition, err)
	}
	assertOutcomeEqualsJournal(t, environment.journal, result.BootTransition, action)
}

func TestCancellationAfterPowerUsesWithoutCancelCleanup(t *testing.T) {
	environment := newEnvironment(t, ModeOwned)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	ctx, cancel := context.WithCancel(context.Background())
	environment.runner.before = func(context.Context, string) { cancel() }
	environment.runner.errors[environment.adapter.config.Paths.OwnedReadbackBundle] = context.Canceled
	action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationOwnedReadback)
	result, err := environment.adapter.Execute(ctx, environment.lane, action)
	if err == nil || result.BootTransition.Reference.Status != laneguard.BootTransitionInterruptedSafeOff ||
		result.BootTransition.Reference.Failure != laneguard.BootTransitionFailureInterrupted {
		t.Fatalf("cancellation outcome = %#v, %v", result.BootTransition, err)
	}
	_, released, powered := environment.gpio.state()
	if released != 1 || powered {
		t.Fatalf("cancellation cleanup released=%d powered=%t", released, powered)
	}
	assertOutcomeEqualsJournal(t, environment.journal, result.BootTransition, action)
}

func TestUnprovenSafeOffQuarantinesLane(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() {} // Simulate a target that remains present after relay release.
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionQuarantined ||
		observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureSafeOffUnproven {
		t.Fatalf("safe-off failure = %#v, %v", observation.BootTransition, err)
	}
	_, released, powered := environment.gpio.state()
	if released != 1 || powered {
		t.Fatalf("quarantine relay released=%d powered=%t", released, powered)
	}
	assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
	acquired, _, _ := environment.gpio.state()
	if _, secondErr := environment.adapter.Observe(context.Background(), environment.lane, action); !errors.Is(secondErr, laneguard.ErrQuarantined) {
		t.Fatalf("quarantined adapter accepted another call: %v", secondErr)
	}
	afterAcquire, _, _ := environment.gpio.state()
	if afterAcquire != acquired {
		t.Fatal("quarantined adapter performed new target I/O")
	}
}

func TestDurableQuarantineBlocksRestartBeforeActionValidationOrTargetIO(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() {} // Leave USB present so safe-off cannot be proven.
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionQuarantined {
		t.Fatalf("initial quarantine = %#v, %v", observation.BootTransition, err)
	}

	restartFS := &fakeFS{devices: map[string][2]string{}}
	restartGPIO := &fakeGPIO{}
	restartRunner := &fakeRunner{outputs: map[string]string{}, errors: map[string]error{}}
	restartPrompter := &fakePrompter{clock: environment.clock, errors: map[operatorprompt.Kind]error{}}
	restarted, err := New(testConfigWithMode(ModeFresh), Dependencies{
		Runner: restartRunner, FS: restartFS, GPIO: restartGPIO, UART: &fakeUART{filesystem: restartFS},
		Sleeper: &fakeSleeper{clock: environment.clock, pollInterval: time.Millisecond},
		Journal: environment.journal, Prompter: restartPrompter, Clock: environment.clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	// The deliberately invalid action proves quarantine is enforced after lane
	// binding/recovery but before action validation in the new process.
	if _, err := restarted.Observe(context.Background(), environment.lane, laneguard.HardwareAction{}); !errors.Is(err, laneguard.ErrQuarantined) {
		t.Fatalf("restarted adapter error = %v, want durable quarantine", err)
	}
	if restartFS.readCount() != 0 || len(restartPrompter.kinds()) != 0 {
		t.Fatalf("durable quarantine performed target I/O: reads=%d prompts=%v", restartFS.readCount(), restartPrompter.kinds())
	}
	acquired, _, powered := restartGPIO.state()
	if acquired != 0 || powered {
		t.Fatalf("durable quarantine acquired relay: acquired=%d powered=%t", acquired, powered)
	}
	restartRunner.mu.Lock()
	runnerCalls := len(restartRunner.calls)
	restartRunner.mu.Unlock()
	if runnerCalls != 0 {
		t.Fatalf("durable quarantine dispatched %d payloads", runnerCalls)
	}
}

func TestRelayReleaseErrorQuarantinesEvenWhenUSBDisappears(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	environment.gpio.releaseErr = errors.New("relay release acknowledgement failed")
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionQuarantined ||
		observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureSafeOffUnproven {
		t.Fatalf("relay release failure = %#v, %v", observation.BootTransition, err)
	}
	assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
}

func TestSafeOffRequiresFixedSysfsNodeDisappearance(t *testing.T) {
	for _, test := range []struct {
		name      string
		backpower func(*fakeFS)
	}{
		{
			name: "same node re-enumerates with another identity",
			backpower: func(filesystem *fakeFS) {
				filesystem.replace("1-1", [2]string{"1234", "5678"})
			},
		},
		{
			name: "fixed node attribute read fails",
			backpower: func(filesystem *fakeFS) {
				filesystem.failRead("/sys/bus/usb/devices/1-1/idVendor", errors.New("injected sysfs read failure"))
			},
		},
		{
			name: "fixed node disappears but another eligible target remains",
			backpower: func(filesystem *fakeFS) {
				filesystem.set(map[string][2]string{"1-2": {broadcomVendorID, bcm2712ProductID}})
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			environment := newEnvironment(t, ModeFresh)
			environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
			environment.gpio.off = func() { test.backpower(environment.filesystem) }
			action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
			observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
			if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionQuarantined ||
				observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureSafeOffUnproven {
				t.Fatalf("safe-off topology outcome = %#v, %v", observation.BootTransition, err)
			}
			assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
		})
	}
}

func TestRestartRecoveryTerminalizesOldPromptBeforeNewIO(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	old := seedIncompleteTransition(t, environment, action)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }

	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err != nil {
		t.Fatal(err)
	}
	recovered, exists, err := environment.journal.GetBootTransition(old.Key)
	if err != nil || !exists || recovered.Status != laneguard.BootTransitionInterruptedSafeOff || recovered.Failure != laneguard.BootTransitionFailureInterrupted {
		t.Fatalf("recovered transition = %#v, %t, %v", recovered, exists, err)
	}
	if observation.BootTransition.Generation != old.Generation+1 {
		t.Fatalf("new generation = %d, old = %d", observation.BootTransition.Generation, old.Generation)
	}
	if got := environment.prompter.kinds(); len(got) != 2 {
		t.Fatalf("old prompt was replayed: %v", got)
	}
}

func TestJournalFailureTerminalizationPreservesLocalProgress(t *testing.T) {
	for _, test := range []struct {
		status      laneguard.BootTransitionStatus
		wantMode    bool
		wantRelease bool
	}{
		{status: laneguard.BootTransitionPowerApplied},
		{status: laneguard.BootTransitionModeObserved, wantMode: true},
		{status: laneguard.BootTransitionOperatorReleased, wantMode: true, wantRelease: true},
	} {
		t.Run(string(test.status), func(t *testing.T) {
			environment := newEnvironment(t, ModeFresh)
			environment.journal.failStatus = test.status
			environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
			environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
			action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
			observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
			if err == nil || observation.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff {
				t.Fatalf("journal failure outcome = %#v, %v", observation.BootTransition, err)
			}
			stored, exists, readErr := environment.journal.GetBootTransition(observation.BootTransition.Reference.TransitionKey)
			if readErr != nil || !exists || stored.PowerAppliedAt.IsZero() || stored.ModeObservedAt.IsZero() != !test.wantMode ||
				stored.OperatorReleasedAt.IsZero() != !test.wantRelease {
				t.Fatalf("preserved durable progress = %#v, exists=%t err=%v", stored, exists, readErr)
			}
			assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
			acquired, released, powered := environment.gpio.state()
			if acquired != 1 || released != 1 || powered {
				t.Fatalf("journal failure relay acquired=%d released=%d powered=%t", acquired, released, powered)
			}
		})
	}
}

func TestTerminalWriteFailureLeavesIncompleteRecordForRestart(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.journal.failStatus = laneguard.BootTransitionAbortedSafeOff
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	environment.runner.errors[environment.adapter.config.Paths.FreshReadbackBundle] = errors.New("injected payload failure")
	action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
	if err == nil || observation.BootTransition != (laneguard.BootTransitionOutcome{}) {
		t.Fatalf("failed terminal write returned an outcome = %#v, %v", observation.BootTransition, err)
	}
	incomplete, readErr := environment.journal.IncompleteBootTransitions()
	if readErr != nil || len(incomplete) != 1 || incomplete[0].Status != laneguard.BootTransitionOperatorReleased {
		t.Fatalf("incomplete durable prefix = %#v, %v", incomplete, readErr)
	}
}

func TestConfigAndDependenciesFailClosed(t *testing.T) {
	config := testConfig()
	config.ExpectedBootImageDigest = strings.TrimPrefix(expectedBoot, "sha256:")
	if _, err := New(config, Dependencies{}); err == nil || !strings.Contains(err.Error(), "canonical sha256:") {
		t.Fatalf("unprefixed boot digest error = %v", err)
	}
	config = testConfig()
	if _, err := New(config, Dependencies{Prompter: &fakePrompter{}}); err == nil || !strings.Contains(err.Error(), "journal") {
		t.Fatalf("missing journal error = %v", err)
	}
	if _, err := New(config, Dependencies{Journal: laneguard.NewMemoryStore()}); err == nil || !strings.Contains(err.Error(), "prompter") {
		t.Fatalf("missing prompter error = %v", err)
	}
}

func TestBootEvidenceValidationRemainsStrict(t *testing.T) {
	for _, test := range []struct {
		name   string
		signed string
		digest string
	}{
		{name: "valid", signed: "00000008", digest: expectedBoot},
		{name: "wrong digest", signed: "00000008", digest: "sha256:" + strings.Repeat("c", 64)},
		{name: "unprefixed digest", signed: "00000008", digest: strings.Repeat("b", 64)},
		{name: "OTP bit clear", signed: "00000000", digest: expectedBoot},
	} {
		err := validateSignedBootEvidence([]byte(signedEvidence(test.signed, test.digest)), expectedBoot)
		if (test.name == "valid") != (err == nil) {
			t.Fatalf("%s error = %v", test.name, err)
		}
	}
}

func TestImmutablePayloadSemanticsRemainFailClosed(t *testing.T) {
	t.Run("authoritative commit metadata resolves late command error", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		environment.runner.errors[environment.adapter.config.Paths.FreshCommitBundle] = errors.New("late USB close error")
		action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationProgramCustomerKeyAndEEPROM)
		result, err := environment.adapter.Execute(context.Background(), environment.lane, action)
		wantAttestation := laneguard.CommitAttestation{
			SchemaVersion:             laneguard.CommitAttestationSchemaVersion,
			TargetFingerprint:         expectedFingerprint,
			CustomerKeyHash:           "sha256:" + expectedKey,
			EEPROMHash:                "sha256:" + expectedEEPROM,
			EEPROMUpdateResult:        "success",
			SecureBootProvisionResult: "success",
		}
		if err != nil || result.OutputDigest == "" || environment.adapter.mode != ModeOwned || result.CommitAttestation != wantAttestation {
			t.Fatalf("commit result = %#v, mode=%s, error=%v", result, environment.adapter.mode, err)
		}
		assertOutcomeEqualsJournal(t, environment.journal, result.BootTransition, action)
	})
	t.Run("commit metadata omission never creates an attestation", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		environment.runner.outputs[environment.adapter.config.Paths.FreshCommitBundle] =
			metadataWithoutEEPROM(expectedKey, true, expectedSerial)
		action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationProgramCustomerKeyAndEEPROM)
		result, err := environment.adapter.Execute(context.Background(), environment.lane, action)
		if !errors.Is(err, ErrMetadataMismatch) || !result.CommitAttestation.IsZero() || environment.adapter.mode != ModeFresh {
			t.Fatalf("incomplete commit metadata result = %#v, mode=%s, error=%v", result, environment.adapter.mode, err)
		}
	})
	t.Run("bounded RPIBOOT output", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		environment.adapter.config.MaximumOutputBytes = 1024
		environment.runner.outputs[environment.adapter.config.Paths.FreshReadbackBundle] = strings.Repeat("x", 1025)
		action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
		observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
		if err == nil || !strings.Contains(err.Error(), "exceeds") || observation.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff {
			t.Fatalf("bounded output outcome = %#v, %v", observation.BootTransition, err)
		}
	})
	t.Run("negative UART marker must be an exact record", func(t *testing.T) {
		environment := newEnvironment(t, ModeOwned)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		environment.uart.evidence = []byte("prefix " + negativeBootProof + " suffix\n")
		action := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationTestNegativeBoot)
		result, err := environment.adapter.Execute(context.Background(), environment.lane, action)
		if !errors.Is(err, ErrUARTTestEvidence) || result.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff {
			t.Fatalf("non-exact marker outcome = %#v, %v", result.BootTransition, err)
		}
	})
}

func TestFreshCommitPreflightRejectsSamePathReplacementBeforeMutation(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	preAction := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	if _, err := environment.adapter.Observe(context.Background(), environment.lane, preAction); err != nil {
		t.Fatalf("establish pre-observation: %v", err)
	}

	environment.runner.mu.Lock()
	environment.runner.calls = nil
	environment.runner.outputs[environment.adapter.config.Paths.FreshReadbackBundle] = metadata(zeroCustomerKey, strings.Repeat("f", 64), false, "A7EB274D")
	environment.runner.mu.Unlock()
	executeAction := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationProgramCustomerKeyAndEEPROM)
	result, err := environment.adapter.Execute(context.Background(), environment.lane, executeAction)
	if !errors.Is(err, laneguard.ErrTargetContinuity) || result.BootTransition.Reference.Failure != laneguard.BootTransitionFailureTargetContinuity {
		t.Fatalf("replacement preflight outcome = %#v, %v", result.BootTransition, err)
	}
	if environment.adapter.mode != ModeFresh || environment.adapter.target == nil || environment.adapter.target.TargetFingerprint != expectedFingerprint {
		t.Fatalf("replacement preflight mutated cached identity: mode=%s target=%#v", environment.adapter.mode, environment.adapter.target)
	}
	environment.runner.mu.Lock()
	defer environment.runner.mu.Unlock()
	for _, call := range environment.runner.calls {
		if len(call.arguments) > 0 && call.arguments[len(call.arguments)-1] == environment.adapter.config.Paths.FreshCommitBundle {
			t.Fatalf("fresh commit runner was called after replacement preflight: %#v", environment.runner.calls)
		}
	}
}

func TestFreshCommitPinnedInstanceRejectsSwapAfterPreflightBeforeRunnerStart(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	preAction := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	if _, err := environment.adapter.Observe(context.Background(), environment.lane, preAction); err != nil {
		t.Fatalf("establish pre-observation: %v", err)
	}

	environment.runner.mu.Lock()
	environment.runner.calls = nil
	environment.runner.mu.Unlock()
	environment.runner.before = func(_ context.Context, bundle string) {
		if bundle == environment.adapter.config.Paths.FreshCommitBundle {
			// Preserve the path and VID/PID while replacing the underlying
			// sysfs device instance after preflight has completed.
			environment.filesystem.replace("1-1", [2]string{broadcomVendorID, bcm2712ProductID})
		}
	}
	executeAction := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationProgramCustomerKeyAndEEPROM)
	result, err := environment.adapter.Execute(context.Background(), environment.lane, executeAction)
	if !errors.Is(err, laneguard.ErrTargetContinuity) || result.BootTransition.Reference.Failure != laneguard.BootTransitionFailureTargetContinuity {
		t.Fatalf("post-preflight swap outcome = %#v, %v", result.BootTransition, err)
	}
	if environment.adapter.mode != ModeFresh || environment.adapter.target == nil || environment.adapter.target.TargetFingerprint != expectedFingerprint {
		t.Fatalf("post-preflight swap mutated cached identity: mode=%s target=%#v", environment.adapter.mode, environment.adapter.target)
	}
	environment.runner.mu.Lock()
	defer environment.runner.mu.Unlock()
	for _, call := range environment.runner.calls {
		if len(call.arguments) > 0 && call.arguments[len(call.arguments)-1] == environment.adapter.config.Paths.FreshCommitBundle {
			t.Fatalf("fresh commit process started after pinned-instance replacement: %#v", environment.runner.calls)
		}
	}
}

func TestFreshCommitIdentityPreflightOutputIsBoundedBeforeMutation(t *testing.T) {
	environment := newEnvironment(t, ModeFresh)
	environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
	environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
	preAction := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
	if _, err := environment.adapter.Observe(context.Background(), environment.lane, preAction); err != nil {
		t.Fatalf("establish pre-observation: %v", err)
	}

	environment.adapter.config.MaximumOutputBytes = 1024
	environment.runner.mu.Lock()
	environment.runner.calls = nil
	environment.runner.outputs[environment.adapter.config.Paths.FreshReadbackBundle] = strings.Repeat("x", 1025)
	environment.runner.mu.Unlock()
	executeAction := testAction(laneguard.HardwarePhaseExecute, laneguard.OperationProgramCustomerKeyAndEEPROM)
	result, err := environment.adapter.Execute(context.Background(), environment.lane, executeAction)
	if err == nil || !strings.Contains(err.Error(), "identity preflight") || !strings.Contains(err.Error(), "exceeds 1024 bytes") ||
		result.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff {
		t.Fatalf("bounded preflight outcome = %#v, %v", result.BootTransition, err)
	}
	environment.runner.mu.Lock()
	defer environment.runner.mu.Unlock()
	for _, call := range environment.runner.calls {
		if len(call.arguments) > 0 && call.arguments[len(call.arguments)-1] == environment.adapter.config.Paths.FreshCommitBundle {
			t.Fatalf("fresh commit runner was called after oversized preflight: %#v", environment.runner.calls)
		}
	}
}

func TestReturnedOutcomeIsDerivedFromReloadedDurableRecord(t *testing.T) {
	t.Run("terminal persisted before write error", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.journal.persistThenFailStatus = laneguard.BootTransitionAbortedSafeOff
		environment.prompter.errors[operatorprompt.KindHoldBOOTSEL] = errors.New("operator rejected")
		action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
		observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
		if err == nil || !strings.Contains(err.Error(), "post-persistence journal failure") ||
			observation.BootTransition.Reference.Status != laneguard.BootTransitionAbortedSafeOff {
			t.Fatalf("post-persistence terminal outcome = %#v, %v", observation.BootTransition, err)
		}
		assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
	})

	t.Run("safe terminal normalization", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.journal.normalize = func(transition laneguard.BootTransition) (laneguard.BootTransition, error) {
			if transition.Status == laneguard.BootTransitionAbortedSafeOff {
				transition.Failure = laneguard.BootTransitionFailureHardware
			}
			return transition, nil
		}
		environment.prompter.errors[operatorprompt.KindHoldBOOTSEL] = errors.New("operator rejected")
		action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
		observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
		if err == nil || observation.BootTransition.Reference.Failure != laneguard.BootTransitionFailureHardware {
			t.Fatalf("normalized terminal outcome = %#v, %v", observation.BootTransition, err)
		}
		assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
	})

	t.Run("completed normalization", func(t *testing.T) {
		environment := newEnvironment(t, ModeFresh)
		environment.gpio.on = func() { environment.filesystem.set(exactTarget()) }
		environment.gpio.off = func() { environment.filesystem.set(map[string][2]string{}) }
		environment.journal.normalize = func(transition laneguard.BootTransition) (laneguard.BootTransition, error) {
			if transition.Status != laneguard.BootTransitionCompleted {
				return transition, nil
			}
			transition.CompletedAt = transition.CompletedAt.Add(time.Second)
			transition.UpdatedAt = transition.CompletedAt
			evidence, err := transition.Evidence()
			if err != nil {
				return laneguard.BootTransition{}, err
			}
			transition.EvidenceDigest, err = evidence.Digest()
			return transition, err
		}
		action := testAction(laneguard.HardwarePhasePreObservation, laneguard.OperationProgramCustomerKeyAndEEPROM)
		observation, err := environment.adapter.Observe(context.Background(), environment.lane, action)
		if err != nil {
			t.Fatal(err)
		}
		if !observation.BootTransition.Evidence.CompletedAt.After(observation.BootTransition.Evidence.SafeOffObservedAt) {
			t.Fatalf("completed normalization was not returned: %#v", observation.BootTransition.Evidence)
		}
		assertOutcomeEqualsJournal(t, environment.journal, observation.BootTransition, action)
	})
}

func newEnvironment(t *testing.T, mode string) *testEnvironment {
	t.Helper()
	clock := &fakeClock{now: time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)}
	filesystem := &fakeFS{devices: map[string][2]string{}}
	runner := &fakeRunner{outputs: map[string]string{
		"/immutable/fresh-readback": metadata(zeroCustomerKey, strings.Repeat("f", 64), false, expectedSerial),
		"/immutable/fresh-commit":   metadata(expectedKey, expectedEEPROM, true, expectedSerial),
		"/immutable/owned-readback": metadata(expectedKey, expectedEEPROM, false, expectedSerial),
		"/immutable/owned-recovery": metadata(expectedKey, expectedEEPROM, false, expectedSerial),
	}, errors: make(map[string]error)}
	gpio := &fakeGPIO{}
	uart := &fakeUART{filesystem: filesystem}
	sleeper := &fakeSleeper{clock: clock, pollInterval: time.Millisecond}
	journal := &recordingJournal{store: laneguard.NewMemoryStore()}
	prompter := &fakePrompter{clock: clock, errors: make(map[operatorprompt.Kind]error)}
	adapter, err := New(testConfigWithMode(mode), Dependencies{
		Runner: runner, FS: filesystem, GPIO: gpio, UART: uart, Sleeper: sleeper,
		Journal: journal, Prompter: prompter, Clock: clock,
	})
	if err != nil {
		t.Fatal(err)
	}
	lane := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: "station-1", LaneID: "lane-1",
		RPIBootSysfsPath: "/sys/bus/usb/devices/1-1", UARTPath: "/dev/serial/by-id/kaiba-uart",
		PowerGPIO: laneguard.GPIODescriptor{ChipPath: "/dev/gpiochip0", Offset: 17}, LeaseSafetyMargin: time.Second,
	}
	return &testEnvironment{
		adapter: adapter, runner: runner, filesystem: filesystem, gpio: gpio, uart: uart,
		sleeper: sleeper, journal: journal, prompter: prompter, clock: clock, lane: lane,
	}
}

func testConfig() Config { return testConfigWithMode(ModeFresh) }

func testConfigWithMode(mode string) Config {
	return Config{
		Paths: ImmutablePaths{
			RPIBootBinary: "/immutable/rpiboot", GPIOSetBinary: "/immutable/gpioset",
			FreshReadbackBundle: "/immutable/fresh-readback", FreshCommitBundle: "/immutable/fresh-commit",
			OwnedReadbackBundle: "/immutable/owned-readback", OwnedRecoveryBundle: "/immutable/owned-recovery",
			NegativeBootBundle: "/immutable/negative", RootIntegrityBundle: "/immutable/root-integrity",
		},
		InitialMode: mode, ExpectedCustomerKeyHash: expectedKey, ExpectedEEPROMHash: expectedEEPROM,
		ExpectedBootImageDigest: expectedBoot, CommandTimeout: 20 * time.Millisecond, UARTTimeout: 20 * time.Millisecond,
		USBDisappearTimeout: 10 * time.Millisecond, USBReappearTimeout: 10 * time.Millisecond,
		USBPollInterval: time.Millisecond, MinimumColdInterval: 5 * time.Millisecond,
		OperatorPromptTimeout: time.Minute, CleanupTimeout: 20 * time.Millisecond, MaximumOutputBytes: 4096,
	}
}

func testAction(phase laneguard.HardwarePhase, operation laneguard.Operation) laneguard.HardwareAction {
	required, _ := laneguard.RequiredBootModeForOperation(operation)
	requested := required
	if phase != laneguard.HardwarePhaseExecute {
		requested = laneguard.BootModeRPIBoot
	}
	action := laneguard.HardwareAction{
		SchemaVersion: laneguard.BootTransitionActionSchemaVersion,
		StationID:     "station-1", LaneID: "lane-1", TransactionID: "transaction-1",
		PlanDigest: testDigest("a"), TargetFingerprint: expectedFingerprint, FenceEpoch: 1,
		ApprovalID: "approval-1", IntentReceipt: "intent-1", IntentSequence: 1, Sequence: 1,
		Operation: operation, OperationDigest: testDigest("b"), AuthorizationID: "authorization-1",
		Phase: phase, OperationRequiredBootMode: required, RequestedBootMode: requested,
	}
	if phase == laneguard.HardwarePhaseReconciliation {
		action.ReconciliationClaimID = "claim-1"
		action.ReconciliationFenceEpoch = 2
	}
	return action
}

func seedIncompleteTransition(t *testing.T, environment *testEnvironment, action laneguard.HardwareAction) laneguard.BootTransition {
	t.Helper()
	started := environment.clock.Now().Add(-10 * time.Second)
	prompt, err := operatorprompt.New(action, operatorprompt.KindHoldBOOTSEL, "old-hold-prompt", holdBOOTSELInstructions, environment.clock.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	transition, err := environment.journal.BeginBootTransition(laneguard.BeginBootTransitionRequest{
		Action: action, StartedAt: started, PowerOffObservedAt: started.Add(time.Second),
		USBAbsentObservedAt: started.Add(2 * time.Second), ColdIntervalEndsAt: started.Add(3 * time.Second),
		RecordedAt: started.Add(2 * time.Second), PromptID: prompt.ID, PromptDigest: prompt.Digest, PromptExpiresAt: prompt.ExpiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return transition
}

func assertOutcomeEqualsJournal(t *testing.T, journal laneguard.Journal, outcome laneguard.BootTransitionOutcome, action laneguard.HardwareAction) {
	t.Helper()
	if err := outcome.ValidateForAction(action); err != nil {
		t.Fatalf("outcome validation: %v", err)
	}
	stored, exists, err := journal.GetBootTransition(outcome.Reference.TransitionKey)
	if err != nil || !exists {
		t.Fatalf("read outcome transition: exists=%t err=%v", exists, err)
	}
	durable, err := stored.Outcome()
	if err != nil || durable != outcome {
		t.Fatalf("returned outcome differs from journal:\nreturned %#v\ndurable %#v\nerror %v", outcome, durable, err)
	}
}

func exactTarget() map[string][2]string {
	return map[string][2]string{"1-1": {broadcomVendorID, bcm2712ProductID}}
}

func targetObservation() rpi5.Observation {
	return rpi5.Observation{TargetFingerprint: expectedFingerprint, CustomerKeyHash: expectedKey, EEPROMHash: expectedEEPROM}
}

func metadata(customerKey, eeprom string, commit bool, serial string) string {
	operationFields := ""
	if commit {
		operationFields = `,"EEPROM_UPDATE":"success","SECURE_BOOT_PROVISION":"success"`
	}
	return fmt.Sprintf(`{"USER_SERIAL_NUM":%q,"MAC_ADDR":"2C:CF:67:70:76:F3","EEPROM_HASH":%q,"CUSTOMER_KEY_HASH":%q,"BOOT_ROM":"0000000A","BOARD_ATTR":"00000000","USER_BOARDREV":"B04170","JTAG_LOCKED":"0","SIGNATURE_MODE":"0","MAC_WIFI_ADDR":"2C:CF:67:70:76:F4","MAC_BT_ADDR":"2C:CF:67:70:76:F5","FACTORY_UUID":"001000911006186073"%s}`, serial, eeprom, customerKey, operationFields)
}

func metadataWithoutEEPROM(customerKey string, commit bool, serial string) string {
	withEEPROM := metadata(customerKey, expectedEEPROM, commit, serial)
	return strings.Replace(withEEPROM, `,"EEPROM_HASH":"`+expectedEEPROM+`"`, "", 1)
}

func signedEvidence(signed, digest string) string {
	return "KAIBA_SECURE_BOOT_EVIDENCE=pass signed=" + signed + " boot_img_sha256=" + digest +
		" root=/dev/mapper/root rollback=unimplemented enrollment_ready=false\n"
}

func testDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
