package laneguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"syscall"
	"time"
)

type AttemptStatus string

const (
	maximumLaneJournalBytes = 8 * 1024 * 1024

	AttemptSchemaVersion      = "provisioning.kaiba.network/lane-guard-attempt/v1alpha2"
	AttemptStoreSchemaVersion = "provisioning.kaiba.network/lane-guard-attempt-store/v1alpha3"

	AttemptStarted             AttemptStatus = "started"
	AttemptUncertain           AttemptStatus = "uncertain"
	AttemptVerified            AttemptStatus = "verified"
	AttemptConfirmedNotApplied AttemptStatus = "confirmed_not_applied"
	AttemptQuarantined         AttemptStatus = "quarantined"
)

// Attempt is the durable execute-once record. Started is persisted before the
// hardware call, so a restart can only observe/reconcile that call, never
// repeat it.
type Attempt struct {
	SchemaVersion             string                `json:"schema_version"`
	Key                       string                `json:"key"`
	TransactionID             string                `json:"transaction_id"`
	PlanDigest                string                `json:"plan_digest"`
	TargetFingerprint         string                `json:"target_fingerprint"`
	FenceEpoch                uint64                `json:"fence_epoch"`
	ApprovalID                string                `json:"approval_id"`
	IntentReceipt             string                `json:"intent_receipt"`
	IntentSequence            uint32                `json:"intent_sequence"`
	Sequence                  uint32                `json:"sequence"`
	Operation                 Operation             `json:"operation"`
	OperationDigest           string                `json:"operation_digest"`
	Status                    AttemptStatus         `json:"status"`
	StartedAt                 time.Time             `json:"started_at"`
	UpdatedAt                 time.Time             `json:"updated_at"`
	Result                    OperationResult       `json:"result"`
	ObservedState             DirectState           `json:"observed_state"`
	PreObservationTransition  BootTransitionOutcome `json:"pre_observation_transition"`
	ExecutionTransition       BootTransitionOutcome `json:"execution_transition"`
	PostObservationTransition BootTransitionOutcome `json:"post_observation_transition"`
	ReconciliationTransition  BootTransitionOutcome `json:"reconciliation_transition"`
	Detail                    string                `json:"detail"`
}

type AttemptStore interface {
	Get(key string) (Attempt, bool, error)
	Put(Attempt) error
}

// BootTransitionStore persists the separate pre-execution operator and
// physical-mode state machine. IncompleteBootTransitions is the restart
// primitive: callers must first restore and prove fail-off, terminalize each
// returned record, and must never resume its old prompt or acknowledgment.
type BootTransitionStore interface {
	BeginBootTransition(BeginBootTransitionRequest) (BootTransition, error)
	GetBootTransition(key string) (BootTransition, bool, error)
	PutBootTransition(BootTransition) error
	IncompleteBootTransitions() ([]BootTransition, error)
}

type Journal interface {
	AttemptStore
	BootTransitionStore
}

type journalState struct {
	Attempts        map[string]Attempt        `json:"attempts"`
	BootTransitions map[string]BootTransition `json:"boot_transitions"`
}

func newJournalState() journalState {
	return journalState{
		Attempts:        make(map[string]Attempt),
		BootTransitions: make(map[string]BootTransition),
	}
}

type MemoryStore struct {
	mu              sync.Mutex
	attempts        map[string]Attempt
	bootTransitions map[string]BootTransition
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		attempts:        make(map[string]Attempt),
		bootTransitions: make(map[string]BootTransition),
	}
}

func (store *MemoryStore) Get(key string) (Attempt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	attempt, ok := store.attempts[key]
	return attempt, ok, nil
}

func (store *MemoryStore) Put(attempt Attempt) error {
	if err := validateAttempt(attempt); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := validateAttemptJournalBindings(attempt, store.bootTransitions); err != nil {
		return err
	}
	if existing, ok := store.attempts[attempt.Key]; ok {
		if err := validAttemptTransition(existing, attempt); err != nil {
			return err
		}
	} else if attempt.Status != AttemptStarted {
		return errors.New("a new attempt must begin with a durable started record")
	}
	store.attempts[attempt.Key] = attempt
	return nil
}

func (store *MemoryStore) GetBootTransition(key string) (BootTransition, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	transition, ok := store.bootTransitions[key]
	return transition, ok, nil
}

func (store *MemoryStore) BeginBootTransition(request BeginBootTransitionRequest) (BootTransition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	transition, err := beginBootTransition(store.bootTransitions, request)
	if err != nil {
		return BootTransition{}, err
	}
	store.bootTransitions[transition.Key] = transition
	return transition, nil
}

func (store *MemoryStore) PutBootTransition(transition BootTransition) error {
	if err := transition.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, ok := store.bootTransitions[transition.Key]; ok {
		if err := validBootTransitionUpdate(existing, transition); err != nil {
			return err
		}
	} else {
		return ErrBootTransitionNotBegun
	}
	store.bootTransitions[transition.Key] = transition
	return nil
}

func (store *MemoryStore) IncompleteBootTransitions() ([]BootTransition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return incompleteBootTransitions(store.bootTransitions), nil
}

// FileStore is a small crash-safe reference store for one guard process. It
// holds an exclusive nonblocking lock on a stable sibling lock file for its
// lifetime, while atomically replacing and fsyncing the secret-free JSON
// journal on every state transition.
type FileStore struct {
	mu       sync.Mutex
	path     string
	lockPath string
	lockFile *os.File
}

func NewFileStore(path string) (*FileStore, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("attempt journal path must be a clean absolute path")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create lane journal directory: %w", err)
	}
	lockPath := path + ".lock"
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open stable lane journal lock: %w", err)
	}
	closeLock := true
	defer func() {
		if closeLock {
			_ = lockFile.Close()
		}
	}()
	info, err := lockFile.Stat()
	stat, statOK := fileStat(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !statOK || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("lane journal lock must be an owner-only regular non-symlink file")
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return nil, fmt.Errorf("lane journal is already owned by another guard: %w", err)
	}
	closeLock = false
	return &FileStore{path: path, lockPath: lockPath, lockFile: lockFile}, nil
}

func (store *FileStore) Close() error {
	store.mu.Lock()
	defer store.mu.Unlock()
	if store.lockFile == nil {
		return nil
	}
	lockFile := store.lockFile
	store.lockFile = nil
	unlockErr := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_UN)
	closeErr := lockFile.Close()
	return errors.Join(unlockErr, closeErr)
}

func (store *FileStore) requireOpen() error {
	if store.lockFile == nil {
		return errors.New("lane journal is closed")
	}
	return nil
}

func (store *FileStore) Get(key string) (Attempt, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireOpen(); err != nil {
		return Attempt{}, false, err
	}
	state, err := store.load()
	if err != nil {
		return Attempt{}, false, err
	}
	attempt, ok := state.Attempts[key]
	return attempt, ok, nil
}

func (store *FileStore) Put(attempt Attempt) error {
	if err := validateAttempt(attempt); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireOpen(); err != nil {
		return err
	}
	state, err := store.load()
	if err != nil {
		return err
	}
	if err := validateAttemptJournalBindings(attempt, state.BootTransitions); err != nil {
		return err
	}
	if existing, ok := state.Attempts[attempt.Key]; ok {
		if err := validAttemptTransition(existing, attempt); err != nil {
			return err
		}
	} else if attempt.Status != AttemptStarted {
		return errors.New("a new attempt must begin with a durable started record")
	}
	state.Attempts[attempt.Key] = attempt
	return store.save(state)
}

func (store *FileStore) GetBootTransition(key string) (BootTransition, bool, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireOpen(); err != nil {
		return BootTransition{}, false, err
	}
	state, err := store.load()
	if err != nil {
		return BootTransition{}, false, err
	}
	transition, ok := state.BootTransitions[key]
	return transition, ok, nil
}

func (store *FileStore) BeginBootTransition(request BeginBootTransitionRequest) (BootTransition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireOpen(); err != nil {
		return BootTransition{}, err
	}
	state, err := store.load()
	if err != nil {
		return BootTransition{}, err
	}
	transition, err := beginBootTransition(state.BootTransitions, request)
	if err != nil {
		return BootTransition{}, err
	}
	state.BootTransitions[transition.Key] = transition
	if err := store.save(state); err != nil {
		return BootTransition{}, err
	}
	return transition, nil
}

func (store *FileStore) PutBootTransition(transition BootTransition) error {
	if err := transition.Validate(); err != nil {
		return err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireOpen(); err != nil {
		return err
	}
	state, err := store.load()
	if err != nil {
		return err
	}
	if existing, ok := state.BootTransitions[transition.Key]; ok {
		if err := validBootTransitionUpdate(existing, transition); err != nil {
			return err
		}
	} else {
		return ErrBootTransitionNotBegun
	}
	state.BootTransitions[transition.Key] = transition
	return store.save(state)
}

func (store *FileStore) IncompleteBootTransitions() ([]BootTransition, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.requireOpen(); err != nil {
		return nil, err
	}
	state, err := store.load()
	if err != nil {
		return nil, err
	}
	return incompleteBootTransitions(state.BootTransitions), nil
}

func (store *FileStore) load() (journalState, error) {
	file, err := os.OpenFile(store.path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return newJournalState(), nil
	}
	if err != nil {
		return journalState{}, fmt.Errorf("open regular non-symlink lane journal: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	stat, statOK := fileStat(info)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || !statOK || stat.Uid != uint32(os.Geteuid()) {
		return journalState{}, errors.New("lane journal must be an owner-only owned regular non-symlink file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximumLaneJournalBytes+1))
	if err != nil {
		return journalState{}, fmt.Errorf("read lane journal: %w", err)
	}
	if len(data) > maximumLaneJournalBytes {
		return journalState{}, errors.New("lane journal exceeds its fixed size limit")
	}
	if err := rejectDuplicateJournalJSON(data); err != nil {
		return journalState{}, fmt.Errorf("decode lane journal: %w", err)
	}
	var envelope struct {
		SchemaVersion   string                    `json:"schema_version"`
		Attempts        map[string]Attempt        `json:"attempts"`
		BootTransitions map[string]BootTransition `json:"boot_transitions"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return journalState{}, fmt.Errorf("decode lane journal: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return journalState{}, errors.New("lane journal contains trailing data")
	}
	if envelope.SchemaVersion != AttemptStoreSchemaVersion || envelope.Attempts == nil || envelope.BootTransitions == nil {
		return journalState{}, errors.New("lane journal has an unsupported schema or missing records")
	}
	for key, attempt := range envelope.Attempts {
		if key != attempt.Key {
			return journalState{}, errors.New("attempt journal key does not match its record")
		}
		if err := validateAttempt(attempt); err != nil {
			return journalState{}, fmt.Errorf("invalid attempt journal record: %w", err)
		}
	}
	for key, transition := range envelope.BootTransitions {
		if key != transition.Key {
			return journalState{}, errors.New("boot-transition journal key does not match its record")
		}
		if err := transition.Validate(); err != nil {
			return journalState{}, fmt.Errorf("invalid boot-transition journal record: %w", err)
		}
	}
	for _, attempt := range envelope.Attempts {
		if err := validateAttemptJournalBindings(attempt, envelope.BootTransitions); err != nil {
			return journalState{}, fmt.Errorf("invalid attempt boot-transition binding: %w", err)
		}
	}
	return journalState{Attempts: envelope.Attempts, BootTransitions: envelope.BootTransitions}, nil
}

func (store *FileStore) save(state journalState) error {
	directory := filepath.Dir(store.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create attempt journal directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".lane-guard-attempts-*")
	if err != nil {
		return fmt.Errorf("create temporary attempt journal: %w", err)
	}
	temporaryPath := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryPath)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect temporary attempt journal: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		SchemaVersion   string                    `json:"schema_version"`
		Attempts        map[string]Attempt        `json:"attempts"`
		BootTransitions map[string]BootTransition `json:"boot_transitions"`
	}{AttemptStoreSchemaVersion, state.Attempts, state.BootTransitions}); err != nil {
		return fmt.Errorf("encode lane journal: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync attempt journal: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close attempt journal: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("replace attempt journal: %w", err)
	}
	removeTemporary = false
	directoryHandle, err := os.Open(directory)
	if err != nil {
		return fmt.Errorf("open attempt journal directory: %w", err)
	}
	defer directoryHandle.Close()
	if err := directoryHandle.Sync(); err != nil {
		return fmt.Errorf("sync attempt journal directory: %w", err)
	}
	return nil
}

func incompleteBootTransitions(transitions map[string]BootTransition) []BootTransition {
	incomplete := make([]BootTransition, 0)
	for _, transition := range transitions {
		if !transition.IsTerminal() {
			incomplete = append(incomplete, transition)
		}
	}
	sort.Slice(incomplete, func(left, right int) bool {
		return incomplete[left].Key < incomplete[right].Key
	})
	return incomplete
}

func fileStat(info os.FileInfo) (*syscall.Stat_t, bool) {
	if info == nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

func rejectDuplicateJournalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := rejectDuplicateJournalValue(decoder, token, "$"); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("lane journal contains trailing data")
		}
		return err
	}
	return nil
}

func rejectDuplicateJournalValue(decoder *json.Decoder, token json.Token, path string) error {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("lane journal object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("%s contains duplicate key %q", path, key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := rejectDuplicateJournalValue(decoder, value, path+"."+key); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	case '[':
		for index := 0; decoder.More(); index++ {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := rejectDuplicateJournalValue(decoder, value, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return errors.New("lane journal contains an unexpected JSON delimiter")
	}
}

func beginBootTransition(transitions map[string]BootTransition, request BeginBootTransitionRequest) (BootTransition, error) {
	if err := request.Action.Validate(); err != nil {
		return BootTransition{}, err
	}
	var maximumGeneration uint64
	for _, existing := range transitions {
		if !sameBootTransitionScope(existing.Action, request.Action) {
			continue
		}
		if !existing.IsTerminal() {
			return BootTransition{}, ErrBootTransitionOpen
		}
		if existing.Generation > maximumGeneration {
			maximumGeneration = existing.Generation
		}
	}
	if maximumGeneration == ^uint64(0) {
		return BootTransition{}, errors.New("boot transition generation is exhausted")
	}
	return request.transition(maximumGeneration + 1)
}

func sameBootTransitionScope(left, right HardwareAction) bool {
	return left.StationID == right.StationID && left.LaneID == right.LaneID &&
		left.TransactionID == right.TransactionID && left.PlanDigest == right.PlanDigest &&
		left.TargetFingerprint == right.TargetFingerprint && left.FenceEpoch == right.FenceEpoch &&
		left.Sequence == right.Sequence && left.Operation == right.Operation && left.Phase == right.Phase
}

func validateAttempt(attempt Attempt) error {
	if attempt.SchemaVersion != AttemptSchemaVersion {
		return fmt.Errorf("unsupported attempt schema %q", attempt.SchemaVersion)
	}
	if attempt.Key == "" || attempt.TransactionID == "" || attempt.PlanDigest == "" || attempt.TargetFingerprint == "" || attempt.FenceEpoch == 0 || attempt.ApprovalID == "" || attempt.IntentReceipt == "" || attempt.IntentSequence == 0 || attempt.IntentSequence != attempt.Sequence || attempt.Sequence == 0 || attempt.OperationDigest == "" {
		return errors.New("attempt is missing required immutable bindings")
	}
	if attempt.Key != fmt.Sprintf("%s/%s/%d/%d", attempt.TransactionID, attempt.PlanDigest, attempt.FenceEpoch, attempt.Sequence) {
		return errors.New("attempt key does not match its immutable bindings")
	}
	if _, allowed := operationClass(attempt.Operation); !allowed {
		return errors.New("attempt contains an unknown operation")
	}
	switch attempt.Status {
	case AttemptStarted, AttemptUncertain, AttemptVerified, AttemptConfirmedNotApplied, AttemptQuarantined:
	default:
		return errors.New("attempt has an invalid status")
	}
	if attempt.StartedAt.IsZero() || attempt.UpdatedAt.IsZero() {
		return errors.New("attempt is missing timestamps")
	}
	if err := validateAttemptBootTransitionOutcomes(attempt); err != nil {
		return err
	}
	return nil
}

func validateAttemptBootTransitionOutcomes(attempt Attempt) error {
	pre := attempt.PreObservationTransition
	if pre == (BootTransitionOutcome{}) || pre.Reference.Status != BootTransitionCompleted {
		return errors.New("attempt requires a completed pre-observation boot transition")
	}
	if !attemptMatchesHardwareAction(attempt, pre.Action) || pre.Action.Phase != HardwarePhasePreObservation ||
		pre.Action.RequestedBootMode != BootModeRPIBoot {
		return errors.New("attempt pre-observation transition does not match its immutable bindings")
	}
	if err := pre.ValidateForAction(pre.Action); err != nil {
		return fmt.Errorf("attempt pre-observation transition: %w", err)
	}

	validatePhase := func(name string, outcome BootTransitionOutcome, phase HardwarePhase) error {
		if outcome == (BootTransitionOutcome{}) {
			return nil
		}
		expected := pre.Action
		expected.Phase = phase
		expected.RequestedBootMode = BootModeRPIBoot
		expected.ReconciliationClaimID = ""
		expected.ReconciliationFenceEpoch = 0
		if phase == HardwarePhaseExecute {
			expected.RequestedBootMode = expected.OperationRequiredBootMode
		}
		if phase == HardwarePhaseReconciliation {
			expected.StationID = outcome.Action.StationID
			expected.LaneID = outcome.Action.LaneID
			expected.ReconciliationClaimID = outcome.Action.ReconciliationClaimID
			expected.ReconciliationFenceEpoch = outcome.Action.ReconciliationFenceEpoch
		}
		if err := outcome.ValidateForAction(expected); err != nil {
			return fmt.Errorf("attempt %s transition: %w", name, err)
		}
		return nil
	}
	if err := validatePhase("execution", attempt.ExecutionTransition, HardwarePhaseExecute); err != nil {
		return err
	}
	if err := validatePhase("post-observation", attempt.PostObservationTransition, HardwarePhasePostObservation); err != nil {
		return err
	}
	if err := validatePhase("reconciliation", attempt.ReconciliationTransition, HardwarePhaseReconciliation); err != nil {
		return err
	}
	if attempt.PostObservationTransition != (BootTransitionOutcome{}) &&
		(attempt.ExecutionTransition == (BootTransitionOutcome{}) || attempt.ExecutionTransition.Reference.Status != BootTransitionCompleted) {
		return errors.New("attempt cannot contain a post-observation transition without completed execution")
	}
	if attempt.Result != (OperationResult{}) {
		if attempt.ExecutionTransition.Reference.Status != BootTransitionCompleted || attempt.Result.BootTransition != attempt.ExecutionTransition {
			return errors.New("attempt result does not match its completed execution transition")
		}
	} else if attempt.ExecutionTransition.Reference.Status == BootTransitionCompleted {
		return errors.New("attempt completed execution transition requires its operation result")
	}
	return nil
}

func attemptMatchesHardwareAction(attempt Attempt, action HardwareAction) bool {
	return action.TransactionID == attempt.TransactionID && action.PlanDigest == attempt.PlanDigest &&
		action.TargetFingerprint == attempt.TargetFingerprint && action.FenceEpoch == attempt.FenceEpoch &&
		action.ApprovalID == attempt.ApprovalID && action.IntentReceipt == attempt.IntentReceipt &&
		action.IntentSequence == attempt.IntentSequence && action.Sequence == attempt.Sequence &&
		action.Operation == attempt.Operation && action.OperationDigest == attempt.OperationDigest
}

func validateAttemptJournalBindings(attempt Attempt, transitions map[string]BootTransition) error {
	for _, outcome := range []BootTransitionOutcome{
		attempt.PreObservationTransition,
		attempt.ExecutionTransition,
		attempt.PostObservationTransition,
		attempt.ReconciliationTransition,
	} {
		if outcome == (BootTransitionOutcome{}) {
			continue
		}
		transition, found := transitions[outcome.Reference.TransitionKey]
		if !found {
			return errors.New("attempt references a missing durable boot transition")
		}
		durable, err := transition.Outcome()
		if err != nil {
			return fmt.Errorf("attempt references an invalid durable boot transition: %w", err)
		}
		if durable != outcome {
			return errors.New("attempt boot-transition outcome differs from its durable record")
		}
	}
	return nil
}

func validAttemptTransition(existing, next Attempt) error {
	if existing.Key != next.Key || existing.TransactionID != next.TransactionID || existing.PlanDigest != next.PlanDigest || existing.TargetFingerprint != next.TargetFingerprint || existing.FenceEpoch != next.FenceEpoch || existing.ApprovalID != next.ApprovalID || existing.IntentReceipt != next.IntentReceipt || existing.IntentSequence != next.IntentSequence || existing.Sequence != next.Sequence || existing.Operation != next.Operation || existing.OperationDigest != next.OperationDigest || existing.StartedAt != next.StartedAt {
		return errors.New("attempt immutable bindings cannot change")
	}
	if existing.Status == AttemptVerified || existing.Status == AttemptConfirmedNotApplied || existing.Status == AttemptQuarantined {
		if existing != next {
			return errors.New("terminal attempt record cannot change")
		}
		return nil
	}
	if existing.Status == AttemptUncertain && next.Status == AttemptStarted {
		return errors.New("an uncertain attempt cannot return to started")
	}
	if existing.PreObservationTransition != next.PreObservationTransition ||
		(existing.ExecutionTransition != (BootTransitionOutcome{}) && existing.ExecutionTransition != next.ExecutionTransition) ||
		(existing.PostObservationTransition != (BootTransitionOutcome{}) && existing.PostObservationTransition != next.PostObservationTransition) ||
		(existing.Result != (OperationResult{}) && existing.Result != next.Result) {
		return errors.New("attempt recorded hardware evidence cannot change")
	}
	return nil
}
