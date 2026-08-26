package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/authoritybridge"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/evidencefile"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/operatorprompt"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/physicalrpi5"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebindingmanifest"
)

type commandHardware struct {
	journal      laneguard.Journal
	observation  laneguard.Observation
	observations int
	executions   int
	transitions  int
	closed       int
	closeErr     error
	executeErr   error
	poststate    laneguard.DirectState
}

func (hardware *commandHardware) Observe(_ context.Context, config laneguard.Config, action laneguard.HardwareAction) (laneguard.Observation, error) {
	hardware.observations++
	hardware.transitions++
	outcome, err := recordCommandBootTransition(hardware.journal, config, action, hardware.transitions, false)
	observation := hardware.observation
	observation.BootTransition = outcome
	return observation, err
}

func (hardware *commandHardware) Execute(_ context.Context, config laneguard.Config, action laneguard.HardwareAction) (laneguard.OperationResult, error) {
	hardware.executions++
	hardware.transitions++
	hardware.observation.State = hardware.poststate
	outcome, transitionErr := recordCommandBootTransition(hardware.journal, config, action, hardware.transitions, hardware.executeErr != nil)
	return laneguard.OperationResult{
		OutputDigest: commandDigest("f"), Detail: "fake physical execution", BootTransition: outcome,
	}, errors.Join(hardware.executeErr, transitionErr)
}

func (hardware *commandHardware) Close() error {
	hardware.closed++
	return hardware.closeErr
}

type commandPromptServer struct {
	closed   int
	closeErr error
}

type commandJournal struct {
	*laneguard.MemoryStore
	closeCalls        int
	failTerminalWrite error
}

func (journal *commandJournal) Put(attempt laneguard.Attempt) error {
	if journal.failTerminalWrite != nil && attempt.Status != laneguard.AttemptStarted {
		return journal.failTerminalWrite
	}
	return journal.MemoryStore.Put(attempt)
}

func (journal *commandJournal) Close() error {
	journal.closeCalls++
	return nil
}

type seededCommandJournal struct {
	*laneguard.MemoryStore
	attempt    laneguard.Attempt
	closeCalls int
}

func (journal *seededCommandJournal) Get(key string) (laneguard.Attempt, bool, error) {
	if key == journal.attempt.Key {
		return journal.attempt, true, nil
	}
	return laneguard.Attempt{}, false, nil
}

func (journal *seededCommandJournal) Close() error {
	journal.closeCalls++
	return nil
}

func (*commandPromptServer) Present(context.Context, operatorprompt.Prompt) (operatorprompt.Acknowledgement, error) {
	return operatorprompt.Acknowledgement{}, errors.New("fake hardware must not call the operator server")
}

func (server *commandPromptServer) Close() error {
	server.closed++
	return server.closeErr
}

func TestDisabledCommandValidatesLaneWithoutMutationInputs(t *testing.T) {
	restoreCommandGlobals(t)
	lookupOperatorGroup = func(string) (*user.Group, error) {
		t.Fatal("disabled command resolved an operator group")
		return nil, nil
	}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) {
		t.Fatal("disabled command created an operator prompt socket")
		return nil, nil
	}
	validateAttemptDestination = func(string) error {
		t.Fatal("disabled command validated an attempt destination")
		return nil
	}
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("disabled command constructed hardware")
		return nil, nil
	}
	if err := run(context.Background(), nil); err != nil {
		t.Fatalf("disabled run: %v", err)
	}
}

func TestImmutableReleaseBindingUsesEveryLinkerValue(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	binding, err := immutableReleaseBinding()
	if err != nil {
		t.Fatal(err)
	}
	if binding != commandReleaseBinding() {
		t.Fatalf("immutable release binding = %#v", binding)
	}
}

func TestEnabledCommandRequiresRootAndImmutableBuildPaths(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 1000 }
	if err := run(context.Background(), []string{"--enable-mutations"}); err == nil || !strings.Contains(err.Error(), "requires root") {
		t.Fatalf("non-root error = %v", err)
	}

	effectiveUID = func() int { return 0 }
	if err := run(context.Background(), []string{"--enable-mutations"}); err == nil || !strings.Contains(err.Error(), "operator-socket") {
		t.Fatalf("missing operator integration flags error = %v", err)
	}
	plan, _ := commandPlanAndRequest()
	directory := t.TempDir()
	draftPath := writeJSON(t, directory, "draft.json", commandDraft(plan))
	err := run(context.Background(), commandMutationArguments(t, directory, draftPath, filepath.Join(directory, "journal.json")))
	if err == nil || !strings.Contains(err.Error(), "immutable") || !strings.Contains(err.Error(), "path") {
		t.Fatalf("missing immutable-path error = %v", err)
	}
}

func TestOneShotCommandUsesDurableJournalAndExactReceiptRetryAvoidsMutation(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	setImmutableTestGlobals(t)
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	hardware := &commandHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-1",
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		poststate: plan.Operations[0].ExpectedPoststate,
	}
	server := &commandPromptServer{}
	listenOperatorPrompt = func(config operatorprompt.Config) (operatorPromptServer, error) {
		if !filepath.IsAbs(config.SocketPath) || filepath.Base(config.SocketPath) != "operator.sock" || config.AllowedPrimaryGID != 4242 {
			t.Fatalf("operator prompt config = %#v", config)
		}
		return server, nil
	}
	buildHardware = func(config physicalrpi5.Config, dependencies physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		if config.Paths.RPIBootBinary != rpibootBinary || config.Paths.FreshCommitBundle != freshCommitBundle || !config.Paths.RequireNixStorePaths {
			t.Fatalf("physical config = %#v", config)
		}
		if dependencies.Journal == nil || dependencies.Prompter != server {
			t.Fatalf("physical dependencies = %#v", dependencies)
		}
		hardware.journal = dependencies.Journal
		return hardware, nil
	}
	directory := t.TempDir()
	draftPath := writeJSON(t, directory, "draft.json", commandDraft(plan))
	journalPath := filepath.Join(directory, "journal.json")
	var output bytes.Buffer
	commandOutput = &output
	arguments := commandMutationArguments(t, directory, draftPath, journalPath)
	if err := run(context.Background(), arguments); err != nil {
		t.Fatalf("one-shot run: %v", err)
	}
	if hardware.executions != 1 || hardware.closed != 1 || server.closed != 1 {
		t.Fatalf("hardware lifecycle = executions:%d hardware-close:%d prompt-close:%d", hardware.executions, hardware.closed, server.closed)
	}
	store, err := laneguard.NewFileStore(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	key := plan.TransactionID + "/" + plan.PlanDigest + "/1/1"
	attempt, ok, err := store.Get(key)
	if err != nil || !ok || attempt.Status != laneguard.AttemptVerified {
		t.Fatalf("durable attempt = %#v, %t, %v", attempt, ok, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var summary struct {
		Path   string                  `json:"path"`
		Status laneguard.AttemptStatus `json:"status"`
		Key    string                  `json:"key"`
	}
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || summary.Status != attempt.Status || summary.Key != attempt.Key {
		t.Fatalf("attempt summary = %#v, %v; output=%q", summary, err, output.String())
	}
	published, err := os.ReadFile(summary.Path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(summary.Path)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatalf("attempt evidence mode = %v, %v", info, err)
	}
	canonical, err := json.Marshal(attempt)
	if err != nil || !bytes.Equal(published, append(canonical, '\n')) {
		t.Fatalf("canonical attempt evidence mismatch: %v\n%s", err, published)
	}
	output.Reset()
	if err := run(context.Background(), arguments); err != nil {
		t.Fatalf("idempotent receipt retry: %v", err)
	}
	var retrySummary struct {
		Path             string                  `json:"path"`
		Status           laneguard.AttemptStatus `json:"status"`
		Key              string                  `json:"key"`
		AlreadyPublished bool                    `json:"already_published"`
	}
	if err := json.Unmarshal(output.Bytes(), &retrySummary); err != nil || !retrySummary.AlreadyPublished ||
		retrySummary.Path != summary.Path || retrySummary.Status != attempt.Status || retrySummary.Key != attempt.Key {
		t.Fatalf("idempotent retry summary = %#v, %v; output=%q", retrySummary, err, output.String())
	}
	after, err := os.ReadFile(summary.Path)
	if err != nil || !bytes.Equal(after, published) || hardware.executions != 1 || hardware.closed != 1 || server.closed != 1 {
		t.Fatalf("existing evidence changed or resources were reopened: %v executions=%d hardware-close=%d prompt-close=%d",
			err, hardware.executions, hardware.closed, server.closed)
	}

	if err := run(context.Background(), []string{"--rpiboot-binary", "/tmp/evil"}); err == nil {
		t.Fatal("caller-selectable rpiboot path flag was accepted")
	}
	if err := run(context.Background(), []string{"--plan", "/tmp/root-plan.json"}); err == nil {
		t.Fatal("root-supplied executable plan flag was accepted")
	}
	if err := run(context.Background(), []string{"--request", "/tmp/root-request.json"}); err == nil {
		t.Fatal("root-supplied executable request flag was accepted")
	}
}

func TestCommandReconcilesRestartWithModeAutoAndNoRedispatch(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	setImmutableTestGlobals(t)
	plan, executeRequest := commandPlanAndRequest()
	reconcileRequest := laneguard.ReconcileRequest{
		SchemaVersion:   laneguard.ReconcileRequestSchemaVersion,
		OriginalRequest: executeRequest,
		Claim: laneguard.ReconciliationClaim{
			StationID: plan.StationID, LaneID: plan.LaneID,
			TransactionID: plan.TransactionID, TargetFingerprint: plan.TargetFingerprint,
			ClaimID: "reconciliation-claim", FenceEpoch: plan.FenceEpoch + 1,
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		},
	}
	authorityCalls := 0
	requestAuthority = func(_ context.Context, socketPath string, request authoritybridge.BridgeRequest) (authoritybridge.BoundRequest, error) {
		authorityCalls++
		if !filepath.IsAbs(socketPath) || request.SchemaVersion != authoritybridge.RequestSchemaVersion ||
			request.TransactionID != plan.TransactionID || request.DraftSnapshot.PlanDigest != plan.PlanDigest {
			t.Fatalf("authority request = %#v via %q", request, socketPath)
		}
		switch request.Mode {
		case authoritybridge.ModeExecute:
			return authoritybridge.BoundRequest{Plan: plan, ExecuteRequest: &executeRequest}, nil
		case authoritybridge.ModeReconcile:
			return authoritybridge.BoundRequest{Plan: plan, ReconcileRequest: &reconcileRequest}, nil
		default:
			t.Fatalf("authority mode = %q", request.Mode)
			return authoritybridge.BoundRequest{}, nil
		}
	}
	hardware := &commandHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-1",
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		poststate:  plan.Operations[0].ExpectedPoststate,
		executeErr: errors.New("response lost after target commit"),
	}
	var adapterModes []string
	buildHardware = func(config physicalrpi5.Config, dependencies physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		adapterModes = append(adapterModes, config.InitialMode)
		hardware.journal = dependencies.Journal
		return hardware, nil
	}
	directory := t.TempDir()
	draftPath := writeJSON(t, directory, "draft.json", commandDraft(plan))
	journalPath := filepath.Join(directory, "journal.json")
	common := commandMutationArguments(t, directory, draftPath, journalPath)
	if err := run(context.Background(), common); !errors.Is(err, laneguard.ErrReconciliationRequired) {
		t.Fatalf("uncertain execution = %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(directory, "attempts"))
	if err != nil || len(entries) != 1 {
		t.Fatalf("uncertain attempt publications = %v, %v", entries, err)
	}
	var uncertain laneguard.Attempt
	data, err := os.ReadFile(filepath.Join(directory, "attempts", entries[0].Name()))
	if err != nil || json.Unmarshal(data, &uncertain) != nil || uncertain.Status != laneguard.AttemptUncertain {
		t.Fatalf("uncertain attempt evidence = %#v, %v", uncertain, err)
	}
	if err := run(context.Background(), append(append([]string(nil), common...), "--mode", "reconcile")); err != nil {
		t.Fatalf("restart reconciliation = %v", err)
	}
	if authorityCalls != 2 || len(adapterModes) != 2 || adapterModes[0] != physicalrpi5.ModeFresh || adapterModes[1] != physicalrpi5.ModeAuto {
		t.Fatalf("dispatch = authority:%d modes:%#v", authorityCalls, adapterModes)
	}
	if hardware.executions != 1 || hardware.observations != 2 {
		t.Fatalf("reconciliation redispatch/double observation: executions=%d observations=%d", hardware.executions, hardware.observations)
	}
	entries, err = os.ReadDir(filepath.Join(directory, "attempts"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("execute and reconciliation publications = %v, %v", entries, err)
	}
}

func TestCommandRejectsMismatchedRequestBeforeConstructingHardware(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	setImmutableTestGlobals(t)
	plan, request := commandPlanAndRequest()
	request.OperationDigest = commandDigest("9")
	stubAuthorityResult(t, plan, request)
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("mismatched request reached hardware construction")
		return nil, nil
	}
	directory := t.TempDir()
	err := run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	))
	if !errors.Is(err, laneguard.ErrPlanMismatch) {
		t.Fatalf("error = %v, want plan mismatch", err)
	}
}

func TestCommandRejectsReleaseThatDiffersFromImmutableBuild(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	setImmutableTestGlobals(t)
	plan, request := commandPlanAndRequest()
	baseDeriver := deriveReleaseMaterial
	deriveReleaseMaterial = func(executable string, paths []releasebindingmanifest.ArtifactPath, expectations releasebindingmanifest.ReleaseExpectations, mode releasebindingmanifest.ValidationMode) (immutableReleaseMaterial, error) {
		material, err := baseDeriver(executable, paths, expectations, mode)
		material.Binding.CompiledArtifactSetDigest = commandDigest("9")
		return material, err
	}
	stubAuthorityResult(t, plan, request)
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("release-binding mismatch reached hardware construction")
		return nil, nil
	}
	directory := t.TempDir()
	err := run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	))
	if !errors.Is(err, laneguard.ErrPlanMismatch) {
		t.Fatalf("error = %v, want plan mismatch", err)
	}
}

func TestCommandRejectsExpiredApprovalBeforeConstructingHardware(t *testing.T) {
	restoreCommandGlobals(t)
	effectiveUID = func() int { return 0 }
	setImmutableTestGlobals(t)
	plan, request := commandPlanAndRequest()
	plan.ApprovalExpiresAt = time.Now().UTC().Add(-time.Minute)
	plan, err := plan.WithDerivedDigests()
	if err != nil {
		t.Fatal(err)
	}
	request.PlanDigest = plan.PlanDigest
	request.ApprovalExpiresAt = plan.ApprovalExpiresAt
	stubAuthorityResult(t, plan, request)
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("expired approval reached hardware construction")
		return nil, nil
	}
	directory := t.TempDir()
	err = run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	))
	if !errors.Is(err, laneguard.ErrApprovalExpired) {
		t.Fatalf("error = %v, want approval expired", err)
	}
}

func TestStrictInputRejectsDuplicateFieldsAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	duplicatePath := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicatePath, []byte(`{"sequence":1,"sequence":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var request laneguard.ExecuteRequest
	if err := loadStrictJSON(duplicatePath, 1024, &request); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate error = %v", err)
	}
	symlinkPath := filepath.Join(directory, "link.json")
	if err := os.Symlink(duplicatePath, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := loadStrictJSON(symlinkPath, 1024, &request); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("symlink error = %v", err)
	}
}

func TestAttemptDestinationIsDigestBoundAndUnsafePathsFailBeforeHardware(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	reconcile := laneguard.ReconcileRequest{
		SchemaVersion: laneguard.ReconcileRequestSchemaVersion, OriginalRequest: request,
		Claim: laneguard.ReconciliationClaim{
			StationID: plan.StationID, LaneID: plan.LaneID, TransactionID: plan.TransactionID,
			TargetFingerprint: plan.TargetFingerprint, ClaimID: "claim-2", FenceEpoch: plan.FenceEpoch + 1,
			ExpiresAt: time.Now().UTC().Add(10 * time.Minute),
		},
	}
	directory := t.TempDir()
	attemptDirectory := filepath.Join(directory, "attempts")
	if err := os.Mkdir(attemptDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	executePath, err := plannedAttemptEvidencePath(attemptDirectory, "execute", request, laneguard.ReconcileRequest{})
	if err != nil {
		t.Fatal(err)
	}
	reconcilePath, err := plannedAttemptEvidencePath(attemptDirectory, "reconcile", laneguard.ExecuteRequest{}, reconcile)
	if err != nil {
		t.Fatal(err)
	}
	if executePath == reconcilePath || filepath.Dir(executePath) != attemptDirectory ||
		!strings.HasPrefix(filepath.Base(executePath), "lane-attempt-") || !strings.HasSuffix(executePath, ".json") {
		t.Fatalf("digest-bound paths = execute:%q reconcile:%q", executePath, reconcilePath)
	}
	if _, err := plannedAttemptEvidencePath("relative", "execute", request, laneguard.ReconcileRequest{}); err == nil {
		t.Fatal("relative attempt directory was accepted")
	}

	stubAuthorityResult(t, plan, request)
	original := []byte("existing immutable evidence")
	if err := os.WriteFile(executePath, original, 0o444); err != nil {
		t.Fatal(err)
	}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) {
		t.Fatal("preexisting attempt destination reached prompt setup")
		return nil, nil
	}
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("preexisting attempt destination reached hardware")
		return nil, nil
	}
	draft := writeJSON(t, directory, "draft.json", commandDraft(plan))
	journal := filepath.Join(directory, "journal.json")
	err = run(context.Background(), commandMutationArguments(t, directory, draft, journal))
	if err == nil || !strings.Contains(err.Error(), "destination") {
		t.Fatalf("pre-mutation destination validation error = %v", err)
	}
	unchanged, readErr := os.ReadFile(executePath)
	if readErr != nil || !bytes.Equal(unchanged, original) {
		t.Fatalf("preexisting attempt evidence changed: %q, %v", unchanged, readErr)
	}
	info, statErr := os.Stat(journal + ".lock")
	if statErr != nil || !info.Mode().IsRegular() {
		t.Fatalf("journal lock created for the required durable preflight is invalid: %v, %v", info, statErr)
	}
}

func TestInvalidOperatorGroupFailsBeforeJournalAndPromptSetup(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	validateAttemptDestination = func(string) error { return nil }
	lookupOperatorGroup = func(string) (*user.Group, error) {
		return &user.Group{Name: "kaiba-operator", Gid: "not-a-gid"}, nil
	}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) {
		t.Fatal("invalid group reached prompt setup")
		return nil, nil
	}
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("invalid group reached hardware")
		return nil, nil
	}
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal.json")
	err := run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), journal,
	))
	if err == nil || !strings.Contains(err.Error(), "invalid numeric GID") {
		t.Fatalf("invalid group error = %v", err)
	}
	if _, statErr := os.Stat(journal + ".lock"); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("journal was opened for invalid group: %v", statErr)
	}
}

func TestAttemptAndOperationErrorsAreJoinedAndResourcesClose(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	executionErr := errors.New("target response lost")
	publicationErr := errors.New("attempt publication failed")
	hardwareCloseErr := errors.New("hardware close failed")
	promptCloseErr := errors.New("prompt close failed")
	hardware := &commandHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-1",
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		poststate: plan.Operations[0].ExpectedPoststate, executeErr: executionErr, closeErr: hardwareCloseErr,
	}
	server := &commandPromptServer{closeErr: promptCloseErr}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) { return server, nil }
	buildHardware = func(_ physicalrpi5.Config, dependencies physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		hardware.journal = dependencies.Journal
		if dependencies.Prompter != server {
			t.Fatalf("prompter dependency = %#v", dependencies.Prompter)
		}
		return hardware, nil
	}
	validateAttemptDestination = func(string) error { return nil }
	var publishedPath string
	var publishedAttempt laneguard.Attempt
	writeAttemptEvidence = func(path string, data []byte) error {
		publishedPath = path
		if decodeErr := json.Unmarshal(data, &publishedAttempt); decodeErr != nil {
			t.Fatalf("decode published uncertain attempt: %v", decodeErr)
		}
		return publicationErr
	}
	directory := t.TempDir()
	journal := filepath.Join(directory, "journal.json")
	err := run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), journal,
	))
	for _, expected := range []error{laneguard.ErrReconciliationRequired, executionErr, publicationErr, hardwareCloseErr, promptCloseErr} {
		if !errors.Is(err, expected) {
			t.Fatalf("combined error %v does not contain %v", err, expected)
		}
	}
	if publishedPath == "" || publishedAttempt.Status != laneguard.AttemptUncertain || hardware.closed != 1 || server.closed != 1 {
		t.Fatalf("publication/close state = path:%q attempt:%#v hardware:%d prompt:%d", publishedPath, publishedAttempt, hardware.closed, server.closed)
	}
	store, openErr := laneguard.NewFileStore(journal)
	if openErr != nil {
		t.Fatalf("lane journal remained locked after errors: %v", openErr)
	}
	if closeErr := store.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
}

func TestTerminalPersistenceFailureNeverPublishesReturnedAttempt(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	persistenceErr := errors.New("terminal attempt persistence failed")
	journal := &commandJournal{
		MemoryStore:       laneguard.NewMemoryStore(),
		failTerminalWrite: persistenceErr,
	}
	openLaneJournal = func(string) (laneJournal, error) { return journal, nil }
	hardware := &commandHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-1",
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		poststate: plan.Operations[0].ExpectedPoststate,
	}
	server := &commandPromptServer{}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) { return server, nil }
	buildHardware = func(_ physicalrpi5.Config, dependencies physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		hardware.journal = dependencies.Journal
		return hardware, nil
	}
	writeAttemptEvidence = func(string, []byte) error {
		t.Fatal("an in-memory terminal attempt was published after its journal write failed")
		return nil
	}
	directory := t.TempDir()
	arguments := commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	)
	err := run(context.Background(), arguments)
	if !errors.Is(err, persistenceErr) || !strings.Contains(err.Error(), "non-terminal status \"started\"") ||
		!strings.Contains(err.Error(), "receipt not published") {
		t.Fatalf("terminal persistence error = %v", err)
	}
	durable, found, getErr := journal.Get(laneguard.AttemptJournalKey(plan, request.Sequence))
	if getErr != nil || !found || durable.Status != laneguard.AttemptStarted {
		t.Fatalf("durable attempt after failed terminal write = %#v, %t, %v", durable, found, getErr)
	}
	entries, readErr := os.ReadDir(filepath.Join(directory, "attempts"))
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("receipt directory after failed terminal write = %v, %v", entries, readErr)
	}
	if hardware.executions != 1 || journal.closeCalls != 1 {
		t.Fatalf("operation/close count = %d/%d", hardware.executions, journal.closeCalls)
	}
}

func TestExistingStartedAttemptDoesNotPublishOrReachHardware(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	journal := &seededCommandJournal{
		MemoryStore: laneguard.NewMemoryStore(),
		attempt:     commandBoundAttempt(plan, request.Sequence, laneguard.AttemptStarted),
	}
	openLaneJournal = func(string) (laneJournal, error) { return journal, nil }
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) {
		t.Fatal("a durable started attempt reached operator prompt setup")
		return nil, nil
	}
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("a durable started attempt reached hardware construction")
		return nil, nil
	}
	writeAttemptEvidence = func(string, []byte) error {
		t.Fatal("a durable started attempt was published")
		return nil
	}
	directory := t.TempDir()
	err := run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	))
	if !errors.Is(err, laneguard.ErrReconciliationRequired) || !strings.Contains(err.Error(), "remains started") ||
		!strings.Contains(err.Error(), "not published") {
		t.Fatalf("started attempt error = %v", err)
	}
	entries, readErr := os.ReadDir(filepath.Join(directory, "attempts"))
	if readErr != nil || len(entries) != 0 || journal.closeCalls != 1 {
		t.Fatalf("started receipt/close state = %v, %v, close=%d", entries, readErr, journal.closeCalls)
	}
}

func TestExistingReceiptMismatchIsRejectedBeforeHardware(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	journal := &seededCommandJournal{
		MemoryStore: laneguard.NewMemoryStore(),
		attempt:     commandBoundAttempt(plan, request.Sequence, laneguard.AttemptVerified),
	}
	openLaneJournal = func(string) (laneJournal, error) { return journal, nil }
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) {
		t.Fatal("mismatched receipt reached operator prompt setup")
		return nil, nil
	}
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("mismatched receipt reached hardware construction")
		return nil, nil
	}
	directory := t.TempDir()
	attemptDirectory := filepath.Join(directory, "attempts")
	if err := os.Mkdir(attemptDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	attemptPath, err := plannedAttemptEvidencePath(attemptDirectory, "execute", request, laneguard.ReconcileRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(attemptPath, []byte("{\"wrong\":true}\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	err = run(context.Background(), commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	))
	if err == nil || !strings.Contains(err.Error(), "differs from the durable journal record") {
		t.Fatalf("mismatched receipt error = %v", err)
	}
	if journal.closeCalls != 1 {
		t.Fatalf("journal close calls = %d", journal.closeCalls)
	}
}

func TestPublicationFailureAfterLinkRetriesWithoutMutation(t *testing.T) {
	restoreCommandGlobals(t)
	setImmutableTestGlobals(t)
	effectiveUID = func() int { return 0 }
	plan, request := commandPlanAndRequest()
	stubAuthorityResult(t, plan, request)
	hardware := &commandHardware{
		observation: laneguard.Observation{
			EligibleTargets: 1, RPIBootSysfsPath: "/sys/bus/usb/devices/1-1",
			TargetFingerprint: plan.TargetFingerprint, State: plan.Operations[0].ExpectedPrestate,
		},
		poststate: plan.Operations[0].ExpectedPoststate,
	}
	server := &commandPromptServer{}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) { return server, nil }
	buildHardware = func(_ physicalrpi5.Config, dependencies physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		hardware.journal = dependencies.Journal
		return hardware, nil
	}
	publicationErr := errors.New("directory fsync result lost")
	writeAttemptEvidence = func(path string, data []byte) error {
		if err := evidencefile.WriteCanonicalNew(path, data); err != nil {
			return err
		}
		return publicationErr
	}
	directory := t.TempDir()
	arguments := commandMutationArguments(
		t, directory, writeJSON(t, directory, "draft.json", commandDraft(plan)), filepath.Join(directory, "journal.json"),
	)
	if err := run(context.Background(), arguments); !errors.Is(err, publicationErr) {
		t.Fatalf("link-complete publication error = %v", err)
	}
	if hardware.executions != 1 {
		t.Fatalf("initial hardware executions = %d", hardware.executions)
	}
	writeAttemptEvidence = func(string, []byte) error {
		t.Fatal("an exact existing receipt was rewritten")
		return nil
	}
	listenOperatorPrompt = func(operatorprompt.Config) (operatorPromptServer, error) {
		t.Fatal("an exact receipt retry reached operator prompt setup")
		return nil, nil
	}
	buildHardware = func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error) {
		t.Fatal("an exact receipt retry reached hardware construction")
		return nil, nil
	}
	var output bytes.Buffer
	commandOutput = &output
	if err := run(context.Background(), arguments); err != nil {
		t.Fatalf("retry after link-complete publication error: %v", err)
	}
	var summary struct {
		AlreadyPublished bool `json:"already_published"`
	}
	if err := json.Unmarshal(output.Bytes(), &summary); err != nil || !summary.AlreadyPublished {
		t.Fatalf("retry summary = %#v, %v; output=%q", summary, err, output.String())
	}
	if hardware.executions != 1 || server.closed != 1 {
		t.Fatalf("retry mutated/reopened resources: executions=%d prompt-close=%d", hardware.executions, server.closed)
	}
}

func commandBoundAttempt(plan laneguard.Plan, sequence uint32, status laneguard.AttemptStatus) laneguard.Attempt {
	operation := plan.Operations[sequence-1]
	now := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC)
	return laneguard.Attempt{
		SchemaVersion: laneguard.AttemptSchemaVersion,
		Key:           laneguard.AttemptJournalKey(plan, sequence),
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest,
		TargetFingerprint: plan.TargetFingerprint, FenceEpoch: plan.FenceEpoch,
		ApprovalID: plan.ApprovalID, IntentReceipt: plan.IntentReceipt, IntentSequence: plan.IntentSequence,
		Sequence: sequence, Operation: operation.Operation, OperationDigest: operation.OperationDigest,
		Status: status, StartedAt: now, UpdatedAt: now,
	}
}

func recordCommandBootTransition(
	journal laneguard.Journal,
	config laneguard.Config,
	action laneguard.HardwareAction,
	ordinal int,
	failed bool,
) (laneguard.BootTransitionOutcome, error) {
	if journal == nil {
		return laneguard.BootTransitionOutcome{}, errors.New("command fake has no shared journal")
	}
	started := time.Date(2026, 8, 15, 10, 0, 0, 0, time.UTC).Add(time.Duration(ordinal) * time.Minute)
	transition, err := journal.BeginBootTransition(laneguard.BeginBootTransitionRequest{
		Action: action, StartedAt: started, RecordedAt: started.Add(2 * time.Second),
		PowerOffObservedAt: started.Add(time.Second), USBAbsentObservedAt: started.Add(2 * time.Second),
		ColdIntervalEndsAt: started.Add(4 * time.Second), PromptID: "hold_prompt",
		PromptDigest: commandDigest("a"), PromptExpiresAt: started.Add(2 * time.Minute),
	})
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	if failed {
		transition.Status = laneguard.BootTransitionAbortedSafeOff
		transition.Failure = laneguard.BootTransitionFailureHardware
		transition.SafeOffObservedAt = started.Add(3 * time.Second)
		transition.UpdatedAt = transition.SafeOffObservedAt
		if err := journal.PutBootTransition(transition); err != nil {
			return laneguard.BootTransitionOutcome{}, err
		}
		return transition.Outcome()
	}
	transition.Status = laneguard.BootTransitionAwaitingOperator
	transition.UpdatedAt = transition.ColdIntervalEndsAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionOperatorAcknowledged
	transition.Operator = laneguard.OperatorPeer{UID: 1000, GID: 4242, PID: int32(2000 + ordinal)}
	transition.OperatorAcknowledgedAt = transition.ColdIntervalEndsAt.Add(time.Second)
	transition.UpdatedAt = transition.OperatorAcknowledgedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionPowerApplied
	transition.PowerAppliedAt = transition.OperatorAcknowledgedAt.Add(time.Second)
	transition.UpdatedAt = transition.PowerAppliedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.Status = laneguard.BootTransitionModeObserved
	transition.ModeObservedAt = transition.PowerAppliedAt.Add(time.Second)
	transition.ObservedMode = action.RequestedBootMode
	transition.RPIBootSysfsPath = config.RPIBootSysfsPath
	transition.RPIBootObservationMethod = laneguard.RPIBootObservationSysfsPoll
	transition.RPIBootPollInterval = 50 * time.Millisecond
	if action.RequestedBootMode == laneguard.BootModeRPIBoot {
		transition.RPIBootEligibleTargets = 1
		transition.ReleasePromptID = "release_prompt"
		transition.ReleasePromptDigest = commandDigest("b")
		transition.ReleasePromptExpiresAt = transition.ModeObservedAt.Add(time.Minute)
	} else {
		transition.UARTPath = config.UARTPath
		transition.UARTOutputDigest = commandDigest("c")
		transition.RPIBootNotObservedThrough = transition.ModeObservedAt
	}
	transition.UpdatedAt = transition.ModeObservedAt
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	if action.RequestedBootMode == laneguard.BootModeRPIBoot {
		transition.Status = laneguard.BootTransitionOperatorReleased
		transition.ReleaseOperator = transition.Operator
		transition.OperatorReleasedAt = transition.ModeObservedAt.Add(time.Second)
		transition.UpdatedAt = transition.OperatorReleasedAt
		if err := journal.PutBootTransition(transition); err != nil {
			return laneguard.BootTransitionOutcome{}, err
		}
	}
	transition.Status = laneguard.BootTransitionCompleted
	transition.SafeOffObservedAt = transition.ModeObservedAt.Add(2 * time.Second)
	if !transition.OperatorReleasedAt.IsZero() {
		transition.SafeOffObservedAt = transition.OperatorReleasedAt.Add(time.Second)
	}
	transition.CompletedAt = transition.SafeOffObservedAt
	transition.UpdatedAt = transition.CompletedAt
	evidence, err := transition.Evidence()
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	transition.EvidenceDigest, err = evidence.Digest()
	if err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	if err := journal.PutBootTransition(transition); err != nil {
		return laneguard.BootTransitionOutcome{}, err
	}
	return transition.Outcome()
}

func commandPlanAndRequest() (laneguard.Plan, laneguard.ExecuteRequest) {
	prestate := laneguard.DirectState{CustomerKeyHash: zeroHash, EEPROMHash: commandDigest("f"), SecurityState: "fresh", PowerState: "powered_off"}
	poststate := laneguard.DirectState{CustomerKeyHash: commandDigest("1"), EEPROMHash: commandDigest("e"), SecurityState: "owned", PowerState: "powered_off"}
	plan := laneguard.Plan{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: "development-station", LaneID: "lane-1",
		TransactionID: "transaction-1", Release: commandReleaseBinding(), TargetFingerprint: "target-1",
		FenceEpoch: 1, ApprovalID: "approval-1", ApprovalExpiresAt: time.Now().UTC().Add(5 * time.Minute), IntentReceipt: "intent-1", IntentSequence: 1,
		Operations: []laneguard.OperationSpec{
			{
				Sequence: 1, Operation: laneguard.OperationProgramCustomerKeyAndEEPROM,
				Classification: laneguard.ClassIrreversible, RequiredBootMode: laneguard.BootModeRPIBoot,
				AuthorizationID: "authorization-1", ExpectedPrestate: prestate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 2, Operation: laneguard.OperationColdPowerCycle,
				Classification: laneguard.ClassReversible, RequiredBootMode: laneguard.BootModeNormal,
				AuthorizationID: "authorization-2", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 3, Operation: laneguard.OperationOwnedReadback,
				Classification: laneguard.ClassReadOnly, RequiredBootMode: laneguard.BootModeRPIBoot,
				AuthorizationID: "authorization-3", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 4, Operation: laneguard.OperationTestOwnedRecovery,
				Classification: laneguard.ClassReversible, RequiredBootMode: laneguard.BootModeRPIBoot,
				AuthorizationID: "authorization-4", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 5, Operation: laneguard.OperationPostRecoveryReadback,
				Classification: laneguard.ClassReadOnly, RequiredBootMode: laneguard.BootModeRPIBoot,
				AuthorizationID: "authorization-5", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 6, Operation: laneguard.OperationTestNegativeBoot,
				Classification: laneguard.ClassReversible, RequiredBootMode: laneguard.BootModeRPIBoot,
				AuthorizationID: "authorization-6", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
			{
				Sequence: 7, Operation: laneguard.OperationTestRootIntegrity,
				Classification: laneguard.ClassReversible, RequiredBootMode: laneguard.BootModeRPIBoot,
				AuthorizationID: "authorization-7", ExpectedPrestate: poststate,
				ExpectedPoststate: poststate, MaximumDuration: time.Minute,
			},
		},
	}
	derived, err := plan.WithDerivedDigests()
	if err != nil {
		panic(err)
	}
	plan = derived
	request := laneguard.ExecuteRequest{
		SchemaVersion: laneguard.ContractSchemaVersion, StationID: plan.StationID, LaneID: plan.LaneID,
		TransactionID: plan.TransactionID, PlanDigest: plan.PlanDigest, Release: plan.Release, TargetFingerprint: plan.TargetFingerprint,
		FenceEpoch: plan.FenceEpoch, ApprovalID: plan.ApprovalID, ApprovalExpiresAt: plan.ApprovalExpiresAt, IntentReceipt: plan.IntentReceipt,
		Sequence: 1, OperationDigest: plan.Operations[0].OperationDigest,
		AuthorizationID: plan.Operations[0].AuthorizationID, RequiredBootMode: plan.Operations[0].RequiredBootMode, ExpectedPrestate: prestate,
		ClaimExpiresAt: time.Now().Add(10 * time.Minute),
	}
	return plan, request
}

func commandDraft(plan laneguard.Plan) laneguard.Plan {
	plan.ApprovalID = ""
	plan.IntentReceipt = ""
	plan.IntentSequence = 0
	return plan
}

func stubAuthorityResult(t *testing.T, plan laneguard.Plan, request laneguard.ExecuteRequest) {
	t.Helper()
	requestAuthority = func(_ context.Context, socketPath string, bridgeRequest authoritybridge.BridgeRequest) (authoritybridge.BoundRequest, error) {
		if !filepath.IsAbs(socketPath) || bridgeRequest.SchemaVersion != authoritybridge.RequestSchemaVersion ||
			bridgeRequest.Mode != authoritybridge.ModeExecute || bridgeRequest.TransactionID != plan.TransactionID ||
			bridgeRequest.DraftSnapshot.ApprovalID != "" || bridgeRequest.DraftSnapshot.IntentReceipt != "" ||
			bridgeRequest.DraftSnapshot.IntentSequence != 0 || bridgeRequest.DraftSnapshot.PlanDigest != plan.PlanDigest {
			t.Fatalf("authority request = %#v via %q", bridgeRequest, socketPath)
		}
		return authoritybridge.BoundRequest{Plan: plan, ExecuteRequest: &request}, nil
	}
}

func commandReleaseBinding() releasebinding.Binding {
	return releasebinding.Binding{
		SignedReleaseManifestDigest: commandDigest("f"),
		LaneGuardPackageDigest:      commandDigest("d"),
		CompiledArtifactSetDigest:   commandDigest("c"),
		ExpectedCustomerKeyHash:     commandDigest("1"),
		ExpectedEEPROMDigest:        commandDigest("e"),
		ExpectedBootImageDigest:     commandDigest("b"),
	}
}

func writeJSON(t *testing.T, directory, name string, value any) string {
	t.Helper()
	path := filepath.Join(directory, name)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func commandMutationArguments(t *testing.T, directory, draftPath, journalPath string) []string {
	t.Helper()
	attemptDirectory := filepath.Join(directory, "attempts")
	if err := os.MkdirAll(attemptDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	return []string{
		"--enable-mutations",
		"--draft", draftPath,
		"--bridge-socket", filepath.Join(directory, "bridge.sock"),
		"--journal", journalPath,
		"--operator-socket", filepath.Join(directory, "operator.sock"),
		"--operator-group", "kaiba-operator",
		"--attempt-directory", attemptDirectory,
	}
}

func setImmutableTestGlobals(t *testing.T) {
	t.Helper()
	rpibootBinary = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-rpiboot/bin/rpiboot"
	gpioSetBinary = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-gpio/bin/gpioset"
	freshReadbackBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fresh-readback"
	freshCommitBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-fresh-commit"
	ownedReadbackBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-owned-readback"
	ownedRecoveryBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-owned-recovery"
	negativeBootBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-negative"
	rootIntegrityBundle = "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-root-integrity"
	expectedCustomerKeyHash = strings.Repeat("1", 64)
	expectedEEPROMHash = strings.Repeat("e", 64)
	expectedBootImageDigest = "sha256:" + strings.Repeat("b", 64)
	signedReleaseManifestDigest = commandDigest("f")
	lookupOperatorGroup = func(name string) (*user.Group, error) {
		if name != "kaiba-operator" {
			t.Fatalf("operator group name = %q", name)
		}
		return &user.Group{Name: name, Gid: "4242"}, nil
	}
	listenOperatorPrompt = func(config operatorprompt.Config) (operatorPromptServer, error) {
		if !filepath.IsAbs(config.SocketPath) || config.AllowedPrimaryGID != 4242 {
			t.Fatalf("operator prompt config = %#v", config)
		}
		return &commandPromptServer{}, nil
	}
	validateAttemptDestination = evidencefile.ValidateNewPath
	readAttemptEvidence = func(path string, maximum int64) ([]byte, error) {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o444 {
			return nil, errors.New("test evidence is not an immutable regular file")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > maximum {
			return nil, errors.New("test evidence exceeds its maximum size")
		}
		return data, nil
	}
	writeAttemptEvidence = evidencefile.WriteCanonicalNew
	commandOutput = io.Discard
	currentExecutable = func() (string, error) {
		return "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-lane-guard/bin/kaiba-provision-lane-guard", nil
	}
	deriveReleaseMaterial = func(executable string, paths []releasebindingmanifest.ArtifactPath, expectations releasebindingmanifest.ReleaseExpectations, mode releasebindingmanifest.ValidationMode) (immutableReleaseMaterial, error) {
		expectedPaths := []releasebindingmanifest.ArtifactPath{
			{Role: releasebindingmanifest.RolePatchedRPIBoot, Path: rpibootBinary},
			{Role: releasebindingmanifest.RoleGPIOSet, Path: gpioSetBinary},
			{Role: releasebindingmanifest.RoleFreshCommitBundle, Path: freshCommitBundle},
			{Role: releasebindingmanifest.RoleFreshReadbackBundle, Path: freshReadbackBundle},
			{Role: releasebindingmanifest.RoleNegativeBootBundle, Path: negativeBootBundle},
			{Role: releasebindingmanifest.RoleOwnedReadbackBundle, Path: ownedReadbackBundle},
			{Role: releasebindingmanifest.RoleOwnedRecoveryBundle, Path: ownedRecoveryBundle},
			{Role: releasebindingmanifest.RoleRootIntegrityBundle, Path: rootIntegrityBundle},
		}
		if executable != "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-lane-guard/bin/kaiba-provision-lane-guard" ||
			mode != releasebindingmanifest.ProductionMode || len(paths) != len(expectedPaths) {
			t.Fatalf("release material inputs = %q, %#v, %v", executable, paths, mode)
		}
		for index := range paths {
			if paths[index] != expectedPaths[index] {
				t.Fatalf("release material path %d = %#v, want %#v", index, paths[index], expectedPaths[index])
			}
		}
		if expectations.SignedReleaseManifestDigest != bundle.Digest(commandDigest("f")) ||
			expectations.ExpectedCustomerKeyHash != bundle.Digest(commandDigest("1")) ||
			expectations.ExpectedEEPROMDigest != bundle.Digest(commandDigest("e")) ||
			expectations.ExpectedBootImageDigest != bundle.Digest(commandDigest("b")) {
			t.Fatalf("release expectations = %#v", expectations)
		}
		return immutableReleaseMaterial{
			SchemaVersion: releaseMaterialSchemaVersion,
			Binding:       commandReleaseBinding(),
		}, nil
	}
}

func restoreCommandGlobals(t *testing.T) {
	t.Helper()
	savedUID, savedFactory, savedAuthority := effectiveUID, buildHardware, requestAuthority
	savedExecutable, savedDeriver := currentExecutable, deriveReleaseMaterial
	savedLookupGroup, savedListenPrompt := lookupOperatorGroup, listenOperatorPrompt
	savedOpenJournal := openLaneJournal
	savedValidateAttempt, savedReadAttempt := validateAttemptDestination, readAttemptEvidence
	savedWriteAttempt, savedOutput := writeAttemptEvidence, commandOutput
	values := []string{
		rpibootBinary, gpioSetBinary, freshReadbackBundle, freshCommitBundle,
		ownedReadbackBundle, ownedRecoveryBundle, negativeBootBundle, rootIntegrityBundle,
		signedReleaseManifestDigest, expectedCustomerKeyHash, expectedEEPROMHash,
		expectedBootImageDigest,
	}
	t.Cleanup(func() {
		effectiveUID, buildHardware, requestAuthority = savedUID, savedFactory, savedAuthority
		currentExecutable, deriveReleaseMaterial = savedExecutable, savedDeriver
		lookupOperatorGroup, listenOperatorPrompt = savedLookupGroup, savedListenPrompt
		openLaneJournal = savedOpenJournal
		validateAttemptDestination, readAttemptEvidence = savedValidateAttempt, savedReadAttempt
		writeAttemptEvidence, commandOutput = savedWriteAttempt, savedOutput
		rpibootBinary, gpioSetBinary = values[0], values[1]
		freshReadbackBundle, freshCommitBundle = values[2], values[3]
		ownedReadbackBundle, ownedRecoveryBundle = values[4], values[5]
		negativeBootBundle, rootIntegrityBundle = values[6], values[7]
		signedReleaseManifestDigest = values[8]
		expectedCustomerKeyHash, expectedEEPROMHash, expectedBootImageDigest = values[9], values[10], values[11]
	})
}

func commandDigest(character string) string { return "sha256:" + strings.Repeat(character, 64) }
