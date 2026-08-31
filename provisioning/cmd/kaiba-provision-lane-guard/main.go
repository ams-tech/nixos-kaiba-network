package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
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

// These values are immutable build inputs populated with -X linker flags by
// the station package. There are intentionally no runtime flags for them.
var (
	rpibootBinary               string
	gpioSetBinary               string
	freshReadbackBundle         string
	freshCommitBundle           string
	ownedReadbackBundle         string
	ownedRecoveryBundle         string
	negativeBootBundle          string
	rootIntegrityBundle         string
	signedReleaseManifestDigest string
	expectedCustomerKeyHash     string
	expectedEEPROMHash          string
	expectedBootImageDigest     string
)

var effectiveUID = os.Geteuid

type hardwareFactory func(physicalrpi5.Config, physicalrpi5.Dependencies) (laneguard.Hardware, error)

var buildHardware hardwareFactory = func(config physicalrpi5.Config, dependencies physicalrpi5.Dependencies) (laneguard.Hardware, error) {
	return physicalrpi5.New(config, dependencies)
}

type operatorPromptServer interface {
	physicalrpi5.Prompter
	io.Closer
}

type laneJournal interface {
	laneguard.Journal
	io.Closer
}

var (
	lookupOperatorGroup  = user.LookupGroup
	listenOperatorPrompt = func(config operatorprompt.Config) (operatorPromptServer, error) {
		return operatorprompt.Listen(config)
	}
	openLaneJournal = func(path string) (laneJournal, error) {
		return laneguard.NewFileStore(path)
	}
	validateAttemptDestination           = evidencefile.ValidateTrustedNewPath
	readAttemptEvidence                  = evidencefile.ReadTrustedExisting
	writeAttemptEvidence                 = evidencefile.WriteCanonicalNewTrusted
	commandOutput              io.Writer = os.Stdout
)

var requestAuthority = authoritybridge.Request

type bridgeDispatchAuthority struct {
	socketPath string
	request    authoritybridge.BridgeRequest
	config     laneguard.Config
	mode       authoritybridge.Mode
}

func (authority bridgeDispatchAuthority) RecheckExecute(ctx context.Context, plan laneguard.Plan, request laneguard.ExecuteRequest) error {
	if authority.mode != authoritybridge.ModeExecute || authority.request.Mode != authoritybridge.ModeExecute {
		return errors.New("execution dispatch used a non-execution authority mode")
	}
	binding, err := requestAuthority(ctx, authority.socketPath, authority.request)
	if err != nil {
		return fmt.Errorf("refresh authenticated execution authority: %w", err)
	}
	if binding.ExecuteRequest == nil || binding.ReconcileRequest != nil {
		return errors.New("refreshed authority returned the wrong request variant for execution")
	}
	if err := laneguard.ValidatePlanRequest(authority.config, binding.Plan, *binding.ExecuteRequest); err != nil {
		return fmt.Errorf("validate refreshed execution authority: %w", err)
	}
	return compareDispatchBinding(
		struct {
			Plan    laneguard.Plan           `json:"plan"`
			Request laneguard.ExecuteRequest `json:"execute_request"`
		}{Plan: plan, Request: request},
		struct {
			Plan    laneguard.Plan           `json:"plan"`
			Request laneguard.ExecuteRequest `json:"execute_request"`
		}{Plan: binding.Plan, Request: *binding.ExecuteRequest},
	)
}

func (authority bridgeDispatchAuthority) RecheckReconciliation(ctx context.Context, plan laneguard.Plan, request laneguard.ReconcileRequest) error {
	if authority.mode != authoritybridge.ModeReconcile || authority.request.Mode != authoritybridge.ModeReconcile {
		return errors.New("reconciliation dispatch used a non-reconciliation authority mode")
	}
	binding, err := requestAuthority(ctx, authority.socketPath, authority.request)
	if err != nil {
		return fmt.Errorf("refresh authenticated reconciliation authority: %w", err)
	}
	if binding.ExecuteRequest != nil || binding.ReconcileRequest == nil {
		return errors.New("refreshed authority returned the wrong request variant for reconciliation")
	}
	if err := laneguard.ValidateReconcileRequest(authority.config, binding.Plan, *binding.ReconcileRequest); err != nil {
		return fmt.Errorf("validate refreshed reconciliation authority: %w", err)
	}
	return compareDispatchBinding(
		struct {
			Plan    laneguard.Plan             `json:"plan"`
			Request laneguard.ReconcileRequest `json:"reconcile_request"`
		}{Plan: plan, Request: request},
		struct {
			Plan    laneguard.Plan             `json:"plan"`
			Request laneguard.ReconcileRequest `json:"reconcile_request"`
		}{Plan: binding.Plan, Request: *binding.ReconcileRequest},
	)
}

func compareDispatchBinding(expected, refreshed any) error {
	expectedBytes, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("encode expected dispatch authority: %w", err)
	}
	refreshedBytes, err := json.Marshal(refreshed)
	if err != nil {
		return fmt.Errorf("encode refreshed dispatch authority: %w", err)
	}
	if !bytes.Equal(expectedBytes, refreshedBytes) {
		return laneguard.ErrPlanMismatch
	}
	return nil
}

var currentExecutable = os.Executable

type releaseMaterialDeriver func(string, []releasebindingmanifest.ArtifactPath, releasebindingmanifest.ReleaseExpectations, releasebindingmanifest.ValidationMode) (immutableReleaseMaterial, error)

var deriveReleaseMaterial releaseMaterialDeriver = snapshotReleaseMaterial

const releaseMaterialSchemaVersion = "kaiba.provisioning.rpi5-lane-release-material/v1alpha1"

type immutableReleaseMaterial struct {
	SchemaVersion       string                                     `json:"schema_version"`
	CompiledArtifactSet releasebindingmanifest.CompiledArtifactSet `json:"compiled_artifact_set"`
	LaneGuardPackage    releasebindingmanifest.LaneGuardPackage    `json:"lane_guard_package"`
	Binding             releasebinding.Binding                     `json:"binding"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "kaiba-provision-lane-guard: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, arguments []string) (resultErr error) {
	flags := flag.NewFlagSet("kaiba-provision-lane-guard", flag.ContinueOnError)
	flags.SetOutput(os.Stderr)
	stationID := flags.String("station-id", "development-station", "fixed station identity")
	laneID := flags.String("lane-id", "lane-1", "fixed lane identity")
	usbPath := flags.String("rpiboot-sysfs", "/sys/bus/usb/devices/1-1", "fixed RPIBOOT sysfs path")
	uartPath := flags.String("uart", "/dev/serial/by-id/kaiba-target-uart", "fixed target UART path")
	powerControl := flags.String("power-control", "relay", "fixed target-power mechanism: relay or manual")
	gpioChip := flags.String("gpio-chip", "/dev/gpiochip0", "fixed power-relay GPIO chip")
	gpioOffset := flags.Uint64("gpio-offset", 0, "fixed power-relay GPIO line offset")
	gpioActiveLow := flags.Bool("gpio-active-low", false, "treat the power-relay line as active-low")
	leaseMargin := flags.Duration("lease-safety-margin", 30*time.Second, "lease lifetime reserved after the worst-case operation duration")
	journalPath := flags.String("journal", "", "absolute durable execute-once journal path")
	draftPath := flags.String("draft", "", "absolute authority-free approved-plan draft JSON path")
	bridgeSocket := flags.String("bridge-socket", "", "absolute authenticated authority-bridge Unix socket path")
	operatorSocket := flags.String("operator-socket", "", "absolute authenticated operator-prompt Unix socket path")
	operatorGroup := flags.String("operator-group", "", "fixed primary group authorized to acknowledge operator prompts")
	attemptDirectory := flags.String("attempt-directory", "", "absolute trusted directory for immutable lane-attempt evidence")
	mode := flags.String("mode", "execute", "one-shot operation: execute or reconcile")
	enableMutations := flags.Bool("enable-mutations", false, "enable the immutable physical RPIBOOT adapter")
	printReleaseBinding := flags.Bool("print-release-binding", false, "print the immutable public release binding as JSON and exit")
	printReleaseMaterial := flags.Bool("print-release-binding-material", false, "print canonical content-derived release material as JSON and exit")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if *powerControl != "relay" && *powerControl != "manual" {
		return errors.New("power-control must be relay or manual")
	}
	if *gpioOffset > math.MaxUint32 {
		return errors.New("GPIO offset exceeds uint32")
	}
	laneConfig := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     *stationID, LaneID: *laneID,
		PowerControlMode: laneguard.PowerControlMode(*powerControl),
		RPIBootSysfsPath: *usbPath, UARTPath: *uartPath,
		PowerGPIO:         laneguard.GPIODescriptor{ChipPath: *gpioChip, Offset: uint32(*gpioOffset), ActiveLow: *gpioActiveLow},
		LeaseSafetyMargin: *leaseMargin,
	}
	if err := laneConfig.Validate(); err != nil {
		return err
	}
	if *printReleaseBinding || *printReleaseMaterial {
		if *enableMutations {
			return errors.New("release-binding inspection cannot be combined with enable-mutations")
		}
		if *printReleaseBinding && *printReleaseMaterial {
			return errors.New("select only one release-binding inspection mode")
		}
		material, err := loadImmutableReleaseMaterial()
		if err != nil {
			return err
		}
		encoder := json.NewEncoder(commandOutput)
		encoder.SetEscapeHTML(false)
		if *printReleaseMaterial {
			return encoder.Encode(material)
		}
		return encoder.Encode(material.Binding)
	}
	if !*enableMutations {
		fmt.Fprintf(commandOutput, "lane guard configuration valid; mutation disabled for %s/%s\n", laneConfig.StationID, laneConfig.LaneID)
		return nil
	}
	if effectiveUID() != 0 {
		return errors.New("physical lane operation requires root")
	}
	if *mode != "execute" && *mode != "reconcile" {
		return errors.New("mode must be execute or reconcile")
	}
	if *journalPath == "" || *draftPath == "" || *bridgeSocket == "" || *operatorSocket == "" || *operatorGroup == "" || *attemptDirectory == "" {
		return errors.New("enabled operation requires journal, draft, bridge-socket, operator-socket, operator-group, and attempt-directory")
	}
	for label, path := range map[string]string{
		"journal": *journalPath, "draft": *draftPath, "bridge socket": *bridgeSocket,
		"operator socket": *operatorSocket, "attempt directory": *attemptDirectory,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return fmt.Errorf("%s path must be clean and absolute", label)
		}
	}
	var draft laneguard.Plan
	if err := loadStrictJSON(*draftPath, 1024*1024, &draft); err != nil {
		return fmt.Errorf("load authority-free plan draft: %w", err)
	}
	immutablePaths := physicalrpi5.ImmutablePaths{
		RPIBootBinary: rpibootBinary, GPIOSetBinary: gpioSetBinary,
		FreshReadbackBundle: freshReadbackBundle, FreshCommitBundle: freshCommitBundle,
		OwnedReadbackBundle: ownedReadbackBundle, OwnedRecoveryBundle: ownedRecoveryBundle,
		NegativeBootBundle: negativeBootBundle, RootIntegrityBundle: rootIntegrityBundle,
		RequireNixStorePaths: true,
	}
	if err := immutablePaths.Validate(); err != nil {
		return fmt.Errorf("validate immutable physical paths: %w", err)
	}
	compiledRelease, err := immutableReleaseBinding()
	if err != nil {
		return err
	}
	bridgeMode := authoritybridge.Mode(*mode)
	bridgeRequest := authoritybridge.BridgeRequest{
		SchemaVersion: authoritybridge.RequestSchemaVersion,
		Mode:          bridgeMode,
		TransactionID: draft.TransactionID,
		DraftSnapshot: draft,
	}
	binding, err := requestAuthority(ctx, *bridgeSocket, bridgeRequest)
	if err != nil {
		return fmt.Errorf("obtain authenticated lane authority: %w", err)
	}
	plan := binding.Plan
	var executeRequest laneguard.ExecuteRequest
	var reconcileRequest laneguard.ReconcileRequest
	var originalRequest laneguard.ExecuteRequest
	if *mode == "reconcile" {
		if binding.ExecuteRequest != nil || binding.ReconcileRequest == nil {
			return errors.New("authority bridge returned the wrong request variant for reconciliation")
		}
		reconcileRequest = *binding.ReconcileRequest
		originalRequest = reconcileRequest.OriginalRequest
		if err := laneguard.ValidateReconcileRequest(laneConfig, plan, reconcileRequest); err != nil {
			return fmt.Errorf("validate authenticated plan and reconciliation request: %w", err)
		}
	} else {
		if binding.ExecuteRequest == nil || binding.ReconcileRequest != nil {
			return errors.New("authority bridge returned the wrong request variant for execution")
		}
		executeRequest = *binding.ExecuteRequest
		originalRequest = executeRequest
		if err := laneguard.ValidatePlanRequest(laneConfig, plan, executeRequest); err != nil {
			return fmt.Errorf("validate authenticated plan and operation request: %w", err)
		}
	}
	if plan.Release != compiledRelease {
		return fmt.Errorf("%w: approved release differs from the immutable lane-guard build", laneguard.ErrPlanMismatch)
	}
	attemptPath, err := plannedAttemptEvidencePath(*attemptDirectory, *mode, executeRequest, reconcileRequest)
	if err != nil {
		return fmt.Errorf("derive immutable attempt destination: %w", err)
	}
	operatorGID, err := resolveOperatorGID(*operatorGroup)
	if err != nil {
		return err
	}
	store, err := openLaneJournal(*journalPath)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, store.Close())
	}()
	attemptKey := laneguard.AttemptJournalKey(plan, originalRequest.Sequence)
	durable, found, err := store.Get(attemptKey)
	if err != nil {
		return fmt.Errorf("read durable attempt before physical I/O: %w", err)
	}
	if found && !attemptMatchesAuthenticatedPlan(durable, plan, originalRequest.Sequence) {
		return fmt.Errorf("%w: durable attempt differs from the authenticated operation", laneguard.ErrPlanMismatch)
	}
	if found {
		if err := laneguard.ValidateAttemptForPlan(plan, durable); err != nil {
			return fmt.Errorf("%w: durable attempt evidence is invalid: %v", laneguard.ErrPlanMismatch, err)
		}
	}
	destinationExists, err := inspectAttemptDestination(attemptPath, durable, found)
	if err != nil {
		return err
	}
	if destinationExists {
		return publishDurableAttempt(attemptPath, durable, destinationExists, attemptStatusError(*mode, durable.Status))
	}
	if found && isPublishableAttemptStatus(durable.Status) &&
		(*mode == "execute" || durable.Status != laneguard.AttemptUncertain) {
		return publishDurableAttempt(attemptPath, durable, false, attemptStatusError(*mode, durable.Status))
	}
	if found && durable.Status == laneguard.AttemptStarted && *mode == "execute" {
		return errors.Join(
			laneguard.ErrReconciliationRequired,
			fmt.Errorf("durable attempt %q remains started; immutable receipt was not published", attemptKey),
		)
	}
	if *mode == "execute" && !time.Now().UTC().Before(plan.ApprovalExpiresAt) {
		return laneguard.ErrApprovalExpired
	}
	initialMode := physicalrpi5.ModeFresh
	if *mode == "reconcile" {
		initialMode = physicalrpi5.ModeAuto
	} else if plan.Operations[originalRequest.Sequence-1].ExpectedPrestate.CustomerKeyHash != zeroHash {
		initialMode = physicalrpi5.ModeOwned
	}
	physicalConfig := physicalrpi5.Config{
		Paths:        immutablePaths,
		PowerControl: *powerControl,
		InitialMode:  initialMode, ExpectedCustomerKeyHash: expectedCustomerKeyHash,
		ExpectedEEPROMHash: expectedEEPROMHash, ExpectedBootImageDigest: expectedBootImageDigest,
	}
	if laneguard.PowerControlMode(physicalConfig.PowerControl) != laneConfig.PowerControlMode {
		return errors.New("physical adapter power control differs from the authorized lane mode")
	}
	promptServer, err := listenOperatorPrompt(operatorprompt.Config{
		SocketPath: *operatorSocket, AllowedPrimaryGID: operatorGID,
	})
	if err != nil {
		return fmt.Errorf("create authenticated operator prompt socket: %w", err)
	}
	defer func() {
		resultErr = errors.Join(resultErr, promptServer.Close())
	}()
	hardware, err := buildHardware(physicalConfig, physicalrpi5.Dependencies{
		Journal: store, Prompter: promptServer,
	})
	if err != nil {
		return fmt.Errorf("construct immutable physical adapter: %w", err)
	}
	if closer, ok := hardware.(io.Closer); ok {
		defer func() {
			resultErr = errors.Join(resultErr, closer.Close())
		}()
	}
	guard, err := laneguard.NewWithDispatchAuthority(laneConfig, hardware, store, bridgeDispatchAuthority{
		socketPath: *bridgeSocket,
		request:    bridgeRequest,
		config:     laneConfig,
		mode:       bridgeMode,
	})
	if err != nil {
		return err
	}
	if *mode != "reconcile" {
		if err := guard.LoadPlan(ctx, plan); err != nil {
			return fmt.Errorf("load approved plan into fixed lane: %w", err)
		}
	}
	if *mode == "reconcile" {
		_, err = guard.ReconcilePlan(ctx, plan, reconcileRequest)
	} else {
		_, err = guard.Execute(ctx, executeRequest)
	}
	durable, found, reloadErr := store.Get(attemptKey)
	if reloadErr != nil {
		return errors.Join(err, fmt.Errorf("reload durable attempt after lane operation; receipt not published: %w", reloadErr))
	}
	if !found {
		return errors.Join(err, fmt.Errorf("durable attempt %q is missing after lane operation; receipt not published", attemptKey))
	}
	if !attemptMatchesAuthenticatedPlan(durable, plan, originalRequest.Sequence) {
		return errors.Join(err, fmt.Errorf("%w: reloaded durable attempt differs from the authenticated operation; receipt not published", laneguard.ErrPlanMismatch))
	}
	if validateErr := laneguard.ValidateAttemptForPlan(plan, durable); validateErr != nil {
		return errors.Join(err, fmt.Errorf("%w: reloaded durable attempt evidence is invalid; receipt not published: %v", laneguard.ErrPlanMismatch, validateErr))
	}
	if !isPublishableAttemptStatus(durable.Status) {
		return errors.Join(err, fmt.Errorf(
			"durable attempt %q has non-terminal status %q after lane operation; receipt not published",
			attemptKey, durable.Status,
		))
	}
	return publishDurableAttempt(attemptPath, durable, false, err)
}

const maximumAttemptEvidenceBytes = 1024 * 1024

func attemptMatchesAuthenticatedPlan(attempt laneguard.Attempt, plan laneguard.Plan, sequence uint32) bool {
	if sequence == 0 || int(sequence) > len(plan.Operations) {
		return false
	}
	operation := plan.Operations[sequence-1]
	return attempt.SchemaVersion == laneguard.AttemptSchemaVersion &&
		attempt.Key == laneguard.AttemptJournalKey(plan, sequence) &&
		attempt.TransactionID == plan.TransactionID && attempt.PlanDigest == plan.PlanDigest &&
		attempt.TargetFingerprint == plan.TargetFingerprint && attempt.FenceEpoch == plan.FenceEpoch &&
		attempt.ApprovalID == plan.ApprovalID && attempt.IntentReceipt == plan.IntentReceipt &&
		attempt.IntentSequence == plan.IntentSequence && attempt.Sequence == sequence &&
		attempt.Operation == operation.Operation && attempt.OperationDigest == operation.OperationDigest
}

func isPublishableAttemptStatus(status laneguard.AttemptStatus) bool {
	switch status {
	case laneguard.AttemptVerified, laneguard.AttemptUncertain,
		laneguard.AttemptConfirmedNotApplied, laneguard.AttemptQuarantined:
		return true
	default:
		return false
	}
}

func canonicalAttemptEvidence(attempt laneguard.Attempt) ([]byte, error) {
	encoded, err := json.Marshal(attempt)
	if err != nil {
		return nil, fmt.Errorf("encode canonical durable attempt evidence: %w", err)
	}
	return append(encoded, '\n'), nil
}

// inspectAttemptDestination distinguishes a genuinely new destination from a
// prior successful (or link-complete) publication. An existing pathname is
// accepted only when the journal already holds the exact publishable attempt
// and the trusted immutable file contains its canonical bytes.
func inspectAttemptDestination(path string, durable laneguard.Attempt, found bool) (bool, error) {
	validationErr := validateAttemptDestination(path)
	if validationErr == nil {
		return false, nil
	}
	if !found || !isPublishableAttemptStatus(durable.Status) {
		return false, errors.Join(
			fmt.Errorf("validate immutable attempt destination before physical I/O: %w", validationErr),
			errors.New("existing receipt cannot be reused without a matching durable publishable attempt"),
		)
	}
	expected, err := canonicalAttemptEvidence(durable)
	if err != nil {
		return false, err
	}
	existing, readErr := readAttemptEvidence(path, maximumAttemptEvidenceBytes)
	if readErr != nil {
		return false, errors.Join(
			fmt.Errorf("validate immutable attempt destination before physical I/O: %w", validationErr),
			fmt.Errorf("read existing immutable attempt evidence: %w", readErr),
		)
	}
	if !bytes.Equal(existing, expected) {
		return false, errors.Join(
			fmt.Errorf("validate immutable attempt destination before physical I/O: %w", validationErr),
			errors.New("existing immutable attempt evidence differs from the durable journal record"),
		)
	}
	return true, nil
}

func publishDurableAttempt(path string, attempt laneguard.Attempt, alreadyPublished bool, operationErr error) error {
	encoded, err := canonicalAttemptEvidence(attempt)
	if err != nil {
		return errors.Join(operationErr, err)
	}
	if !alreadyPublished {
		if writeErr := writeAttemptEvidence(path, encoded); writeErr != nil {
			return errors.Join(operationErr, fmt.Errorf("publish immutable durable attempt evidence: %w", writeErr))
		}
	}
	summary := struct {
		Path             string                  `json:"path"`
		Status           laneguard.AttemptStatus `json:"status"`
		Key              string                  `json:"key"`
		AlreadyPublished bool                    `json:"already_published"`
	}{Path: path, Status: attempt.Status, Key: attempt.Key, AlreadyPublished: alreadyPublished}
	encoder := json.NewEncoder(commandOutput)
	encoder.SetEscapeHTML(false)
	if encodeErr := encoder.Encode(summary); encodeErr != nil {
		return errors.Join(operationErr, fmt.Errorf("encode attempt publication summary: %w", encodeErr))
	}
	return operationErr
}

func attemptStatusError(mode string, status laneguard.AttemptStatus) error {
	switch status {
	case laneguard.AttemptVerified:
		return nil
	case laneguard.AttemptUncertain:
		return laneguard.ErrReconciliationRequired
	case laneguard.AttemptConfirmedNotApplied:
		if mode == "execute" {
			return laneguard.ErrConfirmedNotApplied
		}
		return nil
	case laneguard.AttemptQuarantined:
		return laneguard.ErrQuarantined
	default:
		return fmt.Errorf("durable attempt has non-publishable status %q", status)
	}
}

const attemptPublicationIdentitySchemaVersion = "kaiba.provisioning.lane-attempt-publication/v1alpha2"

func plannedAttemptEvidencePath(directory, mode string, execute laneguard.ExecuteRequest, reconcile laneguard.ReconcileRequest) (string, error) {
	if directory == "" || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return "", errors.New("attempt directory must be a clean absolute path")
	}
	identity := struct {
		SchemaVersion string                      `json:"schema_version"`
		Mode          string                      `json:"mode"`
		Execute       *laneguard.ExecuteRequest   `json:"execute,omitempty"`
		Reconcile     *laneguard.ReconcileRequest `json:"reconcile,omitempty"`
	}{SchemaVersion: attemptPublicationIdentitySchemaVersion, Mode: mode}
	switch mode {
	case "execute":
		identity.Execute = &execute
	case "reconcile":
		identity.Reconcile = &reconcile
	default:
		return "", errors.New("attempt publication mode must be execute or reconcile")
	}
	encoded, err := json.Marshal(identity)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	path := filepath.Join(directory, fmt.Sprintf("lane-attempt-%x.json", digest[:]))
	if filepath.Dir(path) != directory {
		return "", errors.New("attempt evidence escaped its fixed directory")
	}
	return path, nil
}

func resolveOperatorGID(name string) (uint32, error) {
	group, err := lookupOperatorGroup(name)
	if err != nil {
		return 0, fmt.Errorf("resolve operator group %q: %w", name, err)
	}
	if group == nil {
		return 0, fmt.Errorf("resolve operator group %q: lookup returned no group", name)
	}
	value, err := strconv.ParseUint(group.Gid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("operator group %q has invalid numeric GID %q: %w", name, group.Gid, err)
	}
	return uint32(value), nil
}

func immutableReleaseBinding() (releasebinding.Binding, error) {
	material, err := loadImmutableReleaseMaterial()
	if err != nil {
		return releasebinding.Binding{}, err
	}
	return material.Binding, nil
}

func loadImmutableReleaseMaterial() (immutableReleaseMaterial, error) {
	executable, err := currentExecutable()
	if err != nil {
		return immutableReleaseMaterial{}, fmt.Errorf("resolve lane-guard executable: %w", err)
	}
	paths := []releasebindingmanifest.ArtifactPath{
		{Role: releasebindingmanifest.RolePatchedRPIBoot, Path: rpibootBinary},
		{Role: releasebindingmanifest.RoleGPIOSet, Path: gpioSetBinary},
		{Role: releasebindingmanifest.RoleFreshCommitBundle, Path: freshCommitBundle},
		{Role: releasebindingmanifest.RoleFreshReadbackBundle, Path: freshReadbackBundle},
		{Role: releasebindingmanifest.RoleNegativeBootBundle, Path: negativeBootBundle},
		{Role: releasebindingmanifest.RoleOwnedReadbackBundle, Path: ownedReadbackBundle},
		{Role: releasebindingmanifest.RoleOwnedRecoveryBundle, Path: ownedRecoveryBundle},
		{Role: releasebindingmanifest.RoleRootIntegrityBundle, Path: rootIntegrityBundle},
	}
	expectations := releasebindingmanifest.ReleaseExpectations{
		SignedReleaseManifestDigest: bundle.Digest(signedReleaseManifestDigest),
		ExpectedCustomerKeyHash:     bundle.Digest(canonicalExpectedDigest(expectedCustomerKeyHash)),
		ExpectedEEPROMDigest:        bundle.Digest(canonicalExpectedDigest(expectedEEPROMHash)),
		ExpectedBootImageDigest:     bundle.Digest(expectedBootImageDigest),
	}
	material, err := deriveReleaseMaterial(executable, paths, expectations, releasebindingmanifest.ProductionMode)
	if err != nil {
		return immutableReleaseMaterial{}, fmt.Errorf("derive immutable release binding from path contents: %w", err)
	}
	if material.SchemaVersion != releaseMaterialSchemaVersion {
		return immutableReleaseMaterial{}, errors.New("derived release material has an invalid schema")
	}
	if err := material.Binding.Validate(); err != nil {
		return immutableReleaseMaterial{}, fmt.Errorf("validate immutable release binding: %w", err)
	}
	return material, nil
}

func snapshotReleaseMaterial(executable string, paths []releasebindingmanifest.ArtifactPath, expectations releasebindingmanifest.ReleaseExpectations, mode releasebindingmanifest.ValidationMode) (immutableReleaseMaterial, error) {
	if mode != releasebindingmanifest.ProductionMode {
		return immutableReleaseMaterial{}, errors.New("immutable release material requires production validation mode")
	}
	snapshot, err := releasebindingmanifest.SnapshotProductionReleaseMaterial(executable, paths, expectations)
	if err != nil {
		return immutableReleaseMaterial{}, err
	}
	return immutableReleaseMaterial{
		SchemaVersion: releaseMaterialSchemaVersion, CompiledArtifactSet: snapshot.CompiledArtifactSet,
		LaneGuardPackage: snapshot.LaneGuardPackage, Binding: snapshot.Binding,
	}, nil
}

func canonicalExpectedDigest(value string) string {
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	return "sha256:" + value
}

const zeroHash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

func loadStrictJSON(path string, maximum int64, target any) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("JSON path must be clean and absolute")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open regular non-symlink JSON input: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("JSON input must be a regular non-symlink file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maximum {
		return fmt.Errorf("JSON input exceeds %d bytes", maximum)
	}
	if err := rejectDuplicateJSON(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("JSON input has a trailing value")
		}
		return err
	}
	return nil
}

func rejectDuplicateJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := rejectDuplicateToken(decoder, token, "$"); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("JSON input has trailing data")
	}
	return nil
}

func rejectDuplicateToken(decoder *json.Decoder, token json.Token, path string) error {
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
			key := keyToken.(string)
			if _, exists := seen[key]; exists {
				return fmt.Errorf("%s contains duplicate key %q", path, key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := rejectDuplicateToken(decoder, value, path+"."+key); err != nil {
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
			if err := rejectDuplicateToken(decoder, value, fmt.Sprintf("%s[%d]", path, index)); err != nil {
				return err
			}
		}
		_, err := decoder.Token()
		return err
	default:
		return errors.New("unexpected JSON delimiter")
	}
}
