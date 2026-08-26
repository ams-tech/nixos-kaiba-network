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

var (
	lookupOperatorGroup  = user.LookupGroup
	listenOperatorPrompt = func(config operatorprompt.Config) (operatorPromptServer, error) {
		return operatorprompt.Listen(config)
	}
	validateAttemptDestination           = evidencefile.ValidateTrustedNewPath
	writeAttemptEvidence                 = evidencefile.WriteCanonicalNewTrusted
	commandOutput              io.Writer = os.Stdout
)

var requestAuthority = authoritybridge.Request

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
	if *gpioOffset > math.MaxUint32 {
		return errors.New("GPIO offset exceeds uint32")
	}
	laneConfig := laneguard.Config{
		SchemaVersion: laneguard.ContractSchemaVersion,
		StationID:     *stationID, LaneID: *laneID,
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
	binding, err := requestAuthority(ctx, *bridgeSocket, authoritybridge.BridgeRequest{
		SchemaVersion: authoritybridge.RequestSchemaVersion,
		Mode:          bridgeMode,
		TransactionID: draft.TransactionID,
		DraftSnapshot: draft,
	})
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
	if *mode == "execute" && !time.Now().UTC().Before(plan.ApprovalExpiresAt) {
		return laneguard.ErrApprovalExpired
	}
	if plan.Release != compiledRelease {
		return fmt.Errorf("%w: approved release differs from the immutable lane-guard build", laneguard.ErrPlanMismatch)
	}
	attemptPath, err := plannedAttemptEvidencePath(*attemptDirectory, *mode, executeRequest, reconcileRequest)
	if err != nil {
		return fmt.Errorf("derive immutable attempt destination: %w", err)
	}
	if err := validateAttemptDestination(attemptPath); err != nil {
		return fmt.Errorf("validate immutable attempt destination before physical I/O: %w", err)
	}
	operatorGID, err := resolveOperatorGID(*operatorGroup)
	if err != nil {
		return err
	}
	initialMode := physicalrpi5.ModeFresh
	if *mode == "reconcile" {
		initialMode = physicalrpi5.ModeAuto
	} else if plan.Operations[originalRequest.Sequence-1].ExpectedPrestate.CustomerKeyHash != zeroHash {
		initialMode = physicalrpi5.ModeOwned
	}
	physicalConfig := physicalrpi5.Config{
		Paths:       immutablePaths,
		InitialMode: initialMode, ExpectedCustomerKeyHash: expectedCustomerKeyHash,
		ExpectedEEPROMHash: expectedEEPROMHash, ExpectedBootImageDigest: expectedBootImageDigest,
	}
	store, err := laneguard.NewFileStore(*journalPath)
	if err != nil {
		return err
	}
	defer func() {
		resultErr = errors.Join(resultErr, store.Close())
	}()
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
	guard, err := laneguard.New(laneConfig, hardware, store)
	if err != nil {
		return err
	}
	if *mode != "reconcile" {
		if err := guard.LoadPlan(ctx, plan); err != nil {
			return fmt.Errorf("load approved plan into fixed lane: %w", err)
		}
	}
	var attempt laneguard.Attempt
	if *mode == "reconcile" {
		attempt, err = guard.ReconcilePlan(ctx, plan, reconcileRequest)
	} else {
		attempt, err = guard.Execute(ctx, executeRequest)
	}
	if attempt.Key != "" {
		encoded, encodeErr := json.Marshal(attempt)
		if encodeErr != nil {
			return errors.Join(err, fmt.Errorf("encode canonical attempt evidence: %w", encodeErr))
		}
		encoded = append(encoded, '\n')
		if writeErr := writeAttemptEvidence(attemptPath, encoded); writeErr != nil {
			return errors.Join(err, fmt.Errorf("publish immutable attempt evidence: %w", writeErr))
		}
		summary := struct {
			Path   string                  `json:"path"`
			Status laneguard.AttemptStatus `json:"status"`
			Key    string                  `json:"key"`
		}{Path: attemptPath, Status: attempt.Status, Key: attempt.Key}
		encoder := json.NewEncoder(commandOutput)
		encoder.SetEscapeHTML(false)
		if encodeErr := encoder.Encode(summary); encodeErr != nil {
			return errors.Join(err, fmt.Errorf("encode attempt publication summary: %w", encodeErr))
		}
	}
	return err
}

const attemptPublicationIdentitySchemaVersion = "kaiba.provisioning.lane-attempt-publication/v1alpha1"

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
