package unfusedevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
)

const maximumUARTLineBytes = 4096

// Verify validates a prior offline compatibility result, a strict operator
// record, and a bounded UART transcript. It only reads the three named files.
func Verify(compatibilityOutcomePath, observationPath, uartCapturePath string) (Outcome, error) {
	var compatibilityOutcome unfusedcompat.Outcome
	if err := loadStrictJSONFile(compatibilityOutcomePath, maximumCompatibilityOutcomeBytes, &compatibilityOutcome); err != nil {
		return Outcome{}, fmt.Errorf("load compatibility outcome: %w", err)
	}
	compatibilityDigest, err := CompatibilityOutcomeDigest(compatibilityOutcome)
	if err != nil {
		return Outcome{}, fmt.Errorf("validate compatibility outcome: %w", err)
	}

	uartCapture, err := readBoundedRegularFile(uartCapturePath, maximumUARTCaptureBytes)
	if err != nil {
		return Outcome{}, fmt.Errorf("load UART capture: %w", err)
	}
	uartDigest := rawDigest(uartCapture)

	var observation HardwareObservation
	if err := loadStrictJSONFile(observationPath, maximumObservationBytes, &observation); err != nil {
		return Outcome{}, fmt.Errorf("load hardware observation: %w", err)
	}
	if err := observation.validate(compatibilityOutcome, compatibilityDigest, uartDigest); err != nil {
		return Outcome{}, fmt.Errorf("validate hardware observation: %w", err)
	}
	if err := validateUARTCapture(uartCapture, compatibilityOutcome); err != nil {
		return Outcome{}, err
	}
	observationHash, err := observationDigest(observation)
	if err != nil {
		return Outcome{}, err
	}

	return Outcome{
		SchemaVersion: OutcomeSchemaVersion, Status: StatusCompatibilityPassed,
		EvidenceMode: EvidenceModeOperatorHardware, ObservationID: observation.ObservationID,
		ObservationDigest: observationHash, CompatibilityOutcomeDigest: compatibilityDigest,
		LaneID: observation.Before.LaneID, TargetFingerprint: observation.Before.TargetFingerprint,
		CustomerKeyHashBefore: observation.Before.CustomerKeyHash,
		CustomerKeyHashAfter:  observation.After.CustomerKeyHash,
		CapsuleID:             compatibilityOutcome.CapsuleID, CapsuleDigest: compatibilityOutcome.CapsuleDigest,
		BootImageDigest:              compatibilityOutcome.BootImageDigest,
		BootSignatureDigest:          compatibilityOutcome.BootSignatureDigest,
		BootPublicKeyFingerprint:     compatibilityOutcome.BootPublicKeyFingerprint,
		SignatureVerificationReceipt: compatibilityOutcome.SignatureVerificationReceipt,
		SignatureVerified:            compatibilityOutcome.SignatureVerified,
		RootDataDigest:               compatibilityOutcome.RootDataDigest,
		RootHashDigest:               compatibilityOutcome.RootHashDigest,
		UARTCaptureDigest:            uartDigest,
		HardwareObserved:             true, SecurityEnforced: false, MutationEligible: false,
	}, nil
}

func validateUARTCapture(capture []byte, outcome unfusedcompat.Outcome) error {
	if len(capture) == 0 {
		return errors.New("UART capture is empty")
	}
	if !utf8.Valid(capture) || strings.IndexByte(string(capture), 0) >= 0 {
		return errors.New("UART capture must be valid NUL-free UTF-8 text")
	}
	expected, err := ExpectedUARTMarkers(outcome)
	if err != nil {
		return err
	}
	counts := make([]int, len(expected))
	for _, rawLine := range strings.Split(string(capture), "\n") {
		line := strings.TrimSuffix(rawLine, "\r")
		if len(line) > maximumUARTLineBytes {
			return fmt.Errorf("UART capture contains a line longer than %d bytes", maximumUARTLineBytes)
		}
		for index, marker := range expected {
			prefix, _, _ := strings.Cut(marker, " ")
			if line != prefix && !strings.HasPrefix(line, prefix+" ") {
				continue
			}
			if line != marker {
				return fmt.Errorf("UART %s record does not exactly match the capsule binding", prefix)
			}
			counts[index]++
		}
	}
	for index, count := range counts {
		if count != 1 {
			prefix, _, _ := strings.Cut(expected[index], " ")
			return fmt.Errorf("UART capture contains %d exact %s records, want 1", count, prefix)
		}
	}
	return nil
}

func rawDigest(value []byte) string {
	digest := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(digest[:])
}
