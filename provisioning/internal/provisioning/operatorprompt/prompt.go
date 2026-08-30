// Package operatorprompt provides the private, authenticated acknowledgement
// channel used for physical Raspberry Pi 5 boot-mode transitions. The trusted
// lane process creates prompts; the operator client can only acknowledge the
// exact prompt it receives.
package operatorprompt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/laneguard"
)

const (
	PromptSchemaVersion          = "provisioning.kaiba.network/operator-prompt/v1alpha2"
	AcknowledgementSchemaVersion = "provisioning.kaiba.network/operator-acknowledgement/v1alpha1"

	promptDigestDomain = "kaiba.provisioning.operator-prompt.v1alpha2"
	maxInstructions    = 2048
)

var (
	promptIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	digestPattern   = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

// Kind is a closed description of the physical operator action. It is derived
// from a trusted HardwareAction and is not accepted from the operator client.
type Kind string

const (
	KindHoldBOOTSEL         Kind = "hold_bootsel"
	KindReleaseBOOTSEL      Kind = "release_bootsel"
	KindNormalNoAction      Kind = "normal_no_action"
	KindDisconnectPower     Kind = "disconnect_power"
	KindConnectRPIBootPower Kind = "connect_rpiboot_power"
	KindConnectNormalPower  Kind = "connect_normal_power"
)

// Prompt binds the operator ceremony to one exact authority-bound hardware
// action. Digest covers every field other than Digest itself.
type Prompt struct {
	SchemaVersion string                   `json:"schema_version"`
	ID            string                   `json:"id"`
	Digest        string                   `json:"digest"`
	Kind          Kind                     `json:"kind"`
	Instructions  string                   `json:"instructions"`
	ExpiresAt     time.Time                `json:"expires_at"`
	Action        laneguard.HardwareAction `json:"action"`
}

// New constructs a digest-bound prompt. Only the trusted lane process should
// call New; the wire client has no API for constructing or selecting prompts.
func New(action laneguard.HardwareAction, kind Kind, id, instructions string, expiresAt time.Time) (Prompt, error) {
	prompt := Prompt{
		SchemaVersion: PromptSchemaVersion,
		ID:            id,
		Kind:          kind,
		Instructions:  instructions,
		ExpiresAt:     expiresAt.UTC(),
		Action:        action,
	}
	if err := prompt.validateBody(); err != nil {
		return Prompt{}, err
	}
	digest, err := prompt.derivedDigest()
	if err != nil {
		return Prompt{}, err
	}
	prompt.Digest = digest
	return prompt, nil
}

// Validate checks both the closed prompt policy and its canonical digest.
func (prompt Prompt) Validate() error {
	if err := prompt.validateBody(); err != nil {
		return err
	}
	if !digestPattern.MatchString(prompt.Digest) {
		return errors.New("operator prompt requires a canonical digest")
	}
	derived, err := prompt.derivedDigest()
	if err != nil {
		return err
	}
	if prompt.Digest != derived {
		return errors.New("operator prompt digest does not match its contents")
	}
	return nil
}

func (prompt Prompt) validateBody() error {
	if prompt.SchemaVersion != PromptSchemaVersion {
		return fmt.Errorf("unsupported operator prompt schema %q", prompt.SchemaVersion)
	}
	if !promptIDPattern.MatchString(prompt.ID) {
		return errors.New("operator prompt ID is invalid")
	}
	if !utf8.ValidString(prompt.Instructions) || prompt.Instructions == "" ||
		strings.TrimSpace(prompt.Instructions) != prompt.Instructions || len(prompt.Instructions) > maxInstructions ||
		strings.IndexFunc(prompt.Instructions, unicode.IsControl) >= 0 {
		return errors.New("operator prompt instructions must be bounded, printable, and exact")
	}
	if prompt.ExpiresAt.IsZero() {
		return errors.New("operator prompt requires an expiry")
	}
	if err := prompt.Action.Validate(); err != nil {
		return fmt.Errorf("operator prompt action: %w", err)
	}
	switch prompt.Kind {
	case KindHoldBOOTSEL:
		if prompt.Action.RequestedBootMode != laneguard.BootModeRPIBoot || prompt.Action.PowerControlMode != laneguard.PowerControlRelay {
			return errors.New("hold-BOOTSEL prompt requires a relay-powered RPIBOOT hardware action")
		}
	case KindReleaseBOOTSEL:
		if prompt.Action.RequestedBootMode != laneguard.BootModeRPIBoot {
			return errors.New("release-BOOTSEL prompt requires an RPIBOOT hardware action")
		}
	case KindNormalNoAction:
		if prompt.Action.RequestedBootMode != laneguard.BootModeNormal || prompt.Action.PowerControlMode != laneguard.PowerControlRelay {
			return errors.New("normal no-action prompt requires a relay-powered normal-mode hardware action")
		}
	case KindDisconnectPower:
		if (prompt.Action.RequestedBootMode != laneguard.BootModeRPIBoot && prompt.Action.RequestedBootMode != laneguard.BootModeNormal) ||
			prompt.Action.PowerControlMode != laneguard.PowerControlManual {
			return errors.New("disconnect-power prompt requires a manual-power RPIBOOT or normal-mode hardware action")
		}
	case KindConnectRPIBootPower:
		if prompt.Action.RequestedBootMode != laneguard.BootModeRPIBoot || prompt.Action.PowerControlMode != laneguard.PowerControlManual {
			return errors.New("RPIBOOT power-connection prompt requires a manual-power RPIBOOT hardware action")
		}
	case KindConnectNormalPower:
		if prompt.Action.RequestedBootMode != laneguard.BootModeNormal || prompt.Action.PowerControlMode != laneguard.PowerControlManual {
			return errors.New("normal power-connection prompt requires a manual-power normal-mode hardware action")
		}
	default:
		return errors.New("operator prompt kind is outside the closed policy")
	}
	return nil
}

func (prompt Prompt) derivedDigest() (string, error) {
	document := struct {
		Domain       string                   `json:"domain"`
		Schema       string                   `json:"schema_version"`
		ID           string                   `json:"id"`
		Kind         Kind                     `json:"kind"`
		Instructions string                   `json:"instructions"`
		ExpiresAt    time.Time                `json:"expires_at"`
		Action       laneguard.HardwareAction `json:"action"`
	}{
		Domain: promptDigestDomain, Schema: prompt.SchemaVersion, ID: prompt.ID,
		Kind: prompt.Kind, Instructions: prompt.Instructions, ExpiresAt: prompt.ExpiresAt.UTC(), Action: prompt.Action,
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return "", fmt.Errorf("encode operator prompt digest document: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

// ConfirmationPhrase returns the exact ceremony text the command-line client
// requires. It includes the complete prompt ID and a collision-resistant
// prefix of the content digest, so a bare "yes" can never acknowledge a prompt.
func ConfirmationPhrase(prompt Prompt) (string, error) {
	if err := prompt.Validate(); err != nil {
		return "", err
	}
	hexDigest := strings.TrimPrefix(prompt.Digest, "sha256:")
	return "CONFIRM " + prompt.ID + " " + hexDigest[:16], nil
}

// Acknowledgement is generated by the server after peer authentication. The
// client supplies only the prompt ID and digest it received.
type Acknowledgement struct {
	SchemaVersion  string                 `json:"schema_version"`
	PromptID       string                 `json:"prompt_id"`
	PromptDigest   string                 `json:"prompt_digest"`
	Peer           laneguard.OperatorPeer `json:"peer"`
	AcknowledgedAt time.Time              `json:"acknowledged_at"`
}

func (ack Acknowledgement) validateFor(prompt Prompt) error {
	if ack.SchemaVersion != AcknowledgementSchemaVersion || ack.PromptID != prompt.ID || ack.PromptDigest != prompt.Digest {
		return errors.New("operator acknowledgement does not match the prompt")
	}
	if ack.Peer.PID <= 0 || ack.AcknowledgedAt.IsZero() || !ack.AcknowledgedAt.Before(prompt.ExpiresAt) {
		return errors.New("operator acknowledgement has invalid peer or timing evidence")
	}
	return nil
}
