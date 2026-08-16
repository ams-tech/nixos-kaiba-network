// Package physicalrpi5 implements the concrete, one-lane Raspberry Pi 5
// hardware adapter used behind laneguard. Executable and bundle paths are
// supplied only by immutable daemon build configuration, never by an execute
// request.
package physicalrpi5

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const AdapterVersion = "provisioning.kaiba.network/physical-rpi5/v1alpha1"

const (
	ModeFresh = "fresh"
	ModeOwned = "owned"
	ModeAuto  = "auto_reconcile"
)

var (
	hexDigestPattern       = regexp.MustCompile(`^[0-9a-f]{64}$`)
	bootImageDigestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	nixStorePathPattern    = regexp.MustCompile(`^/nix/store/[0-9abcdfghijklmnpqrsvwxyz]{32}-[^/]+(?:/.*)?$`)
)

// ImmutablePaths is populated from Nix-store paths fixed into the lane-guard
// binary at build time. FreshReadback is intentionally distinct from the
// one-way FreshCommit payload.
type ImmutablePaths struct {
	RPIBootBinary        string
	GPIOSetBinary        string
	FreshReadbackBundle  string
	FreshCommitBundle    string
	OwnedReadbackBundle  string
	OwnedRecoveryBundle  string
	NegativeBootBundle   string
	RootIntegrityBundle  string
	RequireNixStorePaths bool
}

func (paths ImmutablePaths) Validate() error {
	values := map[string]string{
		"patched rpiboot":       paths.RPIBootBinary,
		"GPIO setter":           paths.GPIOSetBinary,
		"fresh readback bundle": paths.FreshReadbackBundle,
		"fresh commit bundle":   paths.FreshCommitBundle,
		"owned readback bundle": paths.OwnedReadbackBundle,
		"owned recovery bundle": paths.OwnedRecoveryBundle,
		"negative-boot bundle":  paths.NegativeBootBundle,
		"root-integrity bundle": paths.RootIntegrityBundle,
	}
	for label, value := range values {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("immutable %s path must be a clean absolute path", label)
		}
		if paths.RequireNixStorePaths && !nixStorePathPattern.MatchString(value) {
			return fmt.Errorf("immutable %s path must be in /nix/store", label)
		}
	}
	return nil
}

type Config struct {
	Paths                   ImmutablePaths
	InitialMode             string
	ExpectedCustomerKeyHash string
	ExpectedEEPROMHash      string
	ExpectedBootImageDigest string
	CommandTimeout          time.Duration
	UARTTimeout             time.Duration
	USBDisappearTimeout     time.Duration
	USBReappearTimeout      time.Duration
	USBPollInterval         time.Duration
	MinimumColdInterval     time.Duration
	MaximumOutputBytes      int
}

func (config *Config) applyDefaults() {
	if config.CommandTimeout == 0 {
		config.CommandTimeout = 2 * time.Minute
	}
	if config.UARTTimeout == 0 {
		config.UARTTimeout = 90 * time.Second
	}
	if config.USBDisappearTimeout == 0 {
		config.USBDisappearTimeout = 15 * time.Second
	}
	if config.USBReappearTimeout == 0 {
		config.USBReappearTimeout = 30 * time.Second
	}
	if config.USBPollInterval == 0 {
		config.USBPollInterval = 50 * time.Millisecond
	}
	if config.MinimumColdInterval == 0 {
		config.MinimumColdInterval = 2 * time.Second
	}
	if config.MaximumOutputBytes == 0 {
		config.MaximumOutputBytes = 256 * 1024
	}
}

func (config Config) Validate() error {
	if err := config.Paths.Validate(); err != nil {
		return err
	}
	if config.InitialMode != ModeFresh && config.InitialMode != ModeOwned && config.InitialMode != ModeAuto {
		return errors.New("initial target mode must be fresh, owned, or auto-reconcile")
	}
	for label, value := range map[string]string{
		"customer key hash": config.ExpectedCustomerKeyHash,
		"EEPROM hash":       config.ExpectedEEPROMHash,
	} {
		if !hexDigestPattern.MatchString(value) {
			return fmt.Errorf("expected %s must be 64 lowercase hexadecimal characters", label)
		}
	}
	if !bootImageDigestPattern.MatchString(config.ExpectedBootImageDigest) {
		return errors.New("expected boot image digest must use canonical sha256:<64 lowercase hexadecimal characters> form")
	}
	for label, value := range map[string]time.Duration{
		"command timeout": config.CommandTimeout, "UART timeout": config.UARTTimeout,
		"USB disappearance timeout": config.USBDisappearTimeout,
		"USB reappearance timeout":  config.USBReappearTimeout,
		"USB poll interval":         config.USBPollInterval, "minimum cold interval": config.MinimumColdInterval,
	} {
		if value <= 0 || value > 10*time.Minute {
			return fmt.Errorf("%s must be positive and at most ten minutes", label)
		}
	}
	if config.MaximumOutputBytes < 1024 || config.MaximumOutputBytes > 4*1024*1024 {
		return errors.New("maximum output bytes must be between 1024 and 4194304")
	}
	return nil
}

func normalizeDigest(value string) string {
	return strings.TrimPrefix(value, "sha256:")
}
