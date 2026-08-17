// Package mediastager writes a closed, digest-bound set of images to one
// explicitly identified whole device and verifies the bytes through a later
// reopened readback pass.
package mediastager

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	PlanSchemaVersion    = "provisioning.kaiba.network/media-staging-plan/v1alpha1"
	ResultSchemaVersion  = "provisioning.kaiba.network/media-staging-result/v1alpha1"
	MinimumImageOffset   = uint64(1024 * 1024)
	ImageOffsetAlignment = uint64(4096)
)

type Mode string

const (
	ModeDevice  Mode = "device"
	ModeFixture Mode = "regular_file_fixture"
)

type Action string

const (
	ActionDryRun   Action = "dry_run"
	ActionStage    Action = "stage"
	ActionReadback Action = "readback"
)

type ImageRole string

const (
	RoleBootFilesystem ImageRole = "boot-filesystem"
	RoleRootData       ImageRole = "root-data"
	RoleRootHash       ImageRole = "root-hash"
)

var (
	ErrInvalidPlan      = errors.New("invalid media staging plan")
	ErrUnsafeTarget     = errors.New("target is unsafe for media staging")
	ErrTargetMismatch   = errors.New("target does not match the approved plan")
	ErrTargetBusy       = errors.New("target is exclusively locked")
	ErrImageMismatch    = errors.New("source image does not match the approved plan")
	ErrReadbackMismatch = errors.New("target readback does not match the approved plan")

	partitionAliasPattern = regexp.MustCompile(`-part[0-9]+$`)
	digestPattern         = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

type TargetSpec struct {
	Path              string `json:"path"`
	ExpectedIdentity  string `json:"expected_identity"`
	ExpectedSizeBytes uint64 `json:"expected_size_bytes"`
}

type ImageSpec struct {
	Role        ImageRole `json:"role"`
	Path        string    `json:"path"`
	Digest      string    `json:"digest"`
	SizeBytes   uint64    `json:"size_bytes"`
	OffsetBytes uint64    `json:"offset_bytes"`
}

type Plan struct {
	SchemaVersion string      `json:"schema_version"`
	Target        TargetSpec  `json:"target"`
	Images        []ImageSpec `json:"images"`
}

func (plan Plan) Validate(mode Mode) error {
	if plan.SchemaVersion != PlanSchemaVersion {
		return invalidPlan("unsupported schema_version %q", plan.SchemaVersion)
	}
	if mode != ModeDevice && mode != ModeFixture {
		return invalidPlan("unsupported target mode %q", mode)
	}
	if err := validateTargetPath(plan.Target.Path, mode); err != nil {
		return err
	}
	if !validIdentity(plan.Target.ExpectedIdentity) {
		return invalidPlan("expected_identity must be printable ASCII without path separators")
	}
	if plan.Target.ExpectedSizeBytes == 0 || plan.Target.ExpectedSizeBytes > math.MaxInt64 {
		return invalidPlan("expected_size_bytes must be between 1 and %d", int64(math.MaxInt64))
	}
	expectedRoles := [...]ImageRole{RoleBootFilesystem, RoleRootData, RoleRootHash}
	if len(plan.Images) != len(expectedRoles) {
		return invalidPlan("images must contain exactly boot-filesystem, root-data, and root-hash")
	}
	seenPaths := make(map[string]struct{}, len(plan.Images))
	var previousEnd uint64
	for index, image := range plan.Images {
		if image.Role != expectedRoles[index] {
			return invalidPlan("image %d must have role %q", index+1, expectedRoles[index])
		}
		if !cleanAbsolutePath(image.Path) {
			return invalidPlan("image %q path must be clean and absolute", image.Role)
		}
		if _, duplicate := seenPaths[image.Path]; duplicate {
			return invalidPlan("image paths must be distinct")
		}
		seenPaths[image.Path] = struct{}{}
		if !digestPattern.MatchString(image.Digest) {
			return invalidPlan("image %q digest must use canonical sha256 form", image.Role)
		}
		if image.SizeBytes == 0 || image.SizeBytes > math.MaxInt64 {
			return invalidPlan("image %q size_bytes must be between 1 and %d", image.Role, int64(math.MaxInt64))
		}
		if image.OffsetBytes > math.MaxInt64 {
			return invalidPlan("image %q offset_bytes exceeds the supported file offset", image.Role)
		}
		if image.OffsetBytes < MinimumImageOffset || image.OffsetBytes%ImageOffsetAlignment != 0 {
			return invalidPlan("image %q offset_bytes must be at least %d and %d-byte aligned", image.Role, MinimumImageOffset, ImageOffsetAlignment)
		}
		end := image.OffsetBytes + image.SizeBytes
		if end < image.OffsetBytes || end > plan.Target.ExpectedSizeBytes {
			return invalidPlan("image %q extent exceeds the expected target size", image.Role)
		}
		if index > 0 && image.OffsetBytes < previousEnd {
			return invalidPlan("image extents must be ordered and non-overlapping")
		}
		previousEnd = end
	}
	return nil
}

func validateTargetPath(path string, mode Mode) error {
	if !cleanAbsolutePath(path) {
		return invalidPlan("target path must be clean and absolute")
	}
	if mode == ModeDevice {
		const prefix = "/dev/disk/by-id/"
		if !strings.HasPrefix(path, prefix) {
			return invalidPlan("device target must be an immediate child of /dev/disk/by-id")
		}
		name := strings.TrimPrefix(path, prefix)
		if name == "" || name == "." || strings.Contains(name, "/") || partitionAliasPattern.MatchString(name) {
			return invalidPlan("device target must identify one whole-device by-id alias")
		}
		return nil
	}
	if path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return invalidPlan("regular-file fixture targets must be outside /dev")
	}
	return nil
}

func cleanAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

func validIdentity(value string) bool {
	if value == "" || len(value) > 255 || strings.Contains(value, "/") {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e {
			return false
		}
	}
	return true
}

func invalidPlan(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidPlan, fmt.Sprintf(format, arguments...))
}

type ImageResult struct {
	Role        ImageRole `json:"role"`
	Digest      string    `json:"digest"`
	SizeBytes   uint64    `json:"size_bytes"`
	OffsetBytes uint64    `json:"offset_bytes"`
}

type Result struct {
	SchemaVersion          string        `json:"schema_version"`
	Action                 Action        `json:"action"`
	PlanDigest             string        `json:"plan_digest"`
	TargetPath             string        `json:"target_path"`
	TargetIdentity         string        `json:"target_identity"`
	TargetSizeBytes        uint64        `json:"target_size_bytes"`
	Status                 string        `json:"status"`
	Images                 []ImageResult `json:"images"`
	ReopenedTarget         bool          `json:"reopened_target"`
	ColdPowerCycleObserved bool          `json:"cold_power_cycle_observed"`
	OneTimeSettingsChanged bool          `json:"one_time_settings_changed"`
	ReceiptDigest          string        `json:"receipt_digest"`
}

func resultFor(plan Plan, action Action, status string) Result {
	images := make([]ImageResult, len(plan.Images))
	for index, image := range plan.Images {
		images[index] = ImageResult{
			Role: image.Role, Digest: image.Digest, SizeBytes: image.SizeBytes, OffsetBytes: image.OffsetBytes,
		}
	}
	result := Result{
		SchemaVersion:   ResultSchemaVersion,
		Action:          action,
		PlanDigest:      mediaDigest("kaiba.provisioning.media-staging-plan.v1", plan),
		TargetPath:      plan.Target.Path,
		TargetIdentity:  plan.Target.ExpectedIdentity,
		TargetSizeBytes: plan.Target.ExpectedSizeBytes,
		Status:          status,
		Images:          images,
		ReopenedTarget:  action == ActionReadback,
	}
	result.ReceiptDigest = resultDigest(result)
	return result
}

func sumString(sum [sha256.Size]byte) string {
	return fmt.Sprintf("sha256:%x", sum[:])
}

func resultDigest(result Result) string {
	result.ReceiptDigest = ""
	return mediaDigest("kaiba.provisioning.media-staging-result.v1", result)
}

func mediaDigest(domain string, value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("marshal fixed media-staging value: %v", err))
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(encoded)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}

// VerifyResult checks that a serialized result is the exact deterministic
// receipt for this plan. A reopened readback deliberately remains distinct
// from evidence that an operator actually removed target power.
func VerifyResult(plan Plan, mode Mode, result Result) error {
	if err := plan.Validate(mode); err != nil {
		return err
	}
	var status string
	switch result.Action {
	case ActionDryRun:
		status = "validated_no_write"
	case ActionStage:
		status = "fsync_complete_readback_required"
	case ActionReadback:
		status = "reopened_readback_verified"
	default:
		return fmt.Errorf("%w: unsupported result action %q", ErrInvalidPlan, result.Action)
	}
	expected := resultFor(plan, result.Action, status)
	actualJSON, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("encode media staging result: %w", err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return fmt.Errorf("encode expected media staging result: %w", err)
	}
	if string(actualJSON) != string(expectedJSON) {
		return fmt.Errorf("%w: media staging receipt does not match the plan and action", ErrTargetMismatch)
	}
	return nil
}
