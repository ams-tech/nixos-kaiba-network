package rpi5

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	ManifestSchema      = "kaiba.rpi5-probe-bundle/v1alpha1"
	MaxManifestSize     = 64 * 1024
	MaxCommandOutput    = 256 * 1024
	DefaultProbeTimeout = 60 * time.Second
	SafeRecoveryConfig  = "recovery_metadata=1\n"
	BroadcomVendorID    = "0a5c"
	BCM2712ProductID    = "2712"
)

var (
	usbPathPattern = regexp.MustCompile(`^[0-9]+-[0-9]+(?:\.[0-9]+)*$`)
	laneIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// BundleManifest pins every executable input to a live probe. Files must have
// exactly the bootcode5.bin and config.txt keys. Digests use sha256:<hex>.
type BundleManifest struct {
	Schema       string            `json:"schema"`
	ToolVersion  string            `json:"tool_version"`
	ToolSHA256   string            `json:"tool_sha256"`
	BundleSHA256 string            `json:"bundle_sha256"`
	Files        map[string]string `json:"files"`
}

// ValidatedBundle is returned only after all immutable probe inputs have been
// checked. Callers should not cache it across acquisitions: validation is a
// safety boundary and is repeated immediately before every rpiboot run.
type ValidatedBundle struct {
	Manifest       BundleManifest
	ToolDigest     string
	BundleDigest   string
	FirmwareDigest string
	ConfigDigest   string
}

// ProbeRequest binds the physical provisioning lane and exact USB topology
// path. Neither value is inferred from connected hardware.
type ProbeRequest struct {
	LaneID  string
	USBPath string
}

// EvidenceSource is the platform-local acquisition boundary.
type EvidenceSource interface {
	Acquire(context.Context, ProbeRequest) (RawEvidence, error)
}

// CommandRunner permits deterministic tests without invoking rpiboot.
type CommandRunner interface {
	Run(context.Context, string, []string, io.Writer, io.Writer) error
}

// ExecRunner invokes an executable directly; it never uses a shell.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, executable string, args []string, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, executable, args...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

// USBTarget is the result of an exact preflight lookup. Token changes if the
// sysfs object at the requested physical path is replaced.
type USBTarget struct {
	USBPath string
	Token   string
}

// TargetVerifier rejects absent, ambiguous, or unexpected RPIBOOT targets.
type TargetVerifier interface {
	Verify(context.Context, string) (USBTarget, error)
}

// SysFSVerifier verifies the single BCM2712 RPIBOOT device exposed by Linux.
type SysFSVerifier struct{ Root string }

func (v SysFSVerifier) Verify(ctx context.Context, requested string) (USBTarget, error) {
	if !usbPathPattern.MatchString(requested) {
		return USBTarget{}, fmt.Errorf("invalid USB path %q", requested)
	}
	root := v.Root
	if root == "" {
		root = "/sys/bus/usb/devices"
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return USBTarget{}, fmt.Errorf("read USB sysfs: %w", err)
	}
	type candidate struct{ name, token string }
	candidates := make([]candidate, 0, 1)
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return USBTarget{}, err
		}
		name := entry.Name()
		if !usbPathPattern.MatchString(name) {
			continue
		}
		base := filepath.Join(root, name)
		vendor, err := readSysfsValue(filepath.Join(base, "idVendor"))
		if err != nil {
			continue
		}
		product, err := readSysfsValue(filepath.Join(base, "idProduct"))
		if err != nil {
			continue
		}
		if strings.ToLower(vendor) != BroadcomVendorID || strings.ToLower(product) != BCM2712ProductID {
			continue
		}
		token, err := sysfsToken(base, name)
		if err != nil {
			return USBTarget{}, fmt.Errorf("identify USB target %s: %w", name, err)
		}
		candidates = append(candidates, candidate{name: name, token: token})
	}
	if len(candidates) == 0 {
		return USBTarget{}, errors.New("no BCM2712 RPIBOOT target is present")
	}
	if len(candidates) != 1 {
		return USBTarget{}, fmt.Errorf("expected one BCM2712 RPIBOOT target, found %d", len(candidates))
	}
	if candidates[0].name != requested {
		return USBTarget{}, fmt.Errorf("BCM2712 RPIBOOT target is at %s, not requested path %s", candidates[0].name, requested)
	}
	return USBTarget{USBPath: requested, Token: candidates[0].token}, nil
}

// LiveConfig contains build-time pinned paths. A production CLI must populate
// these from its package build rather than user flags or environment variables.
type LiveConfig struct {
	BinaryPath   string
	BundlePath   string
	ManifestPath string
	Timeout      time.Duration
	Runner       CommandRunner
	Verifier     TargetVerifier
}

// LiveSource performs a guarded, non-persistent rpiboot metadata acquisition.
type LiveSource struct{ Config LiveConfig }

func (s LiveSource) Acquire(ctx context.Context, request ProbeRequest) (RawEvidence, error) {
	if !laneIDPattern.MatchString(request.LaneID) {
		return RawEvidence{}, fmt.Errorf("invalid lane ID %q", request.LaneID)
	}
	if !usbPathPattern.MatchString(request.USBPath) {
		return RawEvidence{}, fmt.Errorf("invalid USB path %q", request.USBPath)
	}
	if err := validateAbsolutePaths(s.Config); err != nil {
		return RawEvidence{}, err
	}
	timeout := s.Config.Timeout
	if timeout == 0 {
		timeout = DefaultProbeTimeout
	}
	if timeout < 0 {
		return RawEvidence{}, errors.New("probe timeout must not be negative")
	}
	probeCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	verifier := s.Config.Verifier
	if verifier == nil {
		verifier = SysFSVerifier{}
	}
	first, err := verifier.Verify(probeCtx, request.USBPath)
	if err != nil {
		return RawEvidence{}, fmt.Errorf("verify target: %w", err)
	}
	validated, err := ValidateBundle(s.Config.BinaryPath, s.Config.BundlePath, s.Config.ManifestPath)
	if err != nil {
		return RawEvidence{}, fmt.Errorf("validate probe bundle: %w", err)
	}
	second, err := verifier.Verify(probeCtx, request.USBPath)
	if err != nil {
		return RawEvidence{}, fmt.Errorf("reverify target: %w", err)
	}
	if first != second {
		return RawEvidence{}, errors.New("USB target changed while preparing the probe")
	}

	runner := s.Config.Runner
	if runner == nil {
		runner = ExecRunner{}
	}
	stdout := &limitedBuffer{limit: MaxCommandOutput}
	stderr := &limitedBuffer{limit: MaxCommandOutput}
	// The packaged rpiboot carries the audited upstream stdout-metadata
	// backport. -j selects file-based output, so it is intentionally absent.
	args := []string{"-p", request.USBPath, "-d", s.Config.BundlePath}
	err = runner.Run(probeCtx, s.Config.BinaryPath, args, stdout, stderr)
	// A complete mutation result is the highest-priority outcome, even if
	// rpiboot also failed or exceeded a capture bound after reporting it.
	if candidate, extractErr := ExtractMetadataObject(stdout.buf.Bytes()); extractErr == nil {
		if mutationErr := rejectMutationSuccess(candidate); mutationErr != nil {
			return RawEvidence{}, mutationErr
		}
	}
	if stdout.overflow || stderr.overflow {
		return RawEvidence{}, fmt.Errorf("rpiboot output exceeds %d bytes", MaxCommandOutput)
	}
	if err != nil {
		if probeCtx.Err() != nil {
			return RawEvidence{}, fmt.Errorf("rpiboot did not complete: %w", probeCtx.Err())
		}
		return RawEvidence{}, fmt.Errorf("rpiboot failed: %w (stderr bytes: %d)", err, stderr.buf.Len())
	}
	metadata, err := ExtractMetadataObject(stdout.buf.Bytes())
	if err != nil {
		return RawEvidence{}, err
	}
	// Scan the strict flat object for mutation results before normalization so
	// an unrelated malformed or missing identifier cannot mask an incident.
	if err := rejectMutationSuccess(metadata); err != nil {
		return RawEvidence{}, err
	}
	return RawEvidence{
		Metadata: append([]byte(nil), metadata...),
		Provenance: Provenance{
			Source: "live-rpiboot", LaneID: request.LaneID, USBPath: request.USBPath,
			ToolVersion: validated.Manifest.ToolVersion, ToolDigest: validated.ToolDigest,
			BundleDigest: validated.BundleDigest, FirmwareDigest: validated.FirmwareDigest,
			ConfigDigest: validated.ConfigDigest,
		},
	}, nil
}

func rejectMutationSuccess(metadata []byte) error {
	mutationFields, err := scanMutationSuccessFields(metadata)
	if err != nil {
		return fmt.Errorf("scan live metadata results: %w", err)
	}
	if len(mutationFields) != 0 {
		return fmt.Errorf("probe safety violation: mutation success reported by %s", strings.Join(mutationFields, ", "))
	}
	return nil
}

func validateAbsolutePaths(config LiveConfig) error {
	for name, value := range map[string]string{"rpiboot binary": config.BinaryPath, "probe bundle": config.BundlePath, "probe manifest": config.ManifestPath} {
		if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value {
			return fmt.Errorf("%s path must be an absolute clean path", name)
		}
	}
	return nil
}

// ValidateBundle strictly parses a manifest and checks the executable and the
// exact two-file metadata-only payload against it.
func ValidateBundle(binaryPath, bundlePath, manifestPath string) (ValidatedBundle, error) {
	manifestBytes, err := readRegularFile(manifestPath, MaxManifestSize, false)
	if err != nil {
		return ValidatedBundle{}, fmt.Errorf("read manifest: %w", err)
	}
	manifest, err := parseManifest(manifestBytes)
	if err != nil {
		return ValidatedBundle{}, err
	}
	if manifest.Schema != ManifestSchema {
		return ValidatedBundle{}, fmt.Errorf("unsupported manifest schema %q", manifest.Schema)
	}
	if len(manifest.ToolVersion) == 0 || len(manifest.ToolVersion) > 256 || strings.ContainsAny(manifest.ToolVersion, "\r\n\x00") {
		return ValidatedBundle{}, errors.New("manifest tool_version is invalid")
	}
	if err := validateDigest("tool_sha256", manifest.ToolSHA256); err != nil {
		return ValidatedBundle{}, err
	}
	if err := validateDigest("bundle_sha256", manifest.BundleSHA256); err != nil {
		return ValidatedBundle{}, err
	}
	if len(manifest.Files) != 2 {
		return ValidatedBundle{}, errors.New("manifest must describe exactly two bundle files")
	}
	for _, name := range []string{"bootcode5.bin", "config.txt"} {
		digest, ok := manifest.Files[name]
		if !ok {
			return ValidatedBundle{}, fmt.Errorf("manifest is missing %s", name)
		}
		if err := validateDigest("files."+name, digest); err != nil {
			return ValidatedBundle{}, err
		}
	}
	for name := range manifest.Files {
		if name != "bootcode5.bin" && name != "config.txt" {
			return ValidatedBundle{}, fmt.Errorf("manifest contains forbidden file %q", name)
		}
	}

	binaryDigest, err := hashRegularFile(binaryPath, true)
	if err != nil {
		return ValidatedBundle{}, fmt.Errorf("hash rpiboot: %w", err)
	}
	if binaryDigest != manifest.ToolSHA256 {
		return ValidatedBundle{}, errors.New("rpiboot digest does not match manifest")
	}
	info, err := os.Lstat(bundlePath)
	if err != nil {
		return ValidatedBundle{}, fmt.Errorf("inspect bundle directory: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ValidatedBundle{}, errors.New("probe bundle must be a non-symlink directory")
	}
	entries, err := os.ReadDir(bundlePath)
	if err != nil {
		return ValidatedBundle{}, fmt.Errorf("read bundle directory: %w", err)
	}
	if len(entries) != 2 {
		return ValidatedBundle{}, fmt.Errorf("probe bundle must contain exactly two files, found %d", len(entries))
	}
	for _, entry := range entries {
		if _, ok := manifest.Files[entry.Name()]; !ok {
			return ValidatedBundle{}, fmt.Errorf("probe bundle contains forbidden file %q", entry.Name())
		}
		if entry.Type()&os.ModeSymlink != 0 || !entry.Type().IsRegular() {
			return ValidatedBundle{}, fmt.Errorf("probe bundle file %q is not a regular non-symlink file", entry.Name())
		}
	}
	actual := make(map[string]string, 2)
	for _, name := range []string{"bootcode5.bin", "config.txt"} {
		digest, err := hashRegularFile(filepath.Join(bundlePath, name), false)
		if err != nil {
			return ValidatedBundle{}, fmt.Errorf("hash bundle file %s: %w", name, err)
		}
		if digest != manifest.Files[name] {
			return ValidatedBundle{}, fmt.Errorf("bundle file %s digest does not match manifest", name)
		}
		actual[name] = digest
	}
	config, err := readRegularFile(filepath.Join(bundlePath, "config.txt"), len(SafeRecoveryConfig)+1, false)
	if err != nil {
		return ValidatedBundle{}, fmt.Errorf("read config.txt: %w", err)
	}
	if string(config) != SafeRecoveryConfig {
		return ValidatedBundle{}, errors.New("config.txt is not the exact metadata-only configuration")
	}
	bundleDigest := ComputeBundleDigest(actual)
	if bundleDigest != manifest.BundleSHA256 {
		return ValidatedBundle{}, errors.New("probe bundle digest does not match manifest")
	}
	return ValidatedBundle{
		Manifest: manifest, ToolDigest: binaryDigest, BundleDigest: bundleDigest,
		FirmwareDigest: actual["bootcode5.bin"], ConfigDigest: actual["config.txt"],
	}, nil
}

// ComputeBundleDigest is a domain-separated digest over the sorted filename
// and sha256 pairs. It deliberately does not depend on directory metadata.
func ComputeBundleDigest(files map[string]string) string {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	h := sha256.New()
	_, _ = h.Write([]byte("kaiba.rpi5.probe-bundle.v1\x00"))
	for _, name := range names {
		_, _ = h.Write([]byte(name))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(files[name]))
		_, _ = h.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

func parseManifest(data []byte) (BundleManifest, error) {
	if len(data) == 0 || len(data) > MaxManifestSize {
		return BundleManifest{}, errors.New("manifest size is invalid")
	}
	if err := validateNoDuplicateJSON(data); err != nil {
		return BundleManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var manifest BundleManifest
	if err := dec.Decode(&manifest); err != nil {
		return BundleManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	if err := requireJSONEOF(dec); err != nil {
		return BundleManifest{}, fmt.Errorf("decode manifest: %w", err)
	}
	return manifest, nil
}

func validateNoDuplicateJSON(data []byte) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	token, err := dec.Token()
	if err != nil {
		return err
	}
	if err := validateJSONToken(dec, token); err != nil {
		return err
	}
	return requireJSONEOF(dec)
}

func validateJSONToken(dec *json.Decoder, token json.Token) error {
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]struct{}{}
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("object key %q is duplicated", key)
			}
			seen[key] = struct{}{}
			value, err := dec.Token()
			if err != nil {
				return err
			}
			if err := validateJSONToken(dec, value); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for dec.More() {
			value, err := dec.Token()
			if err != nil {
				return err
			}
			if err := validateJSONToken(dec, value); err != nil {
				return err
			}
		}
		closing, err := dec.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}

func requireJSONEOF(dec *json.Decoder) error {
	if token, err := dec.Token(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("trailing JSON value %v", token)
	}
	return nil
}

func validateDigest(name, value string) error {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || !hex64Pattern.MatchString(value[len("sha256:"):]) || value != strings.ToLower(value) {
		return fmt.Errorf("manifest %s is not a canonical SHA-256 digest", name)
	}
	return nil
}

func readRegularFile(path string, maxSize int, executable bool) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("file is not a regular non-symlink file")
	}
	if executable && info.Mode().Perm()&0111 == 0 {
		return nil, errors.New("file is not executable")
	}
	if info.Size() > int64(maxSize) {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSize)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("file changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxSize)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxSize {
		return nil, fmt.Errorf("file exceeds %d bytes", maxSize)
	}
	return data, nil
}

func hashRegularFile(path string, executable bool) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("file is not a regular non-symlink file")
	}
	if executable && info.Mode().Perm()&0111 == 0 {
		return "", errors.New("file is not executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !os.SameFile(info, opened) {
		return "", errors.New("file changed while opening")
	}
	h := sha256.New()
	if _, err := io.Copy(h, file); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

func readSysfsValue(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func sysfsToken(base, name string) (string, error) {
	real, err := filepath.EvalSymlinks(base)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(base)
	if err != nil {
		return "", err
	}
	identity := fmt.Sprintf("%s:%s:%d", name, real, info.ModTime().UnixNano())
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		identity += fmt.Sprintf(":%d:%d", stat.Dev, stat.Ino)
	}
	for _, field := range []string{"busnum", "devnum", "devpath"} {
		if value, err := readSysfsValue(filepath.Join(base, field)); err == nil {
			identity += ":" + field + "=" + value
		}
	}
	return digestBytes([]byte(identity)), nil
}

type limitedBuffer struct {
	buf      bytes.Buffer
	limit    int
	overflow bool
}

func (w *limitedBuffer) Write(p []byte) (int, error) {
	remaining := w.limit - w.buf.Len()
	if remaining <= 0 {
		w.overflow = true
		return 0, errors.New("output limit exceeded")
	}
	if len(p) > remaining {
		_, _ = w.buf.Write(p[:remaining])
		w.overflow = true
		return remaining, errors.New("output limit exceeded")
	}
	return w.buf.Write(p)
}

// ExtractMetadataObject extracts exactly one JSON object from rpiboot's mixed
// informational stdout. A second object, an unterminated object, or malformed
// object-like output is rejected instead of guessed around.
func ExtractMetadataObject(output []byte) ([]byte, error) {
	var objects [][]byte
	for offset := 0; offset < len(output); {
		rel := bytes.IndexByte(output[offset:], '{')
		if rel < 0 {
			break
		}
		start := offset + rel
		end, err := matchingJSONObjectEnd(output, start)
		if err != nil {
			return nil, err
		}
		candidate := bytes.TrimSpace(output[start:end])
		if !json.Valid(candidate) {
			return nil, errors.New("rpiboot stdout contains a malformed JSON object")
		}
		objects = append(objects, append([]byte(nil), candidate...))
		offset = end
	}
	if len(objects) == 0 {
		return nil, errors.New("rpiboot stdout contains no metadata JSON object")
	}
	if len(objects) != 1 {
		return nil, fmt.Errorf("rpiboot stdout contains %d JSON objects", len(objects))
	}
	return objects[0], nil
}

func matchingJSONObjectEnd(data []byte, start int) (int, error) {
	depth := 0
	inString, escaped := false, false
	for i := start; i < len(data); i++ {
		c := data[i]
		if inString {
			if escaped {
				escaped = false
				continue
			}
			if c == '\\' {
				escaped = true
				continue
			}
			if c == '"' {
				inString = false
			}
			continue
		}
		if c == '"' {
			inString = true
			continue
		}
		switch c {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i + 1, nil
			}
			if depth < 0 {
				return 0, errors.New("rpiboot stdout contains an unmatched closing brace")
			}
		}
	}
	return 0, errors.New("rpiboot stdout contains an unterminated JSON object")
}
