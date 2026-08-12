package rpi5

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

type fakeRunner struct {
	stdout     string
	stderr     string
	err        error
	waitForCtx bool
	executable string
	args       []string
	calls      int
}

func (r *fakeRunner) Run(ctx context.Context, executable string, args []string, stdout, stderr io.Writer) error {
	r.calls++
	r.executable = executable
	r.args = append([]string(nil), args...)
	if r.waitForCtx {
		<-ctx.Done()
		return ctx.Err()
	}
	if r.stdout != "" {
		_, _ = io.WriteString(stdout, r.stdout)
	}
	if r.stderr != "" {
		_, _ = io.WriteString(stderr, r.stderr)
	}
	return r.err
}

type sequenceVerifier struct {
	targets []USBTarget
	err     error
	calls   int
}

func (v *sequenceVerifier) Verify(_ context.Context, path string) (USBTarget, error) {
	v.calls++
	if v.err != nil {
		return USBTarget{}, v.err
	}
	index := v.calls - 1
	if index >= len(v.targets) {
		index = len(v.targets) - 1
	}
	target := v.targets[index]
	if target.USBPath == "" {
		target.USBPath = path
	}
	return target, nil
}

func TestLiveSourceAcquireUsesExactSafeInvocation(t *testing.T) {
	config, manifest := makeLiveConfig(t)
	runner := &fakeRunner{stdout: "RPIBOOT log\n" + validMetadata + "\nDone\n"}
	verifier := &sequenceVerifier{targets: []USBTarget{{USBPath: "1-2.3", Token: "same"}}}
	config.Runner, config.Verifier = runner, verifier
	source := LiveSource{Config: config}

	got, err := source.Acquire(context.Background(), ProbeRequest{LaneID: "lane-1", USBPath: "1-2.3"})
	if err != nil {
		t.Fatalf("Acquire() error = %v", err)
	}
	if runner.calls != 1 || verifier.calls != 2 {
		t.Fatalf("calls runner=%d verifier=%d", runner.calls, verifier.calls)
	}
	if runner.executable != config.BinaryPath {
		t.Fatalf("executable = %q", runner.executable)
	}
	wantArgs := []string{"-p", "1-2.3", "-d", config.BundlePath}
	if !reflect.DeepEqual(runner.args, wantArgs) {
		t.Fatalf("args = %#v, want %#v", runner.args, wantArgs)
	}
	if string(got.Metadata) != validMetadata {
		t.Fatalf("metadata differs: %q", got.Metadata)
	}
	if got.Provenance.Source != "live-rpiboot" || got.Provenance.LaneID != "lane-1" || got.Provenance.USBPath != "1-2.3" {
		t.Fatalf("provenance = %#v", got.Provenance)
	}
	if got.Provenance.ToolDigest != manifest.ToolSHA256 || got.Provenance.BundleDigest != manifest.BundleSHA256 || got.Provenance.ToolVersion != manifest.ToolVersion {
		t.Fatalf("digest provenance = %#v", got.Provenance)
	}
}

func TestLiveSourceRejectsUnsafeOrFailedAcquisition(t *testing.T) {
	mutation := strings.Replace(validMetadata, `"SIGNATURE_MODE": "0"`, `"EEPROM_UPDATE": "success", "SIGNATURE_MODE": "0"`, 1)
	tests := []struct {
		name      string
		configure func(*LiveConfig, *fakeRunner, *sequenceVerifier)
		want      string
	}{
		{"mutation result", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) { r.stdout = mutation }, "safety violation"},
		{"command failure", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) {
			r.err = errors.New("exit status 1")
			r.stderr = "private diagnostic"
		}, "rpiboot failed"},
		{"mutation result with command failure", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) {
			r.stdout = mutation
			r.err = errors.New("exit status 1")
		}, "safety violation"},
		{"missing object", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) { r.stdout = "only logs" }, "no metadata"},
		{"two objects", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) { r.stdout = validMetadata + validMetadata }, "2 JSON objects"},
		{"oversize stdout", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) {
			r.stdout = strings.Repeat("x", MaxCommandOutput+1)
		}, "output exceeds"},
		{"oversize stderr", func(_ *LiveConfig, r *fakeRunner, _ *sequenceVerifier) {
			r.stderr = strings.Repeat("x", MaxCommandOutput+1)
		}, "output exceeds"},
		{"target replacement", func(_ *LiveConfig, _ *fakeRunner, v *sequenceVerifier) {
			v.targets = []USBTarget{{USBPath: "1-2.3", Token: "first"}, {USBPath: "1-2.3", Token: "second"}}
		}, "target changed"},
		{"verifier failure", func(_ *LiveConfig, _ *fakeRunner, v *sequenceVerifier) { v.err = errors.New("ambiguous") }, "verify target"},
		{"invalid lane", func(_ *LiveConfig, _ *fakeRunner, _ *sequenceVerifier) {}, "invalid lane"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, _ := makeLiveConfig(t)
			runner := &fakeRunner{stdout: validMetadata}
			verifier := &sequenceVerifier{targets: []USBTarget{{USBPath: "1-2.3", Token: "same"}}}
			config.Runner, config.Verifier = runner, verifier
			tt.configure(&config, runner, verifier)
			lane := "lane-1"
			if tt.name == "invalid lane" {
				lane = "../lane"
			}
			_, err := (LiveSource{Config: config}).Acquire(context.Background(), ProbeRequest{LaneID: lane, USBPath: "1-2.3"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
			if tt.name == "command failure" && strings.Contains(err.Error(), "private diagnostic") {
				t.Fatal("stderr contents leaked into error")
			}
		})
	}
}

func TestLiveSourceReportsMutationBeforeOtherNormalizationErrors(t *testing.T) {
	base := strings.Replace(validMetadata, `"EEPROM_HASH":`, `"OTP_BURN": "success", "EEPROM_HASH":`, 1)
	tests := map[string]string{
		"missing required field": removeJSONLine(base, `"USER_SERIAL_NUM"`),
		"duplicate field":        strings.Replace(base, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": "0", "JTAG_LOCKED": "1"`, 1),
		"nested field":           strings.Replace(base, `"JTAG_LOCKED": "0"`, `"JTAG_LOCKED": {"value":"0"}`, 1),
	}
	for name, raw := range tests {
		t.Run(name, func(t *testing.T) {
			config, _ := makeLiveConfig(t)
			config.Runner = &fakeRunner{stdout: raw}
			config.Verifier = &sequenceVerifier{targets: []USBTarget{{USBPath: "1-2.3", Token: "same"}}}
			_, err := (LiveSource{Config: config}).Acquire(context.Background(), ProbeRequest{LaneID: "lane-1", USBPath: "1-2.3"})
			if err == nil || !strings.Contains(err.Error(), "probe safety violation") || !strings.Contains(err.Error(), "OTP_BURN") {
				t.Fatalf("error = %v, want mutation safety violation", err)
			}
		})
	}
}

func TestLiveSourceTimeoutAndParentCancellation(t *testing.T) {
	for _, tt := range []struct {
		name    string
		parent  context.Context
		timeout time.Duration
		want    string
	}{
		{"timeout", context.Background(), time.Millisecond, "deadline exceeded"},
		{"parent cancellation", canceledContext(), time.Second, "canceled"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			config, _ := makeLiveConfig(t)
			config.Timeout = tt.timeout
			config.Runner = &fakeRunner{waitForCtx: true}
			config.Verifier = &sequenceVerifier{targets: []USBTarget{{USBPath: "1-2.3", Token: "same"}}}
			_, err := (LiveSource{Config: config}).Acquire(tt.parent, ProbeRequest{LaneID: "lane-1", USBPath: "1-2.3"})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateBundleRejectsTampering(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(t *testing.T, c LiveConfig)
	}{
		{"extra file", func(t *testing.T, c LiveConfig) {
			mustWrite(t, filepath.Join(c.BundlePath, "pieeprom.bin"), []byte("danger"), 0444)
		}},
		{"dangerous config", func(t *testing.T, c LiveConfig) {
			mustWrite(t, filepath.Join(c.BundlePath, "config.txt"), []byte("recovery_metadata=1\nprogram_pubkey=1\n"), 0444)
		}},
		{"firmware changed", func(t *testing.T, c LiveConfig) {
			mustWrite(t, filepath.Join(c.BundlePath, "bootcode5.bin"), []byte("changed"), 0444)
		}},
		{"tool changed", func(t *testing.T, c LiveConfig) { mustWrite(t, c.BinaryPath, []byte("changed"), 0555) }},
		{"manifest duplicate", func(t *testing.T, c LiveConfig) {
			raw, _ := os.ReadFile(c.ManifestPath)
			raw = []byte(strings.Replace(string(raw), `"schema":`, `"schema":"duplicate","schema":`, 1))
			mustWrite(t, c.ManifestPath, raw, 0444)
		}},
		{"manifest unknown", func(t *testing.T, c LiveConfig) {
			raw, _ := os.ReadFile(c.ManifestPath)
			raw = []byte(strings.Replace(string(raw), `"schema":`, `"owner":"operator","schema":`, 1))
			mustWrite(t, c.ManifestPath, raw, 0444)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config, _ := makeLiveConfig(t)
			tt.mutate(t, config)
			if _, err := ValidateBundle(config.BinaryPath, config.BundlePath, config.ManifestPath); err == nil {
				t.Fatal("ValidateBundle() unexpectedly succeeded")
			}
		})
	}
}

func TestValidateBundleRejectsSymlinks(t *testing.T) {
	config, _ := makeLiveConfig(t)
	real := filepath.Join(t.TempDir(), "firmware")
	mustWrite(t, real, []byte("signed recovery firmware"), 0444)
	if err := os.Remove(filepath.Join(config.BundlePath, "bootcode5.bin")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(config.BundlePath, "bootcode5.bin")); err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateBundle(config.BinaryPath, config.BundlePath, config.ManifestPath); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("error = %v", err)
	}
}

func TestExtractMetadataObject(t *testing.T) {
	object := `{"value":"a { brace } and \" quote"}`
	got, err := ExtractMetadataObject([]byte("prefix\n" + object + "\nsuffix"))
	if err != nil || string(got) != object {
		t.Fatalf("got %q, error %v", got, err)
	}
	for _, raw := range []string{"prefix {", `{} {}`, `prefix {not-json}`} {
		if _, err := ExtractMetadataObject([]byte(raw)); err == nil {
			t.Fatalf("ExtractMetadataObject(%q) succeeded", raw)
		}
	}
}

func TestSysFSVerifier(t *testing.T) {
	root := t.TempDir()
	if _, err := (SysFSVerifier{Root: root}).Verify(context.Background(), "1-2.3"); err == nil || !strings.Contains(err.Error(), "no BCM2712") {
		t.Fatalf("absent-target error = %v", err)
	}
	makeSysfsDevice(t, root, "1-2.3", "0A5C", "2712")
	got, err := (SysFSVerifier{Root: root}).Verify(context.Background(), "1-2.3")
	if err != nil || got.USBPath != "1-2.3" || got.Token == "" {
		t.Fatalf("target = %#v, error = %v", got, err)
	}
	makeSysfsDevice(t, root, "2-1", "0a5c", "2712")
	if _, err := (SysFSVerifier{Root: root}).Verify(context.Background(), "1-2.3"); err == nil || !strings.Contains(err.Error(), "found 2") {
		t.Fatalf("ambiguity error = %v", err)
	}
	if _, err := (SysFSVerifier{Root: root}).Verify(context.Background(), "../../dev"); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("path error = %v", err)
	}
}

func TestSysFSVerifierRejectsUnexpectedPath(t *testing.T) {
	root := t.TempDir()
	makeSysfsDevice(t, root, "1-2.3", "0a5c", "2712")
	if _, err := (SysFSVerifier{Root: root}).Verify(context.Background(), "2-1"); err == nil || !strings.Contains(err.Error(), "not requested path") {
		t.Fatalf("wrong-path error = %v", err)
	}
}

func makeLiveConfig(t *testing.T) (LiveConfig, BundleManifest) {
	t.Helper()
	root := t.TempDir()
	binary := filepath.Join(root, "rpiboot")
	bundle := filepath.Join(root, "bundle")
	manifestPath := filepath.Join(root, "manifest.json")
	if err := os.Mkdir(bundle, 0755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, binary, []byte("pinned rpiboot"), 0555)
	mustWrite(t, filepath.Join(bundle, "bootcode5.bin"), []byte("signed recovery firmware"), 0444)
	mustWrite(t, filepath.Join(bundle, "config.txt"), []byte(SafeRecoveryConfig), 0444)
	files := map[string]string{
		"bootcode5.bin": digestBytes([]byte("signed recovery firmware")),
		"config.txt":    digestBytes([]byte(SafeRecoveryConfig)),
	}
	manifest := BundleManifest{
		Schema: ManifestSchema, ToolVersion: "test-version", ToolSHA256: digestBytes([]byte("pinned rpiboot")),
		BundleSHA256: ComputeBundleDigest(files), Files: files,
	}
	raw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, manifestPath, raw, 0444)
	return LiveConfig{BinaryPath: binary, BundlePath: bundle, ManifestPath: manifestPath}, manifest
}

func makeSysfsDevice(t *testing.T, root, name, vendor, product string) {
	t.Helper()
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0755); err != nil {
		t.Fatal(err)
	}
	for field, value := range map[string]string{"idVendor": vendor, "idProduct": product, "busnum": "1", "devnum": "2", "devpath": "2.3"} {
		mustWrite(t, filepath.Join(dir, field), []byte(value+"\n"), 0444)
	}
}

func mustWrite(t *testing.T, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if _, err := os.Stat(path); err == nil {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
