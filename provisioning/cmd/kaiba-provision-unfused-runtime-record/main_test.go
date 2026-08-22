package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
)

func TestCommandEmitsExactlyTwoBoundedCanonicalRecords(t *testing.T) {
	originalFacts, originalPlan, originalValidate := loadRuntimeFacts, loadMediaPlan, validateFacts
	t.Cleanup(func() { loadRuntimeFacts, loadMediaPlan, validateFacts = originalFacts, originalPlan, originalValidate })
	facts := commandFacts()
	canonical, err := facts.CanonicalJSON()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "runtime-facts.json")
	if err := os.WriteFile(path, append(canonical, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	loadMediaPlan = func(path string) (mediacontract.Plan, error) {
		if path != "/evidence/approved-plan.json" {
			t.Fatalf("plan path = %q", path)
		}
		return mediacontract.Plan{}, nil
	}
	validateFacts = func(actual mediacontract.RuntimeFacts, _ mediacontract.Plan) error {
		if actual != facts {
			t.Fatalf("facts = %#v", actual)
		}
		return nil
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"emit", "--facts", path, "--plan", "/evidence/approved-plan.json"}, &stdout, &stderr)
	if code != exitOK || stderr.Len() != 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lines := strings.Split(strings.TrimSuffix(stdout.String(), "\n"), "\n")
	if len(lines) != 2 || !strings.HasPrefix(lines[0], mediacontract.CompatibilityMarkerPrefix+" ") || !strings.HasPrefix(lines[1], mediacontract.DMVerityMarkerPrefix+" ") {
		t.Fatalf("records = %q", stdout.String())
	}
	if _, err := mediacontract.ParseUARTCapture(stdout.Bytes(), facts); err != nil {
		t.Fatalf("emitted records do not parse: %v", err)
	}
	for _, arguments := range [][]string{
		nil,
		{"emit"},
		{"emit", "--facts", path, "--plan", "/evidence/approved-plan.json", "extra"},
		{"emit", "--facts", path, "--plan", "/evidence/approved-plan.json", "--uart", "/dev/serial/by-id/example"},
	} {
		stdout.Reset()
		stderr.Reset()
		if code := run(arguments, &stdout, &stderr); code != exitUsage || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("arguments=%q exit=%d stdout=%q stderr=%q", arguments, code, stdout.String(), stderr.String())
		}
	}
}

func TestCommandRejectsSymlinkAndNonCanonicalFacts(t *testing.T) {
	directory := t.TempDir()
	realPath := filepath.Join(directory, "real.json")
	if err := os.WriteFile(realPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(directory, "facts.json")
	if err := os.Symlink(realPath, symlink); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"emit", "--facts", symlink, "--plan", "/missing-plan.json"}, &stdout, &stderr)
	if code != exitInvalid || stdout.Len() != 0 || !strings.Contains(stderr.String(), "non-symlink") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func commandFacts() mediacontract.RuntimeFacts {
	return mediacontract.RuntimeFacts{
		SchemaVersion: mediacontract.RuntimeFactsSchemaVersion,
		TransactionID: "transaction:media:1", ReleaseID: "release:rpi5:1",
		SignedReleaseManifestDigest: commandDigest("release"),
		MediaBindingDigest:          commandDigest("binding"), BootImageDigest: commandDigest("boot"),
		BootSignatureDigest: commandDigest("signature"), RootDataDigest: commandDigest("root data"),
		RootHashTreeDigest: commandDigest("root hash tree"), VerityRootHash: commandDigest("root hash"),
		DataPARTUUID: "PARTUUID=33333333-3333-4333-8333-333333333333",
		HashPARTUUID: "PARTUUID=44444444-4444-4444-8444-444444444444",
		Mapper:       "/dev/mapper/root", BootRAMDisk: true, RootReadOnly: true,
	}
}

func commandDigest(value string) mediacontract.Digest {
	sum := sha256.Sum256([]byte(value))
	return mediacontract.Digest("sha256:" + hex.EncodeToString(sum[:]))
}
