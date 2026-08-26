package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandSurfaceHasNoGenericMutationOrHardwareSelectors(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), nil, &stdout, &stderr); code != exitUsage {
		t.Fatalf("run() code = %d", code)
	}
	usage := stderr.String()
	for _, required := range []string{
		"prepare-draft", "install-draft", "propose-approval", "apply-approval",
		"propose-next-intent", "apply-intent", "propose-evidence", "apply-evidence",
		"prepare-reconciliation", "propose-reconciliation", "apply-reconciliation",
	} {
		if !strings.Contains(usage, required) {
			t.Fatalf("usage omits %q", required)
		}
	}
	for _, forbidden := range []string{"--operation", "--boot-mode", "--device", "--gpio", "--uart", "--command", "--enable-mutations"} {
		if strings.Contains(usage, forbidden) {
			t.Fatalf("usage exposes forbidden selector %q", forbidden)
		}
	}
}

func TestLoadStrictJSONRejectsDuplicateFieldsRelativePathsAndSymlinks(t *testing.T) {
	directory := t.TempDir()
	duplicate := filepath.Join(directory, "duplicate.json")
	if err := os.WriteFile(duplicate, []byte(`{"value":"one","value":"two"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var target struct {
		Value string `json:"value"`
	}
	if err := loadStrictJSON(duplicate, &target); err == nil {
		t.Fatal("duplicate JSON fields were accepted")
	}
	if err := loadStrictJSON("relative.json", &target); err == nil {
		t.Fatal("relative input path was accepted")
	}
	regular := filepath.Join(directory, "regular.json")
	if err := os.WriteFile(regular, []byte(`{"value":"ok"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "link.json")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if err := loadStrictJSON(link, &target); err == nil {
		t.Fatal("symlink input was accepted")
	}
	if err := loadStrictJSON(regular, &target); err != nil || target.Value != "ok" {
		t.Fatalf("regular strict input = %#v, %v", target, err)
	}
}

func TestAttemptAuthorityInputMustUseTrustedImmutableFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "attempt.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var target map[string]any
	if err := loadTrustedStrictJSON(path, &target); err == nil {
		t.Fatal("caller-owned or mutable attempt evidence was accepted")
	}
}

func TestPairedAuthorityFlagsRejectUnsafeCredentialPathsBeforeLoadingTLS(t *testing.T) {
	valid := pairedFlags{
		control: controlFlags{
			url: "https://control.example.test", certificate: "/run/credentials/station.crt",
			privateKey: "/run/credentials/station.key", serverCA: "/run/credentials/control-ca.crt",
		},
		auditURL: "https://audit.example.test", auditCA: "/run/credentials/audit-ca.crt",
	}
	tests := map[string]func(*pairedFlags){
		"relative certificate": func(value *pairedFlags) { value.control.certificate = "station.crt" },
		"store key":            func(value *pairedFlags) { value.control.privateKey = "/nix/store/secret-key" },
		"relative control CA":  func(value *pairedFlags) { value.control.serverCA = "control-ca.crt" },
		"relative audit CA":    func(value *pairedFlags) { value.auditCA = "audit-ca.crt" },
		"shared authority CA":  func(value *pairedFlags) { value.auditCA = value.control.serverCA },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := valid
			mutate(&value)
			if _, _, err := value.clients(); err == nil {
				t.Fatal("unsafe paired authority configuration was accepted")
			}
		})
	}
}
