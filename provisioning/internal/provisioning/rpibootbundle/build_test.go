package rpibootbundle

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
)

func TestBuildAndVerifyCanonicalBundleSet(t *testing.T) {
	config := fixtureConfig(t)
	set, err := Build(config)
	if err != nil {
		t.Fatal(err)
	}
	if set.SchemaVersion != SetSchemaV1Alpha1 || len(set.Bundles) != 6 || len(set.Fixtures) != 2 {
		t.Fatalf("unexpected set: %#v", set)
	}
	if set.Fixtures[0].HardwareObserved || set.Fixtures[1].HardwareObserved {
		t.Fatal("software fixture claimed hardware observation")
	}
	if got := string(mustRead(t, filepath.Join(config.Output, "fresh-commit/config.txt"))); got != string(commitConfig) {
		t.Fatalf("fresh commit config = %q", got)
	}
	if got := string(mustRead(t, filepath.Join(config.Output, "owned-recovery/config.txt"))); got != string(readbackConfig) {
		t.Fatalf("owned recovery config = %q", got)
	}
	if strings.Contains(string(mustRead(t, filepath.Join(config.Output, "owned-recovery/config.txt"))), "program_pubkey") {
		t.Fatal("owned recovery retained the irreversible fresh-board setting")
	}
	if string(mustRead(t, filepath.Join(config.Output, "negative-boot/bootcode5.bin"))) != "fresh recovery" {
		t.Fatal("negative recovery fixture does not use unsigned fresh recovery")
	}
	original := mustRead(t, config.RootDataImage)
	tampered := mustRead(t, filepath.Join(config.Output, "root-integrity-test/root-data.tampered.img"))
	if len(original) != len(tampered) || tampered[0] != original[0]^1 || string(tampered[1:]) != string(original[1:]) {
		t.Fatal("root-integrity mutation is not the exact first-byte flip")
	}
	verified, err := Verify(config.Output)
	if err != nil {
		t.Fatal(err)
	}
	firstDigest, err := set.Digest()
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := verified.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("digest changed: %s != %s", firstDigest, secondDigest)
	}
	if _, err := ParseSet(mustRead(t, filepath.Join(config.Output, "bundle-set.json"))); err != nil {
		t.Fatal(err)
	}
}

func TestBuildRejectsUnsafeInputsAndExistingOutput(t *testing.T) {
	t.Run("symlink input", func(t *testing.T) {
		config := fixtureConfig(t)
		alias := filepath.Join(t.TempDir(), "recovery-link")
		if err := os.Symlink(config.FreshRecovery, alias); err != nil {
			t.Fatal(err)
		}
		config.FreshRecovery = alias
		if _, err := Build(config); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Fatalf("Build() error = %v", err)
		}
	})
	t.Run("existing output", func(t *testing.T) {
		config := fixtureConfig(t)
		if err := os.Mkdir(config.Output, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(config); err == nil || !strings.Contains(err.Error(), "exists") {
			t.Fatalf("Build() error = %v", err)
		}
	})
	t.Run("wrong release digest", func(t *testing.T) {
		config := fixtureConfig(t)
		config.ReleaseIntentDigest = "not-a-digest"
		if _, err := Build(config); err == nil {
			t.Fatal("Build accepted invalid lineage")
		}
	})
}

func TestBuildAndVerifyRejectTampering(t *testing.T) {
	t.Run("wrong signature", func(t *testing.T) {
		config := fixtureConfig(t)
		signature := mustRead(t, config.BootSignature)
		signature[len(signature)-3] ^= 1
		if err := os.WriteFile(config.BootSignature, signature, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Build(config); err == nil {
			t.Fatal("Build accepted altered boot signature")
		}
	})
	t.Run("published tree", func(t *testing.T) {
		config := fixtureConfig(t)
		if _, err := Build(config); err != nil {
			t.Fatal(err)
		}
		directory := filepath.Join(config.Output, "owned-readback")
		path := filepath.Join(directory, "bootcode5.bin")
		if err := os.Chmod(config.Output, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("tampered recovery"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(config.Output); err == nil {
			t.Fatal("Verify accepted a changed tree")
		}
	})
}

func TestParseSetRejectsAmbiguousJSON(t *testing.T) {
	config := fixtureConfig(t)
	if _, err := Build(config); err != nil {
		t.Fatal(err)
	}
	valid := mustRead(t, filepath.Join(config.Output, "bundle-set.json"))
	for name, encoded := range map[string][]byte{
		"unknown":   append(valid[:len(valid)-1], []byte(`,"unknown":true}`)...),
		"trailing":  append(append([]byte(nil), valid...), []byte(` {}`)...),
		"duplicate": []byte(strings.Replace(string(valid), `"schema_version":`, `"schema_version":"duplicate","schema_version":`, 1)),
		"null":      []byte(strings.Replace(string(valid), `"fixtures":[`, `"fixtures":[null,`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseSet(encoded); err == nil {
				t.Fatalf("ParseSet accepted %s", name)
			}
		})
	}
}

func fixtureConfig(t *testing.T) BuildConfig {
	t.Helper()
	root := t.TempDir()
	write := func(name string, contents []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, contents, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	bootImage := []byte("signed boot image fixture")
	imageHash := sha256.Sum256(bootImage)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, imageHash[:])
	if err != nil {
		t.Fatal(err)
	}
	document, err := rpi5bootsig.New(bundle.Sum(bootImage), 1_786_968_000, signature)
	if err != nil {
		t.Fatal(err)
	}
	bootSignature, err := document.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})
	signedEEPROM := []byte("signed EEPROM image")
	metadata := []byte(strings.TrimPrefix(string(bundle.Sum(signedEEPROM)), "sha256:") + "\nts: 1786968000\n")
	config := BuildConfig{
		ReleaseIntentDigest: bundle.Sum([]byte("release intent")),
		FreshRecovery:       write("fresh-recovery.bin", []byte("fresh recovery")),
		OwnedRecovery:       write("owned-recovery.bin", []byte("owned customer-counter-signed recovery")),
		SignedEEPROM:        write("pieeprom.bin", signedEEPROM), EEPROMMetadata: write("pieeprom.sig", metadata),
		BootImage: write("boot.img", bootImage), BootSignature: write("boot.sig", bootSignature),
		BootPublicKey: write("public.pem", publicPEM), RootDataImage: write("root-data.img", []byte("root data image")),
		RootHashTreeImage: write("root-hash.img", []byte("root hash tree")), Output: filepath.Join(root, "bundle-set"),
	}
	t.Cleanup(func() {
		_ = filepath.Walk(config.Output, func(path string, info os.FileInfo, err error) error {
			if err == nil && info.IsDir() {
				_ = os.Chmod(path, 0o700)
			}
			return nil
		})
	})
	return config
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}
