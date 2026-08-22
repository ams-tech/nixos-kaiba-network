package rpibootbundle

import (
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
)

const (
	maximumSmallInputBytes int64 = 8 * 1024 * 1024
	maximumLargeInputBytes int64 = 64 * 1024 * 1024 * 1024
	readBufferBytes              = 1024 * 1024
)

var (
	readbackConfig = []byte("uart_2ndstage=1\nrecovery_metadata=1\n")
	commitConfig   = []byte("uart_2ndstage=1\nprogram_pubkey=1\nrecovery_metadata=1\n")
)

// BuildConfig names the already verified public inputs. ReleaseIntentDigest
// is the common cohort authorization lineage. Output must not already exist.
type BuildConfig struct {
	ReleaseIntentDigest bundle.Digest
	FreshRecovery       string
	OwnedRecovery       string
	SignedEEPROM        string
	EEPROMMetadata      string
	BootImage           string
	BootSignature       string
	BootPublicKey       string
	RootDataImage       string
	RootHashTreeImage   string
	Output              string
}

type openedInput struct {
	file *os.File
	info os.FileInfo
}

// Build creates, reopens, and verifies a six-directory bundle set before an
// atomic no-replace publication.
func Build(config BuildConfig) (Set, error) {
	if err := config.ReleaseIntentDigest.Validate(); err != nil {
		return Set{}, fmt.Errorf("release intent digest: %w", err)
	}
	if err := validateOutputPath(config.Output); err != nil {
		return Set{}, err
	}
	inputs := map[string]string{
		"boot_image": config.BootImage, "boot_public_key": config.BootPublicKey,
		"boot_signature": config.BootSignature, "eeprom_update_metadata": config.EEPROMMetadata,
		"fresh_recovery_bootcode": config.FreshRecovery, "owned_recovery_bootcode": config.OwnedRecovery,
		"root_data_image": config.RootDataImage, "root_hash_tree_image": config.RootHashTreeImage,
		"signed_eeprom_image": config.SignedEEPROM,
	}
	records := make(map[string]File, len(inputs))
	for name, path := range inputs {
		record, err := inspectRegular(path, maximumLargeInputBytes)
		if err != nil {
			return Set{}, fmt.Errorf("%s: %w", name, err)
		}
		records[name] = record
	}
	if records["fresh_recovery_bootcode"] == records["owned_recovery_bootcode"] {
		return Set{}, errors.New("owned recovery must differ from unsigned fresh recovery")
	}
	if err := verifyEEPROMMetadata(config.SignedEEPROM, config.EEPROMMetadata); err != nil {
		return Set{}, err
	}
	if err := verifyBootSignature(config.BootImage, config.BootSignature, config.BootPublicKey); err != nil {
		return Set{}, err
	}

	parent := filepath.Dir(config.Output)
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(config.Output)+".tmp-")
	if err != nil {
		return Set{}, fmt.Errorf("create private bundle-set directory: %w", err)
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return Set{}, fmt.Errorf("protect temporary bundle-set directory: %w", err)
	}

	negativeFixture := Fixture{
		SchemaVersion: FixtureSchemaV1Alpha1, FixtureID: negativeFixtureID,
		FailureClass: "unauthorized_recovery", Mutation: "replace_customer_counter_signed_recovery_with_unsigned_fresh_recovery",
		OriginalDigest: records["owned_recovery_bootcode"].Digest, TestInputDigest: records["fresh_recovery_bootcode"].Digest,
		ExpectedOutcome: "owned_rom_rejects_second_stage", HardwareObserved: false,
	}
	rootTamperedPath := filepath.Join(temporary, ".root-data.tampered.img")
	rootTamperedRecord, err := copyMutatingFirstByte(config.RootDataImage, rootTamperedPath)
	if err != nil {
		return Set{}, fmt.Errorf("construct root-integrity fixture: %w", err)
	}
	rootFixture := Fixture{
		SchemaVersion: FixtureSchemaV1Alpha1, FixtureID: rootIntegrityFixtureID,
		FailureClass: "root_integrity", Mutation: "flip_first_root_data_byte_keep_hash_tree",
		OriginalDigest: records["root_data_image"].Digest, TestInputDigest: rootTamperedRecord.Digest,
		ExpectedOutcome: "verity_rejects_root_data", HardwareObserved: false,
	}
	if err := negativeFixture.Validate(); err != nil {
		return Set{}, err
	}
	if err := rootFixture.Validate(); err != nil {
		return Set{}, err
	}

	if err := populateBundles(temporary, config, negativeFixture, rootFixture, rootTamperedPath); err != nil {
		return Set{}, err
	}
	if err := os.Remove(rootTamperedPath); err != nil {
		return Set{}, fmt.Errorf("remove temporary root mutation: %w", err)
	}

	set := Set{
		SchemaVersion: SetSchemaV1Alpha1, ReleaseIntentDigest: config.ReleaseIntentDigest,
		Inputs: canonicalInputs(records), Fixtures: []Fixture{negativeFixture, rootFixture},
	}
	for _, role := range canonicalRoles {
		relative := rolePath(role)
		tree, err := bundle.SnapshotDirectoryTree(filepath.Join(temporary, relative))
		if err != nil {
			return Set{}, fmt.Errorf("snapshot %s: %w", role, err)
		}
		digest, err := tree.Digest()
		if err != nil {
			return Set{}, err
		}
		size, err := tree.SizeBytes()
		if err != nil {
			return Set{}, err
		}
		set.Bundles = append(set.Bundles, Record{Role: role, RelativePath: relative, Digest: digest, SizeBytes: size, Tree: tree})
	}
	encoded, err := set.CanonicalJSON()
	if err != nil {
		return Set{}, err
	}
	if err := writeFile(filepath.Join(temporary, "bundle-set.json"), encoded); err != nil {
		return Set{}, err
	}
	if err := os.Chmod(temporary, 0o555); err != nil {
		return Set{}, fmt.Errorf("freeze bundle-set root: %w", err)
	}
	if _, err := Verify(temporary); err != nil {
		return Set{}, fmt.Errorf("reverify bundle set before publication: %w", err)
	}
	if err := renameNoReplace(temporary, config.Output); err != nil {
		return Set{}, fmt.Errorf("publish bundle set without replacement: %w", err)
	}
	removeTemporary = false
	verified, err := Verify(config.Output)
	if err != nil {
		return Set{}, fmt.Errorf("reopen published bundle set: %w", err)
	}
	return verified, nil
}

func populateBundles(root string, config BuildConfig, negativeFixture, rootFixture Fixture, rootTampered string) error {
	type fileCopy struct{ source, name string }
	type directorySpec struct {
		role    Role
		config  []byte
		copies  []fileCopy
		fixture *Fixture
	}
	specifications := []directorySpec{
		{role: RoleFreshCommit, config: commitConfig, copies: []fileCopy{{config.FreshRecovery, "bootcode5.bin"}, {config.SignedEEPROM, "pieeprom.bin"}, {config.EEPROMMetadata, "pieeprom.sig"}}},
		{role: RoleFreshReadback, config: readbackConfig, copies: []fileCopy{{config.FreshRecovery, "bootcode5.bin"}}},
		{role: RoleNegativeBoot, config: readbackConfig, copies: []fileCopy{{config.FreshRecovery, "bootcode5.bin"}}, fixture: &negativeFixture},
		{role: RoleOwnedReadback, config: readbackConfig, copies: []fileCopy{{config.OwnedRecovery, "bootcode5.bin"}}},
		{role: RoleOwnedRecovery, config: readbackConfig, copies: []fileCopy{{config.OwnedRecovery, "bootcode5.bin"}, {config.SignedEEPROM, "pieeprom.bin"}, {config.EEPROMMetadata, "pieeprom.sig"}}},
		{role: RoleRootIntegrity, config: readbackConfig, copies: []fileCopy{
			{config.OwnedRecovery, "bootcode5.bin"}, {config.BootImage, "boot.img"},
			{config.BootSignature, "boot.sig"}, {config.BootPublicKey, "public.pem"},
			{rootTampered, "root-data.tampered.img"}, {config.RootHashTreeImage, "root-hash-tree.img"},
		}, fixture: &rootFixture},
	}
	for _, specification := range specifications {
		directory := filepath.Join(root, rolePath(specification.role))
		if err := os.Mkdir(directory, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", specification.role, err)
		}
		if err := writeFile(filepath.Join(directory, "config.txt"), specification.config); err != nil {
			return err
		}
		for _, copy := range specification.copies {
			if _, err := copyRegular(copy.source, filepath.Join(directory, copy.name), false); err != nil {
				return fmt.Errorf("copy %s %s: %w", specification.role, copy.name, err)
			}
		}
		if specification.fixture != nil {
			encoded, err := json.Marshal(specification.fixture)
			if err != nil {
				return fmt.Errorf("encode fixture: %w", err)
			}
			if err := writeFile(filepath.Join(directory, "fixture.json"), encoded); err != nil {
				return err
			}
		}
		if err := os.Chmod(directory, 0o555); err != nil {
			return fmt.Errorf("freeze %s: %w", specification.role, err)
		}
	}
	return nil
}

// Verify reopens the published directory, checks its exact layout and compares
// every live filesystem tree with the canonical record.
func Verify(root string) (Set, error) {
	if err := validateExistingDirectory(root); err != nil {
		return Set{}, err
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return Set{}, fmt.Errorf("read bundle-set directory: %w", err)
	}
	expected := map[string]bool{"bundle-set.json": true}
	for _, role := range canonicalRoles {
		expected[rolePath(role)] = true
	}
	if len(entries) != len(expected) {
		return Set{}, errors.New("bundle-set directory does not contain the exact top-level layout")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] || entry.Type()&os.ModeSymlink != 0 {
			return Set{}, errors.New("bundle-set directory contains an unexpected or symbolic entry")
		}
	}
	manifestBytes, err := readRegular(filepath.Join(root, "bundle-set.json"), maxSetBytes)
	if err != nil {
		return Set{}, err
	}
	set, err := ParseSet(manifestBytes)
	if err != nil {
		return Set{}, err
	}
	for index, record := range set.Bundles {
		actual, err := bundle.SnapshotDirectoryTree(filepath.Join(root, record.RelativePath))
		if err != nil {
			return Set{}, fmt.Errorf("snapshot bundles[%d]: %w", index, err)
		}
		actualJSON, _ := actual.CanonicalJSON()
		expectedJSON, _ := record.Tree.CanonicalJSON()
		if !bytes.Equal(actualJSON, expectedJSON) {
			return Set{}, fmt.Errorf("bundle %q differs from its canonical tree", record.Role)
		}
	}
	if err := verifyCrossBundleContents(root, set); err != nil {
		return Set{}, err
	}
	return set, nil
}

func verifyCrossBundleContents(root string, set Set) error {
	input := make(map[string]File, len(set.Inputs))
	for _, record := range set.Inputs {
		input[record.Name] = record.File
	}
	checks := []struct{ relative, inputName string }{
		{"fresh-commit/bootcode5.bin", "fresh_recovery_bootcode"},
		{"fresh-readback/bootcode5.bin", "fresh_recovery_bootcode"},
		{"negative-boot/bootcode5.bin", "fresh_recovery_bootcode"},
		{"owned-readback/bootcode5.bin", "owned_recovery_bootcode"},
		{"owned-recovery/bootcode5.bin", "owned_recovery_bootcode"},
		{"root-integrity-test/bootcode5.bin", "owned_recovery_bootcode"},
		{"fresh-commit/pieeprom.bin", "signed_eeprom_image"},
		{"owned-recovery/pieeprom.bin", "signed_eeprom_image"},
		{"root-integrity-test/boot.img", "boot_image"},
		{"root-integrity-test/boot.sig", "boot_signature"},
		{"root-integrity-test/public.pem", "boot_public_key"},
		{"root-integrity-test/root-hash-tree.img", "root_hash_tree_image"},
	}
	for _, check := range checks {
		actual, err := inspectRegular(filepath.Join(root, check.relative), maximumLargeInputBytes)
		if err != nil || actual != input[check.inputName] {
			return fmt.Errorf("%s does not match input %s", check.relative, check.inputName)
		}
	}
	for _, relative := range []string{"fresh-readback/config.txt", "negative-boot/config.txt", "owned-readback/config.txt", "owned-recovery/config.txt", "root-integrity-test/config.txt"} {
		actual, err := readRegular(filepath.Join(root, relative), int64(len(readbackConfig)))
		if err != nil || !bytes.Equal(actual, readbackConfig) {
			return fmt.Errorf("%s is not the canonical non-mutating metadata config", relative)
		}
	}
	actualCommitConfig, err := readRegular(filepath.Join(root, "fresh-commit/config.txt"), int64(len(commitConfig)))
	if err != nil || !bytes.Equal(actualCommitConfig, commitConfig) {
		return errors.New("fresh-commit/config.txt is not the canonical one-time ownership config")
	}
	for _, pair := range []struct {
		relative string
		fixture  Fixture
	}{
		{"negative-boot/fixture.json", set.Fixtures[0]},
		{"root-integrity-test/fixture.json", set.Fixtures[1]},
	} {
		encoded, err := readRegular(filepath.Join(root, pair.relative), maximumSmallInputBytes)
		if err != nil {
			return err
		}
		want, _ := json.Marshal(pair.fixture)
		if !bytes.Equal(encoded, want) {
			return fmt.Errorf("%s is not the canonical fixture record", pair.relative)
		}
	}
	tampered, err := inspectRegular(filepath.Join(root, "root-integrity-test/root-data.tampered.img"), maximumLargeInputBytes)
	if err != nil || tampered.Digest != set.Fixtures[1].TestInputDigest || tampered.SizeBytes != input["root_data_image"].SizeBytes {
		return errors.New("root-integrity mutation does not match its fixture record")
	}
	if err := verifyEEPROMMetadata(filepath.Join(root, "fresh-commit/pieeprom.bin"), filepath.Join(root, "fresh-commit/pieeprom.sig")); err != nil {
		return fmt.Errorf("fresh-commit EEPROM metadata: %w", err)
	}
	if err := verifyBootSignature(filepath.Join(root, "root-integrity-test/boot.img"), filepath.Join(root, "root-integrity-test/boot.sig"), filepath.Join(root, "root-integrity-test/public.pem")); err != nil {
		return fmt.Errorf("root-integrity signed capsule: %w", err)
	}
	return nil
}

func verifyBootSignature(imagePath, signaturePath, publicPath string) error {
	image, err := inspectRegular(imagePath, maximumLargeInputBytes)
	if err != nil {
		return fmt.Errorf("inspect boot image: %w", err)
	}
	signature, err := readRegular(signaturePath, 4096)
	if err != nil {
		return fmt.Errorf("read boot signature: %w", err)
	}
	document, err := rpi5bootsig.Parse(signature)
	if err != nil {
		return fmt.Errorf("parse boot signature: %w", err)
	}
	if document.ImageDigest != image.Digest {
		return errors.New("boot signature does not bind the exact boot image")
	}
	publicPEM, err := readRegular(publicPath, 16*1024)
	if err != nil {
		return fmt.Errorf("read boot public key: %w", err)
	}
	publicKey, err := parsePublicKey(publicPEM)
	if err != nil {
		return err
	}
	if err := document.Verify(publicKey); err != nil {
		return fmt.Errorf("verify boot signature: %w", err)
	}
	return nil
}

func parsePublicKey(encoded []byte) (*rsa.PublicKey, error) {
	block, rest := pem.Decode(encoded)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 {
		return nil, errors.New("boot public key must be one canonical PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("boot public key is not PKIX DER")
	}
	key, ok := parsed.(*rsa.PublicKey)
	if !ok || key.N.BitLen() != 2048 || key.E != 65537 || key.Size() != 256 {
		return nil, errors.New("boot public key must be RSA-2048 with exponent 65537")
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	canonical := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if !bytes.Equal(encoded, canonical) {
		return nil, errors.New("boot public key PEM is not canonical")
	}
	return key, nil
}

func verifyEEPROMMetadata(imagePath, metadataPath string) error {
	image, err := inspectRegular(imagePath, maximumSmallInputBytes)
	if err != nil {
		return fmt.Errorf("inspect signed EEPROM: %w", err)
	}
	metadata, err := readRegular(metadataPath, 4096)
	if err != nil {
		return fmt.Errorf("read EEPROM metadata: %w", err)
	}
	lines := strings.Split(string(metadata), "\n")
	if len(lines) != 3 || lines[2] != "" || len(lines[0]) != 64 || lines[0] != strings.TrimPrefix(string(image.Digest), "sha256:") || !strings.HasPrefix(lines[1], "ts: ") {
		return errors.New("pieeprom.sig does not canonically bind the signed EEPROM image")
	}
	timestamp := strings.TrimPrefix(lines[1], "ts: ")
	parsed, err := strconv.ParseUint(timestamp, 10, 64)
	if err != nil || parsed == 0 || strconv.FormatUint(parsed, 10) != timestamp {
		return errors.New("pieeprom.sig timestamp is not canonical")
	}
	return nil
}

func inspectRegular(path string, maximum int64) (File, error) {
	opened, err := openRegular(path, maximum)
	if err != nil {
		return File{}, err
	}
	defer opened.file.Close()
	hash := sha256.New()
	read, err := io.CopyBuffer(hash, opened.file, make([]byte, readBufferBytes))
	if err != nil {
		return File{}, fmt.Errorf("hash regular file: %w", err)
	}
	if read != opened.info.Size() {
		return File{}, errors.New("regular file size changed while hashing")
	}
	return File{Digest: bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), SizeBytes: uint64(read)}, nil
}

func readRegular(path string, maximum int64) ([]byte, error) {
	opened, err := openRegular(path, maximum)
	if err != nil {
		return nil, err
	}
	defer opened.file.Close()
	contents, err := io.ReadAll(io.LimitReader(opened.file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("read regular file: %w", err)
	}
	if int64(len(contents)) != opened.info.Size() {
		return nil, errors.New("regular file size changed while reading")
	}
	return contents, nil
}

func openRegular(path string, maximum int64) (openedInput, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return openedInput{}, errors.New("input path must be clean and absolute")
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return openedInput{}, fmt.Errorf("open input without following symlinks: %w", err)
	}
	file := os.NewFile(uintptr(descriptor), path)
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return openedInput{}, fmt.Errorf("inspect input: %w", err)
	}
	if !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		file.Close()
		return openedInput{}, fmt.Errorf("input must be a non-empty regular file no larger than %d bytes", maximum)
	}
	return openedInput{file: file, info: info}, nil
}

func copyRegular(source, destination string, mutateFirst bool) (File, error) {
	opened, err := openRegular(source, maximumLargeInputBytes)
	if err != nil {
		return File{}, err
	}
	defer opened.file.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return File{}, fmt.Errorf("create destination: %w", err)
	}
	succeeded := false
	defer func() {
		_ = output.Close()
		if !succeeded {
			_ = os.Remove(destination)
		}
	}()
	hash := sha256.New()
	writer := io.MultiWriter(output, hash)
	buffered := bufio.NewReaderSize(opened.file, readBufferBytes)
	var written int64
	if mutateFirst {
		first, err := buffered.ReadByte()
		if err != nil {
			return File{}, fmt.Errorf("read first byte: %w", err)
		}
		first ^= 0x01
		if _, err := writer.Write([]byte{first}); err != nil {
			return File{}, err
		}
		written = 1
	}
	copied, err := io.CopyBuffer(writer, buffered, make([]byte, readBufferBytes))
	if err != nil {
		return File{}, fmt.Errorf("copy regular file: %w", err)
	}
	written += copied
	if written != opened.info.Size() {
		return File{}, errors.New("source file size changed while copying")
	}
	if err := output.Sync(); err != nil {
		return File{}, fmt.Errorf("sync copied file: %w", err)
	}
	if err := output.Close(); err != nil {
		return File{}, fmt.Errorf("close copied file: %w", err)
	}
	succeeded = true
	return File{Digest: bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), SizeBytes: uint64(written)}, nil
}

func copyMutatingFirstByte(source, destination string) (File, error) {
	return copyRegular(source, destination, true)
}

func writeFile(path string, contents []byte) error {
	if len(contents) == 0 {
		return errors.New("refuse to write an empty bundle file")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
	if err != nil {
		return fmt.Errorf("create bundle file: %w", err)
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return fmt.Errorf("write bundle file: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync bundle file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close bundle file: %w", err)
	}
	return nil
}

func validateOutputPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("output path must be clean, absolute, and non-root")
	}
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("output parent must be an existing non-symlink directory")
	}
	if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("output path already exists or cannot be inspected")
	}
	return nil
}

func validateExistingDirectory(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return errors.New("bundle-set path must be clean, absolute, and non-root")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect bundle-set path: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("bundle-set path must be a non-symlink directory")
	}
	return nil
}
