package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releaseintent"
)

const (
	maxPlanJSONBytes       = 128 * 1024
	maxResultJSONBytes     = 128 * 1024
	maxEEPROMBytes         = 2 * 1024 * 1024
	maxRecoveryBytes       = 110 * 1024
	maxComponentBytes      = 110 * 1024
	maxBootConfigBytes     = 4096 - 20
	maxPublicKeyBytes      = 16 * 1024
	maxUpdateMetadataBytes = 4096
)

var planFileLimits = map[string]int64{
	"plan.json":             maxPlanJSONBytes,
	"release-intent.json":   releaseintent.MaxBytes,
	"pieeprom.original.bin": maxEEPROMBytes,
	"recovery.original.bin": maxRecoveryBytes,
	"bootcode.original.bin": maxComponentBytes,
	"bootsys.original":      maxComponentBytes,
	"boot.conf":             maxBootConfigBytes,
	"public.pem":            maxPublicKeyBytes,
}

var signedFileLimits = map[string]int64{
	"pieeprom.bin":  maxEEPROMBytes,
	"pieeprom.sig":  maxUpdateMetadataBytes,
	"bootcode5.bin": maxRecoveryBytes,
	"result.json":   maxResultJSONBytes,
}

type loadedPlan struct {
	Plan              eepromsigning.Plan
	PlanJSON          []byte
	ReleaseIntent     releaseintent.Intent
	ReleaseIntentJSON []byte
	OriginalEEPROM    []byte
	OriginalRecovery  []byte
	OriginalBootcode  []byte
	OriginalBootsys   []byte
	BootConfig        []byte
	PublicPEM         []byte
}

type loadedResult struct {
	Result               eepromsigning.Result
	ResultJSON           []byte
	SignedEEPROM         []byte
	EEPROMUpdateMetadata []byte
	FreshRecovery        []byte
}

func loadPlanDirectory(path string) (loadedPlan, error) {
	files, err := readExactDirectory(path, planFileLimits)
	if err != nil {
		return loadedPlan{}, fmt.Errorf("load EEPROM signing plan directory: %w", err)
	}
	plan, err := eepromsigning.ParsePlan(files["plan.json"])
	if err != nil {
		return loadedPlan{}, err
	}
	planJSON, err := plan.CanonicalJSON()
	if err != nil {
		return loadedPlan{}, err
	}
	intent, err := releaseintent.Parse(files["release-intent.json"])
	if err != nil {
		return loadedPlan{}, err
	}
	intentJSON, err := intent.CanonicalJSON()
	if err != nil {
		return loadedPlan{}, err
	}
	if !canonicalJSONFile(files["release-intent.json"], intentJSON) {
		return loadedPlan{}, errors.New("release-intent.json is not canonical JSON")
	}
	intentDigest, err := intent.Digest()
	if err != nil {
		return loadedPlan{}, err
	}
	if intentDigest != plan.ReleaseIntentDigest {
		return loadedPlan{}, errors.New("release-intent.json digest does not match the EEPROM signing plan")
	}
	if intent.SourceDateEpoch != plan.SourceDateEpoch || intent.EEPROMReleaseManifestDigest != plan.EEPROMReleaseManifestDigest ||
		intent.PublicKeyFingerprint != plan.PublicKeyFingerprint || intent.SigningPolicyDigest != plan.SignerPolicyDigest ||
		intent.ExpectedCustomerKeyHash != plan.CustomerKeyHash {
		return loadedPlan{}, errors.New("release intent does not bind the EEPROM plan epoch, release, signer, and customer key")
	}
	for index, input := range plan.SigningInputs {
		role := bundle.ArtifactRole(input.Role)
		approved, found := intent.SigningInput(role)
		if !found || approved.Digest != input.Digest || approved.SizeBytes != input.SizeBytes {
			return loadedPlan{}, fmt.Errorf("release intent does not approve EEPROM signing input %d", index)
		}
	}
	for _, item := range []struct {
		label    string
		record   eepromsigning.File
		contents []byte
	}{
		{"original EEPROM", plan.OriginalEEPROM, files["pieeprom.original.bin"]},
		{"original recovery", plan.OriginalRecovery, files["recovery.original.bin"]},
		{"original bootcode", plan.OriginalBootcode, files["bootcode.original.bin"]},
		{"original bootsys", plan.OriginalBootsys, files["bootsys.original"]},
		{"boot config", plan.BootConfig, files["boot.conf"]},
		{"public key", plan.PublicKeyPEM, files["public.pem"]},
	} {
		if err := item.record.Match(item.label, item.contents); err != nil {
			return loadedPlan{}, err
		}
	}
	recoveryPreimage, err := eepromsigning.FirmwareSigningPreimage(files["recovery.original.bin"])
	if err != nil {
		return loadedPlan{}, fmt.Errorf("owned-recovery signing input: %w", err)
	}
	approvedRecovery, found := intent.SigningInput(bundle.RoleOwnedRecoveryBootcode)
	if !found || approvedRecovery.Digest != bundle.Sum(recoveryPreimage) || approvedRecovery.SizeBytes != uint64(len(recoveryPreimage)) {
		return loadedPlan{}, errors.New("release intent does not approve the exact pinned unsigned recovery image")
	}
	_, fingerprint, customerKey, err := eepromsigning.ParsePublicKey(files["public.pem"])
	if err != nil {
		return loadedPlan{}, err
	}
	if fingerprint != plan.PublicKeyFingerprint || bundle.Sum(customerKey) != plan.CustomerKeyHash {
		return loadedPlan{}, errors.New("public.pem does not match the planned public-key fingerprint and customer-key hash")
	}
	derived, err := eepromsigning.NewSigningInputs(
		files["bootcode.original.bin"], files["bootsys.original"], files["boot.conf"],
	)
	if err != nil {
		return loadedPlan{}, err
	}
	for index := range derived {
		if derived[index] != plan.SigningInputs[index] {
			return loadedPlan{}, fmt.Errorf("signing input %d does not match the plan files", index)
		}
	}
	return loadedPlan{
		Plan: plan, PlanJSON: planJSON, ReleaseIntent: intent, ReleaseIntentJSON: intentJSON,
		OriginalEEPROM: files["pieeprom.original.bin"], OriginalRecovery: files["recovery.original.bin"],
		OriginalBootcode: files["bootcode.original.bin"], OriginalBootsys: files["bootsys.original"],
		BootConfig: files["boot.conf"], PublicPEM: files["public.pem"],
	}, nil
}

func loadResultDirectory(path string) (loadedResult, error) {
	files, err := readExactDirectory(path, signedFileLimits)
	if err != nil {
		return loadedResult{}, fmt.Errorf("load EEPROM signing result directory: %w", err)
	}
	result, err := eepromsigning.ParseResult(files["result.json"])
	if err != nil {
		return loadedResult{}, err
	}
	resultJSON, err := result.CanonicalJSON()
	if err != nil {
		return loadedResult{}, err
	}
	for _, item := range []struct {
		label    string
		record   eepromsigning.File
		contents []byte
	}{
		{"signed EEPROM", result.SignedEEPROM, files["pieeprom.bin"]},
		{"EEPROM update metadata", result.EEPROMUpdateMetadata, files["pieeprom.sig"]},
		{"fresh recovery", result.FreshRecoveryBootcode, files["bootcode5.bin"]},
	} {
		if err := item.record.Match(item.label, item.contents); err != nil {
			return loadedResult{}, err
		}
	}
	return loadedResult{
		Result: result, ResultJSON: resultJSON, SignedEEPROM: files["pieeprom.bin"],
		EEPROMUpdateMetadata: files["pieeprom.sig"], FreshRecovery: files["bootcode5.bin"],
	}, nil
}

func canonicalJSONFile(encoded, canonical []byte) bool {
	return bytes.Equal(encoded, canonical) || (len(encoded) == len(canonical)+1 && encoded[len(encoded)-1] == '\n' && bytes.Equal(encoded[:len(canonical)], canonical))
}

func jsonFile(encoded []byte) []byte {
	result := append([]byte(nil), encoded...)
	return append(result, '\n')
}

func samePlan(left, right loadedPlan) bool {
	return bytes.Equal(left.PlanJSON, right.PlanJSON) && bytes.Equal(left.ReleaseIntentJSON, right.ReleaseIntentJSON) &&
		bytes.Equal(left.OriginalEEPROM, right.OriginalEEPROM) && bytes.Equal(left.OriginalRecovery, right.OriginalRecovery) &&
		bytes.Equal(left.OriginalBootcode, right.OriginalBootcode) && bytes.Equal(left.OriginalBootsys, right.OriginalBootsys) &&
		bytes.Equal(left.BootConfig, right.BootConfig) && bytes.Equal(left.PublicPEM, right.PublicPEM)
}

func sameResult(left, right loadedResult) bool {
	return bytes.Equal(left.ResultJSON, right.ResultJSON) && bytes.Equal(left.SignedEEPROM, right.SignedEEPROM) &&
		bytes.Equal(left.EEPROMUpdateMetadata, right.EEPROMUpdateMetadata) && bytes.Equal(left.FreshRecovery, right.FreshRecovery)
}

func readExactDirectory(path string, expected map[string]int64) (map[string][]byte, error) {
	if err := validateExistingAbsolutePath(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.IsDir() {
		return nil, errors.New("input path must be a non-symlink directory")
	}
	directory, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer directory.Close()
	opened, err := directory.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("input directory changed while opening")
	}
	if err := requireExactDirectoryEntries(directory, expected); err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(expected))
	for name, maximum := range expected {
		contents, err := readRegularFileAt(directory, name, maximum)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", name, err)
		}
		files[name] = contents
	}
	if err := requireExactDirectoryEntries(directory, expected); err != nil {
		return nil, fmt.Errorf("input directory changed while reading: %w", err)
	}
	after, err := directory.Stat()
	if err != nil || !os.SameFile(opened, after) {
		return nil, errors.New("input directory identity changed while reading")
	}
	return files, nil
}

func requireExactDirectoryEntries(directory *os.File, expected map[string]int64) error {
	if _, err := directory.Seek(0, 0); err != nil {
		return err
	}
	names, err := directory.Readdirnames(-1)
	if err != nil {
		return err
	}
	sort.Strings(names)
	wanted := make([]string, 0, len(expected))
	for name := range expected {
		wanted = append(wanted, name)
	}
	sort.Strings(wanted)
	if len(names) != len(wanted) {
		return fmt.Errorf("input directory must contain exactly %s", strings.Join(wanted, ", "))
	}
	for index := range wanted {
		if names[index] != wanted[index] {
			return fmt.Errorf("input directory must contain exactly %s", strings.Join(wanted, ", "))
		}
	}
	return nil
}

func readRegularFileAt(directory *os.File, name string, maximum int64) ([]byte, error) {
	if name == "" || filepath.Base(name) != name || maximum <= 0 {
		return nil, errors.New("invalid fixed input file configuration")
	}
	fd, err := syscall.Openat(int(directory.Fd()), name, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("open input file")
	}
	defer file.Close()
	return readOpenedRegularFile(file, maximum)
}

func readAbsoluteRegularFile(path string, maximum int64) ([]byte, error) {
	if err := validateExistingAbsolutePath(path); err != nil {
		return nil, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular() {
		return nil, errors.New("input must be a regular non-symlink file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return nil, errors.New("input changed while opening")
	}
	return readOpenedRegularFile(file, maximum)
}

func readOpenedRegularFile(file *os.File, maximum int64) ([]byte, error) {
	before, err := file.Stat()
	if err != nil || !before.Mode().IsRegular() {
		return nil, errors.New("input is not a regular file")
	}
	if before.Size() <= 0 || before.Size() > maximum {
		return nil, fmt.Errorf("input size must be between 1 and %d bytes", maximum)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(contents)) != before.Size() {
		return nil, errors.New("input changed while reading")
	}
	after, err := file.Stat()
	if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return nil, errors.New("input identity changed while reading")
	}
	return contents, nil
}

func validateExistingAbsolutePath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.IndexByte(path, 0) >= 0 {
		return errors.New("path must be absolute and clean")
	}
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(path, current), current) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
	}
	return nil
}

func validateNewOutputPath(path string) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == string(filepath.Separator) || strings.IndexByte(path, 0) >= 0 {
		return errors.New("output path must be absolute and clean")
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		if err == nil {
			return errors.New("output path already exists")
		}
		return err
	}
	parent := filepath.Dir(path)
	if err := validateExistingAbsolutePath(parent); err != nil {
		return fmt.Errorf("output parent: %w", err)
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() {
		return errors.New("output parent must be an existing directory")
	}
	return nil
}

func pathsOverlap(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if left == right {
		return true
	}
	relative, err := filepath.Rel(left, right)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return true
	}
	relative, err = filepath.Rel(right, left)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func createAtomicDirectory(output string, files map[string][]byte) error {
	if err := validateNewOutputPath(output); err != nil {
		return err
	}
	parent := filepath.Dir(output)
	temporary, err := os.MkdirTemp(parent, ".kaiba-eeprom-output-*")
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Chmod(temporary, 0o700)
			_ = os.RemoveAll(temporary)
		}
	}()
	if err := os.Chmod(temporary, 0o700); err != nil {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		if filepath.Base(name) != name || name == "" {
			return errors.New("invalid fixed output filename")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(temporary, name)
		file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o444)
		if err != nil {
			return err
		}
		if _, err := file.Write(files[name]); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Chmod(0o444); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return err
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	directory, err := os.Open(temporary)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	if err := directory.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporary, 0o555); err != nil {
		return err
	}
	if err := renameNoReplace(temporary, output); err != nil {
		return err
	}
	removeTemporary = false
	parentDirectory, err := os.Open(parent)
	if err != nil {
		return err
	}
	defer parentDirectory.Close()
	return parentDirectory.Sync()
}
