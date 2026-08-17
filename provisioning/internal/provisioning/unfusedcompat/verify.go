package unfusedcompat

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// VerifyOfflineFixture verifies an exact regular-file capsule tree and a
// strictly bound offline fixture. It performs no subprocess, network, USB,
// serial, GPIO, or block-device operation.
func VerifyOfflineFixture(manifestPath, capsuleRoot, fixturePath string) (Outcome, error) {
	var manifest CapsuleManifest
	if err := loadStrictJSONFile(manifestPath, maximumManifestBytes, &manifest); err != nil {
		return Outcome{}, fmt.Errorf("load capsule manifest: %w", err)
	}
	roles, err := manifest.validate()
	if err != nil {
		return Outcome{}, fmt.Errorf("validate capsule manifest: %w", err)
	}
	if err := verifyCapsuleTree(capsuleRoot, manifest); err != nil {
		return Outcome{}, err
	}

	var fixture OfflineFixture
	if err := loadStrictJSONFile(fixturePath, maximumFixtureBytes, &fixture); err != nil {
		return Outcome{}, fmt.Errorf("load offline fixture: %w", err)
	}
	if err := fixture.validate(manifest, roles); err != nil {
		return Outcome{}, fmt.Errorf("validate offline fixture: %w", err)
	}
	manifestHash, err := manifestDigest(manifest)
	if err != nil {
		return Outcome{}, err
	}
	fixtureHash, err := fixtureDigest(fixture)
	if err != nil {
		return Outcome{}, err
	}
	return Outcome{
		SchemaVersion: OutcomeSchemaVersion, Status: StatusCompatibilityPassed,
		EvidenceMode: EvidenceModeOfflineFixture, FixtureID: fixture.FixtureID,
		CapsuleID: manifest.CapsuleID, ManifestDigest: manifestHash,
		CapsuleDigest: manifest.CapsuleDigest, BootImageDigest: roles.bootImage.SHA256,
		BootSignatureDigest: roles.bootSignature.SHA256,
		RootDataDigest:      roles.rootData.SHA256, RootHashDigest: roles.rootHash.SHA256,
		FixtureDigest: fixtureHash, FilesVerified: len(manifest.Files),
		SignatureVerified: false, SignerTrustAnchored: false,
		HardwareObserved: false, SecurityEnforced: false, MutationEligible: false,
	}, nil
}

func verifyCapsuleTree(root string, manifest CapsuleManifest) error {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return errors.New("capsule root must be a clean absolute path")
	}
	rootInfo, err := os.Lstat(root)
	if err != nil {
		return fmt.Errorf("inspect capsule root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return errors.New("capsule root must be a non-symlink directory")
	}

	expectedDirectories := make(map[string]struct{})
	for _, file := range manifest.Files {
		for directory := filepath.ToSlash(filepath.Dir(filepath.FromSlash(file.Path))); directory != "."; directory = filepath.ToSlash(filepath.Dir(filepath.FromSlash(directory))) {
			expectedDirectories[directory] = struct{}{}
		}
	}
	actualPaths := make([]string, 0, len(manifest.Files))
	err = filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if current == root {
			return nil
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("capsule path %q is a symbolic link", relative)
		}
		if entry.IsDir() {
			if _, expected := expectedDirectories[relative]; !expected {
				return fmt.Errorf("capsule directory %q is not required by the manifest", relative)
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("capsule path %q is not a regular file", relative)
		}
		if err := validateRelativePath(relative); err != nil {
			return fmt.Errorf("capsule path %q is invalid: %w", relative, err)
		}
		actualPaths = append(actualPaths, relative)
		return nil
	})
	if err != nil {
		return fmt.Errorf("inspect capsule tree: %w", err)
	}
	sort.Strings(actualPaths)
	expectedPaths := sortedManifestPaths(manifest)
	if len(actualPaths) != len(expectedPaths) {
		return fmt.Errorf("capsule file count is %d, want %d", len(actualPaths), len(expectedPaths))
	}
	for index := range expectedPaths {
		if actualPaths[index] != expectedPaths[index] {
			return fmt.Errorf("capsule file set differs at %q, want %q", actualPaths[index], expectedPaths[index])
		}
	}

	for _, expected := range manifest.Files {
		if err := verifyRegularFile(filepath.Join(root, filepath.FromSlash(expected.Path)), expected); err != nil {
			return fmt.Errorf("verify capsule file %q: %w", expected.Path, err)
		}
	}
	return nil
}

func verifyRegularFile(filePath string, expected CapsuleFile) error {
	file, err := os.OpenFile(filePath, os.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("open regular non-symlink file: %w", err)
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return fmt.Errorf("inspect file: %w", err)
	}
	if !before.Mode().IsRegular() {
		return errors.New("path is not a regular file")
	}
	if before.Size() != expected.SizeBytes {
		return fmt.Errorf("size is %d, want %d", before.Size(), expected.SizeBytes)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, file)
	if err != nil {
		return fmt.Errorf("hash file: %w", err)
	}
	if written != expected.SizeBytes {
		return errors.New("file size changed while hashing")
	}
	after, err := file.Stat()
	if err != nil {
		return fmt.Errorf("reinspect file: %w", err)
	}
	if !os.SameFile(before, after) || before.Size() != after.Size() || !before.ModTime().Equal(after.ModTime()) {
		return errors.New("file identity changed while hashing")
	}
	actualDigest := "sha256:" + hex.EncodeToString(hash.Sum(nil))
	if actualDigest != expected.SHA256 {
		return errors.New("digest does not match the capsule manifest")
	}
	return nil
}
