// Package mediarelease re-establishes the signed-release lineage of the
// boot artifacts recovered from a staged medium. It has no device access and
// no signing or mutation authority.
package mediarelease

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
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/eepromsigning"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediacontract"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/rpi5bootsig"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signedrelease"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/unfusedcompat"
)

const (
	maximumPublicKeyBytes     = 16 * 1024
	maximumRootIntegrityBytes = 64 * 1024
	maximumCommandLineBytes   = 64 * 1024
)

// FixedVerifier accepts only one linker-pinned signed-release publication and
// one linker-pinned mtools reader. Callers cannot select either at runtime.
type FixedVerifier struct {
	ReleaseRoot string
	MTypePath   string
}

func (verifier FixedVerifier) Validate() error {
	if err := validateStorePath("signed-release publication", verifier.ReleaseRoot, true); err != nil {
		return err
	}
	if err := validateStorePath("mtype executable", verifier.MTypePath, false); err != nil {
		return err
	}
	info, err := os.Stat(verifier.MTypePath)
	if err != nil {
		return fmt.Errorf("inspect fixed mtype executable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("fixed mtype path is not an executable regular file")
	}
	return nil
}

func validateStorePath(label, value string, directory bool) error {
	if value == "" || !filepath.IsAbs(value) || filepath.Clean(value) != value || !strings.HasPrefix(value, "/nix/store/") {
		return fmt.Errorf("generic build has no linker-fixed %s store path", label)
	}
	info, err := os.Lstat(value)
	if err != nil {
		return fmt.Errorf("inspect fixed %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() {
		return fmt.Errorf("fixed %s has the wrong filesystem type", label)
	}
	return nil
}

func (verifier FixedVerifier) Verify(ctx context.Context, files mediacontract.VerifiedBootFiles, plan mediacontract.Plan) error {
	if ctx == nil {
		return errors.New("signed-release verification requires a context")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := verifier.Validate(); err != nil {
		return err
	}
	if err := plan.Validate(); err != nil {
		return err
	}
	manifest, err := signedrelease.VerifyPublication(verifier.ReleaseRoot)
	if err != nil {
		return fmt.Errorf("verify fixed signed-release publication: %w", err)
	}
	manifestDigest, err := manifest.Digest()
	if err != nil {
		return err
	}
	if string(manifestDigest) != string(plan.Release.SignedReleaseManifestDigest) || manifest.ReleaseID != plan.Release.ReleaseID {
		return errors.New("fixed signed release differs from the media plan release binding")
	}

	artifacts := make(map[bundle.ArtifactRole]bundle.ReleaseArtifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifacts[artifact.Role] = artifact
	}
	bindings := []struct {
		role    bundle.ArtifactRole
		binding mediacontract.ArtifactBinding
	}{
		{bundle.RoleBootImage, plan.Layout.Payloads.BootImage},
		{bundle.RoleBootSignature, plan.Layout.Payloads.BootSignature},
		{bundle.RoleRootDataImage, plan.Layout.Payloads.RootData},
		{bundle.RoleRootHashTreeImage, plan.Layout.Payloads.RootHashTree},
		{bundle.RoleRootIntegrity, plan.Layout.Payloads.RootIntegrity},
	}
	for _, expected := range bindings {
		artifact, present := artifacts[expected.role]
		if !present || artifact.Kind != bundle.ArtifactKindRegularFile ||
			string(artifact.Digest) != string(expected.binding.Digest) || artifact.SizeBytes != expected.binding.SizeBytes {
			return fmt.Errorf("signed-release artifact %q differs from the media plan", expected.role)
		}
	}
	if err := verifyBytes("staged boot image", files.BootImage, plan.Layout.Payloads.BootImage); err != nil {
		return err
	}
	if err := verifyBytes("staged boot signature", files.BootSignature, plan.Layout.Payloads.BootSignature); err != nil {
		return err
	}

	publicKeyBytes, err := verifier.readObject(artifacts[bundle.RoleBootPublicKey], maximumPublicKeyBytes)
	if err != nil {
		return fmt.Errorf("read signed-release boot public key: %w", err)
	}
	publicKey, _, customerKeyBinary, err := eepromsigning.ParsePublicKey(publicKeyBytes)
	if err != nil {
		return fmt.Errorf("parse signed-release boot public key: %w", err)
	}
	if err := verifyCustomerKeyHash(manifest, customerKeyBinary); err != nil {
		return err
	}
	document, err := rpi5bootsig.Parse(files.BootSignature)
	if err != nil {
		return fmt.Errorf("parse staged boot signature: %w", err)
	}
	if string(document.ImageDigest) != string(plan.Layout.Payloads.BootImage.Digest) {
		return errors.New("staged boot signature names a different boot image digest")
	}
	if err := document.Verify(publicKey); err != nil {
		return fmt.Errorf("verify staged boot signature: %w", err)
	}

	capsuleFiles := []unfusedcompat.CapsuleFile{
		{Path: "boot.img", SizeBytes: int64(plan.Layout.Payloads.BootImage.SizeBytes), SHA256: string(plan.Layout.Payloads.BootImage.Digest)},
		{Path: "boot.sig", SizeBytes: int64(plan.Layout.Payloads.BootSignature.SizeBytes), SHA256: string(plan.Layout.Payloads.BootSignature.Digest)},
		{Path: "nvme/root-data.img", SizeBytes: int64(plan.Layout.Payloads.RootData.SizeBytes), SHA256: string(plan.Layout.Payloads.RootData.Digest)},
		{Path: "nvme/root-hash.img", SizeBytes: int64(plan.Layout.Payloads.RootHashTree.SizeBytes), SHA256: string(plan.Layout.Payloads.RootHashTree.Digest)},
	}
	capsuleDigest, err := unfusedcompat.ComputeCapsuleDigest(capsuleFiles)
	if err != nil {
		return err
	}
	if capsuleDigest != string(plan.Release.CapsuleDigest) {
		return errors.New("signed-release artifacts do not derive the media plan capsule digest")
	}

	rootIntegrity, err := verifier.readObject(artifacts[bundle.RoleRootIntegrity], maximumRootIntegrityBytes)
	if err != nil {
		return fmt.Errorf("read signed-release root-integrity record: %w", err)
	}
	bootObject := verifier.objectPath(artifacts[bundle.RoleBootImage].Digest)
	embeddedIntegrity, err := verifier.mtype(ctx, bootObject, "::kaiba-root-integrity.json", maximumRootIntegrityBytes)
	if err != nil {
		return fmt.Errorf("extract signed boot root-integrity record: %w", err)
	}
	if !bytes.Equal(embeddedIntegrity, rootIntegrity) {
		return errors.New("signed boot image embeds a different root-integrity record")
	}
	if err := validateRootIntegrity(rootIntegrity, plan); err != nil {
		return err
	}
	commandLine, err := verifier.mtype(ctx, bootObject, "::nixos/default/cmdline.txt", maximumCommandLineBytes)
	if err != nil {
		return fmt.Errorf("extract signed boot command line: %w", err)
	}
	if err := validateCommandLine(commandLine, plan); err != nil {
		return err
	}
	return nil
}

func verifyCustomerKeyHash(manifest bundle.SignedReleaseManifest, customerKeyBinary []byte) error {
	if len(customerKeyBinary) == 0 || bundle.Sum(customerKeyBinary) != manifest.ExpectedCustomerKeyHash {
		return errors.New("signed-release boot key does not derive the manifest expected customer-key hash")
	}
	return nil
}

func verifyBytes(label string, data []byte, binding mediacontract.ArtifactBinding) error {
	if uint64(len(data)) != binding.SizeBytes {
		return fmt.Errorf("%s size is %d, expected %d", label, len(data), binding.SizeBytes)
	}
	sum := sha256.Sum256(data)
	digest := "sha256:" + hex.EncodeToString(sum[:])
	if digest != string(binding.Digest) {
		return fmt.Errorf("%s digest is %s, expected %s", label, digest, binding.Digest)
	}
	return nil
}

func (verifier FixedVerifier) objectPath(digest bundle.Digest) string {
	return filepath.Join(verifier.ReleaseRoot, "objects", "sha256", strings.TrimPrefix(string(digest), "sha256:"))
}

func (verifier FixedVerifier) readObject(artifact bundle.ReleaseArtifact, maximum uint64) ([]byte, error) {
	if artifact.Kind != bundle.ArtifactKindRegularFile || artifact.SizeBytes == 0 || artifact.SizeBytes > maximum {
		return nil, errors.New("signed-release object exceeds its fixed bound or is not regular")
	}
	path := verifier.objectPath(artifact.Digest)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("construct signed-release object handle")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || uint64(info.Size()) != artifact.SizeBytes {
		return nil, errors.New("signed-release object type or size changed")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maximum)+1))
	if err != nil {
		return nil, err
	}
	if err := verifyBundleBytes(data, artifact); err != nil {
		return nil, err
	}
	return data, nil
}

func verifyBundleBytes(data []byte, artifact bundle.ReleaseArtifact) error {
	if uint64(len(data)) != artifact.SizeBytes || bundle.Sum(data) != artifact.Digest {
		return errors.New("signed-release object bytes differ from the manifest")
	}
	return nil
}

type boundedBuffer struct {
	maximum int
	data    []byte
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if len(data) > buffer.maximum-len(buffer.data) {
		return 0, errors.New("command output exceeds fixed bound")
	}
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}

func (verifier FixedVerifier) mtype(ctx context.Context, image, innerPath string, maximum int) ([]byte, error) {
	stdout := &boundedBuffer{maximum: maximum}
	stderr := &boundedBuffer{maximum: 16 * 1024}
	command := exec.CommandContext(ctx, verifier.MTypePath, "-i", image, innerPath)
	command.Env = []string{"LC_ALL=C", "TZ=UTC", "PATH=/empty"}
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		message := strings.TrimSpace(string(stderr.data))
		if message != "" {
			return nil, fmt.Errorf("mtype: %w: %s", err, message)
		}
		return nil, fmt.Errorf("mtype: %w", err)
	}
	if len(stdout.data) == 0 {
		return nil, errors.New("mtype returned an empty file")
	}
	return stdout.data, nil
}

type rootIntegrityRecord struct {
	Schema        string `json:"schema"`
	Algorithm     string `json:"algorithm"`
	DataBlockSize uint64 `json:"data_block_size"`
	HashBlockSize uint64 `json:"hash_block_size"`
	NoSuperblock  bool   `json:"no_superblock"`
	RootHash      string `json:"root_hash"`
	DataDevice    string `json:"data_device"`
	HashDevice    string `json:"hash_device"`
}

func validateRootIntegrity(encoded []byte, plan mediacontract.Plan) error {
	if err := rejectDuplicateJSONKeys(encoded); err != nil {
		return fmt.Errorf("decode signed root-integrity record: %w", err)
	}
	var record rootIntegrityRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return fmt.Errorf("decode signed root-integrity record: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return fmt.Errorf("decode signed root-integrity record: %w", err)
	}
	rootHash := strings.TrimPrefix(string(plan.Layout.Verity.RootHash), "sha256:")
	data := "PARTUUID=" + plan.Layout.Verity.DataPartitionGUID
	hash := "PARTUUID=" + plan.Layout.Verity.HashPartitionGUID
	if record.Schema != "provisioning.kaiba.network/rpi5-boot-integrity/v1alpha1" ||
		record.Algorithm != "sha256" || record.DataBlockSize != 4096 || record.HashBlockSize != 4096 ||
		record.NoSuperblock || record.RootHash != rootHash || record.DataDevice != data || record.HashDevice != hash {
		return errors.New("signed root-integrity record differs from the media plan dm-verity contract")
	}
	return nil
}

func rejectDuplicateJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if err := inspectJSONValue(decoder, token); err != nil {
		return err
	}
	return requireJSONEOF(decoder)
}

func inspectJSONValue(decoder *json.Decoder, token json.Token) error {
	delimiter, container := token.(json.Delim)
	if !container {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			seen[key] = struct{}{}
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONValue(decoder, value); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("JSON object is not terminated")
		}
	case '[':
		for decoder.More() {
			value, err := decoder.Token()
			if err != nil {
				return err
			}
			if err := inspectJSONValue(decoder, value); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("JSON array is not terminated")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func validateCommandLine(encoded []byte, plan mediacontract.Plan) error {
	if len(encoded) == 0 || len(encoded) > maximumCommandLineBytes || bytes.IndexByte(encoded, 0) >= 0 || encoded[len(encoded)-1] != '\n' {
		return errors.New("signed boot command line is empty, unbounded, NUL-containing, or lacks a final newline")
	}
	if strings.Contains(string(encoded), "/dev/nvme") {
		return errors.New("signed boot command line contains a topology-dependent NVMe selector")
	}
	rootHash := strings.TrimPrefix(string(plan.Layout.Verity.RootHash), "sha256:")
	wanted := map[string]string{
		"root":                     "root=fstab",
		"roothash":                 "roothash=" + rootHash,
		"rd.systemd.verity":        "rd.systemd.verity=1",
		"systemd.verity_root_data": "systemd.verity_root_data=PARTUUID=" + plan.Layout.Verity.DataPartitionGUID,
		"systemd.verity_root_hash": "systemd.verity_root_hash=PARTUUID=" + plan.Layout.Verity.HashPartitionGUID,
	}
	seen := make(map[string]bool, len(wanted)+1)
	for _, argument := range strings.Fields(string(encoded)) {
		if argument == "ro" {
			if seen["ro"] {
				return errors.New("signed boot command line repeats ro")
			}
			seen["ro"] = true
			continue
		}
		if argument == "rw" {
			return errors.New("signed boot command line enables a writable root")
		}
		key := argument
		if index := strings.IndexByte(argument, '='); index >= 0 {
			key = argument[:index]
		}
		if expected, owned := wanted[key]; owned {
			if argument != expected || seen[key] {
				return fmt.Errorf("signed boot command line has a non-canonical or repeated %s selector", key)
			}
			seen[key] = true
			continue
		}
		if key == "rootfstype" {
			return errors.New("signed boot command line bypasses the sealed initrd fstab filesystem type")
		}
		if key == "systemd.verity" || strings.HasPrefix(key, "systemd.verity_root_") || strings.HasPrefix(key, "rd.systemd.verity_root_") {
			return fmt.Errorf("signed boot command line contains unsupported verity selector %q", key)
		}
	}
	if !seen["ro"] {
		return errors.New("signed boot command line does not require a read-only root")
	}
	for key := range wanted {
		if !seen[key] {
			return fmt.Errorf("signed boot command line is missing %s", key)
		}
	}
	return nil
}
