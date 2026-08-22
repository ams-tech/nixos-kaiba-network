package mediacontract

import (
	"encoding/json"
	"errors"
	"fmt"
)

const (
	MediaBindingSchemaVersion = "kaiba.provisioning.rpi5-media-binding/v1alpha1"
	MaximumMediaBindingBytes  = 64 * 1024
)

// MediaBinding is the non-circular release record stored in the outer FAT.
// It deliberately excludes layout_digest, plan_digest, its own digest, and the
// full-media digest. Those values depend on the FAT bytes that contain it.
type MediaBinding struct {
	SchemaVersion               string `json:"schema_version"`
	TransactionID               string `json:"transaction_id"`
	ReleaseID                   string `json:"release_id"`
	SignedReleaseManifestDigest Digest `json:"signed_release_manifest_digest"`
	CapsuleDigest               Digest `json:"capsule_digest"`
	BootImageDigest             Digest `json:"boot_image_digest"`
	BootSignatureDigest         Digest `json:"boot_signature_digest"`
	RootDataDigest              Digest `json:"root_data_digest"`
	RootHashTreeDigest          Digest `json:"root_hash_tree_digest"`
	RootIntegrityDigest         Digest `json:"root_integrity_digest"`
	VerityRootHash              Digest `json:"verity_root_hash"`
	BootPartitionGUID           string `json:"boot_partition_guid"`
	DataPartitionGUID           string `json:"data_partition_guid"`
	HashPartitionGUID           string `json:"hash_partition_guid"`
}

func (binding MediaBinding) Validate() error {
	if binding.SchemaVersion != MediaBindingSchemaVersion {
		return fmt.Errorf("unsupported media binding schema_version %q", binding.SchemaVersion)
	}
	if err := validateIdentifier("transaction_id", binding.TransactionID); err != nil {
		return err
	}
	if err := validateIdentifier("release_id", binding.ReleaseID); err != nil {
		return err
	}
	for label, digest := range map[string]Digest{
		"signed_release_manifest_digest": binding.SignedReleaseManifestDigest,
		"capsule_digest":                 binding.CapsuleDigest,
		"boot_image_digest":              binding.BootImageDigest,
		"boot_signature_digest":          binding.BootSignatureDigest,
		"root_data_digest":               binding.RootDataDigest,
		"root_hash_tree_digest":          binding.RootHashTreeDigest,
		"root_integrity_digest":          binding.RootIntegrityDigest,
		"verity_root_hash":               binding.VerityRootHash,
	} {
		if err := validateDigest(label, digest); err != nil {
			return err
		}
	}
	seen := make(map[string]struct{}, 3)
	for label, guid := range map[string]string{
		"boot_partition_guid": binding.BootPartitionGUID,
		"data_partition_guid": binding.DataPartitionGUID,
		"hash_partition_guid": binding.HashPartitionGUID,
	} {
		if err := validateGUID(label, guid); err != nil {
			return err
		}
		if _, duplicate := seen[guid]; duplicate {
			return errors.New("media binding partition GUIDs must be distinct")
		}
		seen[guid] = struct{}{}
	}
	return nil
}

func (binding MediaBinding) ValidateAgainst(plan Plan) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if err := binding.Validate(); err != nil {
		return err
	}
	boot, _ := plan.Layout.partition(PartitionBoot)
	data, _ := plan.Layout.partition(PartitionRootData)
	hash, _ := plan.Layout.partition(PartitionRootHash)
	if binding.TransactionID != plan.TransactionID || binding.ReleaseID != plan.Release.ReleaseID ||
		binding.SignedReleaseManifestDigest != plan.Release.SignedReleaseManifestDigest || binding.CapsuleDigest != plan.Release.CapsuleDigest ||
		binding.BootImageDigest != plan.Layout.Payloads.BootImage.Digest || binding.BootSignatureDigest != plan.Layout.Payloads.BootSignature.Digest ||
		binding.RootDataDigest != plan.Layout.Payloads.RootData.Digest || binding.RootHashTreeDigest != plan.Layout.Payloads.RootHashTree.Digest ||
		binding.RootIntegrityDigest != plan.Layout.Payloads.RootIntegrity.Digest || binding.VerityRootHash != plan.Layout.Verity.RootHash ||
		binding.BootPartitionGUID != boot.UniqueGUID || binding.DataPartitionGUID != data.UniqueGUID || binding.HashPartitionGUID != hash.UniqueGUID {
		return errors.New("outer FAT media binding differs from the approved transaction, release, payload, or partition layout")
	}
	return nil
}

func (binding MediaBinding) CanonicalJSON() ([]byte, error) {
	if err := binding.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(binding)
	if err != nil {
		return nil, fmt.Errorf("encode canonical media binding: %w", err)
	}
	if len(encoded) > MaximumMediaBindingBytes {
		return nil, errors.New("canonical media binding exceeds its fixed byte bound")
	}
	return encoded, nil
}

func ParseMediaBinding(data []byte) (MediaBinding, error) {
	if len(data) > MaximumMediaBindingBytes {
		return MediaBinding{}, errors.New("media binding exceeds its fixed byte bound")
	}
	var binding MediaBinding
	err := strictCanonicalDecode(data, &binding, func() ([]byte, error) { return binding.CanonicalJSON() })
	return binding, err
}
