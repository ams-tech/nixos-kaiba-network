// Package signedrelease verifies and atomically publishes the complete,
// secret-free Raspberry Pi 5 signed-release closure.
package signedrelease

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

const (
	PublicationSchemaV1Alpha1 = "kaiba.provisioning.rpi5-signed-release-publication/v1alpha1"
	publicationDigestDomain   = "kaiba.provisioning.rpi5-signed-release-publication.v1alpha1"

	maxMetadataBytes   = 8 * 1024 * 1024
	maxRegularFileSize = 64 * 1024 * 1024 * 1024
)

// Inputs names every independently produced public boundary. Roles and file
// names are fixed by this package; callers cannot invent additional outputs.
type Inputs struct {
	ReleaseIntentPath             string
	UnsignedArtifactsManifestPath string
	EEPROMReleaseManifestPath     string
	SignedBootDirectory           string
	SignedEEPROMDirectory         string
	EEPROMReplayPlanDirectory     string
	EEPROMReplaySignedDirectory   string
	OwnedReplayPlanDirectory      string
	OwnedReplaySignedDirectory    string
	OwnedRecoveryDirectory        string
	DeviceProfilePath             string
	PlatformAdapterPath           string
	RootIntegrityPath             string
	FreshCommitBundle             string
	FreshReadbackBundle           string
	NegativeBootBundle            string
	OwnedReadbackBundle           string
	OwnedRecoveryBundle           string
	RootIntegrityTestBundle       string
	RootDataImagePath             string
	RootHashTreeImagePath         string
}

// EEPROMReplayVerifier re-runs both linker-pinned EEPROM finalizers and proves
// that the supplied fresh and owned finalized directories are their exact
// deterministic outputs. It is mandatory because public finalized directories
// alone cannot prove the updater/extractor boundaries were replayed.
type EEPROMReplayVerifier interface {
	VerifyEEPROMReplay(ctx context.Context, planDirectory, signedDirectory, finalizedDirectory string) error
	VerifyOwnedRecoveryReplay(ctx context.Context, planDirectory, signedDirectory, finalizedDirectory string) error
}

// EEPROMReplayVerifierFunc adapts a function for tests or an immutable CLI.
type EEPROMReplayVerifierFunc func(context.Context, string, string, string) error

func (f EEPROMReplayVerifierFunc) VerifyEEPROMReplay(ctx context.Context, plan, signed, finalized string) error {
	return f(ctx, plan, signed, finalized)
}

func (f EEPROMReplayVerifierFunc) VerifyOwnedRecoveryReplay(ctx context.Context, plan, signed, finalized string) error {
	return f(ctx, plan, signed, finalized)
}

// Options contains the mandatory no-authority updater replay boundary.
type Options struct {
	EEPROMReplayVerifier EEPROMReplayVerifier
}

// PublicationArtifact maps a manifest role to its content-addressed object.
type PublicationArtifact struct {
	Role           bundle.ArtifactRole `json:"role"`
	Kind           bundle.ArtifactKind `json:"kind"`
	Digest         bundle.Digest       `json:"digest"`
	SizeBytes      uint64              `json:"size_bytes"`
	Path           string              `json:"path"`
	TreeRecordPath string              `json:"tree_record_path,omitempty"`
}

// PublicationRecord preserves public lineage records which are not release
// artifacts themselves.
type PublicationRecord struct {
	ID        string        `json:"id"`
	Digest    bundle.Digest `json:"digest"`
	SizeBytes uint64        `json:"size_bytes"`
	Path      string        `json:"path"`
}

// Publication is the deterministic index at the root of a publication.
type Publication struct {
	SchemaVersion               string                `json:"schema_version"`
	SignedReleaseManifestDigest bundle.Digest         `json:"signed_release_manifest_digest"`
	ManifestPath                string                `json:"manifest_path"`
	ReleaseIntentDigest         bundle.Digest         `json:"release_intent_digest"`
	SourceRevision              string                `json:"source_revision"`
	Artifacts                   []PublicationArtifact `json:"artifacts"`
	Records                     []PublicationRecord   `json:"records"`
}

// CanonicalJSON returns the unique bytes covered by Digest.
func (p Publication) CanonicalJSON() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("encode canonical publication: %w", err)
	}
	return encoded, nil
}

// Digest returns the domain-separated publication index digest.
func (p Publication) Digest() (bundle.Digest, error) {
	encoded, err := p.CanonicalJSON()
	if err != nil {
		return "", err
	}
	return domainDigest(publicationDigestDomain, encoded), nil
}

// ResolvedRelease is the immutable result of strict input verification.
// Its unexported source handles prevent callers from changing role mappings.
type ResolvedRelease struct {
	Manifest    bundle.SignedReleaseManifest
	Publication Publication
	files       map[bundle.ArtifactRole]regularSource
	trees       map[bundle.ArtifactRole]treeSource
	records     map[string]regularSource
}
