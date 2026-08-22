package releasebindingmanifest

import (
	"errors"
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/releasebinding"
)

// ProductionReleaseMaterial is a single content-derived observation of every
// immutable runtime artifact used to construct a lane release binding.
type ProductionReleaseMaterial struct {
	CompiledArtifactSet CompiledArtifactSet
	LaneGuardPackage    LaneGuardPackage
	Binding             releasebinding.Binding
}

// SnapshotCompiledArtifactSet derives every metadata field from the supplied
// filesystem paths and emits artifacts in the schema's fixed role order.
// Callers cannot declare a type, mode, size, or content digest. The function
// snapshots one path at a time rather than locking a multi-path filesystem
// transaction; ProductionMode therefore relies on Nix-store immutability for
// aggregate consistency.
func SnapshotCompiledArtifactSet(paths []ArtifactPath, mode ValidationMode) (CompiledArtifactSet, error) {
	if err := validateMode(mode); err != nil {
		return CompiledArtifactSet{}, err
	}
	if len(paths) != len(compiledArtifactRoles) {
		return CompiledArtifactSet{}, fmt.Errorf("artifact paths must contain exactly %d records", len(compiledArtifactRoles))
	}

	byRole := make(map[ArtifactRole]string, len(paths))
	seenPaths := make(map[string]struct{}, len(paths))
	for index, assignment := range paths {
		if _, supported := expectedArtifactType(assignment.Role); !supported || assignment.Role == RoleLaneGuardExecutable {
			return CompiledArtifactSet{}, fmt.Errorf("artifact paths[%d] has unsupported compiled-artifact role %q", index, assignment.Role)
		}
		if _, duplicate := byRole[assignment.Role]; duplicate {
			return CompiledArtifactSet{}, fmt.Errorf("artifact paths[%d] duplicates role %q", index, assignment.Role)
		}
		if err := validateArtifactPath(assignment.Path, mode); err != nil {
			return CompiledArtifactSet{}, fmt.Errorf("artifact paths[%d]: %w", index, err)
		}
		if _, duplicate := seenPaths[assignment.Path]; duplicate {
			return CompiledArtifactSet{}, fmt.Errorf("artifact paths[%d] duplicates path %q", index, assignment.Path)
		}
		byRole[assignment.Role] = assignment.Path
		seenPaths[assignment.Path] = struct{}{}
	}

	artifacts := make([]Artifact, 0, len(compiledArtifactRoles))
	for _, role := range compiledArtifactRoles {
		path, present := byRole[role]
		if !present {
			return CompiledArtifactSet{}, fmt.Errorf("artifact paths is missing role %q", role)
		}
		artifact, err := snapshotArtifact(role, path, mode)
		if err != nil {
			return CompiledArtifactSet{}, fmt.Errorf("snapshot role %q: %w", role, err)
		}
		artifacts = append(artifacts, artifact)
	}

	manifest := CompiledArtifactSet{
		SchemaVersion: CompiledArtifactSetSchemaV1Alpha1,
		Artifacts:     artifacts,
	}
	if err := manifest.Validate(mode); err != nil {
		return CompiledArtifactSet{}, err
	}
	return manifest, nil
}

// SnapshotLaneGuardPackage verifies the compiled set, hashes the already-built
// lane-guard executable, and builds the acyclic package digest material. Use
// SnapshotProductionReleaseMaterial when the compiled set was just observed
// from immutable production paths and all three records are needed together.
func SnapshotLaneGuardPackage(executablePath string, compiled CompiledArtifactSet, expectations ReleaseExpectations, mode ValidationMode) (LaneGuardPackage, error) {
	if err := compiled.Verify(mode); err != nil {
		return LaneGuardPackage{}, fmt.Errorf("verify compiled artifact set: %w", err)
	}
	return snapshotLaneGuardPackage(executablePath, compiled, expectations, mode)
}

// SnapshotProductionReleaseMaterial observes every covered path exactly once,
// then derives both manifests and the binding from those observations. It is
// intentionally production-only: sequential observation is safe here because
// production validation admits only immutable /nix/store paths.
func SnapshotProductionReleaseMaterial(executablePath string, paths []ArtifactPath, expectations ReleaseExpectations) (ProductionReleaseMaterial, error) {
	compiled, err := SnapshotCompiledArtifactSet(paths, ProductionMode)
	if err != nil {
		return ProductionReleaseMaterial{}, err
	}
	laneGuard, err := snapshotLaneGuardPackage(executablePath, compiled, expectations, ProductionMode)
	if err != nil {
		return ProductionReleaseMaterial{}, err
	}
	binding, err := deriveBindingFromValidatedManifests(compiled, laneGuard, ProductionMode)
	if err != nil {
		return ProductionReleaseMaterial{}, err
	}
	return ProductionReleaseMaterial{
		CompiledArtifactSet: compiled,
		LaneGuardPackage:    laneGuard,
		Binding:             binding,
	}, nil
}

func snapshotLaneGuardPackage(executablePath string, compiled CompiledArtifactSet, expectations ReleaseExpectations, mode ValidationMode) (LaneGuardPackage, error) {
	if err := compiled.Validate(mode); err != nil {
		return LaneGuardPackage{}, fmt.Errorf("validate compiled artifact set: %w", err)
	}
	if err := expectations.Validate(); err != nil {
		return LaneGuardPackage{}, fmt.Errorf("release: %w", err)
	}
	if err := rejectLaneGuardPathCollision(compiled, executablePath); err != nil {
		return LaneGuardPackage{}, err
	}
	compiledDigest, err := compiled.Digest(mode)
	if err != nil {
		return LaneGuardPackage{}, err
	}
	executable, err := snapshotArtifact(RoleLaneGuardExecutable, executablePath, mode)
	if err != nil {
		return LaneGuardPackage{}, fmt.Errorf("snapshot lane-guard executable: %w", err)
	}
	manifest := LaneGuardPackage{
		SchemaVersion:             LaneGuardPackageSchemaV1Alpha1,
		Executable:                executable,
		CompiledArtifactSetDigest: compiledDigest,
		Release:                   expectations,
	}
	if err := manifest.Validate(mode); err != nil {
		return LaneGuardPackage{}, err
	}
	return manifest, nil
}

func rejectLaneGuardPathCollision(compiled CompiledArtifactSet, executablePath string) error {
	for _, artifact := range compiled.Artifacts {
		if artifact.Path == executablePath {
			return errors.New("lane-guard executable path duplicates a compiled artifact path")
		}
	}
	return nil
}

// Verify re-snapshots every path and requires exact equality with the
// canonical compiled manifest.
func (manifest CompiledArtifactSet) Verify(mode ValidationMode) error {
	if err := manifest.Validate(mode); err != nil {
		return err
	}
	for index, expected := range manifest.Artifacts {
		observed, err := snapshotArtifact(expected.Role, expected.Path, mode)
		if err != nil {
			return fmt.Errorf("artifacts[%d]: %w", index, err)
		}
		if observed != expected {
			return fmt.Errorf("artifacts[%d] no longer matches its path content", index)
		}
	}
	return nil
}

// Verify re-snapshots the executable. The compiled set is verified separately
// by DeriveBinding because the package record intentionally embeds only its
// digest, not a second copy of its manifest.
func (manifest LaneGuardPackage) Verify(mode ValidationMode) error {
	if err := manifest.Validate(mode); err != nil {
		return err
	}
	observed, err := snapshotArtifact(RoleLaneGuardExecutable, manifest.Executable.Path, mode)
	if err != nil {
		return err
	}
	if observed != manifest.Executable {
		return errors.New("lane-guard executable no longer matches its path content")
	}
	return nil
}
