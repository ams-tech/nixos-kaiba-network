//go:build !linux

package releasebindingmanifest

import "errors"

func snapshotArtifact(ArtifactRole, string, ValidationMode) (Artifact, error) {
	return Artifact{}, errors.New("artifact snapshotting is supported only on Linux")
}
