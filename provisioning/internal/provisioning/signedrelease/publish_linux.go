//go:build linux

package signedrelease

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
)

var publicationTopLevel = []string{
	"manifests", "objects", "publication-digest", "publication.json", "records", "tree-records", "trees",
}

// Finalize verifies all inputs, builds the exact release closure, publishes it
// atomically without replacement, and reopens the durable result.
func Finalize(ctx context.Context, inputs Inputs, outputDirectory string, options Options) error {
	resolved, err := Resolve(ctx, inputs, options)
	if err != nil {
		return err
	}
	return Publish(resolved, outputDirectory)
}

// Publish writes an already verified release as a content-addressed immutable
// directory. The output must not exist and is never replaced.
func Publish(release ResolvedRelease, outputDirectory string) error {
	if err := release.Manifest.Validate(); err != nil {
		return fmt.Errorf("signed-release manifest: %w", err)
	}
	if err := release.Publication.Validate(); err != nil {
		return fmt.Errorf("publication: %w", err)
	}
	if len(release.files) != 12 || len(release.trees) != 6 || len(release.records) != 9 {
		return errors.New("resolved release does not contain the exact fixed source set")
	}
	if err := validateAbsolutePath(outputDirectory); err != nil {
		return fmt.Errorf("output directory: %w", err)
	}
	parent := filepath.Dir(outputDirectory)
	parentHandle, parentIdentity, err := openAbsolute(parent, true)
	if err != nil {
		return fmt.Errorf("output parent: %w", err)
	}
	defer parentHandle.Close()
	if _, err := os.Lstat(outputDirectory); err == nil {
		return errors.New("output directory already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temporary, err := os.MkdirTemp(parent, "."+filepath.Base(outputDirectory)+".tmp-")
	if err != nil {
		return err
	}
	if err := requireSameDirectoryNode(parent, parentIdentity); err != nil {
		removeTemporaryTree(temporary)
		return fmt.Errorf("output parent changed during staging setup: %w", err)
	}
	temporaryName := filepath.Base(temporary)
	outputName := filepath.Base(outputDirectory)
	keep := false
	defer func() {
		if !keep {
			removeTemporaryTree(temporary)
		}
	}()

	for _, relative := range []string{"manifests/sha256", "objects/sha256", "records/sha256", "tree-records/sha256", "trees/sha256"} {
		if err := os.MkdirAll(filepath.Join(temporary, filepath.FromSlash(relative)), 0755); err != nil {
			return err
		}
	}
	manifestJSON, err := release.Manifest.CanonicalJSON()
	if err != nil {
		return err
	}
	if err := writeImmutable(filepath.Join(temporary, filepath.FromSlash(release.Publication.ManifestPath)), jsonFile(manifestJSON)); err != nil {
		return err
	}

	for _, artifact := range release.Manifest.Artifacts {
		if artifact.Kind == bundle.ArtifactKindRegularFile {
			source, exists := release.files[artifact.Role]
			if !exists {
				return fmt.Errorf("missing source for role %s", artifact.Role)
			}
			destination := filepath.Join(temporary, "objects", "sha256", digestHex(artifact.Digest))
			if err := materializeRegular(source, destination, artifact.Digest, artifact.SizeBytes); err != nil {
				return fmt.Errorf("publish %s: %w", artifact.Role, err)
			}
			continue
		}
		source, exists := release.trees[artifact.Role]
		if !exists {
			return fmt.Errorf("missing tree source for role %s", artifact.Role)
		}
		destination := filepath.Join(temporary, "trees", "sha256", digestHex(artifact.Digest))
		if _, err := os.Lstat(destination); errors.Is(err, os.ErrNotExist) {
			if err := materializeTree(source, destination); err != nil {
				return fmt.Errorf("publish %s: %w", artifact.Role, err)
			}
		} else if err != nil {
			return err
		}
		treeJSON, err := source.tree.CanonicalJSON()
		if err != nil {
			return err
		}
		recordPath := filepath.Join(temporary, "tree-records", "sha256", digestHex(artifact.Digest)+".json")
		if err := writeImmutableDeduplicated(recordPath, jsonFile(treeJSON)); err != nil {
			return err
		}
	}

	for _, record := range release.Publication.Records {
		source, exists := release.records[record.ID]
		if !exists {
			return fmt.Errorf("missing publication record source %q", record.ID)
		}
		destination := filepath.Join(temporary, "records", "sha256", digestHex(record.Digest))
		if err := materializeRegular(source, destination, record.Digest, record.SizeBytes); err != nil {
			return fmt.Errorf("publish record %s: %w", record.ID, err)
		}
	}
	publicationJSON, err := release.Publication.CanonicalJSON()
	if err != nil {
		return err
	}
	if err := writeImmutable(filepath.Join(temporary, "publication.json"), jsonFile(publicationJSON)); err != nil {
		return err
	}
	publicationDigest, err := release.Publication.Digest()
	if err != nil {
		return err
	}
	if err := writeImmutable(filepath.Join(temporary, "publication-digest"), []byte(string(publicationDigest)+"\n")); err != nil {
		return err
	}

	if _, err := VerifyPublication(temporary); err != nil {
		return fmt.Errorf("verify staged publication: %w", err)
	}
	if err := makeInfrastructureReadOnly(temporary); err != nil {
		return err
	}
	if err := syncDirectories(temporary); err != nil {
		return err
	}
	if err := requireSameDirectoryNode(parent, parentIdentity); err != nil {
		return fmt.Errorf("output parent changed before publication: %w", err)
	}
	if err := renameNoReplaceAt(int(parentHandle.Fd()), temporaryName, int(parentHandle.Fd()), outputName); err != nil {
		return fmt.Errorf("publish output without replacement: %w", err)
	}
	keep = true
	if err := parentHandle.Sync(); err != nil {
		return fmt.Errorf("sync output parent: %w", err)
	}
	if err := requireSameDirectoryNode(parent, parentIdentity); err != nil {
		return fmt.Errorf("output parent changed after publication: %w", err)
	}
	if _, err := VerifyPublication(outputDirectory); err != nil {
		return fmt.Errorf("reopen published release: %w", err)
	}
	return nil
}

func materializeRegular(source regularSource, destination string, expectedDigest bundle.Digest, expectedSize uint64) error {
	if existing, err := os.Lstat(destination); err == nil {
		if !existing.Mode().IsRegular() || existing.Mode()&os.ModeSymlink != 0 {
			return errors.New("content-addressed destination collision is not a regular file")
		}
		actual, err := inspectRegular(destination, int64(expectedSize), false)
		if err != nil || actual.digest != expectedDigest || actual.size != expectedSize {
			return errors.New("content-addressed destination collision has different bytes")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	closeWithError := func(cause error) error {
		closeErr := file.Close()
		if cause != nil {
			return cause
		}
		return closeErr
	}
	var reader io.Reader
	if source.path == "" {
		reader = bytes.NewReader(source.contents)
	} else {
		opened, _, err := openAbsolute(source.path, false)
		if err != nil {
			return closeWithError(err)
		}
		defer opened.Close()
		reader = opened
	}
	hash := sha256.New()
	written, err := copyExact(io.MultiWriter(file, hash), reader)
	if err != nil {
		return closeWithError(err)
	}
	actual := bundle.Digest("sha256:" + hex.EncodeToString(hash.Sum(nil)))
	if uint64(written) != expectedSize || actual != expectedDigest || source.size != expectedSize || source.digest != expectedDigest {
		return closeWithError(errors.New("source bytes do not match their verified content-addressed record"))
	}
	if err := file.Sync(); err != nil {
		return closeWithError(err)
	}
	if err := file.Chmod(0444); err != nil {
		return closeWithError(err)
	}
	if err := file.Sync(); err != nil {
		return closeWithError(err)
	}
	return closeWithError(nil)
}

func materializeTree(source treeSource, destination string) error {
	if err := os.Mkdir(destination, 0700); err != nil {
		return err
	}
	directoryModes := make(map[string]os.FileMode)
	rootMode, err := parseMode(source.tree.RootMode)
	if err != nil {
		return err
	}
	directoryModes[destination] = rootMode
	for _, entry := range source.tree.Entries {
		target := filepath.Join(destination, filepath.FromSlash(entry.Path))
		mode, err := parseMode(entry.Mode)
		if err != nil {
			return err
		}
		if entry.Type == bundle.TreeEntryDirectory {
			if err := os.Mkdir(target, 0700); err != nil {
				return err
			}
			directoryModes[target] = mode
			continue
		}
		regular := regularSource{path: filepath.Join(source.path, filepath.FromSlash(entry.Path)), digest: entry.Digest, size: entry.SizeBytes}
		if err := materializeRegular(regular, target, entry.Digest, entry.SizeBytes); err != nil {
			return err
		}
		if err := os.Chmod(target, mode); err != nil {
			return err
		}
		opened, _, err := openAbsolute(target, false)
		if err != nil {
			return err
		}
		err = opened.Sync()
		opened.Close()
		if err != nil {
			return err
		}
	}
	paths := make([]string, 0, len(directoryModes))
	for path := range directoryModes {
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool { return len(paths[i]) > len(paths[j]) })
	for _, path := range paths {
		if err := os.Chmod(path, directoryModes[path]); err != nil {
			return err
		}
	}
	actual, err := bundle.SnapshotDirectoryTree(destination)
	if err != nil {
		return err
	}
	wantJSON, _ := source.tree.CanonicalJSON()
	actualJSON, _ := actual.CanonicalJSON()
	if !bytes.Equal(wantJSON, actualJSON) {
		return errors.New("published directory tree differs from its canonical record")
	}
	current, err := bundle.SnapshotDirectoryTree(source.path)
	if err != nil {
		return err
	}
	currentJSON, _ := current.CanonicalJSON()
	if !bytes.Equal(wantJSON, currentJSON) {
		return errors.New("source directory tree changed while publishing")
	}
	return nil
}

func parseMode(value string) (os.FileMode, error) {
	parsed, err := strconv.ParseUint(value, 8, 12)
	if err != nil || len(value) != 4 {
		return 0, errors.New("invalid canonical permission mode")
	}
	return os.FileMode(parsed), nil
}

func writeImmutable(path string, contents []byte) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	if _, err := file.Write(contents); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	if err := file.Chmod(0444); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func writeImmutableDeduplicated(path string, contents []byte) error {
	if current, err := os.ReadFile(path); err == nil {
		if !bytes.Equal(current, contents) {
			return errors.New("content-addressed record collision")
		}
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return writeImmutable(path, contents)
}

func makeInfrastructureReadOnly(root string) error {
	var directories []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("staged publication contains a symbolic link")
		}
		if info.IsDir() {
			directories = append(directories, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, path := range directories {
		// Preserve artifact-tree modes. Only content-addressing infrastructure
		// and the publication root are normalized here.
		relative, _ := filepath.Rel(root, path)
		if relative == "." || relative == "manifests" || relative == "manifests/sha256" ||
			relative == "objects" || relative == "objects/sha256" || relative == "records" || relative == "records/sha256" ||
			relative == "tree-records" || relative == "tree-records/sha256" || relative == "trees" || relative == "trees/sha256" {
			if err := os.Chmod(path, 0555); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncDirectories(root string) error {
	var directories []string
	if err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			directories = append(directories, path)
		}
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(directories, func(i, j int) bool { return len(directories[i]) > len(directories[j]) })
	for _, path := range directories {
		directory, err := os.Open(path)
		if err != nil {
			return err
		}
		err = directory.Sync()
		directory.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

func removeTemporaryTree(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && info.IsDir() {
			_ = os.Chmod(path, 0700)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}

func digestHex(digest bundle.Digest) string { return strings.TrimPrefix(string(digest), "sha256:") }

// VerifyPublication reopens a publication, rejects additions and unsafe
// filesystem objects, and verifies every content-addressed byte and tree.
func VerifyPublication(root string) (bundle.SignedReleaseManifest, error) {
	if err := requireDirectoryNames(root, publicationTopLevel); err != nil {
		return bundle.SignedReleaseManifest{}, fmt.Errorf("publication root: %w", err)
	}
	publicationSource, err := inspectRegular(filepath.Join(root, "publication.json"), maxMetadataBytes, true)
	if err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	var publication Publication
	if err := strictDecode(publicationSource.contents, &publication); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	canonicalPublication, err := publication.CanonicalJSON()
	if err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	if !bytes.Equal(publicationSource.contents, jsonFile(canonicalPublication)) {
		return bundle.SignedReleaseManifest{}, errors.New("publication.json is not canonical newline-terminated JSON")
	}
	digest, _ := publication.Digest()
	digestSource, err := inspectRegular(filepath.Join(root, "publication-digest"), 128, true)
	if err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	if !bytes.Equal(digestSource.contents, []byte(string(digest)+"\n")) {
		return bundle.SignedReleaseManifest{}, errors.New("publication-digest does not match publication.json")
	}

	manifestFile := filepath.Join(root, filepath.FromSlash(publication.ManifestPath))
	manifestSource, err := inspectRegular(manifestFile, bundle.MaxSignedReleaseManifestBytes, true)
	if err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	manifest, err := bundle.ParseSignedReleaseManifest(manifestSource.contents)
	if err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	manifestJSON, _ := manifest.CanonicalJSON()
	if !bytes.Equal(manifestSource.contents, jsonFile(manifestJSON)) {
		return bundle.SignedReleaseManifest{}, errors.New("signed-release manifest is not canonical newline-terminated JSON")
	}
	manifestDigest, _ := manifest.Digest()
	if manifestDigest != publication.SignedReleaseManifestDigest || manifest.ReleaseIntentDigest != publication.ReleaseIntentDigest || manifest.SourceRevision != publication.SourceRevision {
		return bundle.SignedReleaseManifest{}, errors.New("publication index does not bind the signed-release manifest")
	}
	if err := requireDirectoryNames(filepath.Join(root, "manifests"), []string{"sha256"}); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	if err := requireDirectoryNames(filepath.Join(root, "manifests", "sha256"), []string{digestHex(manifestDigest) + ".json"}); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}

	objectNames, treeNames, treeRecordNames := []string{}, []string{}, []string{}
	artifactByRole := make(map[bundle.ArtifactRole]bundle.ReleaseArtifact, len(manifest.Artifacts))
	for _, artifact := range manifest.Artifacts {
		artifactByRole[artifact.Role] = artifact
	}
	for _, indexed := range publication.Artifacts {
		artifact := artifactByRole[indexed.Role]
		if indexed.Kind != artifact.Kind || indexed.Digest != artifact.Digest || indexed.SizeBytes != artifact.SizeBytes {
			return bundle.SignedReleaseManifest{}, errors.New("publication artifact index differs from manifest")
		}
		if artifact.Kind == bundle.ArtifactKindRegularFile {
			objectNames = append(objectNames, digestHex(artifact.Digest))
			source, err := inspectRegular(filepath.Join(root, filepath.FromSlash(indexed.Path)), int64(artifact.SizeBytes), false)
			if err != nil || source.digest != artifact.Digest || source.size != artifact.SizeBytes {
				return bundle.SignedReleaseManifest{}, fmt.Errorf("artifact %s object does not match manifest", artifact.Role)
			}
		} else {
			treeNames = append(treeNames, digestHex(artifact.Digest))
			treeRecordNames = append(treeRecordNames, digestHex(artifact.Digest)+".json")
			verifiedTree, err := inspectTree(filepath.Join(root, filepath.FromSlash(indexed.Path)))
			if err != nil {
				return bundle.SignedReleaseManifest{}, err
			}
			actualJSON, _ := verifiedTree.tree.CanonicalJSON()
			wantJSON, _ := artifact.Tree.CanonicalJSON()
			if !bytes.Equal(actualJSON, wantJSON) {
				return bundle.SignedReleaseManifest{}, fmt.Errorf("artifact %s tree does not match manifest", artifact.Role)
			}
			record, err := inspectRegular(filepath.Join(root, filepath.FromSlash(indexed.TreeRecordPath)), bundle.MaxDirectoryTreeBytes, true)
			if err != nil || !bytes.Equal(record.contents, jsonFile(wantJSON)) {
				return bundle.SignedReleaseManifest{}, fmt.Errorf("artifact %s tree record does not match manifest", artifact.Role)
			}
		}
	}
	objectNames = uniqueSorted(objectNames)
	treeNames = uniqueSorted(treeNames)
	treeRecordNames = uniqueSorted(treeRecordNames)
	if err := requireAddressDirectory(root, "objects", objectNames); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	if err := requireAddressDirectory(root, "trees", treeNames); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	if err := requireAddressDirectory(root, "tree-records", treeRecordNames); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}

	recordNames := make([]string, 0, len(publication.Records))
	for _, record := range publication.Records {
		recordNames = append(recordNames, digestHex(record.Digest))
		source, err := inspectRegular(filepath.Join(root, filepath.FromSlash(record.Path)), int64(record.SizeBytes), true)
		if err != nil || source.digest != record.Digest || source.size != record.SizeBytes {
			return bundle.SignedReleaseManifest{}, fmt.Errorf("publication record %s does not match its index", record.ID)
		}
	}
	if err := requireAddressDirectory(root, "records", uniqueSorted(recordNames)); err != nil {
		return bundle.SignedReleaseManifest{}, err
	}
	return manifest, nil
}

func requireAddressDirectory(root, name string, leaves []string) error {
	if err := requireDirectoryNames(filepath.Join(root, name), []string{"sha256"}); err != nil {
		return err
	}
	return requireDirectoryNames(filepath.Join(root, name, "sha256"), leaves)
}

func requireDirectoryNames(path string, wanted []string) error {
	directory, _, err := openAbsolute(path, true)
	if err != nil {
		return err
	}
	defer directory.Close()
	wanted = append([]string(nil), wanted...)
	sort.Strings(wanted)
	return requireExactNames(directory, wanted)
}

func uniqueSorted(values []string) []string {
	sort.Strings(values)
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
