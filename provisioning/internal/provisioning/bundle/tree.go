package bundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	// DirectoryTreeSchemaV1Alpha1 is the canonical representation used for
	// directory artifacts passed to rpiboot with its -d option.
	DirectoryTreeSchemaV1Alpha1 = "kaiba.provisioning.rpiboot-directory-tree/v1alpha1"

	// MaxDirectoryTreeBytes bounds both parsed input and canonical output.
	MaxDirectoryTreeBytes = 8 * 1024 * 1024

	maximumDirectoryTreeEntries        = 4096
	maximumDirectoryTreePathCharacters = 1024
	directoryTreeDigestDomain          = "kaiba.provisioning.rpiboot-directory-tree.v1alpha1"
)

// TreeEntryType is the closed vocabulary of filesystem objects accepted in a
// canonical RPIBOOT directory tree.
type TreeEntryType string

const (
	TreeEntryRegularFile TreeEntryType = "regular_file"
	TreeEntryDirectory   TreeEntryType = "directory"
)

// TreeEntry binds one descendant of a directory artifact. Directory entries
// use a zero size and the SHA-256 digest of the empty byte string; regular-file
// entries bind their exact byte size and content digest.
type TreeEntry struct {
	Path      string        `json:"path"`
	Type      TreeEntryType `json:"type"`
	Mode      string        `json:"mode"`
	SizeBytes uint64        `json:"size_bytes"`
	Digest    Digest        `json:"digest"`
}

// DirectoryTree is the canonical, platform-independent description of one
// directory artifact. RootMode binds the root without assigning it the
// otherwise forbidden relative path ".".
type DirectoryTree struct {
	SchemaVersion string      `json:"schema_version"`
	RootMode      string      `json:"root_mode"`
	Entries       []TreeEntry `json:"entries"`
}

// NewDirectoryTree copies and sorts entries into canonical path order, then
// applies the same validation used for untrusted parsed trees.
func NewDirectoryTree(rootMode string, entries []TreeEntry) (DirectoryTree, error) {
	canonicalEntries := append([]TreeEntry(nil), entries...)
	sort.Slice(canonicalEntries, func(left, right int) bool {
		return canonicalEntries[left].Path < canonicalEntries[right].Path
	})
	tree := DirectoryTree{
		SchemaVersion: DirectoryTreeSchemaV1Alpha1,
		RootMode:      rootMode,
		Entries:       canonicalEntries,
	}
	if err := tree.Validate(); err != nil {
		return DirectoryTree{}, err
	}
	return tree, nil
}

// ParseDirectoryTree strictly parses a bounded tree. Unknown fields,
// duplicate keys, JSON nulls, trailing values, non-canonical records, and
// unsupported schema versions are rejected.
func ParseDirectoryTree(data []byte) (DirectoryTree, error) {
	if len(data) == 0 || len(data) > MaxDirectoryTreeBytes {
		return DirectoryTree{}, fmt.Errorf("directory tree size must be between 1 and %d bytes", MaxDirectoryTreeBytes)
	}
	if err := rejectDirectoryTreeNulls(data); err != nil {
		return DirectoryTree{}, fmt.Errorf("decode directory tree: %w", err)
	}
	var tree DirectoryTree
	if err := strictDecode(data, &tree); err != nil {
		return DirectoryTree{}, fmt.Errorf("decode directory tree: %w", err)
	}
	if err := tree.Validate(); err != nil {
		return DirectoryTree{}, err
	}
	return tree, nil
}

// Validate checks schema, canonical path ordering, entry semantics, and the
// complete parent-directory relationship.
func (tree DirectoryTree) Validate() error {
	_, err := tree.validatedSizeBytes()
	return err
}

// CanonicalJSON returns the deterministic representation covered by Digest.
// Transport whitespace and a trailing newline are deliberately excluded.
func (tree DirectoryTree) CanonicalJSON() ([]byte, error) {
	if err := tree.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(tree)
	if err != nil {
		return nil, fmt.Errorf("encode canonical directory tree: %w", err)
	}
	return encoded, nil
}

// Digest returns the domain-separated digest of the canonical tree.
func (tree DirectoryTree) Digest() (Digest, error) {
	canonical, err := tree.CanonicalJSON()
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(directoryTreeDigestDomain))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(canonical)
	return Digest("sha256:" + hex.EncodeToString(hash.Sum(nil))), nil
}

// SizeBytes returns the sum of all regular-file byte lengths. Directory inode
// sizes are filesystem-specific and are never included.
func (tree DirectoryTree) SizeBytes() (uint64, error) {
	return tree.validatedSizeBytes()
}

func (tree DirectoryTree) validatedSizeBytes() (uint64, error) {
	if tree.SchemaVersion != DirectoryTreeSchemaV1Alpha1 {
		return 0, fmt.Errorf("unsupported directory tree schema_version %q", tree.SchemaVersion)
	}
	if err := validateTreeMode(tree.RootMode); err != nil {
		return 0, fmt.Errorf("root_mode: %w", err)
	}
	if len(tree.Entries) == 0 || len(tree.Entries) > maximumDirectoryTreeEntries {
		return 0, fmt.Errorf("entries must contain between 1 and %d records", maximumDirectoryTreeEntries)
	}

	emptyDigest := Sum(nil)
	entryTypes := make(map[string]TreeEntryType, len(tree.Entries))
	var total uint64
	for index, entry := range tree.Entries {
		if err := validateTreePath(entry.Path); err != nil {
			return 0, fmt.Errorf("entries[%d].path: %w", index, err)
		}
		if index > 0 && tree.Entries[index-1].Path >= entry.Path {
			return 0, errors.New("directory tree entries must be uniquely sorted by path")
		}
		if err := validateTreeMode(entry.Mode); err != nil {
			return 0, fmt.Errorf("entries[%d].mode: %w", index, err)
		}
		if err := entry.Digest.Validate(); err != nil {
			return 0, fmt.Errorf("entries[%d].digest: %w", index, err)
		}

		switch entry.Type {
		case TreeEntryDirectory:
			if entry.SizeBytes != 0 || entry.Digest != emptyDigest {
				return 0, fmt.Errorf("entries[%d] directory must have zero size and the empty-content digest", index)
			}
		case TreeEntryRegularFile:
			if math.MaxUint64-total < entry.SizeBytes {
				return 0, errors.New("directory tree regular-file size sum overflows uint64")
			}
			total += entry.SizeBytes
		default:
			return 0, fmt.Errorf("entries[%d].type %q is not supported", index, entry.Type)
		}

		parent := path.Dir(entry.Path)
		if parent != "." {
			parentType, present := entryTypes[parent]
			if !present {
				return 0, fmt.Errorf("entries[%d] is missing parent directory %q", index, parent)
			}
			if parentType != TreeEntryDirectory {
				return 0, fmt.Errorf("entries[%d] parent %q is not a directory", index, parent)
			}
		}
		entryTypes[entry.Path] = entry.Type
	}
	encoded, err := json.Marshal(tree)
	if err != nil {
		return 0, fmt.Errorf("encode directory tree for size validation: %w", err)
	}
	if len(encoded) > MaxDirectoryTreeBytes {
		return 0, fmt.Errorf("canonical directory tree exceeds %d bytes", MaxDirectoryTreeBytes)
	}
	return total, nil
}

func validateTreeMode(value string) error {
	if len(value) != 4 || value[0] != '0' {
		return errors.New("must be a canonical four-character octal mode")
	}
	for _, digit := range value[1:] {
		if digit < '0' || digit > '7' {
			return errors.New("must be a canonical four-character octal mode")
		}
	}
	return nil
}

func validateTreePath(value string) error {
	if value == "" || !utf8.ValidString(value) ||
		utf8.RuneCountInString(value) > maximumDirectoryTreePathCharacters ||
		value != path.Clean(value) || strings.HasPrefix(value, "/") || value == "." ||
		value == ".." || strings.HasPrefix(value, "../") || strings.Contains(value, "\\") ||
		strings.ContainsRune(value, '\x00') {
		return fmt.Errorf("must be a canonical UTF-8 relative slash-separated path of at most %d characters", maximumDirectoryTreePathCharacters)
	}
	for _, component := range strings.Split(value, "/") {
		if component == "" || component == "." || component == ".." {
			return errors.New("must not contain empty, dot, or parent components")
		}
	}
	return nil
}

func rejectDirectoryTreeNulls(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if token == nil {
			return errors.New("JSON null is not permitted")
		}
	}
}
