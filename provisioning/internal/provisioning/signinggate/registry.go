// Package signinggate implements the durable, approval-gated control-host
// bridge between Raspberry Pi's HSM-wrapper protocol and a fixed key backend.
package signinggate

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"syscall"
	"time"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/bundle"
	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/signing"
)

const (
	RegistrySchemaV1Alpha2 = "kaiba.provisioning.signing-grant-registry/v1alpha2"
	GrantSchemaV1Alpha2    = "kaiba.provisioning.signing-grant/v1alpha2"
	MaxRegistryBytes       = 1024 * 1024
	MaxRegistryGrants      = 512
)

var (
	grantIdentifierPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:-]{0,127}$`)
	expiryPattern          = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
)

// Grant binds one immutable, approval-authorized artifact to its complete
// transaction context. The client never supplies any of these fields.
type Grant struct {
	SchemaVersion string          `json:"schema_version"`
	GrantID       string          `json:"grant_id"`
	ExpiresAt     string          `json:"expires_at"`
	Request       signing.Request `json:"request"`
}

// Registry is loaded once from a root-managed file when the daemon starts.
type Registry struct {
	SchemaVersion string  `json:"schema_version"`
	Grants        []Grant `json:"grants"`
}

type RegistryConfig struct {
	Path     string
	OwnerUID uint32
}

// LoadRegistry verifies file and parent ownership before strictly decoding the
// grant registry. Group/world-writable files or directories and symlinks are
// rejected so an unprivileged client cannot replace authorization state.
func LoadRegistry(config RegistryConfig) (Registry, error) {
	data, err := readManagedFile(config.Path, config.OwnerUID, MaxRegistryBytes)
	if err != nil {
		return Registry{}, fmt.Errorf("load signing grant registry: %w", err)
	}
	var registry Registry
	if err := strictDecode(data, &registry); err != nil {
		return Registry{}, fmt.Errorf("decode signing grant registry: %w", err)
	}
	if err := registry.Validate(); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func (r Registry) Validate() error {
	if r.SchemaVersion != RegistrySchemaV1Alpha2 {
		return fmt.Errorf("unsupported signing grant registry schema_version %q", r.SchemaVersion)
	}
	if len(r.Grants) == 0 || len(r.Grants) > MaxRegistryGrants {
		return fmt.Errorf("grant registry must contain between 1 and %d grants", MaxRegistryGrants)
	}
	grantIDs := make(map[string]struct{}, len(r.Grants))
	requestIDs := make(map[string]struct{}, len(r.Grants))
	var previous string
	for index, grant := range r.Grants {
		if err := grant.Validate(); err != nil {
			return fmt.Errorf("grants[%d]: %w", index, err)
		}
		if _, exists := grantIDs[grant.GrantID]; exists {
			return fmt.Errorf("grant_id %q is duplicated", grant.GrantID)
		}
		grantIDs[grant.GrantID] = struct{}{}
		if _, exists := requestIDs[grant.Request.RequestID]; exists {
			return fmt.Errorf("request_id %q is duplicated", grant.Request.RequestID)
		}
		requestIDs[grant.Request.RequestID] = struct{}{}
		if index > 0 && grant.GrantID <= previous {
			return errors.New("grants must be sorted by grant_id in strictly increasing order")
		}
		previous = grant.GrantID
	}
	return nil
}

func (g Grant) Validate() error {
	if g.SchemaVersion != GrantSchemaV1Alpha2 {
		return fmt.Errorf("unsupported grant schema_version %q", g.SchemaVersion)
	}
	if !grantIdentifierPattern.MatchString(g.GrantID) {
		return errors.New("grant_id must be a canonical lower-case identifier")
	}
	if _, err := g.Expiry(); err != nil {
		return err
	}
	if err := g.Request.Validate(); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	return nil
}

func (g Grant) Expiry() (time.Time, error) {
	if !expiryPattern.MatchString(g.ExpiresAt) {
		return time.Time{}, errors.New("expires_at must use canonical UTC RFC3339 seconds")
	}
	expiresAt, err := time.Parse(time.RFC3339, g.ExpiresAt)
	if err != nil || expiresAt.Format(time.RFC3339) != g.ExpiresAt {
		return time.Time{}, errors.New("expires_at must use canonical UTC RFC3339 seconds")
	}
	return expiresAt, nil
}

// CurrentGrant resolves authorization using only the digest calculated by the
// daemon. Zero or multiple current grants fail closed.
func (r Registry) CurrentGrant(digest bundle.Digest, now time.Time) (Grant, error) {
	if err := digest.Validate(); err != nil {
		return Grant{}, err
	}
	matches := make([]Grant, 0, 1)
	for _, grant := range r.Grants {
		expiresAt, _ := grant.Expiry()
		if grant.Request.ArtifactDigest == digest && now.Before(expiresAt) {
			matches = append(matches, grant)
		}
	}
	if len(matches) == 0 {
		return Grant{}, errors.New("no current signing grant matches the artifact digest")
	}
	if len(matches) != 1 {
		return Grant{}, fmt.Errorf("artifact digest matches %d current signing grants", len(matches))
	}
	return matches[0], nil
}

// NewRegistry sorts grants into canonical order and validates the result. It
// is useful for the separate grant-authoring workflow; the gate only loads a
// pre-existing root-managed registry.
func NewRegistry(grants []Grant) (Registry, error) {
	canonical := append([]Grant(nil), grants...)
	sort.Slice(canonical, func(i, j int) bool { return canonical[i].GrantID < canonical[j].GrantID })
	registry := Registry{SchemaVersion: RegistrySchemaV1Alpha2, Grants: canonical}
	if err := registry.Validate(); err != nil {
		return Registry{}, err
	}
	return registry, nil
}

func readManagedFile(path string, ownerUID uint32, maxBytes int) ([]byte, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("path must be absolute and clean")
	}
	if err := validateManagedDirectory(filepath.Dir(path), ownerUID, false); err != nil {
		return nil, fmt.Errorf("registry parent: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("registry must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return nil, errors.New("registry must not be group- or world-writable")
	}
	if err := requireOwner(info, ownerUID); err != nil {
		return nil, err
	}
	if info.Size() <= 0 || info.Size() > int64(maxBytes) {
		return nil, fmt.Errorf("registry size must be between 1 and %d bytes", maxBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, errors.New("registry changed while opening")
	}
	data, err := io.ReadAll(io.LimitReader(file, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxBytes {
		return nil, fmt.Errorf("registry exceeds %d bytes", maxBytes)
	}
	return data, nil
}

func validateManagedDirectory(path string, ownerUID uint32, private bool) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("directory path must be absolute and clean")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errors.New("path must be a non-symlink directory")
	}
	if err := requireOwner(info, ownerUID); err != nil {
		return err
	}
	forbidden := os.FileMode(0o022)
	if private {
		forbidden = 0o077
	}
	if info.Mode().Perm()&forbidden != 0 {
		return errors.New("directory permissions are too broad")
	}
	return nil
}

func requireOwner(info os.FileInfo, ownerUID uint32) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("file ownership metadata is unavailable")
	}
	if stat.Uid != ownerUID {
		return fmt.Errorf("owner uid is %d, want %d", stat.Uid, ownerUID)
	}
	return nil
}
