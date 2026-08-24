// Package mediainventory contains only read-only Linux target discovery and
// usage facts. In particular, it has no dependency on any media writer.
package mediainventory

import (
	"context"
	"errors"
	"path/filepath"
	"regexp"
	"strings"
)

type Mode string

const (
	ModeDevice         Mode = "device"
	ModeSelectedDevice Mode = "selected_device"
	ModeFixture        Mode = "regular_file_fixture"
)

var (
	ErrUnsafeTarget = errors.New("target is unsafe for media staging")
	partitionAlias  = regexp.MustCompile(`-part[0-9]+$`)
	bootIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

type TargetKind string

const (
	TargetBlockDevice TargetKind = "block_device"
	TargetRegularFile TargetKind = "regular_file"
)

type TargetFacts struct {
	RequestedPath string
	ResolvedPath  string
	Identity      string
	SizeBytes     uint64
	Kind          TargetKind
	WholeDevice   bool
	DeviceNumber  uint64
	// DiskSequence is Linux's boot-local identity for this disk attachment.
	// BootID must accompany it anywhere the pair is persisted.
	DiskSequence uint64
	BootID       string
	FileDevice   uint64
	Inode        uint64
	SysfsPath    string
}

type TargetUsage struct {
	Mounted     bool
	System      bool
	Root        bool
	Swap        bool
	MountPoints []string
	SwapSources []string
}

type Inventory interface {
	Inspect(context.Context, string, Mode) (TargetFacts, error)
	Usage(context.Context, TargetFacts, Mode) (TargetUsage, error)
}

func validateTargetPath(path string, mode Mode) error {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return errors.New("target path must be clean and absolute")
	}
	if mode == ModeDevice {
		const prefix = "/dev/disk/by-id/"
		name := strings.TrimPrefix(path, prefix)
		if !strings.HasPrefix(path, prefix) || name == "" || name == "." || strings.Contains(name, "/") || partitionAlias.MatchString(name) {
			return errors.New("device target must identify one whole-device by-id alias")
		}
		return nil
	}
	if mode == ModeSelectedDevice {
		const byPathPrefix = "/dev/disk/by-path/"
		if strings.HasPrefix(path, byPathPrefix) {
			name := strings.TrimPrefix(path, byPathPrefix)
			if name == "" || name == "." || strings.Contains(name, "/") || strings.ContainsAny(name, " \t\r\n") || partitionAlias.MatchString(name) {
				return errors.New("selected device path must identify one whole-device by-path alias")
			}
			return nil
		}
		const devicePrefix = "/dev/"
		name := strings.TrimPrefix(path, devicePrefix)
		if !strings.HasPrefix(path, devicePrefix) || name == "" || name == "." || strings.Contains(name, "/") || strings.ContainsAny(name, " \t\r\n") {
			return errors.New("selected device path must be one immediate /dev node or /dev/disk/by-path alias")
		}
		return nil
	}
	if mode != ModeFixture {
		return errors.New("unsupported target mode")
	}
	if path == "/dev" || strings.HasPrefix(path, "/dev/") {
		return errors.New("regular-file fixture targets must be outside /dev")
	}
	return nil
}

func cleanAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}
