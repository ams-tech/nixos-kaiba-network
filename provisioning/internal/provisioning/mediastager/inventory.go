package mediastager

import (
	"context"
	"fmt"
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
	// It is only compared within one Inspect/open operation, never persisted.
	DiskSequence uint64
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

func validateSameTargetFacts(initial, current TargetFacts) error {
	if current != initial {
		return fmt.Errorf("%w: inspected target identity changed", ErrTargetMismatch)
	}
	return nil
}

func validateTargetFacts(plan Plan, mode Mode, facts TargetFacts, usage TargetUsage) error {
	if facts.RequestedPath != plan.Target.Path || facts.ResolvedPath == "" || !cleanAbsolutePath(facts.ResolvedPath) {
		return fmt.Errorf("%w: inventory resolved a different target path", ErrTargetMismatch)
	}
	if facts.Identity != plan.Target.ExpectedIdentity {
		return fmt.Errorf("%w: target identity is %q, expected %q", ErrTargetMismatch, facts.Identity, plan.Target.ExpectedIdentity)
	}
	if facts.SizeBytes != plan.Target.ExpectedSizeBytes {
		return fmt.Errorf("%w: target size is %d, expected %d", ErrTargetMismatch, facts.SizeBytes, plan.Target.ExpectedSizeBytes)
	}
	if mode == ModeDevice {
		if facts.Kind != TargetBlockDevice || !facts.WholeDevice || facts.DeviceNumber == 0 || facts.DiskSequence == 0 || facts.SysfsPath == "" {
			return fmt.Errorf("%w: target is not one verified whole block device", ErrUnsafeTarget)
		}
	} else if facts.Kind != TargetRegularFile || facts.WholeDevice || facts.DeviceNumber != 0 || facts.DiskSequence != 0 || facts.FileDevice == 0 || facts.Inode == 0 {
		return fmt.Errorf("%w: fixture target is not one verified regular file", ErrUnsafeTarget)
	}
	if usage.Mounted || usage.System || usage.Root || usage.Swap {
		return fmt.Errorf(
			"%w: mounted=%t system=%t root=%t swap=%t",
			ErrUnsafeTarget, usage.Mounted, usage.System, usage.Root, usage.Swap,
		)
	}
	return nil
}
