package mediastager

import (
	"fmt"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

type TargetKind = mediainventory.TargetKind

const (
	TargetBlockDevice = mediainventory.TargetBlockDevice
	TargetRegularFile = mediainventory.TargetRegularFile
)

type TargetFacts = mediainventory.TargetFacts
type TargetUsage = mediainventory.TargetUsage
type Inventory = mediainventory.Inventory
type SystemInventory = mediainventory.SystemInventory

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
		return fmt.Errorf("%w: mounted=%t system=%t root=%t swap=%t", ErrUnsafeTarget, usage.Mounted, usage.System, usage.Root, usage.Swap)
	}
	return nil
}
