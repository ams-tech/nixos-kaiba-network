package mediainventory

import "testing"

func TestSelectedDevicePathIsSeparateFromLegacyByIDSelection(t *testing.T) {
	for _, path := range []string{
		"/dev/nvme0n1",
		"/dev/disk/by-path/platform-1000120000.pcie-pci-0000:01:00.0-nvme-1",
	} {
		if err := validateTargetPath(path, ModeSelectedDevice); err != nil {
			t.Fatalf("validateTargetPath(%q, ModeSelectedDevice): %v", path, err)
		}
	}
	for _, path := range []string{
		"/dev/disk/by-id/nvme-KAIBA_SERIAL",
		"/dev/disk/by-path/platform-example-part1",
		"/dev/mapper/crypted",
		"/dev/../dev/nvme0n1",
	} {
		if err := validateTargetPath(path, ModeSelectedDevice); err == nil {
			t.Fatalf("validateTargetPath(%q, ModeSelectedDevice) accepted a prohibited selector", path)
		}
	}
	if err := validateTargetPath("/dev/disk/by-id/nvme-KAIBA_SERIAL", ModeDevice); err != nil {
		t.Fatalf("legacy ModeDevice rejected a by-id selector: %v", err)
	}
}
