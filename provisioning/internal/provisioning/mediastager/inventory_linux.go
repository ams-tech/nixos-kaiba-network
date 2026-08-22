//go:build linux

package mediastager

// The legacy synthetic stager uses the read-only inventory through aliases in
// inventory.go. Its destructive executor remains isolated from production
// media verification, which imports mediainventory directly.

import (
	"os"

	"github.com/ams-tech/nixos-kaiba-network/provisioning/internal/provisioning/mediainventory"
)

func blockDeviceSize(file *os.File) (uint64, error) {
	return mediainventory.BlockDeviceSize(file)
}

func blockDeviceDiskSequence(file *os.File) (uint64, error) {
	return mediainventory.BlockDeviceDiskSequence(file)
}
