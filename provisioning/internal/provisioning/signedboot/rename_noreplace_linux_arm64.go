//go:build linux && arm64

package signedboot

// Linux arm64 __NR_renameat2 from asm-generic/unistd.h.
const renameat2Trap = 276
