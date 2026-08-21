//go:build linux && amd64

package signedboot

// Linux x86-64 __NR_renameat2 from asm/unistd_64.h.
const renameat2Trap = 316
