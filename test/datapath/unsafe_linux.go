//go:build linux

package datapath

import "unsafe"

// unsafePointerOf hands an ioctl request buffer to the kernel. Confined to one
// file and one call so the unsafe import does not spread through the tests.
func unsafePointerOf(b *[40]byte) unsafe.Pointer { return unsafe.Pointer(b) }
