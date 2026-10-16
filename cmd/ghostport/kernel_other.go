//go:build !linux

package main

// checkKernelSupportsTCX is a no-op off Linux: GhostPort cannot run at all
// on a non-Linux kernel, and the real compatibility gate is the TCX attach
// call in run(), which already fails with a clear error on this platform.
func checkKernelSupportsTCX() error {
	return nil
}

// kernelRelease is unavailable off Linux.
func kernelRelease() string {
	return ""
}
