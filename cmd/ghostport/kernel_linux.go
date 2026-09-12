//go:build linux

package main

import (
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Minimum kernel version required for TCX. GhostPort intentionally has no
// fallback attachment path (such as classic tc/clsact via netlink): that
// would mean maintaining a second attach/detach code path, with its own
// failure modes, for kernels that predate the currently supported
// distribution baselines this project targets. Reported to the owner via
// docs/OWNER_CHECKLIST.md and the pull request that introduced this check.
const (
	minKernelMajor = 6
	minKernelMinor = 6
)

// checkKernelSupportsTCX reports a clear, actionable error before GhostPort
// attempts to load or attach anything if the running kernel is known to be
// too old for TCX, instead of surfacing only the kernel's own attach-time
// error. It fails open (returns nil) if the running kernel version cannot
// be determined, since that is a diagnostic best effort, not the actual
// compatibility gate — the real gate is the TCX attach call itself.
func checkKernelSupportsTCX() error {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return nil
	}
	release := unix.ByteSliceToString(uname.Release[:])
	major, minor, ok := parseKernelVersion(release)
	if !ok {
		return nil
	}
	if major < minKernelMajor || (major == minKernelMajor && minor < minKernelMinor) {
		return fmt.Errorf("kernel %s does not support TCX (requires %d.%d or newer); GhostPort has no fallback attachment path", release, minKernelMajor, minKernelMinor)
	}
	return nil
}

// parseKernelVersion extracts the major and minor version from a
// uname release string such as "6.8.0-49-generic".
func parseKernelVersion(release string) (major, minor int, ok bool) {
	fields := strings.SplitN(release, ".", 3)
	if len(fields) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, 0, false
	}
	minor, ok = leadingInt(fields[1])
	if !ok {
		return 0, 0, false
	}
	return major, minor, true
}

// kernelRelease returns the running kernel's uname release string (e.g.
// "6.8.0-49-generic"), or "" if it cannot be determined. Used for
// diagnostics only (the status event), never for a compatibility decision
// - that is checkKernelSupportsTCX's job.
func kernelRelease() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return ""
	}
	return unix.ByteSliceToString(uname.Release[:])
}

// leadingInt parses the run of leading decimal digits in s, allowing a
// trailing non-digit suffix (as in "6.6.0-generic", whose second field is
// "6" with nothing to trim, or "6.6-rc1", whose second field is "6-rc1").
func leadingInt(s string) (int, bool) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(s[:end])
	return n, err == nil
}
