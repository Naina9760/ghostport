//go:build linux

package main

import "testing"

func TestParseKernelVersion(t *testing.T) {
	tests := []struct {
		release   string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{"6.6.0-generic", 6, 6, true},
		{"6.8.0-49-generic", 6, 8, true},
		{"5.15.0-91-generic", 5, 15, true},
		{"6.6-rc1", 6, 6, true},
		{"6", 0, 0, false},
		{"linux", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range tests {
		major, minor, ok := parseKernelVersion(tc.release)
		if ok != tc.wantOK || major != tc.wantMajor || minor != tc.wantMinor {
			t.Errorf("parseKernelVersion(%q) = (%d, %d, %v), want (%d, %d, %v)",
				tc.release, major, minor, ok, tc.wantMajor, tc.wantMinor, tc.wantOK)
		}
	}
}

func FuzzParseKernelVersion(f *testing.F) {
	for _, seed := range []string{
		"6.6.0-generic",
		"6.8.0-49-generic",
		"5.15.0-91-generic",
		"6.6-rc1",
		"6",
		"",
		"...",
		"999999999999999999999.0.0",
		"6.-1.0",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, release string) {
		// Must never panic, regardless of what uname(2) could plausibly
		// (or implausibly) return.
		parseKernelVersion(release)
	})
}

func TestCheckKernelSupportsTCXRejectsOldKernels(t *testing.T) {
	tests := []struct {
		release string
		wantErr bool
	}{
		{"6.6.0-generic", false},
		{"6.12.0-generic", false},
		{"7.0.0-generic", false},
		{"6.5.0-generic", true},
		{"5.15.0-generic", true},
	}
	for _, tc := range tests {
		major, minor, ok := parseKernelVersion(tc.release)
		if !ok {
			t.Fatalf("parseKernelVersion(%q) failed unexpectedly", tc.release)
		}
		tooOld := major < minKernelMajor || (major == minKernelMajor && minor < minKernelMinor)
		if tooOld != tc.wantErr {
			t.Errorf("release %q: tooOld = %v, want %v", tc.release, tooOld, tc.wantErr)
		}
	}
}
