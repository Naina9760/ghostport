package main

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestVersionInjection builds the actual binary the way
// scripts/package-release.sh does (-ldflags -X main.version=...) and runs
// --version against it, proving the release version-injection mechanism
// actually works end to end rather than only asserting on the ldflags
// string in the packaging script.
func TestVersionInjection(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping a real `go build` invocation in -short mode")
	}

	const wantVersion = "v9.9.9-test"
	bin := filepath.Join(t.TempDir(), "ghostport-version-test")

	// `go test` normally runs with the package directory as the working
	// directory, but a precompiled test binary (as CI's privileged test
	// step runs, via `go test -c` then `sudo ./bin/ghostport.test`) does
	// not get that for free - it inherits whatever directory it happened
	// to be invoked from. Resolve this file's own directory explicitly
	// instead of assuming ".".
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed to resolve this test file's path")
	}
	pkgDir := filepath.Dir(thisFile)

	build := exec.Command("go", "build",
		"-ldflags=-X main.version="+wantVersion,
		"-o", bin,
		".",
	)
	build.Dir = pkgDir
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build (in %s): %v\n%s", pkgDir, err, out)
	}

	out, err := exec.Command(bin, "--version").CombinedOutput()
	if err != nil {
		t.Fatalf("run --version: %v\n%s", err, out)
	}
	got := strings.TrimSpace(string(out))
	want := "ghostport " + wantVersion
	if got != want {
		t.Fatalf("--version output = %q, want %q", got, want)
	}
}
