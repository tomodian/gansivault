package main

import (
	"os"
	"testing"
)

// TestMainEntryPoint exercises main() itself by swapping out os.Exit, so the
// binary's only statement is covered without spawning a subprocess.
func TestMainEntryPoint(t *testing.T) {
	originalExit, originalArgs := osExit, os.Args

	t.Cleanup(func() {
		osExit, os.Args = originalExit, originalArgs
	})

	code := -1
	osExit = func(c int) { code = c }

	os.Args = []string{"gansivault", "--version"}

	main()

	if code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
}
