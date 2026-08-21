package cliapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	// testPassword is the password behind the committed fixtures.
	testPassword = "mypassword"

	// helloPlaintext is what testdata/hello_11.vault contains.
	helloPlaintext = "hello world\n"
)

var errBoom = errors.New("boom")

// fixturesDir points at the repository level testdata directory shared with
// the library tests, so the CLI is exercised against the same real
// ansible-vault output.
func fixturesDir(t *testing.T) string {
	t.Helper()

	return filepath.Join("..", "..", "testdata")
}

// harness runs the CLI in-process with captured streams.
type harness struct {
	t   *testing.T
	app *App

	stdout bytes.Buffer
	stderr bytes.Buffer

	// dir is a per-test scratch directory.
	dir string
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	h := &harness{t: t, dir: t.TempDir()}
	h.app = &App{
		Stdin:  strings.NewReader(""),
		Stdout: &h.stdout,
		Stderr: &h.stderr,
		Prompt: func(string) ([]byte, error) { return []byte(testPassword), nil },
	}

	// Keep the developer's own Ansible environment out of the tests.
	for _, key := range []string{
		"ANSIBLE_VAULT_PASSWORD_FILE",
		"ANSIBLE_VAULT_IDENTITY_LIST",
		"ANSIBLE_VAULT_ENCRYPT_IDENTITY",
	} {
		t.Setenv(key, "")
	}

	return h
}

// stdin replaces standard input for the next run.
func (h *harness) stdin(s string) *harness {
	h.app.Stdin = strings.NewReader(s)

	return h
}

// run executes the CLI with args after the program name.
func (h *harness) run(args ...string) error {
	h.t.Helper()

	h.stdout.Reset()
	h.stderr.Reset()

	return h.app.Run(context.Background(), append([]string{"gansivault"}, args...))
}

// mustRun fails the test if the command errors.
func (h *harness) mustRun(args ...string) {
	h.t.Helper()

	if err := h.run(args...); err != nil {
		h.t.Fatalf("gansivault %s: %v\nstderr: %s", strings.Join(args, " "), err, h.stderr.String())
	}
}

// out returns captured standard output.
func (h *harness) out() string { return h.stdout.String() }

// err returns captured standard error.
func (h *harness) errOut() string { return h.stderr.String() }

// passFile writes a password file into the scratch directory.
func (h *harness) passFile(name, password string) string {
	h.t.Helper()

	return h.file(name, password, 0o600)
}

// file writes an arbitrary file into the scratch directory.
func (h *harness) file(name, content string, mode os.FileMode) string {
	h.t.Helper()

	path := filepath.Join(h.dir, name)

	// Earlier subtests may have left a read-only file behind at this name.
	_ = os.Remove(path)

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		h.t.Fatalf("writing %s: %v", path, err)
	}

	if err := os.Chmod(path, mode); err != nil {
		h.t.Fatalf("chmod %s: %v", path, err)
	}

	return path
}

// copyFixture copies a testdata file into the scratch directory so in-place
// commands do not touch the committed fixtures.
func (h *harness) copyFixture(name string) string {
	h.t.Helper()

	data, err := os.ReadFile(filepath.Join(fixturesDir(h.t), name))
	if err != nil {
		h.t.Fatalf("reading fixture %s: %v", name, err)
	}

	return h.file(name, string(data), 0o600)
}

// read returns the contents of a scratch file.
func (h *harness) read(path string) string {
	h.t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		h.t.Fatalf("reading %s: %v", path, err)
	}

	return string(data)
}

// failWriter fails every write, for exercising output error paths.
type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errBoom }

// failReader fails every read.
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errBoom }
