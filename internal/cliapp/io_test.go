package cliapp

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEditorCommand(t *testing.T) {
	for _, key := range []string{"ANSIBLE_EDITOR", "EDITOR", "VISUAL"} {
		t.Setenv(key, "")
	}

	if got := editorCommand(); got != "vi" {
		t.Fatalf("with no environment: got %q, want vi", got)
	}

	t.Setenv("VISUAL", "nano")

	if got := editorCommand(); got != "nano" {
		t.Fatalf("VISUAL: got %q", got)
	}

	t.Setenv("EDITOR", "  emacs  ")

	if got := editorCommand(); got != "emacs" {
		t.Fatalf("EDITOR should win over VISUAL and be trimmed: got %q", got)
	}

	t.Setenv("ANSIBLE_EDITOR", "code --wait")

	if got := editorCommand(); got != "code --wait" {
		t.Fatalf("ANSIBLE_EDITOR should win: got %q", got)
	}
}

func TestLaunchEditor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "file.txt")

	if err := os.WriteFile(path, []byte("before"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	var out, errOut bytes.Buffer

	t.Run("runs the command with the path appended", func(t *testing.T) {
		if err := launchEditor("/bin/sh -c", "cat \"$0\"", strings.NewReader(""), &out, &errOut); err != nil {
			t.Fatalf("launchEditor: %v", err)
		}
	})

	t.Run("reports command failure", func(t *testing.T) {
		err := launchEditor("/bin/sh -c", "exit 7", strings.NewReader(""), &out, &errOut)
		if err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("rejects an empty editor", func(t *testing.T) {
		err := launchEditor("   ", path, strings.NewReader(""), &out, &errOut)
		if err == nil || !strings.Contains(err.Error(), "$EDITOR") {
			t.Fatalf("got %v", err)
		}
	})
}

func TestAppEditUsesTheConfiguredEditor(t *testing.T) {
	t.Setenv("ANSIBLE_EDITOR", "/usr/bin/true")
	t.Setenv("EDITOR", "")
	t.Setenv("VISUAL", "")

	app := &App{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}

	if err := app.edit(filepath.Join(t.TempDir(), "f")); err != nil {
		t.Fatalf("edit: %v", err)
	}
}

func TestTerminalHelpers(t *testing.T) {
	t.Parallel()

	// These wrap golang.org/x/term. Under "go test" standard input is not a
	// terminal, so the calls simply have to be reachable and consistent.
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	defer f.Close() //nolint:errcheck // read-only handle

	if isTerminal(f) {
		t.Fatal(os.DevNull + " should not be a terminal")
	}

	if _, err := readPasswordNoEcho(f); err == nil {
		t.Fatal("reading a password from a non-terminal should fail")
	}
}

func TestNewPrompt(t *testing.T) {
	t.Parallel()

	t.Run("reads a line when stdin is not a terminal", func(t *testing.T) {
		t.Parallel()

		var out bytes.Buffer

		got, err := newPrompt(strings.NewReader("secret\n"), &out)("Vault password: ")
		if err != nil {
			t.Fatalf("prompt: %v", err)
		}

		if string(got) != "secret" {
			t.Fatalf("got %q", got)
		}

		if out.String() != "Vault password: " {
			t.Fatalf("prompt text: %q", out.String())
		}
	})

	t.Run("accepts input without a trailing newline", func(t *testing.T) {
		t.Parallel()

		got, err := newPrompt(strings.NewReader("secret"), &bytes.Buffer{})("p: ")
		if err != nil {
			t.Fatalf("prompt: %v", err)
		}

		if string(got) != "secret" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("strips a carriage return", func(t *testing.T) {
		t.Parallel()

		got, err := newPrompt(strings.NewReader("secret\r\n"), &bytes.Buffer{})("p: ")
		if err != nil {
			t.Fatalf("prompt: %v", err)
		}

		if string(got) != "secret" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("propagates read errors", func(t *testing.T) {
		t.Parallel()

		if _, err := newPrompt(failReader{}, &bytes.Buffer{})("p: "); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})
}

func TestNewPromptTerminalPath(t *testing.T) {
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open: %v", err)
	}

	defer f.Close() //nolint:errcheck // read-only handle

	originalIsTerminal, originalRead := isTerminal, readPasswordNoEcho

	isTerminal = func(*os.File) bool { return true }
	readPasswordNoEcho = func(*os.File) ([]byte, error) { return []byte("typed"), nil }

	t.Cleanup(func() {
		isTerminal, readPasswordNoEcho = originalIsTerminal, originalRead
	})

	var out bytes.Buffer

	got, err := newPrompt(f, &out)("Vault password: ")
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}

	if string(got) != "typed" {
		t.Fatalf("got %q", got)
	}

	if !strings.HasSuffix(out.String(), "\n") {
		t.Fatalf("the terminal path should emit a newline, got %q", out.String())
	}
}

func TestReadInput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "in.txt")

	if err := os.WriteFile(path, []byte("from file"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	app := &App{Stdin: strings.NewReader("from stdin")}

	for _, name := range []string{"", stdioName} {
		got, err := app.readInput(name)
		if err != nil {
			t.Fatalf("readInput(%q): %v", name, err)
		}

		if string(got) != "from stdin" {
			t.Fatalf("readInput(%q) = %q", name, got)
		}

		app.Stdin = strings.NewReader("from stdin")
	}

	got, err := app.readInput(path)
	if err != nil {
		t.Fatalf("readInput: %v", err)
	}

	if string(got) != "from file" {
		t.Fatalf("got %q", got)
	}

	if _, err := app.readInput(filepath.Join(dir, "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want os.ErrNotExist", err)
	}
}

func TestWriteOutput(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	var out bytes.Buffer

	app := &App{Stdout: &out}

	for _, name := range []string{"", stdioName} {
		out.Reset()

		if err := app.writeOutput(name, []byte("hi"), defaultFileMode); err != nil {
			t.Fatalf("writeOutput(%q): %v", name, err)
		}

		if out.String() != "hi" {
			t.Fatalf("got %q", out.String())
		}
	}

	path := filepath.Join(dir, "out.txt")

	if err := app.writeOutput(path, []byte("hi"), 0o640); err != nil {
		t.Fatalf("writeOutput: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if info.Mode().Perm() != 0o640 {
		t.Fatalf("mode %v", info.Mode().Perm())
	}

	if err := app.writeOutput(filepath.Join(dir, "missing", "out"), nil, defaultFileMode); err == nil {
		t.Fatal("want an error for a missing directory")
	}

	failing := &App{Stdout: failWriter{}}
	if err := failing.writeOutput(stdioName, []byte("x"), defaultFileMode); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
}

func TestFileMode(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "m.txt")

	if err := os.WriteFile(path, nil, 0o640); err != nil {
		t.Fatalf("write: %v", err)
	}

	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	if got := fileMode(path); got != 0o640 {
		t.Fatalf("got %v, want 0640", got)
	}

	for _, name := range []string{"", stdioName, filepath.Join(dir, "absent")} {
		if got := fileMode(name); got != defaultFileMode {
			t.Fatalf("fileMode(%q) = %v, want %v", name, got, defaultFileMode)
		}
	}
}

func TestEnsureTrailingNewline(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"a":     "a\n",
		"a\n":   "a\n",
		"":      "\n",
		"a\n\n": "a\n\n",
	}

	for in, want := range cases {
		if got := string(ensureTrailingNewline([]byte(in))); got != want {
			t.Fatalf("ensureTrailingNewline(%q) = %q, want %q", in, got, want)
		}
	}

	in := make([]byte, 1, 8)
	in[0] = 'a'

	_ = ensureTrailingNewline(in)

	if len(in) != 1 {
		t.Fatal("input slice was extended in place")
	}
}

func TestReadAllStdin(t *testing.T) {
	t.Parallel()

	app := &App{Stdin: strings.NewReader("piped")}

	got, err := app.readAllStdin()
	if err != nil {
		t.Fatalf("readAllStdin: %v", err)
	}

	if string(got) != "piped" {
		t.Fatalf("got %q", got)
	}

	failing := &App{Stdin: failReader{}}
	if _, err := failing.readAllStdin(); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
}
