package gansivault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestStaticSecret(t *testing.T) {
	t.Parallel()

	s := NewStaticSecret("prod", []byte("  spaces kept  "))

	if s.ID() != "prod" {
		t.Fatalf("got id %q", s.ID())
	}

	got, err := s.Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	if string(got) != "  spaces kept  " {
		t.Fatalf("static secrets must not be trimmed, got %q", got)
	}

	if id := NewStaticSecret("", []byte("x")).ID(); id != DefaultVaultID {
		t.Fatalf("empty id should normalise to %q, got %q", DefaultVaultID, id)
	}

	if _, err := NewStaticSecret("empty", nil).Bytes(); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("got %v, want ErrEmptyPassword", err)
	}
}

func TestFileSecret(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	t.Run("reads and trims", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "plain.pass", "  hunter2 \r\n\n", 0o600)

		s := NewFileSecret("dev", path)
		if s.ID() != "dev" || s.Path() != path {
			t.Fatalf("got id %q path %q", s.ID(), s.Path())
		}

		got, err := s.Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}

		if string(got) != "hunter2" {
			t.Fatalf("got %q, want %q", got, "hunter2")
		}
	})

	t.Run("caches the read", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "cached.pass", "first", 0o600)

		s := NewFileSecret("", path)

		if _, err := s.Bytes(); err != nil {
			t.Fatalf("Bytes: %v", err)
		}

		if err := os.WriteFile(path, []byte("second"), 0o600); err != nil {
			t.Fatalf("rewrite: %v", err)
		}

		got, err := s.Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}

		if string(got) != "first" {
			t.Fatalf("second call re-read the file: %q", got)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		t.Parallel()

		_, err := NewFileSecret("", filepath.Join(dir, "absent")).Bytes()
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want os.ErrNotExist", err)
		}
	})

	t.Run("directory", func(t *testing.T) {
		t.Parallel()

		_, err := NewFileSecret("", dir).Bytes()
		if err == nil || !strings.Contains(err.Error(), "is a directory") {
			t.Fatalf("got %v, want a directory error", err)
		}
	})

	t.Run("empty file", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "blank.pass", "\n\n  \n", 0o600)

		if _, err := NewFileSecret("", path).Bytes(); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})

	t.Run("unreadable file", func(t *testing.T) {
		t.Parallel()

		if os.Geteuid() == 0 {
			t.Skip("root can read anything")
		}

		path := writeFile(t, dir, "locked.pass", "nope", 0o200)

		if _, err := NewFileSecret("", path).Bytes(); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v, want os.ErrPermission", err)
		}
	})
}

func TestFileSecretScript(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell password scripts are a POSIX feature")
	}

	t.Parallel()

	dir := t.TempDir()

	t.Run("executable file is run", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "pass.sh", "#!/bin/sh\necho ' from-script '\n", 0o700)

		got, err := NewFileSecret("", path).Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}

		if string(got) != "from-script" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("client scripts receive the vault id", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "vault-client", "#!/bin/sh\necho \"$1=$2\"\n", 0o700)

		got, err := NewFileSecret("staging", path).Bytes()
		if err != nil {
			t.Fatalf("Bytes: %v", err)
		}

		if string(got) != "--vault-id=staging" {
			t.Fatalf("got %q, want --vault-id=staging", got)
		}
	})

	t.Run("failing script reports stderr", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "boom.sh", "#!/bin/sh\necho 'no keyring' >&2\nexit 3\n", 0o700)

		_, err := NewFileSecret("", path).Bytes()
		if err == nil || !strings.Contains(err.Error(), "no keyring") {
			t.Fatalf("got %v, want the script stderr", err)
		}
	})

	t.Run("failing script without stderr", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "quiet.sh", "#!/bin/sh\nexit 4\n", 0o700)

		_, err := NewFileSecret("", path).Bytes()
		if err == nil || !strings.Contains(err.Error(), "exit status 4") {
			t.Fatalf("got %v, want an exit status", err)
		}
	})

	t.Run("script printing nothing", func(t *testing.T) {
		t.Parallel()

		path := writeFile(t, dir, "silent.sh", "#!/bin/sh\nexit 0\n", 0o700)

		if _, err := NewFileSecret("", path).Bytes(); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})
}

// TestFileSecretScriptWithBareRelativeName is deliberately not parallel:
// t.Chdir is process wide. A bare name such as "vault-pass.sh" must be
// resolved on disk rather than looked up through $PATH.
func TestFileSecretScriptWithBareRelativeName(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell password scripts are a POSIX feature")
	}

	dir := t.TempDir()
	writeFile(t, dir, "vault-pass.sh", "#!/bin/sh\necho relative-ok\n", 0o700)

	t.Chdir(dir)

	got, err := NewFileSecret("", "vault-pass.sh").Bytes()
	if err != nil {
		t.Fatalf("Bytes: %v", err)
	}

	if string(got) != "relative-ok" {
		t.Fatalf("got %q", got)
	}
}

func TestPromptSecret(t *testing.T) {
	t.Parallel()

	t.Run("prompts once and trims", func(t *testing.T) {
		t.Parallel()

		calls := 0

		s := NewPromptSecret("dev", func(prompt string) ([]byte, error) {
			calls++

			if !strings.Contains(prompt, "dev") {
				t.Errorf("prompt should name the vault id, got %q", prompt)
			}

			return []byte(" typed \n"), nil
		})

		for range 3 {
			got, err := s.Bytes()
			if err != nil {
				t.Fatalf("Bytes: %v", err)
			}

			if string(got) != "typed" {
				t.Fatalf("got %q", got)
			}
		}

		if calls != 1 {
			t.Fatalf("prompted %d times, want 1", calls)
		}
	})

	t.Run("nil prompt fails instead of blocking", func(t *testing.T) {
		t.Parallel()

		s := NewPromptSecret("", nil)

		if s.ID() != DefaultVaultID {
			t.Fatalf("got id %q", s.ID())
		}

		if _, err := s.Bytes(); err == nil || !strings.Contains(err.Error(), "no prompt available") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("prompt error", func(t *testing.T) {
		t.Parallel()

		s := NewPromptSecret("", func(string) ([]byte, error) { return nil, errBoom })

		if _, err := s.Bytes(); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})

	t.Run("empty answer", func(t *testing.T) {
		t.Parallel()

		s := NewPromptSecret("", func(string) ([]byte, error) { return []byte("  \n"), nil })

		if _, err := s.Bytes(); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})
}

func TestSplitVaultID(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in     string
		id     string
		source string
	}{
		{"~/.vault_pass", DefaultVaultID, "~/.vault_pass"},
		{"dev@~/.vault_pass", "dev", "~/.vault_pass"},
		{"dev@prompt", "dev", "prompt"},
		{"@prompt", DefaultVaultID, "prompt"},
		{"dev@host@path", "dev", "host@path"},
		{"", DefaultVaultID, ""},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()

			id, source := SplitVaultID(tc.in)
			if id != tc.id || source != tc.source {
				t.Fatalf("got (%q, %q), want (%q, %q)", id, source, tc.id, tc.source)
			}
		})
	}
}

func TestNewSecretFromVaultID(t *testing.T) {
	t.Parallel()

	ask := func(string) ([]byte, error) { return []byte("typed"), nil }

	t.Run("prompt sources", func(t *testing.T) {
		t.Parallel()

		for _, source := range []string{promptSource, promptAskPassSource} {
			s := NewSecretFromVaultID("dev@"+source, ask)

			if _, ok := s.(*PromptSecret); !ok {
				t.Fatalf("%s produced %T, want *PromptSecret", source, s)
			}

			if s.ID() != "dev" {
				t.Fatalf("got id %q", s.ID())
			}

			got, err := s.Bytes()
			if err != nil || string(got) != "typed" {
				t.Fatalf("got %q, err %v", got, err)
			}
		}
	})

	t.Run("file source", func(t *testing.T) {
		t.Parallel()

		path := filepath.Join("testdata", "mypassword.pass")

		s := NewSecretFromVaultID("prod@"+path, ask)

		fs, ok := s.(*FileSecret)
		if !ok {
			t.Fatalf("got %T, want *FileSecret", s)
		}

		if fs.Path() != path || fs.ID() != "prod" {
			t.Fatalf("got id %q path %q", fs.ID(), fs.Path())
		}

		got, err := s.Bytes()
		if err != nil || string(got) != fixturePassword {
			t.Fatalf("got %q, err %v", got, err)
		}
	})
}

func TestTrimPassword(t *testing.T) {
	t.Parallel()

	if got := trimPassword([]byte("\t a b \r\n")); !bytes.Equal(got, []byte("a b")) {
		t.Fatalf("got %q", got)
	}
}

// writeFile creates a fixture file and returns its path.
func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()

	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}

	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("chmod %s: %v", path, err)
	}

	return path
}
