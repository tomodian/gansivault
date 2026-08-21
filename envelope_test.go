package gansivault

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestIsEncrypted(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		in   []byte
		want bool
	}{
		{"header", []byte("$ANSIBLE_VAULT;1.1;AES256\n6162"), true},
		{"header only", []byte(Header), true},
		{"plain text", []byte("hello"), false},
		{"empty", nil, false},
		{"leading space", []byte("  $ANSIBLE_VAULT;1.1;AES256"), false},
		{"non ascii", []byte("$ANSIBLE_VAULT;1.1;AES256\xff"), false},
		{"truncated header", []byte("$ANSIBLE"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := IsEncrypted(tc.in); got != tc.want {
				t.Fatalf("IsEncrypted(%q) = %v, want %v", tc.in, got, tc.want)
			}

			if got := IsEncryptedString(string(tc.in)); got != tc.want {
				t.Fatalf("IsEncryptedString(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsEncryptedReader(t *testing.T) {
	t.Parallel()

	t.Run("short input", func(t *testing.T) {
		t.Parallel()

		got, err := IsEncryptedReader(strings.NewReader("no"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got {
			t.Fatal("want false for short non-vault input")
		}
	})

	t.Run("vault", func(t *testing.T) {
		t.Parallel()

		got, err := IsEncryptedReader(strings.NewReader(Header + ";1.1;AES256"))
		if err != nil || !got {
			t.Fatalf("got %v, err %v; want true, nil", got, err)
		}
	})

	t.Run("reader error", func(t *testing.T) {
		t.Parallel()

		if _, err := IsEncryptedReader(errReader{}); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})
}

func TestIsEncryptedFile(t *testing.T) {
	t.Parallel()

	got, err := IsEncryptedFile(filepath.Join("testdata", "hello_11.vault"))
	if err != nil || !got {
		t.Fatalf("got %v, err %v; want true, nil", got, err)
	}

	got, err = IsEncryptedFile(filepath.Join("testdata", "hello.txt"))
	if err != nil || got {
		t.Fatalf("got %v, err %v; want false, nil", got, err)
	}

	if _, err := IsEncryptedFile(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("want error for missing file")
	}
}

func TestParseEnvelope(t *testing.T) {
	t.Parallel()

	t.Run("version 1.1", func(t *testing.T) {
		t.Parallel()

		env := mustParse(t, readFixture(t, "hello_11.vault"))

		if env.Version != Version11 || env.Cipher != CipherAES256 || env.VaultID != "" {
			t.Fatalf("got %+v", env)
		}

		if len(env.Body) == 0 {
			t.Fatal("empty body")
		}
	})

	t.Run("version 1.2 carries the vault id", func(t *testing.T) {
		t.Parallel()

		env := mustParse(t, readFixture(t, "hello_12.vault"))

		if env.Version != Version12 || env.VaultID != "myid" {
			t.Fatalf("got %+v", env)
		}
	})

	t.Run("tolerates yaml block indentation", func(t *testing.T) {
		t.Parallel()

		raw := string(readFixture(t, "hello_11.vault"))

		var indented strings.Builder
		for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
			indented.WriteString("      " + line + "  \n")
		}

		if _, err := ParseEnvelope([]byte(indented.String())); err != nil {
			t.Fatalf("indented parse failed: %v", err)
		}
	})

	errCases := []struct {
		name string
		in   string
		want error
	}{
		{"not a vault", "just text", ErrNotVault},
		{"short header", "$ANSIBLE_VAULT;1.1\n6162", ErrMalformedEnvelope},
		{"bad version", "$ANSIBLE_VAULT;9.9;AES256\n6162", ErrUnsupportedVersion},
		{"bad cipher", "$ANSIBLE_VAULT;1.1;AES128\n6162", ErrUnsupportedCipher},
		{"bad hex", "$ANSIBLE_VAULT;1.1;AES256\nzzzz", ErrMalformedEnvelope},
	}

	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := ParseEnvelope([]byte(tc.in))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestFormatEnvelope(t *testing.T) {
	t.Parallel()

	body := bytes.Repeat([]byte("A"), 100)

	t.Run("default id emits 1.1", func(t *testing.T) {
		t.Parallel()

		for _, id := range []string{"", DefaultVaultID} {
			out := string(FormatEnvelope(body, id))
			if !strings.HasPrefix(out, "$ANSIBLE_VAULT;1.1;AES256\n") {
				t.Fatalf("id %q produced %q", id, out)
			}
		}
	})

	t.Run("named id emits 1.2", func(t *testing.T) {
		t.Parallel()

		out := string(FormatEnvelope(body, "prod"))
		if !strings.HasPrefix(out, "$ANSIBLE_VAULT;1.2;AES256;prod\n") {
			t.Fatalf("got %q", out)
		}
	})

	t.Run("wraps at 80 columns", func(t *testing.T) {
		t.Parallel()

		lines := strings.Split(string(FormatEnvelope(body, "")), "\n")
		encoded := hex.EncodeToString(body)

		wantLines := 1 + (len(encoded)+lineWidth-1)/lineWidth
		if len(lines) != wantLines {
			t.Fatalf("got %d lines, want %d", len(lines), wantLines)
		}

		for _, line := range lines[1:] {
			if len(line) > lineWidth {
				t.Fatalf("line of %d chars exceeds %d", len(line), lineWidth)
			}
		}

		if strings.Join(lines[1:], "") != encoded {
			t.Fatal("wrapped payload does not rejoin to the hex body")
		}
	})

	t.Run("empty body has no payload lines", func(t *testing.T) {
		t.Parallel()

		if got := string(FormatEnvelope(nil, "")); got != "$ANSIBLE_VAULT;1.1;AES256" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestFormatEnvelopeMatchesAnsibleLayout(t *testing.T) {
	t.Parallel()

	// Re-wrapping a body parsed out of a real ansible-vault file must
	// reproduce that file byte for byte.
	fixture := bytes.TrimRight(readFixture(t, "hello_11.vault"), "\n")

	env := mustParse(t, fixture)
	if got := FormatEnvelope(env.Body, env.VaultID); !bytes.Equal(got, fixture) {
		t.Fatalf("round trip mismatch:\n got %q\nwant %q", got, fixture)
	}

	fixture12 := bytes.TrimRight(readFixture(t, "hello_12.vault"), "\n")

	env12 := mustParse(t, fixture12)
	if got := FormatEnvelope(env12.Body, env12.VaultID); !bytes.Equal(got, fixture12) {
		t.Fatalf("1.2 round trip mismatch:\n got %q\nwant %q", got, fixture12)
	}
}

// --- helpers -------------------------------------------------------------

var errBoom = errors.New("boom")

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errBoom }

func readFixture(t *testing.T, name string) []byte {
	t.Helper()

	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading fixture %s: %v", name, err)
	}

	return data
}

func mustParse(t *testing.T, in []byte) *Envelope {
	t.Helper()

	env, err := ParseEnvelope(in)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}

	return env
}
