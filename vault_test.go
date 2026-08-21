package gansivault

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const fixturePassword = "mypassword"

// ansibleFixtures pairs every committed ansible-vault output with the exact
// plaintext ansible-vault was given. These files were produced by ansible-core
// 2.20, so passing this test is the compatibility guarantee.
var ansibleFixtures = []struct {
	vault     string
	plaintext string
	vaultID   string
}{
	{"hello_11.vault", "hello.txt", ""},
	{"hello_12.vault", "hello.txt", "myid"},
	{"empty.vault", "empty.txt", ""},
	{"unicode.vault", "unicode.txt", ""},
	{"block_aligned.vault", "block_aligned.txt", ""},
	{"binary.vault", "binary.bin", ""},
	{"multiline.vault", "multiline.txt", ""},
}

func TestDecryptAnsibleFixtures(t *testing.T) {
	t.Parallel()

	for _, tc := range ansibleFixtures {
		t.Run(tc.vault, func(t *testing.T) {
			t.Parallel()

			got, err := Decrypt(readFixture(t, tc.vault), []byte(fixturePassword))
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if want := readFixture(t, tc.plaintext); !bytes.Equal(got, want) {
				t.Fatalf("plaintext mismatch: got %d bytes, want %d", len(got), len(want))
			}

			env := mustParse(t, readFixture(t, tc.vault))
			if env.VaultID != tc.vaultID {
				t.Fatalf("vault id: got %q, want %q", env.VaultID, tc.vaultID)
			}
		})
	}
}

func TestDecryptAnsibleFixtureWithWhitespacePassword(t *testing.T) {
	t.Parallel()

	// odd_password.pass has surrounding whitespace that ansible strips, so a
	// FileSecret must strip it too or this fixture will not open.
	v := New(NewFileSecret("", filepath.Join("testdata", "odd_password.pass")))

	got, err := v.Decrypt(readFixture(t, "odd_password.vault"))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if want := readFixture(t, "odd_password.txt"); !bytes.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRoundTrip(t *testing.T) {
	t.Parallel()

	payloads := [][]byte{
		nil,
		[]byte(""),
		[]byte("a"),
		[]byte("exactly-sixteen!"),
		[]byte(strings.Repeat("long ", 5000)),
		{0x00, 0xff, 0x0a, 0x0d},
	}

	for i, want := range payloads {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			t.Parallel()

			sealed, err := Encrypt(want, []byte("pw"))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			if !IsEncrypted(sealed) {
				t.Fatal("output is not recognised as a vault payload")
			}

			got, err := Decrypt(sealed, []byte("pw"))
			if err != nil {
				t.Fatalf("Decrypt: %v", err)
			}

			if !bytes.Equal(got, want) {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestEncryptUsesAFreshSaltEveryTime(t *testing.T) {
	t.Parallel()

	a, err := Encrypt([]byte("same"), []byte("pw"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	b, err := Encrypt([]byte("same"), []byte("pw"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(a, b) {
		t.Fatal("two encryptions of the same plaintext were identical")
	}
}

func TestStringHelpers(t *testing.T) {
	t.Parallel()

	sealed, err := EncryptString("hello", "pw")
	if err != nil {
		t.Fatalf("EncryptString: %v", err)
	}

	got, err := DecryptString(sealed, "pw")
	if err != nil {
		t.Fatalf("DecryptString: %v", err)
	}

	if got != "hello" {
		t.Fatalf("got %q", got)
	}

	if _, err := DecryptString("not a vault", "pw"); !errors.Is(err, ErrNotVault) {
		t.Fatalf("got %v, want ErrNotVault", err)
	}
}

func TestStringHelpersPropagateEncryptErrors(t *testing.T) {
	original := randRead
	randRead = func([]byte) error { return errBoom }

	t.Cleanup(func() { randRead = original })

	if _, err := EncryptString("x", "pw"); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
}

func TestEncryptWithVaultID(t *testing.T) {
	t.Parallel()

	sealed, err := EncryptWithVaultID([]byte("prod data"), []byte("pw"), "prod")
	if err != nil {
		t.Fatalf("EncryptWithVaultID: %v", err)
	}

	env := mustParse(t, sealed)
	if env.Version != Version12 || env.VaultID != "prod" {
		t.Fatalf("got %+v", env)
	}

	plaintext, id, err := New(NewStaticSecret("prod", []byte("pw"))).DecryptAndGetVaultID(sealed)
	if err != nil {
		t.Fatalf("DecryptAndGetVaultID: %v", err)
	}

	if string(plaintext) != "prod data" || id != "prod" {
		t.Fatalf("got %q / %q", plaintext, id)
	}
}

func TestVaultSecretSelection(t *testing.T) {
	t.Parallel()

	prod := NewStaticSecret("prod", []byte("prod-pw"))
	dev := NewStaticSecret("dev", []byte("dev-pw"))

	v := New(prod, dev)

	t.Run("Secrets returns a copy", func(t *testing.T) {
		t.Parallel()

		got := v.Secrets()
		if len(got) != 2 {
			t.Fatalf("got %d secrets", len(got))
		}

		got[0] = nil

		if v.Secrets()[0] == nil {
			t.Fatal("mutating the returned slice affected the vault")
		}
	})

	t.Run("Encrypt uses the first secret", func(t *testing.T) {
		t.Parallel()

		sealed, err := v.Encrypt([]byte("x"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		if id := mustParse(t, sealed).VaultID; id != "prod" {
			t.Fatalf("got vault id %q, want prod", id)
		}
	})

	t.Run("EncryptWithVaultID selects by label", func(t *testing.T) {
		t.Parallel()

		sealed, err := v.EncryptWithVaultID([]byte("x"), "dev")
		if err != nil {
			t.Fatalf("EncryptWithVaultID: %v", err)
		}

		if id := mustParse(t, sealed).VaultID; id != "dev" {
			t.Fatalf("got vault id %q, want dev", id)
		}

		plaintext, err := New(dev).Decrypt(sealed)
		if err != nil || string(plaintext) != "x" {
			t.Fatalf("got %q, err %v", plaintext, err)
		}
	})

	t.Run("EncryptWithVaultID rejects unknown labels", func(t *testing.T) {
		t.Parallel()

		_, err := v.EncryptWithVaultID([]byte("x"), "staging")
		if !errors.Is(err, ErrNoSecrets) {
			t.Fatalf("got %v, want ErrNoSecrets", err)
		}
	})

	t.Run("decryption falls back across secrets", func(t *testing.T) {
		t.Parallel()

		// Sealed under "dev" but the vault lists "prod" first; the label match
		// must reorder, and an unlabelled 1.1 payload must still be found by
		// trying every secret.
		sealed, err := New(dev).Encrypt([]byte("dev data"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		plaintext, id, err := v.DecryptAndGetVaultID(sealed)
		if err != nil || string(plaintext) != "dev data" || id != "dev" {
			t.Fatalf("got %q / %q, err %v", plaintext, id, err)
		}

		unlabelled, err := Encrypt([]byte("plain"), []byte("dev-pw"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		plaintext, id, err = v.DecryptAndGetVaultID(unlabelled)
		if err != nil || string(plaintext) != "plain" || id != "dev" {
			t.Fatalf("got %q / %q, err %v", plaintext, id, err)
		}
	})

	t.Run("unknown label falls back to trying everything", func(t *testing.T) {
		t.Parallel()

		sealed, err := New(NewStaticSecret("staging", []byte("dev-pw"))).Encrypt([]byte("s"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		plaintext, id, err := v.DecryptAndGetVaultID(sealed)
		if err != nil || string(plaintext) != "s" || id != "dev" {
			t.Fatalf("got %q / %q, err %v", plaintext, id, err)
		}
	})
}

func TestOpenReportsTheSecretThatWorked(t *testing.T) {
	t.Parallel()

	prod := NewStaticSecret("prod", []byte("prod-pw"))
	dev := NewStaticSecret("dev", []byte("dev-pw"))

	sealed, err := New(dev).Encrypt([]byte("dev data"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	plaintext, used, err := New(prod, dev).Open(sealed)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if string(plaintext) != "dev data" {
		t.Fatalf("got %q", plaintext)
	}

	if used != dev {
		t.Fatalf("got secret %v, want the dev secret", used)
	}

	if _, _, err := New().Open(sealed); !errors.Is(err, ErrNoSecrets) {
		t.Fatalf("got %v, want ErrNoSecrets", err)
	}

	if _, _, err := New(prod).Open([]byte("not a vault")); !errors.Is(err, ErrNotVault) {
		t.Fatalf("got %v, want ErrNotVault", err)
	}
}

func TestEncryptWithSecret(t *testing.T) {
	t.Parallel()

	secret := NewStaticSecret("prod", []byte("pw"))

	t.Run("empty vault id uses the secret's own", func(t *testing.T) {
		t.Parallel()

		sealed, err := EncryptWithSecret([]byte("x"), secret, "")
		if err != nil {
			t.Fatalf("EncryptWithSecret: %v", err)
		}

		if id := mustParse(t, sealed).VaultID; id != "prod" {
			t.Fatalf("got %q, want prod", id)
		}
	})

	t.Run("label can differ from the secret id", func(t *testing.T) {
		t.Parallel()

		// This is what "edit" needs: re-seal under the identity that opened
		// the file while keeping the label the file already carried.
		sealed, err := EncryptWithSecret([]byte("x"), secret, "legacy")
		if err != nil {
			t.Fatalf("EncryptWithSecret: %v", err)
		}

		if id := mustParse(t, sealed).VaultID; id != "legacy" {
			t.Fatalf("got %q, want legacy", id)
		}

		plaintext, err := New(secret).Decrypt(sealed)
		if err != nil || string(plaintext) != "x" {
			t.Fatalf("got %q, err %v", plaintext, err)
		}
	})

	t.Run("propagates secret errors", func(t *testing.T) {
		t.Parallel()

		if _, err := EncryptWithSecret([]byte("x"), NewStaticSecret("", nil), ""); !errors.Is(err, ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})
}

func TestVaultAddSecret(t *testing.T) {
	t.Parallel()

	v := New()

	if _, err := v.Encrypt([]byte("x")); !errors.Is(err, ErrNoSecrets) {
		t.Fatalf("got %v, want ErrNoSecrets", err)
	}

	if _, err := v.EncryptWithVaultID([]byte("x"), "any"); !errors.Is(err, ErrNoSecrets) {
		t.Fatalf("got %v, want ErrNoSecrets", err)
	}

	if _, err := v.Decrypt(readFixture(t, "hello_11.vault")); !errors.Is(err, ErrNoSecrets) {
		t.Fatalf("got %v, want ErrNoSecrets", err)
	}

	v.AddSecret(NewStaticSecret("", []byte(fixturePassword)))

	if _, err := v.Decrypt(readFixture(t, "hello_11.vault")); err != nil {
		t.Fatalf("Decrypt after AddSecret: %v", err)
	}
}

func TestDecryptErrors(t *testing.T) {
	t.Parallel()

	v := NewWithPassword([]byte("wrong"))

	t.Run("not a vault", func(t *testing.T) {
		t.Parallel()

		if _, err := v.Decrypt([]byte("nope")); !errors.Is(err, ErrNotVault) {
			t.Fatalf("got %v, want ErrNotVault", err)
		}
	})

	t.Run("malformed payload", func(t *testing.T) {
		t.Parallel()

		bad := FormatEnvelope([]byte("only-one-field"), "")
		if _, err := v.Decrypt(bad); !errors.Is(err, ErrMalformedEnvelope) {
			t.Fatalf("got %v, want ErrMalformedEnvelope", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		t.Parallel()

		_, err := v.Decrypt(readFixture(t, "hello_11.vault"))
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("got %v, want ErrDecryptionFailed", err)
		}

		if !strings.Contains(err.Error(), "HMAC") {
			t.Fatalf("error should name the underlying cause: %v", err)
		}
	})

	t.Run("secret that cannot be loaded", func(t *testing.T) {
		t.Parallel()

		broken := New(NewFileSecret("", filepath.Join(t.TempDir(), "absent")))

		_, err := broken.Decrypt(readFixture(t, "hello_11.vault"))
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("got %v, want ErrDecryptionFailed", err)
		}
	})
}

func TestEncryptPropagatesSecretErrors(t *testing.T) {
	t.Parallel()

	v := New(NewStaticSecret("", nil))

	if _, err := v.Encrypt([]byte("x")); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("got %v, want ErrEmptyPassword", err)
	}
}

func TestEncryptPropagatesSaltErrors(t *testing.T) {
	original := randRead
	randRead = func([]byte) error { return errBoom }

	t.Cleanup(func() { randRead = original })

	if _, err := Encrypt([]byte("x"), []byte("pw")); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
}

func TestEncryptWithSaltPropagatesKDFErrors(t *testing.T) {
	withStubbedKDF(t, func() ([]byte, error) { return nil, errBoom })

	if _, err := encryptWithSalt([]byte("x"), []byte("pw"), []byte("salt"), ""); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}
}

func TestRekey(t *testing.T) {
	t.Parallel()

	v := NewWithPassword([]byte(fixturePassword))

	resealed, err := v.Rekey(readFixture(t, "hello_11.vault"), NewStaticSecret("next", []byte("newpw")))
	if err != nil {
		t.Fatalf("Rekey: %v", err)
	}

	got, err := Decrypt(resealed, []byte("newpw"))
	if err != nil {
		t.Fatalf("Decrypt after rekey: %v", err)
	}

	if string(got) != "hello world\n" {
		t.Fatalf("got %q", got)
	}

	if id := mustParse(t, resealed).VaultID; id != "next" {
		t.Fatalf("got vault id %q, want next", id)
	}

	if _, err := v.Rekey([]byte("not a vault"), NewStaticSecret("", []byte("x"))); !errors.Is(err, ErrNotVault) {
		t.Fatalf("got %v, want ErrNotVault", err)
	}
}

func TestDecryptFile(t *testing.T) {
	t.Parallel()

	got, err := DecryptFile(filepath.Join("testdata", "hello_11.vault"), []byte(fixturePassword))
	if err != nil {
		t.Fatalf("DecryptFile: %v", err)
	}

	if string(got) != "hello world\n" {
		t.Fatalf("got %q", got)
	}

	if _, err := DecryptFile(filepath.Join(t.TempDir(), "absent"), []byte("pw")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v, want os.ErrNotExist", err)
	}
}
