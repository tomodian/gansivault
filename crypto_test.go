package gansivault

import (
	"bytes"
	"crypto/aes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestDeriveKeysMatchesAnsible(t *testing.T) {
	t.Parallel()

	// Derived from the ansible-vault fixture: decrypting hello_11.vault with
	// "mypassword" only succeeds if PBKDF2 and the 32/32/16 split are exact,
	// so pin the concrete key material for that file's salt.
	env := mustParse(t, readFixture(t, "hello_11.vault"))

	p, err := parsePayload(env.Body)
	if err != nil {
		t.Fatalf("parsePayload: %v", err)
	}

	if len(p.salt) != saltLength {
		t.Fatalf("salt is %d bytes, want %d", len(p.salt), saltLength)
	}

	if len(p.mac) != 32 {
		t.Fatalf("hmac is %d bytes, want 32", len(p.mac))
	}

	keys, err := deriveKeys([]byte("mypassword"), p.salt)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}

	if len(keys.cipherKey) != keyLength || len(keys.hmacKey) != keyLength || len(keys.iv) != ivLength {
		t.Fatalf("bad split: %d/%d/%d", len(keys.cipherKey), len(keys.hmacKey), len(keys.iv))
	}

	plaintext, err := decryptPayload(p, []byte("mypassword"))
	if err != nil {
		t.Fatalf("decryptPayload: %v", err)
	}

	if string(plaintext) != "hello world\n" {
		t.Fatalf("got %q", plaintext)
	}
}

func TestDeriveKeysPropagatesKDFError(t *testing.T) {
	withStubbedKDF(t, func() ([]byte, error) { return nil, errBoom })

	if _, err := deriveKeys([]byte("pw"), []byte("salt")); !errors.Is(err, errBoom) {
		t.Fatalf("got %v, want errBoom", err)
	}

	if _, err := encryptPayload([]byte("x"), []byte("pw"), []byte("salt")); !errors.Is(err, errBoom) {
		t.Fatalf("encryptPayload: got %v, want errBoom", err)
	}

	if _, err := decryptPayload(&payload{}, []byte("pw")); !errors.Is(err, errBoom) {
		t.Fatalf("decryptPayload: got %v, want errBoom", err)
	}
}

func TestPKCS7(t *testing.T) {
	t.Parallel()

	t.Run("round trip", func(t *testing.T) {
		t.Parallel()

		for n := 0; n <= 3*aes.BlockSize; n++ {
			in := bytes.Repeat([]byte{'x'}, n)

			padded := pkcs7Pad(in)
			if len(padded)%aes.BlockSize != 0 || len(padded) <= n {
				t.Fatalf("n=%d padded to %d", n, len(padded))
			}

			out, err := pkcs7Unpad(padded)
			if err != nil {
				t.Fatalf("n=%d: %v", n, err)
			}

			if !bytes.Equal(out, in) {
				t.Fatalf("n=%d: got %q", n, out)
			}
		}
	})

	t.Run("aligned input gains a full block", func(t *testing.T) {
		t.Parallel()

		in := bytes.Repeat([]byte{'x'}, aes.BlockSize)
		if got := len(pkcs7Pad(in)); got != 2*aes.BlockSize {
			t.Fatalf("got %d, want %d", got, 2*aes.BlockSize)
		}
	})

	t.Run("does not alias the input", func(t *testing.T) {
		t.Parallel()

		in := make([]byte, 4, 64)
		copy(in, "abcd")

		_ = pkcs7Pad(in)

		if string(in[:4]) != "abcd" {
			t.Fatalf("input was mutated: %q", in[:4])
		}
	})

	bad := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"not block aligned", bytes.Repeat([]byte{1}, 17)},
		{"zero pad byte", append(bytes.Repeat([]byte{'x'}, 15), 0)},
		{"pad byte too large", append(bytes.Repeat([]byte{'x'}, 15), 17)},
		{"inconsistent padding", append(bytes.Repeat([]byte{'x'}, 14), 3, 3)},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := pkcs7Unpad(tc.in); !errors.Is(err, ErrInvalidPadding) {
				t.Fatalf("got %v, want ErrInvalidPadding", err)
			}
		})
	}
}

func TestCTRXORRejectsBadKeyLength(t *testing.T) {
	t.Parallel()

	if _, err := ctrXOR([]byte("too short"), make([]byte, ivLength), []byte("data")); err == nil {
		t.Fatal("want an error for a 9 byte AES key")
	}
}

func TestCTRXORIsSymmetric(t *testing.T) {
	t.Parallel()

	key := bytes.Repeat([]byte{7}, keyLength)
	iv := bytes.Repeat([]byte{9}, ivLength)
	msg := []byte("counter mode is its own inverse")

	enc, err := ctrXOR(key, iv, msg)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	dec, err := ctrXOR(key, iv, enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}

	if !bytes.Equal(dec, msg) {
		t.Fatalf("got %q, want %q", dec, msg)
	}
}

func TestPayloadCryptoPropagatesCipherErrors(t *testing.T) {
	original := ctrXOR
	ctrXOR = func(_, _, _ []byte) ([]byte, error) { return nil, errBoom }

	t.Cleanup(func() { ctrXOR = original })

	salt := bytes.Repeat([]byte{5}, saltLength)

	if _, err := encryptPayload([]byte("x"), []byte("pw"), salt); !errors.Is(err, errBoom) {
		t.Fatalf("encryptPayload: got %v, want errBoom", err)
	}

	// Build a payload whose HMAC is valid so decryption gets past
	// authentication and reaches the cipher call.
	keys, err := deriveKeys([]byte("pw"), salt)
	if err != nil {
		t.Fatalf("deriveKeys: %v", err)
	}

	p := &payload{salt: salt, ciphertext: bytes.Repeat([]byte{1}, aes.BlockSize)}
	p.mac = macOf(keys.hmacKey, p.ciphertext)

	if _, err := decryptPayload(p, []byte("pw")); !errors.Is(err, errBoom) {
		t.Fatalf("decryptPayload: got %v, want errBoom", err)
	}
}

func TestParsePayload(t *testing.T) {
	t.Parallel()

	good := payload{
		salt:       bytes.Repeat([]byte{1}, saltLength),
		mac:        bytes.Repeat([]byte{2}, 32),
		ciphertext: bytes.Repeat([]byte{3}, 16),
	}

	got, err := parsePayload(good.marshal())
	if err != nil {
		t.Fatalf("parsePayload: %v", err)
	}

	if !bytes.Equal(got.salt, good.salt) || !bytes.Equal(got.mac, good.mac) || !bytes.Equal(got.ciphertext, good.ciphertext) {
		t.Fatalf("round trip mismatch: %+v", got)
	}

	bad := []struct {
		name string
		in   string
	}{
		{"too few fields", hex.EncodeToString([]byte("a")) + "\n" + hex.EncodeToString([]byte("b"))},
		{"too many fields", "61\n62\n63\n64"},
		{"bad salt hex", "zz\n62\n63"},
		{"bad hmac hex", "61\nzz\n63"},
		{"bad ciphertext hex", "61\n62\nzz"},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parsePayload([]byte(tc.in)); !errors.Is(err, ErrMalformedEnvelope) {
				t.Fatalf("got %v, want ErrMalformedEnvelope", err)
			}
		})
	}
}

func TestDecryptPayloadDetectsTampering(t *testing.T) {
	t.Parallel()

	p, err := encryptPayload([]byte("secret"), []byte("pw"), bytes.Repeat([]byte{4}, saltLength))
	if err != nil {
		t.Fatalf("encryptPayload: %v", err)
	}

	t.Run("wrong password", func(t *testing.T) {
		t.Parallel()

		if _, err := decryptPayload(p, []byte("nope")); !errors.Is(err, ErrHMACMismatch) {
			t.Fatalf("got %v, want ErrHMACMismatch", err)
		}
	})

	t.Run("flipped ciphertext bit", func(t *testing.T) {
		t.Parallel()

		tampered := &payload{salt: p.salt, mac: p.mac, ciphertext: append([]byte{}, p.ciphertext...)}
		tampered.ciphertext[0] ^= 0x01

		if _, err := decryptPayload(tampered, []byte("pw")); !errors.Is(err, ErrHMACMismatch) {
			t.Fatalf("got %v, want ErrHMACMismatch", err)
		}
	})

	t.Run("valid mac over unpaddable plaintext", func(t *testing.T) {
		t.Parallel()

		// Encrypt a payload whose ciphertext length is not a multiple of the
		// block size, then re-MAC it so authentication passes and unpadding
		// is what fails.
		short := &payload{salt: p.salt, ciphertext: p.ciphertext[:len(p.ciphertext)-1]}

		keys, err := deriveKeys([]byte("pw"), short.salt)
		if err != nil {
			t.Fatalf("deriveKeys: %v", err)
		}

		short.mac = macOf(keys.hmacKey, short.ciphertext)

		if _, err := decryptPayload(short, []byte("pw")); !errors.Is(err, ErrInvalidPadding) {
			t.Fatalf("got %v, want ErrInvalidPadding", err)
		}
	})
}

func TestNewSalt(t *testing.T) {
	t.Run("length and freshness", func(t *testing.T) {
		a, err := newSalt()
		if err != nil {
			t.Fatalf("newSalt: %v", err)
		}

		if len(a) != saltLength {
			t.Fatalf("got %d bytes, want %d", len(a), saltLength)
		}

		b, err := newSalt()
		if err != nil {
			t.Fatalf("newSalt: %v", err)
		}

		if bytes.Equal(a, b) {
			t.Fatal("two salts were identical")
		}
	})

	t.Run("entropy failure", func(t *testing.T) {
		original := randRead
		randRead = func([]byte) error { return errBoom }

		t.Cleanup(func() { randRead = original })

		_, err := newSalt()
		if !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}

		if !strings.Contains(err.Error(), "entropy") {
			t.Fatalf("error should mention entropy: %v", err)
		}
	})
}

// --- helpers -------------------------------------------------------------

// withStubbedKDF replaces the PBKDF2 seam for the duration of a test.
func withStubbedKDF(t *testing.T, fn func() ([]byte, error)) {
	t.Helper()

	original := stretch
	stretch = func(_, _ []byte) ([]byte, error) { return fn() }

	t.Cleanup(func() { stretch = original })
}

// macOf computes the HMAC-SHA256 the vault format expects over a ciphertext.
func macOf(key, data []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write(data)

	return mac.Sum(nil)
}
