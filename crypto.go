package gansivault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
)

const (
	// keyLength is the AES-256 key size.
	keyLength = 32

	// ivLength is the AES block size, used as the CTR counter block.
	ivLength = aes.BlockSize

	// saltLength is the number of random bytes Ansible draws per encryption.
	saltLength = 32

	// iterations is the PBKDF2 round count hard-coded in Ansible.
	iterations = 10000
)

// randRead is indirected so tests can simulate entropy failures.
var randRead = func(b []byte) error {
	_, err := io.ReadFull(rand.Reader, b)

	return err
}

// stretch is indirected so tests can simulate a KDF failure. With the constant
// parameters used here the standard library never actually fails.
var stretch = func(password, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, string(password), salt, iterations, 2*keyLength+ivLength)
}

// derivedKeys holds the three values PBKDF2 produces for one salt/password
// pair: the AES key, the HMAC key and the CTR counter block.
type derivedKeys struct {
	cipherKey []byte
	hmacKey   []byte
	iv        []byte
}

// deriveKeys stretches password with PBKDF2-HMAC-SHA256 over salt and splits
// the 80 byte output the way Ansible does.
func deriveKeys(password, salt []byte) (derivedKeys, error) {
	raw, err := stretch(password, salt)
	if err != nil {
		return derivedKeys{}, fmt.Errorf("gansivault: deriving key: %w", err)
	}

	return derivedKeys{
		cipherKey: raw[:keyLength],
		hmacKey:   raw[keyLength : 2*keyLength],
		iv:        raw[2*keyLength : 2*keyLength+ivLength],
	}, nil
}

// payload is the inner, hex-encoded triple carried by an Envelope body.
type payload struct {
	salt       []byte
	mac        []byte
	ciphertext []byte
}

// marshal renders the payload as "hex(salt)\nhex(hmac)\nhex(ciphertext)",
// which is what gets hex-encoded a second time by FormatEnvelope.
func (p payload) marshal() []byte {
	var out bytes.Buffer

	out.WriteString(hex.EncodeToString(p.salt))
	out.WriteByte('\n')
	out.WriteString(hex.EncodeToString(p.mac))
	out.WriteByte('\n')
	out.WriteString(hex.EncodeToString(p.ciphertext))

	return out.Bytes()
}

// parsePayload splits an Envelope body back into salt, hmac and ciphertext.
func parsePayload(body []byte) (*payload, error) {
	fields := bytes.Split(body, []byte{'\n'})
	if len(fields) != 3 {
		return nil, fmt.Errorf("%w: payload has %d fields, want 3", ErrMalformedEnvelope, len(fields))
	}

	names := [3]string{"salt", "hmac", "ciphertext"}
	decoded := make([][]byte, 3)

	for i, field := range fields {
		raw, err := hex.DecodeString(string(bytes.TrimSpace(field)))
		if err != nil {
			return nil, fmt.Errorf("%w: bad %s hex: %w", ErrMalformedEnvelope, names[i], err)
		}

		decoded[i] = raw
	}

	return &payload{salt: decoded[0], mac: decoded[1], ciphertext: decoded[2]}, nil
}

// pkcs7Pad appends PKCS#7 padding to a full AES block boundary. A message that
// is already aligned gains a whole block of padding, as the standard requires.
func pkcs7Pad(data []byte) []byte {
	n := aes.BlockSize - len(data)%aes.BlockSize

	return append(append([]byte{}, data...), bytes.Repeat([]byte{byte(n)}, n)...)
}

// pkcs7Unpad removes and validates PKCS#7 padding.
func pkcs7Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 || len(data)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: length %d is not a positive multiple of %d", ErrInvalidPadding, len(data), aes.BlockSize)
	}

	n := int(data[len(data)-1])
	if n == 0 || n > aes.BlockSize {
		return nil, fmt.Errorf("%w: pad byte %d out of range", ErrInvalidPadding, n)
	}

	want := bytes.Repeat([]byte{byte(n)}, n)
	if subtle.ConstantTimeCompare(data[len(data)-n:], want) != 1 {
		return nil, fmt.Errorf("%w: padding bytes are inconsistent", ErrInvalidPadding)
	}

	return data[:len(data)-n], nil
}

// ctrXOR runs AES-256-CTR over src using the given key and counter block. CTR
// is symmetric, so this both encrypts and decrypts. It is a variable so tests
// can reach the error paths of its callers, which the real implementation
// cannot produce with a fixed 32 byte key.
var ctrXOR = func(key, iv, src []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("gansivault: aes: %w", err)
	}

	dst := make([]byte, len(src))
	cipher.NewCTR(block, iv).XORKeyStream(dst, src)

	return dst, nil
}

// encryptPayload performs the AES256 half of an encryption: pad, encrypt in
// CTR mode, then authenticate the ciphertext with HMAC-SHA256.
func encryptPayload(plaintext, password, salt []byte) (*payload, error) {
	keys, err := deriveKeys(password, salt)
	if err != nil {
		return nil, err
	}

	ciphertext, err := ctrXOR(keys.cipherKey, keys.iv, pkcs7Pad(plaintext))
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, keys.hmacKey)
	mac.Write(ciphertext)

	return &payload{salt: salt, mac: mac.Sum(nil), ciphertext: ciphertext}, nil
}

// decryptPayload verifies the HMAC before touching the ciphertext, mirroring
// Ansible's encrypt-then-MAC ordering.
func decryptPayload(p *payload, password []byte) ([]byte, error) {
	keys, err := deriveKeys(password, p.salt)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, keys.hmacKey)
	mac.Write(p.ciphertext)

	if !hmac.Equal(mac.Sum(nil), p.mac) {
		return nil, ErrHMACMismatch
	}

	padded, err := ctrXOR(keys.cipherKey, keys.iv, p.ciphertext)
	if err != nil {
		return nil, err
	}

	return pkcs7Unpad(padded)
}

// newSalt draws a fresh 32 byte salt.
func newSalt() ([]byte, error) {
	salt := make([]byte, saltLength)
	if err := randRead(salt); err != nil {
		return nil, fmt.Errorf("gansivault: reading entropy: %w", err)
	}

	return salt, nil
}
