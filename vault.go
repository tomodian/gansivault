// Package gansivault is a dependency-free, byte-compatible port of Ansible
// Vault for Go.
//
// It reads and writes the same "$ANSIBLE_VAULT;1.1;AES256" payloads that the
// ansible-vault command line tool produces: PBKDF2-HMAC-SHA256 (10000
// iterations, 32 byte salt) key derivation, AES-256-CTR encryption, PKCS#7
// padding and encrypt-then-MAC with HMAC-SHA256. Both the 1.1 and the 1.2
// (vault id) header variants are supported.
//
// The simplest use is the package level helper pair:
//
//	sealed, err := gansivault.Encrypt([]byte("s3cret"), []byte("password"))
//	plain, err := gansivault.Decrypt(sealed, []byte("password"))
//
// For multiple identities, password files or password scripts, build a Vault
// from one or more Secret values:
//
//	v := gansivault.New(
//		gansivault.NewFileSecret("prod", "/run/secrets/prod.pass"),
//		gansivault.NewStaticSecret("dev", []byte("devpassword")),
//	)
//	plain, id, err := v.DecryptAndGetVaultID(sealed)
package gansivault

import (
	"fmt"
	"os"
)

// Vault holds an ordered set of secrets and performs encryption and
// decryption with them. The zero value is not usable; call New.
//
// A Vault is safe for concurrent use as long as its secrets are, which is true
// of every Secret in this package.
type Vault struct {
	secrets []Secret
}

// New builds a Vault from the given secrets. Order matters: the first secret
// is the default encryption identity, and decryption tries secrets in order
// after any vault-id match.
func New(secrets ...Secret) *Vault {
	return &Vault{secrets: append([]Secret{}, secrets...)}
}

// NewWithPassword is shorthand for a Vault holding a single default-identity
// password.
func NewWithPassword(password []byte) *Vault {
	return New(NewStaticSecret(DefaultVaultID, password))
}

// AddSecret appends a secret to the vault.
func (v *Vault) AddSecret(s Secret) {
	v.secrets = append(v.secrets, s)
}

// Secrets returns a copy of the configured secrets, in order.
func (v *Vault) Secrets() []Secret {
	return append([]Secret{}, v.secrets...)
}

// Encrypt seals plaintext with the vault's first secret, labelling the output
// with that secret's vault id.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	if len(v.secrets) == 0 {
		return nil, ErrNoSecrets
	}

	return v.encryptWith(plaintext, v.secrets[0])
}

// EncryptWithVaultID seals plaintext with the secret registered under vaultID.
// This backs ansible-vault's --encrypt-vault-id.
func (v *Vault) EncryptWithVaultID(plaintext []byte, vaultID string) ([]byte, error) {
	if len(v.secrets) == 0 {
		return nil, ErrNoSecrets
	}

	want := normalizeID(vaultID)

	for _, s := range v.secrets {
		if normalizeID(s.ID()) == want {
			return v.encryptWith(plaintext, s)
		}
	}

	return nil, fmt.Errorf("%w: no secret for vault id %q", ErrNoSecrets, want)
}

func (v *Vault) encryptWith(plaintext []byte, s Secret) ([]byte, error) {
	return EncryptWithSecret(plaintext, s, "")
}

// EncryptWithSecret seals plaintext with an explicit secret. vaultID overrides
// the label written into the header; pass "" to use the secret's own id.
//
// The override exists so that re-encrypting an existing file can keep its
// original 1.2 label even when the secret that opened it is registered under a
// different identity, which is what "ansible-vault edit" does.
func EncryptWithSecret(plaintext []byte, s Secret, vaultID string) ([]byte, error) {
	password, err := s.Bytes()
	if err != nil {
		return nil, err
	}

	salt, err := newSalt()
	if err != nil {
		return nil, err
	}

	if vaultID == "" {
		vaultID = s.ID()
	}

	return encryptWithSalt(plaintext, password, salt, vaultID)
}

// encryptWithSalt is the deterministic core of encryption, split out so tests
// can pin the salt and compare against fixtures produced by ansible-vault.
func encryptWithSalt(plaintext, password, salt []byte, vaultID string) ([]byte, error) {
	p, err := encryptPayload(plaintext, password, salt)
	if err != nil {
		return nil, err
	}

	return FormatEnvelope(p.marshal(), vaultID), nil
}

// Decrypt opens a vault payload with whichever configured secret works.
func (v *Vault) Decrypt(vaultText []byte) ([]byte, error) {
	plaintext, _, err := v.DecryptAndGetVaultID(vaultText)

	return plaintext, err
}

// DecryptAndGetVaultID opens a vault payload and also reports the vault id of
// the secret that succeeded.
func (v *Vault) DecryptAndGetVaultID(vaultText []byte) ([]byte, string, error) {
	plaintext, s, err := v.Open(vaultText)
	if err != nil {
		return nil, "", err
	}

	return plaintext, normalizeID(s.ID()), nil
}

// Open decrypts a vault payload and returns the secret that succeeded, which
// is what a caller needs in order to re-encrypt the same data under the same
// identity.
//
// Secrets whose id matches the label in a 1.2 header are tried first; the
// remaining secrets are then tried in order, mirroring Ansible's behaviour of
// falling back when the label does not match anything configured.
func (v *Vault) Open(vaultText []byte) ([]byte, Secret, error) {
	if len(v.secrets) == 0 {
		return nil, nil, ErrNoSecrets
	}

	env, err := ParseEnvelope(vaultText)
	if err != nil {
		return nil, nil, err
	}

	p, err := parsePayload(env.Body)
	if err != nil {
		return nil, nil, err
	}

	var lastErr error

	for _, s := range v.orderSecrets(env.VaultID) {
		password, err := s.Bytes()
		if err != nil {
			lastErr = err

			continue
		}

		plaintext, err := decryptPayload(p, password)
		if err != nil {
			lastErr = err

			continue
		}

		return plaintext, s, nil
	}

	// The secret list is non-empty and every iteration records an error, so
	// lastErr always describes the final attempt by the time we get here.
	return nil, nil, fmt.Errorf("%w: %w", ErrDecryptionFailed, lastErr)
}

// orderSecrets puts secrets matching vaultID first, preserving relative order.
func (v *Vault) orderSecrets(vaultID string) []Secret {
	if vaultID == "" {
		return v.secrets
	}

	want := normalizeID(vaultID)

	matched := make([]Secret, 0, len(v.secrets))
	rest := make([]Secret, 0, len(v.secrets))

	for _, s := range v.secrets {
		if normalizeID(s.ID()) == want {
			matched = append(matched, s)

			continue
		}

		rest = append(rest, s)
	}

	return append(matched, rest...)
}

// Rekey decrypts vaultText with the vault's secrets and re-encrypts it under
// newSecret, backing ansible-vault rekey.
func (v *Vault) Rekey(vaultText []byte, newSecret Secret) ([]byte, error) {
	plaintext, err := v.Decrypt(vaultText)
	if err != nil {
		return nil, err
	}

	return v.encryptWith(plaintext, newSecret)
}

// DecryptFile reads a vault file from disk and opens it.
func (v *Vault) DecryptFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- the caller chose this file
	if err != nil {
		return nil, err
	}

	return v.Decrypt(data)
}

// Encrypt seals plaintext with a single password under the default vault id.
func Encrypt(plaintext, password []byte) ([]byte, error) {
	return NewWithPassword(password).Encrypt(plaintext)
}

// EncryptWithVaultID seals plaintext with a single password and labels the
// output with vaultID, producing a 1.2 header unless vaultID is "default".
func EncryptWithVaultID(plaintext, password []byte, vaultID string) ([]byte, error) {
	return New(NewStaticSecret(vaultID, password)).Encrypt(plaintext)
}

// Decrypt opens a vault payload with a single password.
func Decrypt(vaultText, password []byte) ([]byte, error) {
	return NewWithPassword(password).Decrypt(vaultText)
}

// EncryptString is the string flavour of Encrypt.
func EncryptString(plaintext, password string) (string, error) {
	out, err := Encrypt([]byte(plaintext), []byte(password))
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// DecryptString is the string flavour of Decrypt.
func DecryptString(vaultText, password string) (string, error) {
	out, err := Decrypt([]byte(vaultText), []byte(password))
	if err != nil {
		return "", err
	}

	return string(out), nil
}

// DecryptFile reads a vault file from disk and opens it with a single
// password.
func DecryptFile(path string, password []byte) ([]byte, error) {
	return NewWithPassword(password).DecryptFile(path)
}
