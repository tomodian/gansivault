package gansivault

import "errors"

// Errors returned by the vault. They mirror the failure modes of
// ansible.parsing.vault so that callers can branch on them the same way an
// Ansible user would read the CLI output.
var (
	// ErrNotVault is returned when the input does not carry the
	// "$ANSIBLE_VAULT" header.
	ErrNotVault = errors.New("gansivault: input is not vault encrypted data")

	// ErrMalformedEnvelope is returned when the header is present but the
	// envelope cannot be parsed (bad version line, odd hex, missing fields).
	ErrMalformedEnvelope = errors.New("gansivault: malformed vault envelope")

	// ErrUnsupportedVersion is returned for vault format versions other than
	// 1.1 and 1.2.
	ErrUnsupportedVersion = errors.New("gansivault: unsupported vault format version")

	// ErrUnsupportedCipher is returned for ciphers other than AES256.
	ErrUnsupportedCipher = errors.New("gansivault: unsupported vault cipher")

	// ErrHMACMismatch is returned when the message authentication code does
	// not match, which usually means a wrong password or a tampered payload.
	ErrHMACMismatch = errors.New("gansivault: HMAC verification failed (wrong password or corrupt data)")

	// ErrInvalidPadding is returned when the decrypted plaintext does not
	// carry valid PKCS#7 padding.
	ErrInvalidPadding = errors.New("gansivault: invalid PKCS#7 padding")

	// ErrNoSecrets is returned when a vault has no secret configured.
	ErrNoSecrets = errors.New("gansivault: no vault secrets found")

	// ErrDecryptionFailed is returned when none of the configured secrets can
	// decrypt the payload.
	ErrDecryptionFailed = errors.New("gansivault: decryption failed (no matching vault secret)")

	// ErrEmptyPassword is returned when a password source yields an empty
	// password.
	ErrEmptyPassword = errors.New("gansivault: vault password is empty")

	// ErrAlreadyEncrypted is returned when encrypting data that already
	// carries a vault header.
	ErrAlreadyEncrypted = errors.New("gansivault: input is already vault encrypted data")

	// ErrNotUTF8 is returned by DecryptYAML when a decrypted value cannot be
	// inlined into a YAML document because it is not valid UTF-8.
	ErrNotUTF8 = errors.New("gansivault: decrypted value is not valid UTF-8")
)
