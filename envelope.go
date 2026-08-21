package gansivault

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	// Header is the magic prefix every Ansible Vault payload starts with.
	Header = "$ANSIBLE_VAULT"

	// Version11 is the original vault format, which has no vault id field.
	Version11 = "1.1"

	// Version12 adds a vault id label to the header line.
	Version12 = "1.2"

	// CipherAES256 is the only cipher Ansible Vault has ever shipped.
	CipherAES256 = "AES256"

	// DefaultVaultID is the vault id Ansible assumes when none is given.
	// Encrypting with this id emits a 1.1 header, matching Ansible.
	DefaultVaultID = "default"

	// lineWidth is the column at which Ansible wraps the hex payload.
	lineWidth = 80
)

// Envelope is the outer, unencrypted structure of a vault payload: the header
// line plus the hex-decoded body.
type Envelope struct {
	// Version is "1.1" or "1.2".
	Version string

	// Cipher is always "AES256".
	Cipher string

	// VaultID is the label from a 1.2 header, or "" for 1.1.
	VaultID string

	// Body is the once-unhexlified payload, i.e. the three newline separated
	// hex fields "salt\nhmac\nciphertext".
	Body []byte
}

// IsEncrypted reports whether data starts with the vault header. It matches
// ansible.parsing.vault.is_encrypted: the header must be at the very start,
// with no leading whitespace, and the data must be ASCII.
func IsEncrypted(data []byte) bool {
	for _, b := range data {
		if b > 0x7f {
			return false
		}
	}

	return bytes.HasPrefix(data, []byte(Header))
}

// IsEncryptedString reports whether s starts with the vault header.
func IsEncryptedString(s string) bool {
	return IsEncrypted([]byte(s))
}

// IsEncryptedReader reports whether the first bytes read from r carry the
// vault header. It reads at most len(Header) bytes.
func IsEncryptedReader(r io.Reader) (bool, error) {
	buf := make([]byte, len(Header))

	n, err := io.ReadFull(r, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return false, err
	}

	return IsEncrypted(buf[:n]), nil
}

// IsEncryptedFile reports whether the file at path is a vault file. A missing
// or unreadable file yields an error.
func IsEncryptedFile(path string) (bool, error) {
	f, err := os.Open(path) // #nosec G304 -- path is supplied by the caller on purpose
	if err != nil {
		return false, err
	}
	defer f.Close() //nolint:errcheck // read-only handle

	return IsEncryptedReader(f)
}

// ParseEnvelope splits a vault payload into its header fields and hex-decoded
// body. Leading and trailing whitespace on every line is tolerated so that
// payloads lifted out of YAML block scalars parse without pre-processing.
func ParseEnvelope(vaultText []byte) (*Envelope, error) {
	trimmed := bytes.TrimSpace(vaultText)
	if !IsEncrypted(trimmed) {
		return nil, ErrNotVault
	}

	lines := strings.Split(string(trimmed), "\n")

	fields := strings.Split(strings.TrimSpace(lines[0]), ";")
	if len(fields) < 3 {
		return nil, fmt.Errorf("%w: header has %d fields, want at least 3", ErrMalformedEnvelope, len(fields))
	}

	env := &Envelope{
		Version: strings.TrimSpace(fields[1]),
		Cipher:  strings.TrimSpace(fields[2]),
	}

	if len(fields) >= 4 {
		env.VaultID = strings.TrimSpace(fields[3])
	}

	switch env.Version {
	case Version11, Version12:
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedVersion, env.Version)
	}

	if env.Cipher != CipherAES256 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedCipher, env.Cipher)
	}

	var payload strings.Builder
	for _, line := range lines[1:] {
		payload.WriteString(strings.TrimSpace(line))
	}

	body, err := hex.DecodeString(payload.String())
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrMalformedEnvelope, err)
	}

	env.Body = body

	return env, nil
}

// FormatEnvelope renders a header line plus the hex-encoded body wrapped at 80
// columns, byte-for-byte identical to Ansible's format_vaulttext_envelope.
// A vaultID of "" or "default" produces a 1.1 header.
func FormatEnvelope(body []byte, vaultID string) []byte {
	parts := []string{Header, Version11, CipherAES256}

	if vaultID != "" && vaultID != DefaultVaultID {
		parts = []string{Header, Version12, CipherAES256, vaultID}
	}

	var out bytes.Buffer
	out.WriteString(strings.Join(parts, ";"))

	encoded := hex.EncodeToString(body)
	for i := 0; i < len(encoded); i += lineWidth {
		end := i + lineWidth
		if end > len(encoded) {
			end = len(encoded)
		}

		out.WriteByte('\n')
		out.WriteString(encoded[i:end])
	}

	return out.Bytes()
}
