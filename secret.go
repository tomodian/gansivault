package gansivault

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Secret is a source of a vault password. Implementations are expected to be
// lazy: nothing is read, executed or prompted for until Bytes is called.
type Secret interface {
	// ID returns the vault id this secret is registered under. An empty id
	// is treated as DefaultVaultID.
	ID() string

	// Bytes returns the password. Implementations should cache the result so
	// that repeated decryption attempts do not re-prompt the user.
	Bytes() ([]byte, error)
}

// normalizeID maps the empty vault id onto Ansible's "default".
func normalizeID(id string) string {
	if id == "" {
		return DefaultVaultID
	}

	return id
}

// trimPassword strips surrounding whitespace, matching Ansible, which calls
// bytes.strip() on both password files and password script output.
func trimPassword(b []byte) []byte {
	return bytes.TrimSpace(b)
}

// StaticSecret is a password held in memory. It is the right choice for
// Lambda handlers and other services that pull the password from an
// environment variable or a secrets manager.
type StaticSecret struct {
	id       string
	password []byte
}

// NewStaticSecret wraps an in-memory password under the given vault id. Pass
// an empty id for Ansible's "default" identity.
func NewStaticSecret(id string, password []byte) *StaticSecret {
	return &StaticSecret{id: normalizeID(id), password: password}
}

// ID implements Secret.
func (s *StaticSecret) ID() string { return s.id }

// Bytes implements Secret. Unlike file and script secrets the password is
// returned verbatim, without whitespace trimming, so that callers stay in
// control of exactly what they supply.
func (s *StaticSecret) Bytes() ([]byte, error) {
	if len(s.password) == 0 {
		return nil, fmt.Errorf("%w: static secret %q", ErrEmptyPassword, s.id)
	}

	return s.password, nil
}

// FileSecret reads a password from --vault-password-file. If the file carries
// an executable bit it is run instead of read, exactly like Ansible: stdout
// becomes the password. Scripts whose name ends in "-client" additionally
// receive "--vault-id <id>".
type FileSecret struct {
	id   string
	path string

	once sync.Once
	pw   []byte
	err  error
}

// NewFileSecret creates a password-file backed secret.
func NewFileSecret(id, path string) *FileSecret {
	return &FileSecret{id: normalizeID(id), path: path}
}

// ID implements Secret.
func (s *FileSecret) ID() string { return s.id }

// Path returns the password file location.
func (s *FileSecret) Path() string { return s.path }

// Bytes implements Secret. The file is read (or the script executed) at most
// once per FileSecret.
func (s *FileSecret) Bytes() ([]byte, error) {
	s.once.Do(func() {
		s.pw, s.err = s.load()
	})

	return s.pw, s.err
}

func (s *FileSecret) load() ([]byte, error) {
	info, err := os.Stat(s.path)
	if err != nil {
		return nil, fmt.Errorf("gansivault: could not read vault password file %s: %w", s.path, err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("gansivault: vault password file %s is a directory", s.path)
	}

	var raw []byte

	if isExecutable(info) {
		raw, err = s.runScript()
	} else {
		raw, err = os.ReadFile(s.path) // #nosec G304 -- the path is the user's --vault-password-file
		if err != nil {
			err = fmt.Errorf("gansivault: could not read vault password file %s: %w", s.path, err)
		}
	}

	if err != nil {
		return nil, err
	}

	pw := trimPassword(raw)
	if len(pw) == 0 {
		return nil, fmt.Errorf("%w: %s", ErrEmptyPassword, s.path)
	}

	return pw, nil
}

// runScript executes an executable password file and captures stdout.
func (s *FileSecret) runScript() ([]byte, error) {
	args := []string{}
	if strings.HasSuffix(s.path, "-client") {
		args = append(args, "--vault-id", s.id)
	}

	// exec.Command resolves a bare name such as "vault-pass.sh" through $PATH,
	// but a password file is always a filesystem path. Anchoring it to the
	// current directory keeps the lookup on disk where it belongs.
	path := s.path
	if filepath.Base(path) == path {
		path = "." + string(filepath.Separator) + path
	}

	cmd := exec.Command(path, args...) // #nosec G204 -- executing the user's own password script is the point

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("gansivault: vault password script %s failed: %w: %s", s.path, err, msg)
		}

		return nil, fmt.Errorf("gansivault: vault password script %s failed: %w", s.path, err)
	}

	return stdout.Bytes(), nil
}

// isExecutable reports whether any execute bit is set.
func isExecutable(info os.FileInfo) bool {
	return info.Mode().Perm()&0o111 != 0
}

// PromptFunc asks the operator for a password. The prompt argument is the
// message to display.
type PromptFunc func(prompt string) ([]byte, error)

// PromptSecret asks for the password interactively, backing --ask-vault-pass
// and the "label@prompt" form of --vault-id.
type PromptSecret struct {
	id     string
	prompt string
	ask    PromptFunc

	once sync.Once
	pw   []byte
	err  error
}

// NewPromptSecret builds an interactive secret. Passing a nil PromptFunc makes
// Bytes fail rather than block, which keeps non-interactive callers safe.
func NewPromptSecret(id string, ask PromptFunc) *PromptSecret {
	nid := normalizeID(id)

	return &PromptSecret{
		id:     nid,
		prompt: fmt.Sprintf("Vault password (%s): ", nid),
		ask:    ask,
	}
}

// ID implements Secret.
func (s *PromptSecret) ID() string { return s.id }

// Bytes implements Secret. The operator is prompted at most once.
func (s *PromptSecret) Bytes() ([]byte, error) {
	s.once.Do(func() {
		if s.ask == nil {
			s.err = fmt.Errorf("gansivault: no prompt available for vault id %q", s.id)

			return
		}

		raw, err := s.ask(s.prompt)
		if err != nil {
			s.err = err

			return
		}

		pw := trimPassword(raw)
		if len(pw) == 0 {
			s.err = fmt.Errorf("%w: prompt for vault id %q", ErrEmptyPassword, s.id)

			return
		}

		s.pw = pw
	})

	return s.pw, s.err
}

// SplitVaultID splits an Ansible --vault-id argument into its label and
// source. It reproduces ansible.cli.CLI.split_vault_id: the split happens at
// the first "@", and an argument without "@" is all source with the default
// label.
//
//	"dev@~/.vault_pass"  -> ("dev", "~/.vault_pass")
//	"~/.vault_pass"      -> ("default", "~/.vault_pass")
//	"dev@prompt"         -> ("dev", "prompt")
func SplitVaultID(arg string) (id, source string) {
	label, src, found := strings.Cut(arg, "@")
	if !found {
		return DefaultVaultID, arg
	}

	return normalizeID(label), src
}

// Prompt sources recognised inside a --vault-id argument.
const (
	promptSource        = "prompt"
	promptAskPassSource = "prompt_ask_vault_pass"
)

// NewSecretFromVaultID turns a --vault-id argument into a Secret. Sources
// "prompt" and "prompt_ask_vault_pass" become interactive secrets; anything
// else is treated as a password file or script.
func NewSecretFromVaultID(arg string, ask PromptFunc) Secret {
	id, source := SplitVaultID(arg)

	if source == promptSource || source == promptAskPassSource {
		return NewPromptSecret(id, ask)
	}

	return NewFileSecret(id, source)
}
