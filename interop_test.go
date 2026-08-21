package gansivault_test

import (
	"bytes"
	"crypto/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomodian/gansivault"
)

// TestInteropWithRealAnsibleVault drives the actual ansible-vault binary in
// both directions. It is skipped when ansible-vault is not installed, so the
// committed fixtures remain the baseline guarantee and this is the live check
// that runs in the interop CI job.
func TestInteropWithRealAnsibleVault(t *testing.T) {
	t.Parallel()

	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		t.Skip("ansible-vault is not installed; skipping live interop test")
	}

	dir := t.TempDir()

	const password = "interop-p@ssw0rd"

	passFile := filepath.Join(dir, "vault.pass")
	if err := os.WriteFile(passFile, []byte(password+"\n"), 0o600); err != nil {
		t.Fatalf("writing the password file: %v", err)
	}

	binaryBlob := make([]byte, 4096)
	if _, err := rand.Read(binaryBlob); err != nil {
		t.Fatalf("generating a random payload: %v", err)
	}

	payloads := map[string][]byte{
		"empty":         {},
		"short":         []byte("a"),
		"block_aligned": []byte("exactly-sixteen!"),
		"multiline":     []byte("one\ntwo\nthree\n"),
		"unicode":       []byte("ελληνικά 日本語 🔐\n"),
		"binary":        binaryBlob,
		"large":         bytes.Repeat([]byte("payload "), 20000),
	}

	for name, plaintext := range payloads {
		t.Run("go_encrypts_ansible_decrypts/"+name, func(t *testing.T) {
			t.Parallel()

			sealed, err := gansivault.Encrypt(plaintext, []byte(password))
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}

			path := filepath.Join(t.TempDir(), "sealed.vault")
			if err := os.WriteFile(path, append(sealed, '\n'), 0o600); err != nil {
				t.Fatalf("writing the vault file: %v", err)
			}

			got := runAnsible(t, bin, "decrypt", "--vault-password-file", passFile, "--output", "-", path)

			if !bytes.Equal(got, plaintext) {
				t.Fatalf("ansible-vault decrypted %d bytes, want %d", len(got), len(plaintext))
			}
		})

		t.Run("ansible_encrypts_go_decrypts/"+name, func(t *testing.T) {
			t.Parallel()

			sub := t.TempDir()

			plain := filepath.Join(sub, "plain")
			if err := os.WriteFile(plain, plaintext, 0o600); err != nil {
				t.Fatalf("writing the plaintext: %v", err)
			}

			sealed := filepath.Join(sub, "sealed.vault")
			runAnsible(t, bin, "encrypt", "--vault-password-file", passFile, "--output", sealed, plain)

			got, err := gansivault.DecryptFile(sealed, []byte(password))
			if err != nil {
				t.Fatalf("DecryptFile: %v", err)
			}

			if !bytes.Equal(got, plaintext) {
				t.Fatalf("gansivault decrypted %d bytes, want %d", len(got), len(plaintext))
			}
		})
	}

	t.Run("vault_id_1.2_round_trip", func(t *testing.T) {
		t.Parallel()

		sealed, err := gansivault.EncryptWithVaultID([]byte("labelled\n"), []byte(password), "prod")
		if err != nil {
			t.Fatalf("EncryptWithVaultID: %v", err)
		}

		if !strings.HasPrefix(string(sealed), "$ANSIBLE_VAULT;1.2;AES256;prod\n") {
			t.Fatalf("unexpected header: %q", strings.SplitN(string(sealed), "\n", 2)[0])
		}

		path := filepath.Join(t.TempDir(), "prod.vault")
		if err := os.WriteFile(path, append(sealed, '\n'), 0o600); err != nil {
			t.Fatalf("writing the vault file: %v", err)
		}

		got := runAnsible(t, bin, "decrypt", "--vault-id", "prod@"+passFile, "--output", "-", path)

		if string(got) != "labelled\n" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("go_encrypt_string_is_valid_yaml_for_ansible", func(t *testing.T) {
		t.Parallel()

		sealed, err := gansivault.Encrypt([]byte("hunter2"), []byte(password))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		block := gansivault.FormatYAML(sealed, "mypass", gansivault.DefaultYAMLIndent)

		sub := t.TempDir()

		vars := filepath.Join(sub, "vars.yml")
		if err := os.WriteFile(vars, []byte(block+"\n"), 0o600); err != nil {
			t.Fatalf("writing vars.yml: %v", err)
		}

		// ansible-vault itself cannot read a !vault block, but ansible can, so
		// only run this leg when a playbook runner is available.
		playbookBin, err := exec.LookPath("ansible-playbook")
		if err != nil {
			t.Skip("ansible-playbook is not installed")
		}

		playbook := filepath.Join(sub, "play.yml")

		const play = `- hosts: localhost
  gather_facts: no
  vars_files: [vars.yml]
  tasks:
    - debug: msg="secret={{ mypass }}"
`

		if err := os.WriteFile(playbook, []byte(play), 0o600); err != nil {
			t.Fatalf("writing the playbook: %v", err)
		}

		cmd := exec.CommandContext(t.Context(), playbookBin, "-i", "localhost,", "--vault-password-file", passFile, playbook)
		cmd.Dir = sub

		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("ansible-playbook: %v\n%s", err, out)
		}

		if !bytes.Contains(out, []byte("secret=hunter2")) {
			t.Fatalf("the playbook did not resolve the vaulted variable:\n%s", out)
		}
	})
}

// runAnsible executes ansible-vault and returns its standard output.
func runAnsible(t *testing.T, bin string, args ...string) []byte {
	t.Helper()

	cmd := exec.CommandContext(t.Context(), bin, args...)

	var stdout, stderr bytes.Buffer

	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		t.Fatalf("ansible-vault %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}

	return stdout.Bytes()
}
