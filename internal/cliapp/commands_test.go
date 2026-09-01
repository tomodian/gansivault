package cliapp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomodian/gansivault"
)

func TestEncryptDecryptRoundTripInPlace(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.file("secrets.yml", "db_password: hunter2\n", 0o640)

	h.mustRun("encrypt", "--vault-password-file", pw, target)

	if !strings.Contains(h.errOut(), "Encryption successful") {
		t.Fatalf("stderr: %q", h.errOut())
	}

	sealed := h.read(target)
	if !gansivault.IsEncryptedString(sealed) {
		t.Fatalf("file was not encrypted: %q", sealed)
	}

	if !strings.HasSuffix(sealed, "\n") {
		t.Fatal("vault file should end with a newline")
	}

	info, err := os.Stat(target)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if info.Mode().Perm() != 0o640 {
		t.Fatalf("permissions changed to %v", info.Mode().Perm())
	}

	h.mustRun("decrypt", "--vault-password-file", pw, target)

	if got := h.read(target); got != "db_password: hunter2\n" {
		t.Fatalf("got %q", got)
	}

	if !strings.Contains(h.errOut(), "Decryption successful") {
		t.Fatalf("stderr: %q", h.errOut())
	}
}

func TestEncryptMultipleFiles(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	a := h.file("a.txt", "alpha\n", 0o600)
	b := h.file("b.txt", "beta\n", 0o600)

	h.mustRun("encrypt", "--vault-password-file", pw, a, b)

	for _, path := range []string{a, b} {
		if !gansivault.IsEncryptedString(h.read(path)) {
			t.Fatalf("%s was not encrypted", path)
		}
	}

	h.mustRun("decrypt", "--vault-password-file", pw, a, b)

	if h.read(a) != "alpha\n" || h.read(b) != "beta\n" {
		t.Fatalf("got %q and %q", h.read(a), h.read(b))
	}
}

func TestEncryptStdinToStdout(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	h.stdin("piped secret")
	h.mustRun("encrypt", "--vault-password-file", pw)

	sealed := h.out()
	if !gansivault.IsEncryptedString(sealed) {
		t.Fatalf("got %q", sealed)
	}

	h.stdin(sealed)
	h.mustRun("decrypt", "--vault-password-file", pw, "-")

	if h.out() != "piped secret" {
		t.Fatalf("got %q", h.out())
	}
}

func TestEncryptToOutputFile(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	src := h.file("plain.txt", "keep me\n", 0o600)
	dst := filepath.Join(h.dir, "sealed.vault")

	h.mustRun("encrypt", "--vault-password-file", pw, "--output", dst, src)

	if h.read(src) != "keep me\n" {
		t.Fatal("--output must not modify the input")
	}

	if !gansivault.IsEncryptedString(h.read(dst)) {
		t.Fatalf("output was not encrypted: %q", h.read(dst))
	}

	h.mustRun("decrypt", "--vault-password-file", pw, "-o", "-", dst)

	if h.out() != "keep me\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestOutputRejectsMultipleInputs(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	a := h.file("a.txt", "a", 0o600)
	b := h.file("b.txt", "b", 0o600)

	for _, cmd := range []string{"encrypt", "decrypt"} {
		err := h.run(cmd, "--vault-password-file", pw, "--output", filepath.Join(h.dir, "out"), a, b)
		if !errors.Is(err, errOutputSingleFile) {
			t.Fatalf("%s: got %v, want errOutputSingleFile", cmd, err)
		}
	}
}

func TestEncryptRefusesAlreadyEncryptedInput(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.copyFixture("hello_11.vault")

	err := h.run("encrypt", "--vault-password-file", pw, target)
	if !errors.Is(err, gansivault.ErrAlreadyEncrypted) {
		t.Fatalf("got %v, want ErrAlreadyEncrypted", err)
	}

	h.stdin("$ANSIBLE_VAULT;1.1;AES256\n6161")

	err = h.run("encrypt", "--vault-password-file", pw)
	if err == nil || !strings.Contains(err.Error(), "<stdin>") {
		t.Fatalf("got %v, want an error naming <stdin>", err)
	}
}

func TestDecryptAnsibleFixtures(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	h.mustRun("decrypt", "--vault-password-file", pw, "-o", "-", h.copyFixture("hello_11.vault"))

	if h.out() != helloPlaintext {
		t.Fatalf("got %q", h.out())
	}

	h.mustRun("decrypt", "--vault-password-file", pw, "-o", "-", h.copyFixture("hello_12.vault"))

	if h.out() != helloPlaintext {
		t.Fatalf("1.2 fixture: got %q", h.out())
	}
}

func TestViewCommand(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	a := h.copyFixture("hello_11.vault")
	b := h.copyFixture("hello_12.vault")

	h.mustRun("view", "--vault-password-file", pw, a, b)

	if h.out() != helloPlaintext+helloPlaintext {
		t.Fatalf("got %q", h.out())
	}

	if h.read(a) == helloPlaintext {
		t.Fatal("view must not modify the file")
	}
}

func TestViewFromStdin(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	h.stdin(h.read(h.copyFixture("hello_11.vault")))
	h.mustRun("view", "--vault-password-file", pw)

	if h.out() != helloPlaintext {
		t.Fatalf("got %q", h.out())
	}
}

func TestViewErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	t.Run("missing file", func(t *testing.T) {
		if err := h.run("view", "--vault-password-file", pw, filepath.Join(h.dir, "absent")); err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		other := h.passFile("other", "not-it")

		err := h.run("view", "--vault-password-file", other, h.copyFixture("hello_11.vault"))
		if !errors.Is(err, gansivault.ErrDecryptionFailed) {
			t.Fatalf("got %v, want ErrDecryptionFailed", err)
		}
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("view", h.copyFixture("hello_11.vault")); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("stdout write failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Stdout = failWriter{}

		if err := h.run("view", "--vault-password-file", pw, h.copyFixture("hello_11.vault")); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})
}

func TestDecryptErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	t.Run("missing input", func(t *testing.T) {
		if err := h.run("decrypt", "--vault-password-file", pw, filepath.Join(h.dir, "absent")); err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("plain input", func(t *testing.T) {
		plain := h.file("plain.txt", "not a vault", 0o600)

		if err := h.run("decrypt", "--vault-password-file", pw, plain); !errors.Is(err, gansivault.ErrNotVault) {
			t.Fatalf("got %v, want ErrNotVault", err)
		}
	})

	t.Run("unwritable output", func(t *testing.T) {
		err := h.run("decrypt", "--vault-password-file", pw,
			"-o", filepath.Join(h.dir, "no-such-dir", "out"), h.copyFixture("hello_11.vault"))
		if err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("decrypt", h.copyFixture("hello_11.vault")); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})
}

func TestEncryptErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	t.Run("missing input", func(t *testing.T) {
		if err := h.run("encrypt", "--vault-password-file", pw, filepath.Join(h.dir, "absent")); err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("unwritable output", func(t *testing.T) {
		src := h.file("src.txt", "x", 0o600)

		err := h.run("encrypt", "--vault-password-file", pw, "-o", filepath.Join(h.dir, "nope", "out"), src)
		if err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("encrypt", h.file("x.txt", "x", 0o600)); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("empty password file", func(t *testing.T) {
		empty := h.passFile("empty", "  \n")

		if err := h.run("encrypt", "--vault-password-file", empty, h.file("y.txt", "y", 0o600)); !errors.Is(err, gansivault.ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})

	t.Run("stdin read failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Stdin = failReader{}

		if err := h.run("encrypt", "--vault-password-file", pw); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})

	t.Run("stdout write failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Stdout = failWriter{}
		h.stdin("plain")

		if err := h.run("encrypt", "--vault-password-file", pw); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})
}

func TestVaultIDFlags(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.file("prod.yml", "prod: data\n", 0o600)

	h.mustRun("encrypt", "--vault-id", "prod@"+pw, target)

	if !strings.HasPrefix(h.read(target), "$ANSIBLE_VAULT;1.2;AES256;prod\n") {
		t.Fatalf("got header %q", strings.SplitN(h.read(target), "\n", 2)[0])
	}

	h.mustRun("view", "--vault-id", "prod@"+pw, target)

	if h.out() != "prod: data\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestVaultIDPromptSource(t *testing.T) {
	h := newHarness(t)
	target := h.file("p.yml", "prompted\n", 0o600)

	h.mustRun("encrypt", "--vault-id", "dev@prompt", target)
	h.mustRun("view", "--vault-id", "dev@prompt", target)

	if h.out() != "prompted\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestAskVaultPassFlag(t *testing.T) {
	h := newHarness(t)
	target := h.file("a.yml", "asked\n", 0o600)

	h.mustRun("encrypt", "-J", target)
	h.mustRun("view", "--ask-vault-pass", target)

	if h.out() != "asked\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestEncryptVaultIDSelection(t *testing.T) {
	h := newHarness(t)
	prod := h.passFile("prod.pass", "prod-pw")
	dev := h.passFile("dev.pass", "dev-pw")
	target := h.file("multi.yml", "multi\n", 0o600)

	t.Run("ambiguous without --encrypt-vault-id", func(t *testing.T) {
		err := h.run("encrypt", "--vault-id", "prod@"+prod, "--vault-id", "dev@"+dev, target)
		if err == nil || !strings.Contains(err.Error(), "--encrypt-vault-id") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("explicit selection", func(t *testing.T) {
		h.mustRun("encrypt", "--vault-id", "prod@"+prod, "--vault-id", "dev@"+dev,
			"--encrypt-vault-id", "dev", target)

		if !strings.HasPrefix(h.read(target), "$ANSIBLE_VAULT;1.2;AES256;dev\n") {
			t.Fatalf("got %q", strings.SplitN(h.read(target), "\n", 2)[0])
		}

		// Either identity opens it, because decryption falls back.
		h.mustRun("view", "--vault-id", "prod@"+prod, "--vault-id", "dev@"+dev, target)

		if h.out() != "multi\n" {
			t.Fatalf("got %q", h.out())
		}
	})

	t.Run("unknown selection", func(t *testing.T) {
		err := h.run("encrypt", "--vault-id", "prod@"+prod, "--encrypt-vault-id", "staging",
			h.file("z.yml", "z\n", 0o600))
		if err == nil || !strings.Contains(err.Error(), "staging") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("repeated identity is not ambiguous", func(t *testing.T) {
		// Two sources under the same vault id must not trigger the ambiguity
		// check, only two distinct ids do.
		target := h.file("same.yml", "same\n", 0o600)
		h.mustRun("encrypt", "--vault-password-file", prod, "--vault-password-file", dev, target)

		h.mustRun("view", "--vault-password-file", prod, target)

		if h.out() != "same\n" {
			t.Fatalf("got %q", h.out())
		}
	})
}

func TestRekeyCommand(t *testing.T) {
	h := newHarness(t)
	oldPW := h.passFile("old.pass", testPassword)
	newPW := h.passFile("new.pass", "rotated")

	a := h.copyFixture("hello_11.vault")
	b := h.copyFixture("hello_12.vault")

	h.mustRun("rekey", "--vault-password-file", oldPW, "--new-vault-password-file", newPW, a, b)

	if !strings.Contains(h.errOut(), "Rekey successful") {
		t.Fatalf("stderr: %q", h.errOut())
	}

	h.mustRun("view", "--vault-password-file", newPW, a, b)

	if h.out() != helloPlaintext+helloPlaintext {
		t.Fatalf("got %q", h.out())
	}
}

func TestRekeyWithNewVaultID(t *testing.T) {
	h := newHarness(t)
	oldPW := h.passFile("old.pass", testPassword)
	newPW := h.passFile("new.pass", "rotated")
	target := h.copyFixture("hello_11.vault")

	h.mustRun("rekey", "--vault-password-file", oldPW, "--new-vault-id", "prod@"+newPW, target)

	if !strings.HasPrefix(h.read(target), "$ANSIBLE_VAULT;1.2;AES256;prod\n") {
		t.Fatalf("got %q", strings.SplitN(h.read(target), "\n", 2)[0])
	}
}

func TestRekeyPromptsForTheNewPassword(t *testing.T) {
	h := newHarness(t)
	oldPW := h.passFile("old.pass", testPassword)
	target := h.copyFixture("hello_11.vault")

	// The harness prompt answers with the fixture password, so the file is
	// simply re-encrypted under the same secret.
	h.mustRun("rekey", "--vault-password-file", oldPW, target)
	h.mustRun("view", "--vault-password-file", oldPW, target)

	if h.out() != helloPlaintext {
		t.Fatalf("got %q", h.out())
	}
}

func TestRekeyErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	newPW := h.passFile("new.pass", "rotated")

	t.Run("no files", func(t *testing.T) {
		err := h.run("rekey", "--vault-password-file", pw, "--new-vault-password-file", newPW)
		if err == nil || !strings.Contains(err.Error(), "at least one FILE") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("rekey", h.copyFixture("hello_11.vault")); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		err := h.run("rekey", "--vault-password-file", pw, "--new-vault-password-file", newPW,
			filepath.Join(h.dir, "absent"))
		if err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("plain file", func(t *testing.T) {
		plain := h.file("plain.txt", "nope", 0o600)

		err := h.run("rekey", "--vault-password-file", pw, "--new-vault-password-file", newPW, plain)
		if !errors.Is(err, gansivault.ErrNotVault) {
			t.Fatalf("got %v, want ErrNotVault", err)
		}
	})

	t.Run("unwritable target", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can write anything")
		}

		target := h.copyFixture("hello_11.vault")

		if err := os.Chmod(target, 0o400); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		err := h.run("rekey", "--vault-password-file", pw, "--new-vault-password-file", newPW, target)
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v, want os.ErrPermission", err)
		}
	})

	t.Run("bad new password file", func(t *testing.T) {
		err := h.run("rekey", "--vault-password-file", pw,
			"--new-vault-password-file", filepath.Join(h.dir, "absent-pass"), h.copyFixture("hello_11.vault"))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want os.ErrNotExist", err)
		}
	})
}

// pemKey stands in for the multi-line, dash-leading values encrypt_string is
// most often pointed at.
const pemKey = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA==\n-----END PRIVATE KEY-----\n"

func TestEncryptStringCommand(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	t.Run("named values", func(t *testing.T) {
		h.mustRun("encrypt_string", "--vault-password-file", pw, "-n", "first", "-n", "second", "alpha", "beta")

		out := h.out()
		if !strings.HasPrefix(out, "first: !vault |\n") || !strings.Contains(out, "\nsecond: !vault |\n") {
			t.Fatalf("got:\n%s", out)
		}

		for name, want := range map[string]string{"first": "alpha", "second": "beta"} {
			block := blockFor(t, out, name)

			got, err := gansivault.Decrypt([]byte(gansivault.ExtractVaultText(block)), []byte(testPassword))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}

			if string(got) != want {
				t.Fatalf("%s: got %q, want %q", name, got, want)
			}
		}
	})

	t.Run("unnamed value", func(t *testing.T) {
		h.mustRun("encrypt_string", "--vault-password-file", pw, "solo")

		if !strings.HasPrefix(h.out(), "!vault |\n") {
			t.Fatalf("got:\n%s", h.out())
		}
	})

	t.Run("from stdin with a name", func(t *testing.T) {
		h.stdin("piped")
		h.mustRun("encrypt_string", "--vault-password-file", pw, "--stdin-name", "piped_var")

		if !strings.HasPrefix(h.out(), "piped_var: !vault |\n") {
			t.Fatalf("got:\n%s", h.out())
		}

		got, err := gansivault.Decrypt([]byte(gansivault.ExtractVaultText(h.out())), []byte(testPassword))
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if string(got) != "piped" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("from stdin without a name", func(t *testing.T) {
		h.stdin("anon")
		h.mustRun("encrypt_string", "--vault-password-file", pw)

		if !strings.HasPrefix(h.out(), "!vault |\n") {
			t.Fatalf("got:\n%s", h.out())
		}
	})

	t.Run("custom indent", func(t *testing.T) {
		h.mustRun("encrypt_string", "--vault-password-file", pw, "--indent", "4", "-n", "v", "x")

		if !strings.Contains(h.out(), "\n    $ANSIBLE_VAULT") {
			t.Fatalf("got:\n%s", h.out())
		}
	})

	t.Run("to a file", func(t *testing.T) {
		dst := filepath.Join(h.dir, "vars.yml")
		h.mustRun("encrypt_string", "--vault-password-file", pw, "-o", dst, "-n", "v", "x")

		if !strings.HasPrefix(h.read(dst), "v: !vault |\n") {
			t.Fatalf("got:\n%s", h.read(dst))
		}
	})

	// A PEM key is the argument encrypt_string is most often handed, and the
	// shell strips the user's quotes long before argv arrives, so it has to
	// work bare as well as after a separator.
	t.Run("a PEM key as a positional argument", func(t *testing.T) {
		for _, args := range [][]string{
			{"-n", "tls_key", pemKey},
			{"-n", "tls_key", "--", pemKey},
			{pemKey, "-n", "tls_key"},
		} {
			h.mustRun(append([]string{"encrypt_string", "--vault-password-file", pw}, args...)...)

			if !strings.HasPrefix(h.out(), "tls_key: !vault |\n") {
				t.Fatalf("%v: got:\n%s", args, h.out())
			}

			got, err := gansivault.Decrypt([]byte(gansivault.ExtractVaultText(h.out())), []byte(testPassword))
			if err != nil {
				t.Fatalf("%v: Decrypt: %v", args, err)
			}

			if string(got) != pemKey {
				t.Fatalf("%v: got %q, want %q", args, got, pemKey)
			}
		}
	})

	// The flag parser would claim the dash-leading ones and trim the padded
	// ones; a secret has to survive both untouched.
	t.Run("values the parser would otherwise mangle", func(t *testing.T) {
		for _, value := range []string{
			"----BEGIN",
			"-----BEGIN CERTIFICATE-----",
			"--", // only reachable after an explicit separator
			"-5",
			"- leading dash and a space",
			"  padded  ",
			"trailing newline\n",
			"\n",
			"",
		} {
			args := []string{"encrypt_string", "--vault-password-file", pw, "-n", "v"}
			if value == doubleDash {
				args = append(args, doubleDash)
			}

			h.mustRun(append(args, value)...)

			got, err := gansivault.Decrypt([]byte(gansivault.ExtractVaultText(h.out())), []byte(testPassword))
			if err != nil {
				t.Fatalf("%q: Decrypt: %v", value, err)
			}

			if string(got) != value {
				t.Fatalf("got %q, want %q", got, value)
			}
		}
	})

	t.Run("a PEM key on stdin", func(t *testing.T) {
		h.stdin(pemKey)
		h.mustRun("encrypt_string", "--vault-password-file", pw, "--stdin-name", "tls_key")

		got, err := gansivault.Decrypt([]byte(gansivault.ExtractVaultText(h.out())), []byte(testPassword))
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if string(got) != pemKey {
			t.Fatalf("got %q, want %q", got, pemKey)
		}
	})

	t.Run("matches the ansible fixture layout", func(t *testing.T) {
		h.stdin("hunter2")
		h.mustRun("encrypt_string", "--vault-password-file", pw, "--stdin-name", "mypass")

		fixture, err := os.ReadFile(filepath.Join(fixturesDir(t), "encrypt_string.yml"))
		if err != nil {
			t.Fatalf("reading fixture: %v", err)
		}

		gotLines := strings.Split(strings.TrimRight(h.out(), "\n"), "\n")
		wantLines := strings.Split(strings.TrimRight(string(fixture), "\n"), "\n")

		if len(gotLines) != len(wantLines) || gotLines[0] != wantLines[0] {
			t.Fatalf("layout differs:\ngot:\n%s\nwant:\n%s", h.out(), fixture)
		}

		for i := range gotLines {
			if gotIndent, wantIndent := indentOf(gotLines[i]), indentOf(wantLines[i]); gotIndent != wantIndent {
				t.Fatalf("line %d indent %d, want %d", i, gotIndent, wantIndent)
			}
		}
	})
}

func TestEncryptStringErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("encrypt_string", "x"); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("stdin failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Stdin = failReader{}

		if err := h.run("encrypt_string", "--vault-password-file", pw); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})

	t.Run("unwritable output", func(t *testing.T) {
		err := h.run("encrypt_string", "--vault-password-file", pw, "-o",
			filepath.Join(h.dir, "nope", "out"), "x")
		if err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("empty password", func(t *testing.T) {
		empty := h.passFile("empty.pass", " \n")

		if err := h.run("encrypt_string", "--vault-password-file", empty, "x"); !errors.Is(err, gansivault.ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})

	// A token shaped exactly like a flag name cannot be told apart from a
	// misspelled flag, so it is still rejected rather than encrypted.
	t.Run("a flag-shaped value", func(t *testing.T) {
		for _, arg := range []string{"-hunter2", "--hunter2", "--naem"} {
			if err := h.run("encrypt_string", "--vault-password-file", pw, arg); !errors.Is(err, errDashValue) {
				t.Fatalf("%s: got %v, want errDashValue", arg, err)
			}

			// The argument may be the secret, so it must not be echoed back,
			// and the flag list must not be dumped over it either.
			if out := h.errOut() + h.out(); strings.Contains(out, "hunter2") || strings.Contains(out, "OPTIONS:") {
				t.Fatalf("%s: leaked the value or dumped help:\n%s", arg, out)
			}
		}
	})

	t.Run("other usage errors keep the default report", func(t *testing.T) {
		if err := h.run("encrypt_string", "--vault-password-file", pw, "--indent", "wide", "x"); err == nil {
			t.Fatal("want an error")
		}

		// urfave/cli reports the failure on stderr and the help on stdout.
		if !strings.Contains(h.errOut(), "Incorrect Usage:") || !strings.Contains(h.out(), "OPTIONS:") {
			t.Fatalf("stderr:\n%s\nstdout:\n%s", h.errOut(), h.out())
		}
	})
}

func TestCreateCommand(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := filepath.Join(h.dir, "new.yml")

	h.app.Editor = func(path string) error {
		return os.WriteFile(path, []byte("created: true\n"), 0o600)
	}

	h.mustRun("create", "--vault-password-file", pw, target)

	if !gansivault.IsEncryptedString(h.read(target)) {
		t.Fatalf("got %q", h.read(target))
	}

	h.mustRun("view", "--vault-password-file", pw, target)

	if h.out() != "created: true\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestCreateErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	h.app.Editor = func(string) error { return nil }

	t.Run("wrong argument count", func(t *testing.T) {
		for _, args := range [][]string{{}, {"a", "b"}} {
			err := h.run(append([]string{"create", "--vault-password-file", pw}, args...)...)
			if err == nil || !strings.Contains(err.Error(), "exactly one FILE") {
				t.Fatalf("args %v: got %v", args, err)
			}
		}
	})

	t.Run("existing non-empty file", func(t *testing.T) {
		existing := h.file("exists.yml", "content", 0o600)

		err := h.run("create", "--vault-password-file", pw, existing)
		if err == nil || !strings.Contains(err.Error(), "already exists") {
			t.Fatalf("got %v", err)
		}
	})

	t.Run("existing empty file is allowed", func(t *testing.T) {
		empty := h.file("blank.yml", "", 0o600)
		h.mustRun("create", "--vault-password-file", pw, empty)
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("create", filepath.Join(h.dir, "n.yml")); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("editor failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = func(string) error { return errBoom }

		err := h.run("create", "--vault-password-file", pw, filepath.Join(h.dir, "n.yml"))
		if !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})

	t.Run("password only fails once it is needed", func(t *testing.T) {
		h := newHarness(t)
		empty := h.passFile("empty.pass", "  \n")
		h.app.Editor = func(path string) error { return os.WriteFile(path, []byte("x\n"), 0o600) }

		err := h.run("create", "--vault-password-file", empty, filepath.Join(h.dir, "late.yml"))
		if !errors.Is(err, gansivault.ErrEmptyPassword) {
			t.Fatalf("got %v, want ErrEmptyPassword", err)
		}
	})

	t.Run("temp file cannot be written", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = func(string) error { return nil }

		original := createTemp

		// Hand back a handle that is already closed, so writing the seed
		// fails the way a full or disconnected filesystem would.
		createTemp = func(dir, pattern string) (*os.File, error) {
			f, err := os.CreateTemp(dir, pattern)
			if err != nil {
				return nil, err
			}

			_ = f.Close()

			return f, nil
		}

		t.Cleanup(func() { createTemp = original })

		if err := h.run("create", "--vault-password-file", pw, filepath.Join(h.dir, "n.yml")); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("got %v, want os.ErrClosed", err)
		}
	})

	t.Run("editor deletes the temp file", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = os.Remove

		err := h.run("create", "--vault-password-file", pw, filepath.Join(h.dir, "gone.yml"))
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want os.ErrNotExist", err)
		}
	})

	t.Run("temp file cannot be created", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = func(string) error { return nil }

		err := h.run("create", "--vault-password-file", pw, filepath.Join(h.dir, "no-such-dir", "n.yml"))
		if err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("unwritable target", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can write anything")
		}

		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = func(string) error { return nil }

		dir := filepath.Join(h.dir, "ro")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir: %v", err)
		}

		target := filepath.Join(dir, "n.yml")

		if err := os.WriteFile(target, nil, 0o400); err != nil {
			t.Fatalf("write: %v", err)
		}

		if err := h.run("create", "--vault-password-file", pw, target); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v, want os.ErrPermission", err)
		}
	})
}

func TestEditCommand(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.copyFixture("hello_11.vault")

	var seen string

	h.app.Editor = func(path string) error {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}

		seen = string(data)

		return os.WriteFile(path, []byte("edited\n"), 0o600)
	}

	h.mustRun("edit", "--vault-password-file", pw, target)

	if seen != helloPlaintext {
		t.Fatalf("editor saw %q, want %q", seen, helloPlaintext)
	}

	h.mustRun("view", "--vault-password-file", pw, target)

	if h.out() != "edited\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestEditPreservesTheVaultID(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.copyFixture("hello_12.vault")

	h.app.Editor = func(path string) error { return os.WriteFile(path, []byte("still 1.2\n"), 0o600) }

	h.mustRun("edit", "--vault-id", "myid@"+pw, target)

	if !strings.HasPrefix(h.read(target), "$ANSIBLE_VAULT;1.2;AES256;myid\n") {
		t.Fatalf("got %q", strings.SplitN(h.read(target), "\n", 2)[0])
	}
}

func TestEditKeepsTheLabelWhenTheSecretIsUnlabelled(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.copyFixture("hello_12.vault")

	h.app.Editor = func(path string) error { return os.WriteFile(path, []byte("kept\n"), 0o600) }

	// The secret comes from --vault-password-file, so it is registered under
	// "default". The file's own "myid" label must survive the round trip
	// rather than being downgraded to a 1.1 header.
	h.mustRun("edit", "--vault-password-file", pw, target)

	if !strings.HasPrefix(h.read(target), "$ANSIBLE_VAULT;1.2;AES256;myid\n") {
		t.Fatalf("got %q", strings.SplitN(h.read(target), "\n", 2)[0])
	}

	h.mustRun("view", "--vault-password-file", pw, target)

	if h.out() != "kept\n" {
		t.Fatalf("got %q", h.out())
	}
}

func TestEditCanChangeTheVaultID(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)
	target := h.copyFixture("hello_11.vault")

	h.app.Editor = func(path string) error { return os.WriteFile(path, []byte("relabelled\n"), 0o600) }

	h.mustRun("edit", "--vault-id", "prod@"+pw, "--encrypt-vault-id", "prod", target)

	if !strings.HasPrefix(h.read(target), "$ANSIBLE_VAULT;1.2;AES256;prod\n") {
		t.Fatalf("got %q", strings.SplitN(h.read(target), "\n", 2)[0])
	}
}

func TestEditErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	h.app.Editor = func(path string) error { return os.WriteFile(path, []byte("x\n"), 0o600) }

	t.Run("wrong argument count", func(t *testing.T) {
		if err := h.run("edit", "--vault-password-file", pw); err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("edit", h.copyFixture("hello_11.vault")); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("missing file", func(t *testing.T) {
		if err := h.run("edit", "--vault-password-file", pw, filepath.Join(h.dir, "absent")); err == nil {
			t.Fatal("want an error")
		}
	})

	t.Run("plain file", func(t *testing.T) {
		plain := h.file("plain.txt", "nope", 0o600)

		if err := h.run("edit", "--vault-password-file", pw, plain); !errors.Is(err, gansivault.ErrNotVault) {
			t.Fatalf("got %v, want ErrNotVault", err)
		}
	})

	t.Run("editor failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = func(string) error { return errBoom }

		if err := h.run("edit", "--vault-password-file", pw, h.copyFixture("hello_11.vault")); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		other := h.passFile("other.pass", "not-it")

		err := h.run("edit", "--vault-password-file", other, h.copyFixture("hello_11.vault"))
		if !errors.Is(err, gansivault.ErrDecryptionFailed) {
			t.Fatalf("got %v, want ErrDecryptionFailed", err)
		}
	})

	t.Run("re-encryption identity cannot be loaded", func(t *testing.T) {
		// Decryption succeeds through the good secret, then
		// --encrypt-vault-id points at an identity whose password file is
		// missing, so the failure lands on the re-encryption.
		target := h.copyFixture("hello_11.vault")

		err := h.run("edit",
			"--vault-password-file", pw,
			"--vault-id", "broken@"+filepath.Join(h.dir, "absent.pass"),
			"--encrypt-vault-id", "broken",
			target)
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want os.ErrNotExist", err)
		}
	})

	t.Run("unknown encrypt vault id", func(t *testing.T) {
		target := h.copyFixture("hello_11.vault")

		err := h.run("edit", "--vault-password-file", pw, "--encrypt-vault-id", "nobody", target)
		if err == nil || !strings.Contains(err.Error(), "nobody") {
			t.Fatalf("got %v, want an error naming the unknown identity", err)
		}
	})

	t.Run("unwritable target", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root can write anything")
		}

		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Editor = func(path string) error { return os.WriteFile(path, []byte("x\n"), 0o600) }

		target := h.copyFixture("hello_11.vault")

		if err := os.Chmod(target, 0o400); err != nil {
			t.Fatalf("chmod: %v", err)
		}

		if err := h.run("edit", "--vault-password-file", pw, target); !errors.Is(err, os.ErrPermission) {
			t.Fatalf("got %v, want os.ErrPermission", err)
		}
	})
}

func TestDescribe(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{"": "<stdin>", "-": "<stdin>", "a.yml": "a.yml"} {
		if got := describe(in); got != want {
			t.Fatalf("describe(%q) = %q, want %q", in, got, want)
		}
	}
}

// blockFor returns the YAML block for a given variable name.
func blockFor(t *testing.T, out, name string) string {
	t.Helper()

	idx := strings.Index(out, name+": !vault |")
	if idx < 0 {
		t.Fatalf("no block for %q in:\n%s", name, out)
	}

	rest := out[idx:]

	var block []string

	for i, line := range strings.Split(rest, "\n") {
		if i > 0 && line != "" && !strings.HasPrefix(line, " ") {
			break
		}

		block = append(block, line)
	}

	return strings.Join(block, "\n")
}

// indentOf counts the leading spaces on a line.
func indentOf(line string) int {
	return len(line) - len(strings.TrimLeft(line, " "))
}

// yamlDoc is a small document with vault blocks at two depths, the shape that
// makes "view" fail and "yaml" the right tool.
func yamlDoc(t *testing.T) string {
	t.Helper()

	block := func(value, name string, indent int) string {
		sealed, err := gansivault.Encrypt([]byte(value), []byte(testPassword))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		return gansivault.FormatYAML(sealed, name, indent)
	}

	return "hello: world\n\n" +
		block("top", "secret", 2) + "\n\n" +
		"nested:\n  value:\n    foo: foo\n\n    " + block("buried", "bar", 6) + "\n"
}

func TestYAMLCommand(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	want := "hello: world\n\nsecret: top\n\nnested:\n  value:\n    foo: foo\n\n    bar: buried\n"

	t.Run("to stdout", func(t *testing.T) {
		src := h.file("doc.yml", yamlDoc(t), 0o600)
		before := h.read(src)

		h.mustRun("yaml", "--vault-password-file", pw, src)

		if h.out() != want {
			t.Fatalf("got:\n%s\nwant:\n%s", h.out(), want)
		}

		if h.read(src) != before {
			t.Fatal("yaml must not modify the input file")
		}
	})

	t.Run("to a file", func(t *testing.T) {
		src := h.file("doc.yml", yamlDoc(t), 0o600)
		dst := filepath.Join(h.dir, "out.yml")

		h.mustRun("yaml", "--vault-password-file", pw, "-o", dst, src)

		if got := h.read(dst); got != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}

		if h.out() != "" {
			t.Fatalf("nothing should reach stdout, got %q", h.out())
		}
	})

	t.Run("from stdin", func(t *testing.T) {
		h.stdin(yamlDoc(t))
		h.mustRun("yaml", "--vault-password-file", pw)

		if h.out() != want {
			t.Fatalf("got:\n%s", h.out())
		}
	})

	t.Run("several files", func(t *testing.T) {
		a := h.file("a.yml", yamlDoc(t), 0o600)
		b := h.file("b.yml", yamlDoc(t), 0o600)

		h.mustRun("yaml", "--vault-password-file", pw, a, b)

		if h.out() != want+want {
			t.Fatalf("got:\n%s", h.out())
		}
	})

	t.Run("a document without vault blocks is passed through", func(t *testing.T) {
		doc := "# comment\nkey: value\nlist:\n  - one\n"
		src := h.file("plain.yml", doc, 0o600)

		h.mustRun("yaml", "--vault-password-file", pw, src)

		if h.out() != doc {
			t.Fatalf("got %q, want %q", h.out(), doc)
		}
	})
}

func TestYAMLCommandErrors(t *testing.T) {
	h := newHarness(t)
	pw := h.passFile("pw", testPassword)

	t.Run("missing file", func(t *testing.T) {
		if err := h.run("yaml", "--vault-password-file", pw, filepath.Join(h.dir, "absent")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("got %v, want os.ErrNotExist", err)
		}
	})

	t.Run("wrong password names the file", func(t *testing.T) {
		other := h.passFile("other", "not-it")
		src := h.file("doc.yml", yamlDoc(t), 0o600)

		err := h.run("yaml", "--vault-password-file", other, src)
		if !errors.Is(err, gansivault.ErrDecryptionFailed) {
			t.Fatalf("got %v, want ErrDecryptionFailed", err)
		}

		if !strings.Contains(err.Error(), "doc.yml") || !strings.Contains(err.Error(), "line 3") {
			t.Fatalf("error should name the file and the line, got %v", err)
		}
	})

	t.Run("no password source", func(t *testing.T) {
		if err := h.run("yaml", h.file("doc.yml", yamlDoc(t), 0o600)); !errors.Is(err, errNoPassword) {
			t.Fatalf("got %v, want errNoPassword", err)
		}
	})

	t.Run("output with several inputs", func(t *testing.T) {
		src := h.file("doc.yml", yamlDoc(t), 0o600)

		err := h.run("yaml", "--vault-password-file", pw, "-o", filepath.Join(h.dir, "out.yml"), src, src)
		if !errors.Is(err, errOutputSingleFile) {
			t.Fatalf("got %v, want errOutputSingleFile", err)
		}
	})

	t.Run("stdout write failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		src := h.file("doc.yml", yamlDoc(t), 0o600)
		h.app.Stdout = failWriter{}

		if err := h.run("yaml", "--vault-password-file", pw, src); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})

	t.Run("stdin read failure", func(t *testing.T) {
		h := newHarness(t)
		pw := h.passFile("pw", testPassword)
		h.app.Stdin = failReader{}

		if err := h.run("yaml", "--vault-password-file", pw); !errors.Is(err, errBoom) {
			t.Fatalf("got %v, want errBoom", err)
		}
	})
}
