package gansivault

import (
	"strings"
	"testing"
)

func TestFormatYAML(t *testing.T) {
	t.Parallel()

	sealed := []byte("$ANSIBLE_VAULT;1.1;AES256\n6161\n6262\n")

	t.Run("named block", func(t *testing.T) {
		t.Parallel()

		got := FormatYAML(sealed, "mypass", 0)
		want := "mypass: !vault |\n" +
			"          $ANSIBLE_VAULT;1.1;AES256\n" +
			"          6161\n" +
			"          6262"

		if got != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("anonymous block", func(t *testing.T) {
		t.Parallel()

		got := FormatYAML(sealed, "", 2)
		want := "!vault |\n" +
			"  $ANSIBLE_VAULT;1.1;AES256\n" +
			"  6161\n" +
			"  6262"

		if got != want {
			t.Fatalf("got:\n%s\nwant:\n%s", got, want)
		}
	})

	t.Run("negative indent falls back to the default", func(t *testing.T) {
		t.Parallel()

		if !strings.Contains(FormatYAML(sealed, "", -5), strings.Repeat(" ", DefaultYAMLIndent)+"$ANSIBLE_VAULT") {
			t.Fatal("negative indent should use DefaultYAMLIndent")
		}
	})
}

func TestFormatYAMLMatchesAnsible(t *testing.T) {
	t.Parallel()

	// The fixture is verbatim "ansible-vault encrypt_string" output, so the
	// only difference from ours may be the ciphertext itself.
	fixture := strings.TrimRight(string(readFixture(t, "encrypt_string.yml")), "\n")

	vaultText := ExtractVaultText(fixture)

	if got := FormatYAML([]byte(vaultText), "mypass", DefaultYAMLIndent); got != fixture {
		t.Fatalf("layout differs from ansible-vault:\ngot:\n%s\nwant:\n%s", got, fixture)
	}
}

func TestExtractVaultText(t *testing.T) {
	t.Parallel()

	t.Run("round trips through the yaml block", func(t *testing.T) {
		t.Parallel()

		sealed, err := Encrypt([]byte("secret value"), []byte("pw"))
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}

		block := FormatYAML(sealed, "mypass", DefaultYAMLIndent)

		got, err := Decrypt([]byte(ExtractVaultText(block)), []byte("pw"))
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}

		if string(got) != "secret value" {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("bare payload is passed through", func(t *testing.T) {
		t.Parallel()

		in := "$ANSIBLE_VAULT;1.1;AES256\n6161"
		if got := ExtractVaultText(in); got != in {
			t.Fatalf("got %q", got)
		}
	})

	t.Run("drops blank lines and preamble", func(t *testing.T) {
		t.Parallel()

		in := "\nsome: preamble\n\nmypass: !vault |\n   $ANSIBLE_VAULT;1.1;AES256\n\n   6161\n"
		if got := ExtractVaultText(in); got != "$ANSIBLE_VAULT;1.1;AES256\n6161" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestDecryptAnsibleEncryptStringFixture(t *testing.T) {
	t.Parallel()

	block := string(readFixture(t, "encrypt_string.yml"))

	got, err := Decrypt([]byte(ExtractVaultText(block)), []byte(fixturePassword))
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if string(got) != "hunter2" {
		t.Fatalf("got %q, want hunter2", got)
	}
}
