package gansivault

import (
	"errors"
	"strings"
	"testing"
)

// sealString is a helper that encrypts a value under fixturePassword and
// renders it as an indented "!vault |" block, the way a YAML document written
// by "ansible-vault encrypt_string" carries it.
func sealString(t *testing.T, value, name string, indent int) string {
	t.Helper()

	sealed, err := Encrypt([]byte(value), []byte(fixturePassword))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	return FormatYAML(sealed, name, indent)
}

// fixtureVault is a vault holding the password behind the committed fixtures.
func fixtureVault() *Vault {
	return NewWithPassword([]byte(fixturePassword))
}

// staticDecrypt returns a decrypt function that ignores its input and answers
// with a fixed plaintext, so the rendering rules can be tested on their own.
func staticDecrypt(plaintext string) func([]byte) ([]byte, error) {
	return func([]byte) ([]byte, error) { return []byte(plaintext), nil }
}

// renderOne runs the inline decryptor over a one block document and returns
// the rewritten value line.
func renderOne(t *testing.T, plaintext string) string {
	t.Helper()

	doc := "key: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6161\n"

	out, err := inlineDecryptYAML([]byte(doc), staticDecrypt(plaintext))
	if err != nil {
		t.Fatalf("inlineDecryptYAML: %v", err)
	}

	return strings.TrimRight(string(out), "\n")
}

func TestDecryptYAMLNested(t *testing.T) {
	t.Parallel()

	doc := "hello: world\n\n" +
		sealString(t, "top secret", "secret", 2) + "\n\n" +
		"nested:\n  value:\n    foo: foo\n\n" +
		"    " + sealString(t, "buried", "bar", 6) + "\n"

	got, err := fixtureVault().DecryptYAML([]byte(doc))
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}

	want := "hello: world\n\n" +
		"secret: \"top secret\"\n\n" +
		"nested:\n  value:\n    foo: foo\n\n" +
		"    bar: buried\n"

	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDecryptYAMLFixture(t *testing.T) {
	t.Parallel()

	// The fixture is verbatim "ansible-vault encrypt_string" output.
	got, err := fixtureVault().DecryptYAML(readFixture(t, "encrypt_string.yml"))
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}

	if strings.TrimRight(string(got), "\n") != "mypass: hunter2" {
		t.Fatalf("got %q", got)
	}
}

func TestDecryptYAMLPassesEverythingElseThrough(t *testing.T) {
	t.Parallel()

	doc := "# a comment\nkey: value # trailing\nlist:\n  - one\n  - two\n\n\n"

	got, err := fixtureVault().DecryptYAML([]byte(doc))
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}

	if string(got) != doc {
		t.Fatalf("document changed:\ngot:\n%q\nwant:\n%q", got, doc)
	}
}

func TestDecryptYAMLBlockShapes(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		doc  string
		want string
	}{
		"sequence item": {
			doc:  "items:\n  - !vault |\n      $ANSIBLE_VAULT;1.1;AES256\n      6161\n",
			want: "items:\n  - value\n",
		},
		"document root": {
			doc:  "!vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6161\n",
			want: "value\n",
		},
		"sequence item with a key": {
			doc:  "- name: !vault |\n    $ANSIBLE_VAULT;1.1;AES256\n    6161\n",
			want: "- name: value\n",
		},
		"tab indented": {
			doc:  "root:\n\tkey: !vault |\n\t  $ANSIBLE_VAULT;1.1;AES256\n\t  6161\n",
			want: "root:\n\tkey: value\n",
		},
		"blank line inside the block": {
			doc:  "key: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n\n  6161\nnext: keep\n",
			want: "key: value\nnext: keep\n",
		},
		"block followed by a dedent": {
			doc:  "a:\n  key: !vault |\n    $ANSIBLE_VAULT;1.1;AES256\nb: keep\n",
			want: "a:\n  key: value\nb: keep\n",
		},
		"header without a body is left alone": {
			doc:  "key: !vault |\nnext: keep\n",
			want: "key: !vault |\nnext: keep\n",
		},
		"chomping indicator on the header": {
			doc:  "key: !vault |-\n  $ANSIBLE_VAULT;1.1;AES256\n",
			want: "key: value\n",
		},
		"not a vault tag": {
			doc:  "key: !other |\n  body\n",
			want: "key: !other |\n  body\n",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := inlineDecryptYAML([]byte(tc.doc), staticDecrypt("value"))
			if err != nil {
				t.Fatalf("inlineDecryptYAML: %v", err)
			}

			if string(got) != tc.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

func TestDecryptYAMLScalarRendering(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		plaintext string
		want      string
	}{
		"plain word":            {"hunter2", "key: hunter2"},
		"path like":             {"/etc/ssl/key.pem", "key: /etc/ssl/key.pem"},
		"empty":                 {"", `key: ""`},
		"spaces are quoted":     {"two words", `key: "two words"`},
		"digits are quoted":     {"1234", `key: "1234"`},
		"booleans are quoted":   {"yes", `key: "yes"`},
		"null is quoted":        {"Null", `key: "Null"`},
		"leading dash quoted":   {"-dash", `key: "-dash"`},
		"hash quoted":           {"a#b", `key: "a#b"`},
		"colon quoted":          {"a:b", `key: "a:b"`},
		"quotes are escaped":    {`say "hi"`, `key: "say \"hi\""`},
		"backslash escaped":     {`a\b`, `key: "a\\b"`},
		"tab escaped":           {"a\tb", `key: "a\tb"`},
		"control char escaped":  {"a\x01b", `key: "a\x01b"`},
		"del escaped":           {"a\x7fb", `key: "a\x7fb"`},
		"unicode kept":          {"pässwörd", `key: "pässwörd"`},
		"multi line":            {"one\ntwo", "key: |-\n  one\n  two"},
		"multi line kept nl":    {"one\ntwo\n", "key: |\n  one\n  two"},
		"single line kept nl":   {"one\n", "key: |\n  one"},
		"blank line inside":     {"one\n\ntwo", "key: |-\n  one\n\n  two"},
		"two trailing newlines": {"one\n\n", `key: "one\n\n"`},
		"carriage return":       {"one\r\ntwo", `key: "one\r\ntwo"`},
		"leading space":         {"  indented\nnext", `key: "  indented\nnext"`},
		"leading tab":           {"\tindented\nnext", `key: "\tindented\nnext"`},
		"trailing space":        {"one \ntwo", `key: "one \ntwo"`},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if got := renderOne(t, tc.plaintext); got != tc.want {
				t.Fatalf("got:\n%q\nwant:\n%q", got, tc.want)
			}
		})
	}
}

func TestDecryptYAMLMultilineRoundTrip(t *testing.T) {
	t.Parallel()

	key := "-----BEGIN KEY-----\nabc\ndef\n-----END KEY-----\n"

	doc := "tls:\n  " + sealString(t, key, "private_key", 4) + "\n"

	got, err := fixtureVault().DecryptYAML([]byte(doc))
	if err != nil {
		t.Fatalf("DecryptYAML: %v", err)
	}

	want := "tls:\n  private_key: |\n" +
		"    -----BEGIN KEY-----\n    abc\n    def\n    -----END KEY-----\n"

	if string(got) != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestDecryptYAMLErrors(t *testing.T) {
	t.Parallel()

	t.Run("reports the line of a failing block", func(t *testing.T) {
		t.Parallel()

		doc := "first: ok\n\nbroken: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6161\n"

		_, err := fixtureVault().DecryptYAML([]byte(doc))
		if err == nil {
			t.Fatal("want an error")
		}

		if !strings.HasPrefix(err.Error(), "line 3: ") {
			t.Fatalf("got %q, want it to start with the line number", err)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		t.Parallel()

		doc := sealString(t, "secret", "key", 2) + "\n"

		_, err := NewWithPassword([]byte("wrong")).DecryptYAML([]byte(doc))
		if !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("got %v, want ErrDecryptionFailed", err)
		}
	})

	t.Run("value that is not utf-8", func(t *testing.T) {
		t.Parallel()

		doc := "key: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  6161\n"

		_, err := inlineDecryptYAML([]byte(doc), staticDecrypt("\xff\xfe"))
		if !errors.Is(err, ErrNotUTF8) {
			t.Fatalf("got %v, want ErrNotUTF8", err)
		}
	})
}
