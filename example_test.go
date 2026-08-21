package gansivault_test

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/tomodian/gansivault"
)

// The package level helpers cover the common case of one password.
func Example() {
	sealed, err := gansivault.Encrypt([]byte("db_password: hunter2\n"), []byte("correct horse"))
	if err != nil {
		log.Fatal(err)
	}

	plain, err := gansivault.Decrypt(sealed, []byte("correct horse"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", plain)
	// Output: db_password: hunter2
}

// Vault files written by ansible-vault open with nothing but the password.
func ExampleDecryptFile() {
	plain, err := gansivault.DecryptFile(filepath.Join("testdata", "hello_11.vault"), []byte("mypassword"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", plain)
	// Output: hello world
}

// A Lambda handler typically holds the password in the environment and needs
// no files at all.
func ExampleNewStaticSecret() {
	password := os.Getenv("VAULT_PASSWORD")
	if password == "" {
		password = "mypassword"
	}

	v := gansivault.New(gansivault.NewStaticSecret("", []byte(password)))

	plain, err := v.DecryptFile(filepath.Join("testdata", "hello_11.vault"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", plain)
	// Output: hello world
}

// Several identities can be registered at once; the label in a 1.2 header
// picks the right one, and the others are still tried as a fallback.
func ExampleVault_DecryptAndGetVaultID() {
	v := gansivault.New(
		gansivault.NewStaticSecret("prod", []byte("prod-password")),
		gansivault.NewStaticSecret("myid", []byte("mypassword")),
	)

	sealed, err := os.ReadFile(filepath.Join("testdata", "hello_12.vault"))
	if err != nil {
		log.Fatal(err)
	}

	plain, id, err := v.DecryptAndGetVaultID(sealed)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s opened by %s\n", plain[:len(plain)-1], id)
	// Output: hello world opened by myid
}

// FileSecret reads --vault-password-file style files, including executable
// password scripts.
func ExampleNewFileSecret() {
	v := gansivault.New(gansivault.NewFileSecret("", filepath.Join("testdata", "mypassword.pass")))

	plain, err := v.DecryptFile(filepath.Join("testdata", "hello_11.vault"))
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%s", plain)
	// Output: hello world
}

// FormatYAML produces the same block ansible-vault encrypt_string emits, ready
// to paste into a vars file.
func ExampleFormatYAML() {
	sealed := []byte("$ANSIBLE_VAULT;1.1;AES256\n3132\n3334")

	fmt.Println(gansivault.FormatYAML(sealed, "db_password", gansivault.DefaultYAMLIndent))
	// Output:
	// db_password: !vault |
	//           $ANSIBLE_VAULT;1.1;AES256
	//           3132
	//           3334
}

// SplitVaultID parses the --vault-id argument syntax.
func ExampleSplitVaultID() {
	for _, arg := range []string{"~/.vault_pass", "prod@~/.vault_prod", "dev@prompt"} {
		id, source := gansivault.SplitVaultID(arg)
		fmt.Printf("%-20s id=%-8s source=%s\n", arg, id, source)
	}
	// Output:
	// ~/.vault_pass        id=default  source=~/.vault_pass
	// prod@~/.vault_prod   id=prod     source=~/.vault_prod
	// dev@prompt           id=dev      source=prompt
}
