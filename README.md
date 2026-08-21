# gansivault

[![CI](https://github.com/tomodian/gansivault/actions/workflows/ci.yml/badge.svg)](https://github.com/tomodian/gansivault/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/tomodian/gansivault.svg)](https://pkg.go.dev/github.com/tomodian/gansivault)
[![Go Report Card](https://goreportcard.com/badge/github.com/tomodian/gansivault)](https://goreportcard.com/report/github.com/tomodian/gansivault)

A byte-compatible port of [Ansible Vault](https://docs.ansible.com/ansible/latest/vault_guide/index.html) to Go, as a **zero-dependency library** and an **`ansible-vault` work-alike CLI**.

Files written by `gansivault` are read by `ansible-vault`, and files written by `ansible-vault` are read by `gansivault` — both the `1.1` and the `1.2` (vault id) header variants. CI proves this on every push by round-tripping real payloads through three versions of `ansible-core`.

## Why

- **AWS Lambda.** Decrypt secrets in a Go handler on `provided.al2023` with a plain `CGO_ENABLED=0` binary. No Python, no container image built solely to carry an `ansible` install.
- **Any Go codebase.** The library imports nothing outside the standard library, so it adds no transitive dependencies to your `go.mod`.
- **Drop-in CLI.** The same subcommands and the same flags as `ansible-vault`, including `--vault-password-file`, `--vault-id`, `--ask-vault-pass`, `--encrypt-vault-id` and `--output`.

## Install

Requires Go 1.24 or newer (the library uses the standard library's `crypto/pbkdf2`).

Library:

```sh
go get github.com/tomodian/gansivault
```

CLI:

```sh
go install github.com/tomodian/gansivault/cmd/gansivault@latest
```

Or run it straight from the checkout:

```sh
go run ./cmd/gansivault encrypt --vault-password-file ~/.vault_pass secrets.yml
```

## Library

The common case is one password:

```go
sealed, err := gansivault.Encrypt([]byte("db_password: hunter2\n"), []byte("correct horse"))
plain,  err := gansivault.Decrypt(sealed, []byte("correct horse"))
```

Reading a file that `ansible-vault` produced:

```go
plain, err := gansivault.DecryptFile("group_vars/prod/vault.yml", []byte(os.Getenv("VAULT_PASSWORD")))
```

### In a Lambda handler

Nothing here touches the filesystem or the network, so a cold start costs one PBKDF2 run:

```go
package main

import (
	"context"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/tomodian/gansivault"
)

var vault = gansivault.NewWithPassword([]byte(os.Getenv("VAULT_PASSWORD")))

func handle(ctx context.Context, event Event) (Response, error) {
	creds, err := vault.Decrypt([]byte(event.SealedCredentials))
	if err != nil {
		return Response{}, err
	}

	// ... use creds ...
	return Response{}, nil
}

func main() { lambda.Start(handle) }
```

### Multiple identities

Secrets are tried in order, after any that match the vault id in a `1.2` header:

```go
v := gansivault.New(
	gansivault.NewFileSecret("prod", "/run/secrets/prod.pass"),
	gansivault.NewFileSecret("dev", "~/.vault_dev"),
	gansivault.NewStaticSecret("ci", []byte(os.Getenv("CI_VAULT_PASSWORD"))),
)

plain, vaultID, err := v.DecryptAndGetVaultID(sealed)
```

`Open` returns the `Secret` itself rather than just its id, which is what you want in order to re-seal the same data under the same identity:

```go
plain, secret, err := v.Open(sealed)
// ... modify plain ...
resealed, err := gansivault.EncryptWithSecret(plain, secret, "" /* keep the secret's own id */)
```

`Secret` is a two-method interface, so a secrets manager, a keyring or an SSM parameter drops straight in:

```go
type Secret interface {
	ID() string
	Bytes() ([]byte, error)
}
```

### Password sources

| Constructor | Ansible equivalent | Behaviour |
| --- | --- | --- |
| `NewStaticSecret(id, pw)` | — | In-memory password, used verbatim |
| `NewFileSecret(id, path)` | `--vault-password-file` | Reads the file and trims surrounding whitespace; an **executable** file is run instead and its stdout used. A script whose name ends in `-client` also receives `--vault-id <id>` |
| `NewPromptSecret(id, ask)` | `--ask-vault-pass`, `label@prompt` | Prompts once and caches |
| `NewSecretFromVaultID(arg, ask)` | `--vault-id` | Parses `[LABEL@]SOURCE` and picks the right kind |

### YAML `!vault` blocks

```go
sealed, _ := gansivault.Encrypt([]byte("hunter2"), []byte("password"))
fmt.Println(gansivault.FormatYAML(sealed, "db_password", gansivault.DefaultYAMLIndent))
```

```yaml
db_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          33653735326332386261383836356362346635386561333933343231373033633231363931666264
          ...
```

`ExtractVaultText` reverses it, so a vaulted value lifted out of a vars file decrypts without any pre-processing.

## CLI

```
gansivault encrypt          encrypt one or more files in place
gansivault decrypt          decrypt one or more files in place
gansivault view             print the decrypted contents of one or more files
gansivault create           create a new encrypted file in an editor
gansivault edit             decrypt a file into an editor and re-encrypt it on save
gansivault rekey            re-encrypt one or more files under a new password
gansivault encrypt_string   encrypt a string into an Ansible YAML block
```

### Flags

Every subcommand accepts the password-source flags:

| Flag | Env | Notes |
| --- | --- | --- |
| `--vault-password-file`, `--vault-pass-file` | `ANSIBLE_VAULT_PASSWORD_FILE` | Repeatable. A bare path under the `default` identity — never split on `@`. Executable files are run as password scripts |
| `--vault-id` | `ANSIBLE_VAULT_IDENTITY_LIST` | Repeatable. `[LABEL@]SOURCE`, where SOURCE may be `prompt` |
| `--ask-vault-password`, `--ask-vault-pass`, `-J` | | Prompts with echo disabled on a terminal |

Writing subcommands additionally take:

| Flag | Env | Notes |
| --- | --- | --- |
| `--encrypt-vault-id` | `ANSIBLE_VAULT_ENCRYPT_IDENTITY` | Required when several distinct identities are configured |
| `--output`, `-o` | | Write elsewhere instead of in place; `-` means stdout |

`rekey` takes `--new-vault-id` and `--new-vault-password-file`; `encrypt_string` takes `--name`/`-n`, `--stdin-name` and `--indent`.

### Examples

```sh
# In place, exactly like ansible-vault
gansivault encrypt --vault-password-file ~/.vault_pass group_vars/prod/vault.yml
gansivault view    --vault-password-file ~/.vault_pass group_vars/prod/vault.yml

# Pipe through stdin and stdout
echo -n 'hunter2' | gansivault encrypt --vault-password-file ~/.vault_pass > secret.vault
gansivault decrypt --vault-password-file ~/.vault_pass -o - secret.vault

# Labelled identities produce a 1.2 header
gansivault encrypt --vault-id prod@~/.vault_prod secrets.yml

# A vars file entry Ansible can consume directly
echo -n 'hunter2' | gansivault encrypt_string --vault-password-file ~/.vault_pass --stdin-name db_password

# Rotate a password across a tree
gansivault rekey --vault-password-file ~/.vault_old \
                 --new-vault-password-file ~/.vault_new \
                 group_vars/*/vault.yml
```

`--ask-vault-pass` reads without echo when stdin is a terminal and falls back to a plain line read otherwise, so `echo pw | gansivault view -J file` works in CI.

## Format

`gansivault` implements the AES256 vault format as shipped by Ansible:

```
$ANSIBLE_VAULT;1.1;AES256              header (1.2 appends ;<vault_id>)
<hex>                                  payload, wrapped at 80 columns
```

Decoding the payload once yields three newline-separated hex fields — `salt`, `hmac`, `ciphertext`:

| Step | Parameters |
| --- | --- |
| Key derivation | PBKDF2-HMAC-SHA256, 10000 iterations, 32-byte random salt, 80 bytes out |
| Key split | `[0:32]` AES key, `[32:64]` HMAC key, `[64:80]` CTR counter block |
| Padding | PKCS#7 to the 16-byte AES block size |
| Encryption | AES-256-CTR |
| Authentication | HMAC-SHA256 over the ciphertext, encrypt-then-MAC, verified before decrypting |

The HMAC is compared in constant time and checked *before* the ciphertext is touched, so a wrong password or a tampered file fails as `ErrHMACMismatch` rather than producing garbage.

### Errors

`errors.Is` works against `ErrNotVault`, `ErrMalformedEnvelope`, `ErrUnsupportedVersion`, `ErrUnsupportedCipher`, `ErrHMACMismatch`, `ErrInvalidPadding`, `ErrNoSecrets`, `ErrDecryptionFailed`, `ErrEmptyPassword` and `ErrAlreadyEncrypted`.

## Compatibility

- Vault format **1.1** and **1.2**, cipher **AES256** — every format Ansible has shipped.
- Verified against `ansible-core` 2.16, 2.18 and latest in CI, in both directions, over empty, single-byte, block-aligned, multiline, Unicode, 4 KiB binary and 160 KiB payloads.
- `testdata/` holds real `ansible-vault` output committed to the repository, so the compatibility tests run even where Ansible is not installed.

### Not implemented

- Password files that are themselves vault-encrypted. Ansible supports nesting a vault file as a password source; `gansivault` reads password files as plain text or as scripts.
- The `view` subcommand prints to stdout rather than invoking a pager.

## Development

```sh
make test       # race detector
make cover      # enforces the 100% gate locally
make lint       # golangci-lint
make interop    # round trip against a locally installed ansible-vault
```

Test coverage is **100% of statements** across all three packages and CI fails below that.

## License

MIT — see [LICENSE](LICENSE).

This is an independent implementation of the Ansible Vault *file format*, written against the published format and verified against the `ansible-vault` binary. It contains no code from the Ansible project.
