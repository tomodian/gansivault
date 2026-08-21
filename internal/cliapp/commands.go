package cliapp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/tomodian/gansivault"
	"github.com/urfave/cli/v3"
)

// errOutputSingleFile guards the --output plus multiple inputs combination,
// which ansible-vault also rejects.
var errOutputSingleFile = errors.New("gansivault: --output can only be used with a single input")

// targets returns the files a command should act on. An empty argument list
// means standard input, expressed as the single target "-".
func targets(cmd *cli.Command) []string {
	args := cmd.Args().Slice()
	if len(args) == 0 {
		return []string{stdioName}
	}

	return args
}

// resolveOutputs pairs each input with its destination. Without --output every
// file is rewritten in place; with --output there must be exactly one input.
func resolveOutputs(cmd *cli.Command, inputs []string) ([]string, error) {
	out := cmd.String(flagOutput)
	if out == "" {
		return inputs, nil
	}

	if len(inputs) != 1 {
		return nil, errOutputSingleFile
	}

	return []string{out}, nil
}

// encryptAction implements "gansivault encrypt".
func (a *App) encryptAction(_ context.Context, cmd *cli.Command) error {
	secret, err := a.encryptionSecret(cmd)
	if err != nil {
		return err
	}

	vault := gansivault.New(secret)

	inputs := targets(cmd)

	outputs, err := resolveOutputs(cmd, inputs)
	if err != nil {
		return err
	}

	for i, in := range inputs {
		plaintext, err := a.readInput(in)
		if err != nil {
			return err
		}

		if gansivault.IsEncrypted(plaintext) {
			return fmt.Errorf("%w: %s", gansivault.ErrAlreadyEncrypted, describe(in))
		}

		sealed, err := vault.Encrypt(plaintext)
		if err != nil {
			return err
		}

		if err := a.writeOutput(outputs[i], ensureTrailingNewline(sealed), fileMode(in)); err != nil {
			return err
		}
	}

	a.note("Encryption successful")

	return nil
}

// decryptAction implements "gansivault decrypt".
func (a *App) decryptAction(_ context.Context, cmd *cli.Command) error {
	vault, err := a.openVault(cmd)
	if err != nil {
		return err
	}

	inputs := targets(cmd)

	outputs, err := resolveOutputs(cmd, inputs)
	if err != nil {
		return err
	}

	for i, in := range inputs {
		sealed, err := a.readInput(in)
		if err != nil {
			return err
		}

		plaintext, err := vault.Decrypt(sealed)
		if err != nil {
			return fmt.Errorf("%s: %w", describe(in), err)
		}

		if err := a.writeOutput(outputs[i], plaintext, fileMode(in)); err != nil {
			return err
		}
	}

	a.note("Decryption successful")

	return nil
}

// viewAction implements "gansivault view".
func (a *App) viewAction(_ context.Context, cmd *cli.Command) error {
	vault, err := a.openVault(cmd)
	if err != nil {
		return err
	}

	for _, in := range targets(cmd) {
		sealed, err := a.readInput(in)
		if err != nil {
			return err
		}

		plaintext, err := vault.Decrypt(sealed)
		if err != nil {
			return fmt.Errorf("%s: %w", describe(in), err)
		}

		if _, err := a.Stdout.Write(plaintext); err != nil {
			return err
		}
	}

	return nil
}

// createAction implements "gansivault create".
func (a *App) createAction(ctx context.Context, cmd *cli.Command) error {
	path, err := singleFileArg(cmd, "create")
	if err != nil {
		return err
	}

	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return fmt.Errorf("gansivault: %s already exists; use edit instead", path)
	}

	secret, err := a.encryptionSecret(cmd)
	if err != nil {
		return err
	}

	plaintext, err := a.editInTemp(ctx, path, nil)
	if err != nil {
		return err
	}

	sealed, err := gansivault.New(secret).Encrypt(plaintext)
	if err != nil {
		return err
	}

	if err := a.writeOutput(path, ensureTrailingNewline(sealed), defaultFileMode); err != nil {
		return err
	}

	a.note("Encryption successful")

	return nil
}

// editAction implements "gansivault edit". The vault id of the original file
// is preserved unless --encrypt-vault-id says otherwise.
func (a *App) editAction(ctx context.Context, cmd *cli.Command) error {
	path, err := singleFileArg(cmd, "edit")
	if err != nil {
		return err
	}

	vault, err := a.openVault(cmd)
	if err != nil {
		return err
	}

	sealed, err := a.readInput(path)
	if err != nil {
		return err
	}

	env, err := gansivault.ParseEnvelope(sealed)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	plaintext, secret, err := vault.Open(sealed)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}

	edited, err := a.editInTemp(ctx, path, plaintext)
	if err != nil {
		return err
	}

	// Keep whatever label the file already carried, so editing a 1.2 file with
	// a plain --vault-password-file does not silently downgrade it to 1.1.
	// --encrypt-vault-id overrides both the label and the identity used.
	label := env.VaultID

	if want := cmd.String(flagEncryptVaultID); want != "" {
		if secret, err = a.encryptionSecret(cmd); err != nil {
			return err
		}

		label = want
	}

	resealed, err := gansivault.EncryptWithSecret(edited, secret, label)
	if err != nil {
		return err
	}

	if err := a.writeOutput(path, ensureTrailingNewline(resealed), fileMode(path)); err != nil {
		return err
	}

	a.note("Encryption successful")

	return nil
}

// rekeyAction implements "gansivault rekey".
func (a *App) rekeyAction(_ context.Context, cmd *cli.Command) error {
	vault, err := a.openVault(cmd)
	if err != nil {
		return err
	}

	newSecret := a.rekeySecret(cmd)

	files := cmd.Args().Slice()
	if len(files) == 0 {
		return errors.New("gansivault: rekey needs at least one FILE")
	}

	for _, path := range files {
		sealed, err := a.readInput(path)
		if err != nil {
			return err
		}

		resealed, err := vault.Rekey(sealed, newSecret)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}

		if err := a.writeOutput(path, ensureTrailingNewline(resealed), fileMode(path)); err != nil {
			return err
		}
	}

	a.note("Rekey successful")

	return nil
}

// encryptStringAction implements "gansivault encrypt_string".
func (a *App) encryptStringAction(_ context.Context, cmd *cli.Command) error {
	secret, err := a.encryptionSecret(cmd)
	if err != nil {
		return err
	}

	vault := gansivault.New(secret)
	names := cmd.StringSlice(flagName)
	indent := cmd.Int(flagIndent)

	values := cmd.Args().Slice()

	if len(values) == 0 {
		raw, err := a.readAllStdin()
		if err != nil {
			return err
		}

		values = []string{string(raw)}

		if stdinName := cmd.String(flagStdinName); stdinName != "" {
			names = []string{stdinName}
		}
	}

	var rendered []byte

	for i, value := range values {
		sealed, err := vault.Encrypt([]byte(value))
		if err != nil {
			return err
		}

		name := ""
		if i < len(names) {
			name = names[i]
		}

		rendered = append(rendered, gansivault.FormatYAML(sealed, name, indent)...)
		rendered = append(rendered, '\n')
	}

	if err := a.writeOutput(cmd.String(flagOutput), rendered, defaultFileMode); err != nil {
		return err
	}

	a.note("Encryption successful")

	return nil
}

// editInTemp writes seed to a temporary file next to target, opens it in an
// editor and returns the edited bytes. Keeping the temp file in the same
// directory keeps plaintext off a possibly world-readable /tmp.
func (a *App) editInTemp(ctx context.Context, target string, seed []byte) ([]byte, error) {
	tmp, err := createTemp(filepath.Dir(target), ".gansivault-*")
	if err != nil {
		return nil, fmt.Errorf("gansivault: %w", err)
	}

	name := tmp.Name()

	defer func() {
		_ = os.Remove(name)
	}()

	_, writeErr := tmp.Write(seed)

	if err := errors.Join(writeErr, tmp.Close()); err != nil {
		return nil, fmt.Errorf("gansivault: %w", err)
	}

	if err := a.edit(ctx, name); err != nil {
		return nil, fmt.Errorf("gansivault: editor failed: %w", err)
	}

	edited, err := os.ReadFile(name) // #nosec G304 -- our own temp file
	if err != nil {
		return nil, fmt.Errorf("gansivault: %w", err)
	}

	return edited, nil
}

// singleFileArg extracts the one positional argument a command accepts.
func singleFileArg(cmd *cli.Command, name string) (string, error) {
	args := cmd.Args().Slice()
	if len(args) != 1 {
		return "", fmt.Errorf("gansivault: %s needs exactly one FILE, got %d", name, len(args))
	}

	return args[0], nil
}

// describe names an input for error messages.
func describe(name string) string {
	if name == "" || name == stdioName {
		return "<stdin>"
	}

	return name
}
