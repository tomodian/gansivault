package cliapp

import (
	"errors"
	"fmt"

	"github.com/tomodian/gansivault"
	"github.com/urfave/cli/v3"
)

// errNoPassword is reported when a command needs a password but none of
// --vault-id, --vault-password-file or --ask-vault-pass was supplied.
var errNoPassword = errors.New("gansivault: no vault password supplied; use --vault-password-file, --vault-id or --ask-vault-pass")

// buildSecrets assembles the vault secrets from the standard Ansible flags.
//
// Order matters, because the first secret is the default encryption identity:
// --vault-id entries come first in the order given, then
// --vault-password-file entries, then the interactive prompt.
func (a *App) buildSecrets(cmd *cli.Command) ([]gansivault.Secret, error) {
	var secrets []gansivault.Secret

	for _, arg := range cmd.StringSlice(flagVaultID) {
		if arg == "" {
			continue
		}

		secrets = append(secrets, gansivault.NewSecretFromVaultID(arg, a.prompt()))
	}

	// Unlike --vault-id, a --vault-password-file value is a bare path: Ansible
	// registers it under the default identity and never splits it on "@", so
	// a path such as /home/user@corp/.vault keeps working.
	for _, path := range cmd.StringSlice(flagVaultPasswordFile) {
		if path == "" {
			continue
		}

		secrets = append(secrets, gansivault.NewFileSecret(gansivault.DefaultVaultID, path))
	}

	if cmd.Bool(flagAskVaultPass) {
		secrets = append(secrets, gansivault.NewPromptSecret(gansivault.DefaultVaultID, a.prompt()))
	}

	if len(secrets) == 0 {
		return nil, errNoPassword
	}

	return secrets, nil
}

// openVault builds a Vault for reading, i.e. for decrypt, view, edit and the
// read half of rekey.
func (a *App) openVault(cmd *cli.Command) (*gansivault.Vault, error) {
	secrets, err := a.buildSecrets(cmd)
	if err != nil {
		return nil, err
	}

	return gansivault.New(secrets...), nil
}

// encryptionSecret picks the identity to encrypt with. When several distinct
// vault ids are configured, --encrypt-vault-id is required, exactly as
// ansible-vault demands.
func (a *App) encryptionSecret(cmd *cli.Command) (gansivault.Secret, error) {
	secrets, err := a.buildSecrets(cmd)
	if err != nil {
		return nil, err
	}

	if want := cmd.String(flagEncryptVaultID); want != "" {
		for _, s := range secrets {
			if s.ID() == want {
				return s, nil
			}
		}

		return nil, fmt.Errorf("gansivault: no vault secret found for --encrypt-vault-id %q", want)
	}

	ids := distinctIDs(secrets)
	if len(ids) > 1 {
		return nil, fmt.Errorf("gansivault: multiple vault identities are available (%v); choose one with --encrypt-vault-id", ids)
	}

	return secrets[0], nil
}

// distinctIDs lists the unique vault ids across secrets, in first-seen order.
func distinctIDs(secrets []gansivault.Secret) []string {
	seen := map[string]bool{}

	var ids []string

	for _, s := range secrets {
		if seen[s.ID()] {
			continue
		}

		seen[s.ID()] = true

		ids = append(ids, s.ID())
	}

	return ids
}

// rekeySecret builds the destination identity for the rekey command from
// --new-vault-id and --new-vault-password-file, falling back to a prompt.
// The secret is lazy, so any problem with the source surfaces when the
// password is actually needed.
func (a *App) rekeySecret(cmd *cli.Command) gansivault.Secret {
	if arg := cmd.String(flagNewVaultID); arg != "" {
		return gansivault.NewSecretFromVaultID(arg, a.prompt())
	}

	if path := cmd.String(flagNewVaultPasswordFile); path != "" {
		return gansivault.NewFileSecret(gansivault.DefaultVaultID, path)
	}

	return gansivault.NewPromptSecret(gansivault.DefaultVaultID, a.prompt())
}
