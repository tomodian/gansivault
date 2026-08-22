// Package cliapp implements the gansivault command line interface, an
// ansible-vault work-alike built on github.com/urfave/cli.
package cliapp

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/tomodian/gansivault"
	"github.com/urfave/cli/v3"
)

// Flag names, kept as constants so the actions and the flag definitions cannot
// drift apart.
//
// line flag names, not credentials.
//
//nolint:gosec // G101 fires on the "password" in these names; they are command
const (
	flagVaultID              = "vault-id"
	flagVaultPasswordFile    = "vault-password-file"
	flagAskVaultPass         = "ask-vault-password"
	flagEncryptVaultID       = "encrypt-vault-id"
	flagOutput               = "output"
	flagNewVaultID           = "new-vault-id"
	flagNewVaultPasswordFile = "new-vault-password-file"
	flagName                 = "name"
	flagStdinName            = "stdin-name"
	flagIndent               = "indent"
)

// Version is the reported build version. It is overridden at link time.
var Version = "dev"

// App wires the command tree to a set of streams. Every external interaction
// is reachable through a field, which keeps the whole CLI testable in-process.
type App struct {
	// Stdin, Stdout and Stderr default to the process streams.
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer

	// Prompt overrides interactive password reading. When nil, a terminal
	// aware prompt built from Stdin and Stderr is used.
	Prompt gansivault.PromptFunc

	// Editor overrides the editor launched by create and edit. When nil,
	// $ANSIBLE_EDITOR, $EDITOR or $VISUAL is used, falling back to vi.
	Editor func(path string) error
}

// New returns an App bound to the process streams.
func New() *App {
	return &App{Stdin: os.Stdin, Stdout: os.Stdout, Stderr: os.Stderr}
}

// prompt returns the configured password prompt.
func (a *App) prompt() gansivault.PromptFunc {
	if a.Prompt != nil {
		return a.Prompt
	}

	return newPrompt(a.Stdin, a.Stderr)
}

// edit opens path in an editor. Cancelling ctx, which is the command's own
// context, tears the editor down with it.
func (a *App) edit(ctx context.Context, path string) error {
	if a.Editor != nil {
		return a.Editor(path)
	}

	return launchEditor(ctx, editorCommand(), path, a.Stdin, a.Stdout, a.Stderr)
}

// note writes a status line to standard error, the way ansible-vault reports
// "Encryption successful".
func (a *App) note(format string, args ...any) {
	_, _ = fmt.Fprintf(a.Stderr, format+"\n", args...)
}

// passwordFlags are the password-source flags shared by every subcommand.
func passwordFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringSliceFlag{
			Name:    flagVaultID,
			Usage:   "the vault identity to use, as `[LABEL@]SOURCE` where SOURCE is a password file, a password script, or the literal \"prompt\" (repeatable)",
			Sources: cli.EnvVars("ANSIBLE_VAULT_IDENTITY_LIST"),
		},
		&cli.StringSliceFlag{
			Name:    flagVaultPasswordFile,
			Aliases: []string{"vault-pass-file"},
			Usage:   "vault password `FILE`; an executable file is run and its stdout used (repeatable)",
			Sources: cli.EnvVars("ANSIBLE_VAULT_PASSWORD_FILE"),
		},
		&cli.BoolFlag{
			Name:    flagAskVaultPass,
			Aliases: []string{"ask-vault-pass", "J"},
			Usage:   "ask for the vault password interactively",
		},
	}
}

// encryptFlags adds the identity selector used by the writing subcommands.
func encryptFlags() []cli.Flag {
	return append(passwordFlags(), &cli.StringFlag{
		Name:    flagEncryptVaultID,
		Usage:   "the vault `ID` to encrypt with (required when several identities are configured)",
		Sources: cli.EnvVars("ANSIBLE_VAULT_ENCRYPT_IDENTITY"),
	})
}

// outputFlag is the shared --output/-o definition.
func outputFlag() cli.Flag {
	return &cli.StringFlag{
		Name:    flagOutput,
		Aliases: []string{"o"},
		Usage:   "write to `FILE` instead of in place; use - for stdout",
	}
}

// Command builds the full command tree.
func (a *App) Command() *cli.Command {
	return &cli.Command{
		Name:                      "gansivault",
		Usage:                     "encrypt and decrypt Ansible Vault files, without Ansible",
		Version:                   Version,
		Reader:                    a.Stdin,
		Writer:                    a.Stdout,
		ErrWriter:                 a.Stderr,
		DisableSliceFlagSeparator: true,

		// urfave/cli's default handler calls os.Exit itself. Neutralising it
		// keeps every failure a returned error, so Main owns the exit code and
		// the whole tree stays testable in-process.
		ExitErrHandler: func(context.Context, *cli.Command, error) {},

		Description: "gansivault is a byte-compatible reimplementation of ansible-vault in Go.\n" +
			"Files it writes can be read by ansible-vault and vice versa.",
		Commands: []*cli.Command{
			{
				Name:      "encrypt",
				Usage:     "encrypt one or more files in place",
				ArgsUsage: "[FILE...]",
				Description: "With no FILE, or with -, plaintext is read from standard input and the\n" +
					"vault payload is written to standard output.",
				Flags:  append(encryptFlags(), outputFlag()),
				Action: a.encryptAction,
			},
			{
				Name:      "decrypt",
				Usage:     "decrypt one or more files in place",
				ArgsUsage: "[FILE...]",
				Flags:     append(passwordFlags(), outputFlag()),
				Action:    a.decryptAction,
			},
			{
				Name:      "view",
				Usage:     "print the decrypted contents of one or more files",
				ArgsUsage: "[FILE...]",
				Flags:     passwordFlags(),
				Action:    a.viewAction,
			},
			{
				Name:      "yaml",
				Usage:     "decrypt the !vault blocks inside YAML files and print the result",
				ArgsUsage: "[FILE...]",
				Description: "Every \"!vault |\" block in the document is replaced by its decrypted\n" +
					"value, at any nesting depth, and everything else is passed through as\n" +
					"written. This is the counterpart to encrypt_string, and the command to\n" +
					"reach for when view fails because the file is a YAML document that\n" +
					"merely contains vault blocks rather than being one vault payload.\n\n" +
					"The result goes to standard output; the input file is never rewritten.\n" +
					"With no FILE, or with -, the document is read from standard input.",
				Flags:  append(passwordFlags(), outputFlag()),
				Action: a.yamlAction,
			},
			{
				Name:      "create",
				Usage:     "create a new encrypted file in an editor",
				ArgsUsage: "FILE",
				Flags:     encryptFlags(),
				Action:    a.createAction,
			},
			{
				Name:      "edit",
				Usage:     "decrypt a file into an editor and re-encrypt it on save",
				ArgsUsage: "FILE",
				Flags:     encryptFlags(),
				Action:    a.editAction,
			},
			{
				Name:      "rekey",
				Usage:     "re-encrypt one or more files under a new password",
				ArgsUsage: "FILE...",
				Flags: append(passwordFlags(),
					&cli.StringFlag{
						Name:  flagNewVaultID,
						Usage: "the new vault identity, as `[LABEL@]SOURCE`",
					},
					&cli.StringFlag{
						Name:  flagNewVaultPasswordFile,
						Usage: "new vault password `FILE`",
					},
				),
				Action: a.rekeyAction,
			},
			{
				Name:      "encrypt_string",
				Aliases:   []string{"encrypt-string"},
				Usage:     "encrypt a string into an Ansible YAML block",
				ArgsUsage: "[STRING...]",
				Description: "Each STRING is encrypted and printed as a !vault YAML block. Names given\n" +
					"with --name are paired with the strings positionally. With no STRING, the\n" +
					"value is read from standard input.",
				Flags: append(encryptFlags(),
					&cli.StringSliceFlag{
						Name:    flagName,
						Aliases: []string{"n"},
						Usage:   "the YAML variable `NAME` to emit (repeatable)",
					},
					&cli.StringFlag{
						Name:  flagStdinName,
						Usage: "the YAML variable `NAME` for the value read from stdin",
					},
					&cli.IntFlag{
						Name:  flagIndent,
						Usage: "indentation `WIDTH` for the YAML block body",
						Value: gansivault.DefaultYAMLIndent,
					},
					outputFlag(),
				),
				Action: a.encryptStringAction,
			},
		},
	}
}

// Run executes the command tree against args, which must include argv[0].
func (a *App) Run(ctx context.Context, args []string) error {
	return a.Command().Run(ctx, args)
}

// Main runs the CLI and returns a process exit code. Errors are reported on
// stderr in the same shape ansible-vault uses.
func Main(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	app := &App{Stdin: stdin, Stdout: stdout, Stderr: stderr}

	if err := app.Run(ctx, args); err != nil {
		_, _ = fmt.Fprintf(stderr, "ERROR! %v\n", err)

		return 1
	}

	return 0
}
