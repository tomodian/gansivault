package cliapp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tomodian/gansivault"
	"github.com/urfave/cli/v3"
)

func TestNewUsesProcessStreams(t *testing.T) {
	t.Parallel()

	app := New()

	if app.Stdin != os.Stdin || app.Stdout != os.Stdout || app.Stderr != os.Stderr {
		t.Fatal("New should bind the process streams")
	}
}

func TestPromptDefaultsToTheStreams(t *testing.T) {
	t.Parallel()

	var errOut bytes.Buffer

	app := &App{Stdin: strings.NewReader("typed\n"), Stdout: &bytes.Buffer{}, Stderr: &errOut}

	got, err := app.prompt()("Vault password: ")
	if err != nil {
		t.Fatalf("prompt: %v", err)
	}

	if string(got) != "typed" {
		t.Fatalf("got %q", got)
	}

	if !strings.Contains(errOut.String(), "Vault password") {
		t.Fatalf("the prompt should go to stderr, got %q", errOut.String())
	}

	app.Prompt = func(string) ([]byte, error) { return []byte("override"), nil }

	got, err = app.prompt()("x")
	if err != nil || string(got) != "override" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestNote(t *testing.T) {
	t.Parallel()

	var errOut bytes.Buffer

	(&App{Stderr: &errOut}).note("hello %s", "world")

	if errOut.String() != "hello world\n" {
		t.Fatalf("got %q", errOut.String())
	}
}

func TestCommandMetadata(t *testing.T) {
	t.Parallel()

	root := (&App{}).Command()

	if root.Name != "gansivault" || root.Version != Version {
		t.Fatalf("got name %q version %q", root.Name, root.Version)
	}

	if !root.DisableSliceFlagSeparator {
		t.Fatal("comma splitting must stay off so paths with commas survive")
	}

	want := map[string]bool{
		"encrypt":        false,
		"decrypt":        false,
		"view":           false,
		"create":         false,
		"edit":           false,
		"rekey":          false,
		"encrypt_string": false,
	}

	for _, sub := range root.Commands {
		if _, ok := want[sub.Name]; ok {
			want[sub.Name] = true
		}
	}

	for name, found := range want {
		if !found {
			t.Fatalf("subcommand %q is missing", name)
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"--help"}, {"--version"}, {"encrypt", "--help"}} {
		var out bytes.Buffer

		app := &App{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &bytes.Buffer{}}

		if err := app.Run(context.Background(), append([]string{"gansivault"}, args...)); err != nil {
			t.Fatalf("%v: %v", args, err)
		}

		if out.Len() == 0 {
			t.Fatalf("%v produced no output", args)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	t.Parallel()

	app := &App{Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}

	if err := app.Run(context.Background(), []string{"gansivault", "nope"}); err == nil {
		t.Fatal("want an error for an unknown command")
	}
}

func TestMain_(t *testing.T) {
	dir := t.TempDir()

	pass := filepath.Join(dir, "pw")
	if err := os.WriteFile(pass, []byte(testPassword), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	vault, err := os.ReadFile(filepath.Join(fixturesDir(t), "hello_11.vault"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	target := filepath.Join(dir, "hello.vault")
	if err := os.WriteFile(target, vault, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Run("success", func(t *testing.T) {
		var out, errOut bytes.Buffer

		code := Main(context.Background(),
			[]string{"gansivault", "view", "--vault-password-file", pass, target},
			strings.NewReader(""), &out, &errOut)

		if code != 0 {
			t.Fatalf("exit code %d, stderr %q", code, errOut.String())
		}

		if out.String() != helloPlaintext {
			t.Fatalf("got %q", out.String())
		}
	})

	t.Run("failure", func(t *testing.T) {
		var out, errOut bytes.Buffer

		code := Main(context.Background(),
			[]string{"gansivault", "view", target},
			strings.NewReader(""), &out, &errOut)

		if code != 1 {
			t.Fatalf("exit code %d, want 1", code)
		}

		if !strings.HasPrefix(errOut.String(), "ERROR! ") {
			t.Fatalf("stderr should use the ansible-vault error prefix, got %q", errOut.String())
		}
	})
}

func TestPasswordFlagsReadEnvironment(t *testing.T) {
	dir := t.TempDir()

	pass := filepath.Join(dir, "pw")
	if err := os.WriteFile(pass, []byte(testPassword), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	vault, err := os.ReadFile(filepath.Join(fixturesDir(t), "hello_11.vault"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	target := filepath.Join(dir, "hello.vault")
	if err := os.WriteFile(target, vault, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	t.Setenv("ANSIBLE_VAULT_IDENTITY_LIST", "")
	t.Setenv("ANSIBLE_VAULT_PASSWORD_FILE", pass)

	var out bytes.Buffer

	app := &App{Stdin: strings.NewReader(""), Stdout: &out, Stderr: &bytes.Buffer{}}

	if err := app.Run(context.Background(), []string{"gansivault", "view", target}); err != nil {
		t.Fatalf("view: %v", err)
	}

	if out.String() != helloPlaintext {
		t.Fatalf("got %q", out.String())
	}
}

func TestDistinctIDs(t *testing.T) {
	t.Parallel()

	got := distinctIDs([]gansivault.Secret{
		gansivault.NewStaticSecret("a", []byte("1")),
		gansivault.NewStaticSecret("b", []byte("2")),
		gansivault.NewStaticSecret("a", []byte("3")),
	})

	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("got %v", got)
	}
}

func TestTargetsAndResolveOutputs(t *testing.T) {
	t.Parallel()

	var captured *cli.Command

	app := &cli.Command{
		Name:  "root",
		Flags: []cli.Flag{&cli.StringFlag{Name: flagOutput}},
		Action: func(_ context.Context, cmd *cli.Command) error {
			captured = cmd

			return nil
		},
	}

	t.Run("no arguments means stdin", func(t *testing.T) {
		if err := app.Run(context.Background(), []string{"root"}); err != nil {
			t.Fatalf("run: %v", err)
		}

		if got := targets(captured); len(got) != 1 || got[0] != stdioName {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("in place without --output", func(t *testing.T) {
		if err := app.Run(context.Background(), []string{"root", "a", "b"}); err != nil {
			t.Fatalf("run: %v", err)
		}

		in := targets(captured)

		out, err := resolveOutputs(captured, in)
		if err != nil {
			t.Fatalf("resolveOutputs: %v", err)
		}

		if len(out) != 2 || out[0] != "a" || out[1] != "b" {
			t.Fatalf("got %v", out)
		}
	})

	t.Run("single input with --output", func(t *testing.T) {
		if err := app.Run(context.Background(), []string{"root", "--output", "dst", "a"}); err != nil {
			t.Fatalf("run: %v", err)
		}

		out, err := resolveOutputs(captured, targets(captured))
		if err != nil {
			t.Fatalf("resolveOutputs: %v", err)
		}

		if len(out) != 1 || out[0] != "dst" {
			t.Fatalf("got %v", out)
		}
	})

	t.Run("multiple inputs with --output", func(t *testing.T) {
		if err := app.Run(context.Background(), []string{"root", "--output", "dst", "a", "b"}); err != nil {
			t.Fatalf("run: %v", err)
		}

		if _, err := resolveOutputs(captured, targets(captured)); !errors.Is(err, errOutputSingleFile) {
			t.Fatalf("got %v, want errOutputSingleFile", err)
		}
	})
}

func TestBuildSecretsSkipsEmptyValues(t *testing.T) {
	t.Parallel()

	var captured *cli.Command

	root := &cli.Command{
		Name:                      "root",
		DisableSliceFlagSeparator: true,
		Flags:                     passwordFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			captured = cmd

			return nil
		},
	}

	if err := root.Run(context.Background(), []string{
		"root",
		"--vault-id", "",
		"--vault-id", "dev@prompt",
		"--vault-password-file", "",
		"--vault-password-file", "/etc/vault.pass",
	}); err != nil {
		t.Fatalf("run: %v", err)
	}

	app := &App{Prompt: func(string) ([]byte, error) { return []byte("x"), nil }}

	secrets, err := app.buildSecrets(captured)
	if err != nil {
		t.Fatalf("buildSecrets: %v", err)
	}

	if len(secrets) != 2 {
		t.Fatalf("got %d secrets, want 2 (empty values skipped)", len(secrets))
	}

	if secrets[0].ID() != "dev" || secrets[1].ID() != gansivault.DefaultVaultID {
		t.Fatalf("got ids %q and %q", secrets[0].ID(), secrets[1].ID())
	}
}

func TestPasswordFileIsNotSplitOnAtSign(t *testing.T) {
	t.Parallel()

	// Ansible treats --vault-password-file as a bare path under the default
	// identity, so a path containing "@" must survive intact.
	const path = "/home/user@corp/.vault_pass"

	var captured *cli.Command

	root := &cli.Command{
		Name:                      "root",
		DisableSliceFlagSeparator: true,
		Flags:                     passwordFlags(),
		Action: func(_ context.Context, cmd *cli.Command) error {
			captured = cmd

			return nil
		},
	}

	if err := root.Run(context.Background(), []string{"root", "--vault-pass-file", path}); err != nil {
		t.Fatalf("run: %v", err)
	}

	secrets, err := (&App{}).buildSecrets(captured)
	if err != nil {
		t.Fatalf("buildSecrets: %v", err)
	}

	if len(secrets) != 1 {
		t.Fatalf("got %d secrets, want 1", len(secrets))
	}

	file, ok := secrets[0].(*gansivault.FileSecret)
	if !ok {
		t.Fatalf("got %T, want *gansivault.FileSecret", secrets[0])
	}

	if file.Path() != path {
		t.Fatalf("got path %q, want %q", file.Path(), path)
	}

	if file.ID() != gansivault.DefaultVaultID {
		t.Fatalf("got id %q, want %q", file.ID(), gansivault.DefaultVaultID)
	}
}

func TestRekeyPasswordFileIsNotSplitOnAtSign(t *testing.T) {
	t.Parallel()

	const path = "/home/user@corp/.vault_new"

	var captured *cli.Command

	root := &cli.Command{
		Name: "root",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: flagNewVaultID},
			&cli.StringFlag{Name: flagNewVaultPasswordFile},
		},
		Action: func(_ context.Context, cmd *cli.Command) error {
			captured = cmd

			return nil
		},
	}

	if err := root.Run(context.Background(), []string{"root", "--new-vault-password-file", path}); err != nil {
		t.Fatalf("run: %v", err)
	}

	file, ok := (&App{}).rekeySecret(captured).(*gansivault.FileSecret)
	if !ok {
		t.Fatal("want a *gansivault.FileSecret")
	}

	if file.Path() != path || file.ID() != gansivault.DefaultVaultID {
		t.Fatalf("got id %q path %q", file.ID(), file.Path())
	}
}
