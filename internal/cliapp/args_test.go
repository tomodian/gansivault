package cliapp

import (
	"slices"
	"testing"
)

// TestShieldValueArgs pins down which tokens are treated as values, since the
// distinction is what keeps a misspelled flag from being encrypted by mistake.
func TestShieldValueArgs(t *testing.T) {
	root := (&App{}).Command()

	// s wraps a token the way shieldValueArgs is expected to.
	s := func(v string) string { return shield + v + shield }

	cases := []struct {
		name string
		args []string
		want []string
	}{
		{
			name: "a dash-leading value becomes a positional",
			args: []string{"gansivault", "encrypt_string", "-n", "k", "-----BEGIN KEY-----\nx\n"},
			want: []string{"gansivault", "encrypt_string", "-n", "k", s("-----BEGIN KEY-----\nx\n")},
		},
		{
			name: "a value before the flags is still a value",
			args: []string{"gansivault", "encrypt_string", "----BEGIN", "-n", "k"},
			want: []string{"gansivault", "encrypt_string", s("----BEGIN"), "-n", "k"},
		},
		{
			name: "an ordinary value is shielded against trimming",
			args: []string{"gansivault", "encrypt_string", "  padded  "},
			want: []string{"gansivault", "encrypt_string", s("  padded  ")},
		},
		{
			name: "a flag's own value is left alone",
			args: []string{"gansivault", "encrypt_string", "-o", "-", "--indent=4", "x"},
			want: []string{"gansivault", "encrypt_string", "-o", "-", "--indent=4", s("x")},
		},
		{
			name: "a boolean flag does not swallow the value after it",
			args: []string{"gansivault", "encrypt_string", "-J", "-----BEGIN"},
			want: []string{"gansivault", "encrypt_string", "-J", s("-----BEGIN")},
		},
		{
			name: "everything after a separator is a value",
			args: []string{"gansivault", "encrypt_string", "--", "--name", "-x"},
			want: []string{"gansivault", "encrypt_string", "--", s("--name"), s("-x")},
		},
		{
			name: "a plausible flag name is left for the parser to reject",
			args: []string{"gansivault", "encrypt_string", "--naem", "-hunter2"},
			want: []string{"gansivault", "encrypt_string", "--naem", "-hunter2"},
		},
		{
			name: "the alias is recognised too",
			args: []string{"gansivault", "encrypt-string", "-----BEGIN"},
			want: []string{"gansivault", "encrypt-string", s("-----BEGIN")},
		},
		{
			name: "root flags before the subcommand are skipped",
			args: []string{"gansivault", "--help", "encrypt_string", "-----BEGIN"},
			want: []string{"gansivault", "--help", "encrypt_string", s("-----BEGIN")},
		},
		{
			name: "other subcommands are untouched",
			args: []string{"gansivault", "encrypt", "-o", "-", "-----BEGIN"},
			want: []string{"gansivault", "encrypt", "-o", "-", "-----BEGIN"},
		},
		{
			name: "a file named encrypt_string does not trigger the rewrite",
			args: []string{"gansivault", "view", "encrypt_string", "-----BEGIN"},
			want: []string{"gansivault", "view", "encrypt_string", "-----BEGIN"},
		},
		{
			name: "no subcommand at all",
			args: []string{"gansivault"},
			want: []string{"gansivault"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := slices.Clone(tc.args)

			got := shieldValueArgs(root, tc.args)
			if !slices.Equal(got, tc.want) {
				t.Fatalf("got  %q\nwant %q", got, tc.want)
			}

			// os.Args is shared process state, so the caller's slice must
			// come back untouched.
			if !slices.Equal(tc.args, input) {
				t.Fatalf("mutated the input: %q", tc.args)
			}
		})
	}
}

func TestUnshieldValues(t *testing.T) {
	got := unshieldValues([]string{shield + "a\n" + shield, "plain", ""})

	if want := []string{"a\n", "plain", ""}; !slices.Equal(got, want) {
		t.Fatalf("got %q, want %q", got, want)
	}
}
