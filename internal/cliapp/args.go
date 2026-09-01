package cliapp

import (
	"regexp"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
)

// doubleDash is the conventional end-of-flags separator.
const doubleDash = "--"

// shield wraps an encrypt_string value on its way past the flag parser. A NUL
// byte terminates a C string, so it cannot appear inside an element of argv:
// no real invocation can collide with it, and it is not whitespace, so it
// survives a trim.
const shield = "\x00"

// cmdEncryptString is the subcommand whose positional arguments are secrets
// rather than file names.
const cmdEncryptString = "encrypt_string"

// flagPattern matches a token that could name a flag: one or two dashes, then a
// letter, then name characters, optionally followed by "=value". Anything else
// after the dashes — a third dash, a space, a newline — cannot be a flag name,
// which is what makes "-----BEGIN PRIVATE KEY-----" safe to reclassify.
var flagPattern = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9._-]*(=|$)`)

// shieldValueArgs wraps the positional arguments of encrypt_string so they
// reach the action as the user typed them. urfave/cli otherwise mangles them
// twice over: a value beginning with "-", a PEM key being the usual case, is
// rejected as an unknown flag, and every positional argument is silently
// trimmed of surrounding whitespace, which quietly drops the newline a key
// ends with. Shell quoting cannot express the difference, because the quotes
// are gone long before argv arrives, so the distinction is drawn here.
//
// Only tokens that could not possibly be a flag name are reclassified. A
// plausible flag name is still parsed as one, so a misspelled flag stays an
// error rather than being silently encrypted.
func shieldValueArgs(root *cli.Command, args []string) []string {
	start, sub := encryptStringArgs(root, args)
	if sub == nil {
		return args
	}

	out := slices.Clone(args)

	for i := start; i < len(out); i++ {
		tok := out[i]

		// Everything past an explicit separator is a value already.
		if tok == doubleDash {
			for j := i + 1; j < len(out); j++ {
				out[j] = shield + out[j] + shield
			}

			break
		}

		if name, ok := parsedFlagName(tok); ok {
			// A flag's own value is never a positional argument, so step
			// over it; "-o -" must keep meaning standard output.
			if !strings.Contains(tok, "=") && takesValue(lookupFlag(sub, name)) {
				i++
			}

			continue
		}

		out[i] = shield + tok + shield
	}

	return out
}

// unshieldValues undoes shieldValueArgs. It is applied to the positional
// arguments of encrypt_string only, which are the only ones ever shielded.
func unshieldValues(values []string) []string {
	out := make([]string, len(values))
	for i, v := range values {
		out[i] = strings.TrimSuffix(strings.TrimPrefix(v, shield), shield)
	}

	return out
}

// encryptStringArgs locates an encrypt_string invocation in args and returns
// the index of its first argument along with the subcommand itself. A nil
// command means some other subcommand was invoked.
func encryptStringArgs(root *cli.Command, args []string) (int, *cli.Command) {
	sub := root.Command(cmdEncryptString)
	if sub == nil {
		return 0, nil
	}

	names := append([]string{sub.Name}, sub.Aliases...)

	// args[0] is the program name. The root command's own flags are all
	// boolean, so anything dash-leading before the subcommand is one of them
	// and never swallows the token after it.
	for i := 1; i < len(args); i++ {
		switch {
		case slices.Contains(names, args[i]):
			return i + 1, sub
		case strings.HasPrefix(args[i], "-"):
			continue
		default:
			return 0, nil
		}
	}

	return 0, nil
}

// parsedFlagName returns the name a token would be parsed as, and whether the
// token could name a flag at all.
func parsedFlagName(tok string) (string, bool) {
	if !flagPattern.MatchString(tok) {
		return "", false
	}

	name, _, _ := strings.Cut(strings.TrimLeft(tok, "-"), "=")

	return name, true
}

// lookupFlag finds the flag a name refers to, or nil when the command defines
// no such flag.
func lookupFlag(cmd *cli.Command, name string) cli.Flag {
	for _, f := range cmd.Flags {
		if slices.Contains(f.Names(), name) {
			return f
		}
	}

	return nil
}

// takesValue reports whether a flag consumes the argument that follows it.
// Unknown flags are assumed not to, so that the parser is left to complain
// about them rather than swallowing the next token.
//
// TakesValue is answered from the flag's type parameter, so unlike IsBoolFlag
// it is meaningful before the command has been parsed.
func takesValue(f cli.Flag) bool {
	d, ok := f.(interface{ TakesValue() bool })

	return ok && d.TakesValue()
}
