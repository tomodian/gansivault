package gansivault

import (
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// DefaultYAMLIndent is the body indentation ansible-vault encrypt_string uses.
const DefaultYAMLIndent = 10

// FormatYAML renders a vault payload as an Ansible YAML block scalar, the
// format produced by "ansible-vault encrypt_string".
//
// With a name:
//
//	myvar: !vault |
//	          $ANSIBLE_VAULT;1.1;AES256
//	          6162...
//
// With an empty name the "myvar: " prefix is omitted. An indent of zero falls
// back to DefaultYAMLIndent.
func FormatYAML(vaultText []byte, name string, indent int) string {
	if indent <= 0 {
		indent = DefaultYAMLIndent
	}

	var b strings.Builder

	if name != "" {
		b.WriteString(name)
		b.WriteString(": ")
	}

	b.WriteString("!vault |")

	pad := strings.Repeat(" ", indent)
	for _, line := range strings.Split(strings.TrimRight(string(vaultText), "\n"), "\n") {
		b.WriteString("\n")
		b.WriteString(pad)
		b.WriteString(line)
	}

	return b.String()
}

// ExtractVaultText pulls the raw vault payload out of a YAML block scalar such
// as the one FormatYAML produces, undoing the "name: !vault |" header and the
// block indentation. Input that is already a bare vault payload is returned
// with each line trimmed, so this is safe to call unconditionally.
func ExtractVaultText(s string) string {
	var out []string

	for _, line := range strings.Split(s, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		if strings.HasSuffix(trimmed, "!vault |") {
			out = out[:0]

			continue
		}

		out = append(out, trimmed)
	}

	return strings.Join(out, "\n")
}

// vaultBlockRe matches the header line of an inline "!vault" block scalar, the
// shape "ansible-vault encrypt_string" writes:
//
//	secret: !vault |
//	- !vault |
//	!vault |
//
// Group one is the indentation, group two whatever sits between it and the tag
// (a mapping key, a sequence dash, both, or nothing).
var vaultBlockRe = regexp.MustCompile(`^([ \t]*)((?:- +)?(?:[^:#]+: +)?)!vault +\|[+-]?[ \t]*$`)

// plainScalarRe matches values that can be written as a YAML plain scalar
// without changing meaning. It is deliberately narrow: anything starting with a
// digit, sign or punctuation, and anything holding a space, is quoted instead.
var plainScalarRe = regexp.MustCompile(`^[A-Za-z_/][A-Za-z0-9_./@+-]*$`)

// reservedPlain lists the plain scalars a YAML 1.1 reader such as PyYAML
// resolves to a boolean or a null rather than to a string.
var reservedPlain = map[string]bool{
	"y": true, "yes": true, "n": true, "no": true,
	"true": true, "false": true, "on": true, "off": true,
	"null": true, "nil": true, "none": true,
}

// DecryptYAML rewrites a YAML document, replacing every inline "!vault" block
// scalar with its decrypted value. Everything else in the document, including
// comments, key order and formatting, is passed through untouched.
//
//	secret: !vault |          becomes          secret: hunter2
//	  $ANSIBLE_VAULT;1.1;AES256
//	  3530...
//
// Blocks at any depth are handled. A value that spans several lines is written
// as a block scalar, a value that would be ambiguous as a plain scalar is
// double quoted, and a value that is not valid UTF-8 is an error.
//
// A document with no "!vault" block comes back unchanged, so this is safe to
// run over a whole tree of YAML.
func (v *Vault) DecryptYAML(doc []byte) ([]byte, error) {
	return inlineDecryptYAML(doc, v.Decrypt)
}

// inlineDecryptYAML is the engine behind DecryptYAML, taking the decryption
// step as a function so it can be tested without a vault.
func inlineDecryptYAML(doc []byte, decrypt func([]byte) ([]byte, error)) ([]byte, error) {
	lines := strings.Split(string(doc), "\n")
	out := make([]string, 0, len(lines))

	for i := 0; i < len(lines); {
		m := vaultBlockRe.FindStringSubmatch(lines[i])
		if m == nil {
			out = append(out, lines[i])
			i++

			continue
		}

		body, next := vaultBlockBody(lines, i+1, m[1])

		vaultText := ExtractVaultText(strings.Join(body, "\n"))
		if vaultText == "" {
			// A header with no block under it is not something we can rewrite,
			// so leave it for the caller's YAML parser to complain about.
			out = append(out, lines[i])
			i++

			continue
		}

		plaintext, err := decrypt([]byte(vaultText))
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}

		if !utf8.Valid(plaintext) {
			return nil, fmt.Errorf("line %d: %w", i+1, ErrNotUTF8)
		}

		out = append(out, renderScalar(m[1], m[2], string(plaintext)))
		i = next
	}

	return []byte(strings.Join(out, "\n")), nil
}

// vaultBlockBody collects the lines belonging to a block scalar opened at the
// given indentation, returning them and the index of the first line after the
// block. Blank lines inside the block are kept, blank lines trailing it are
// not.
func vaultBlockBody(lines []string, start int, indent string) ([]string, int) {
	width := indentWidth(indent)
	end := start

	for i := start; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == "" {
			continue
		}

		if indentWidth(lines[i]) <= width {
			break
		}

		end = i + 1
	}

	return lines[start:end], end
}

// indentWidth counts the leading whitespace of a line.
func indentWidth(line string) int {
	return len(line) - len(strings.TrimLeft(line, " \t"))
}

// renderScalar rewrites one "!vault" header line as the plaintext value it
// stands for. indent and lead are the two leading groups of vaultBlockRe.
func renderScalar(indent, lead, s string) string {
	body := strings.TrimRight(s, "\n")
	trailing := len(s) - len(body)

	switch {
	case trailing == 0 && !strings.Contains(body, "\n"):
		return indent + lead + plainOrQuoted(body)
	case trailing <= 1 && blockSafe(body):
		return blockScalar(indent, lead, body, trailing == 1)
	default:
		// Trailing blank lines and content a block scalar would mangle survive
		// double quoting, which can express any string on one line.
		return indent + lead + quoteYAML(s)
	}
}

// plainOrQuoted renders a single line value, quoting whenever a plain scalar
// would read back as a different value or as a different type.
func plainOrQuoted(s string) string {
	if plainScalarRe.MatchString(s) && !reservedPlain[strings.ToLower(s)] {
		return s
	}

	return quoteYAML(s)
}

// blockSafe reports whether body round trips through a literal block scalar.
// Carriage returns, trailing whitespace and a first line that starts with
// whitespace all either change the value or need an indentation indicator, so
// they are handled by quoting instead.
func blockSafe(body string) bool {
	if body == "" || strings.ContainsRune(body, '\r') || strings.HasPrefix(body, " ") || strings.HasPrefix(body, "\t") {
		return false
	}

	for _, line := range strings.Split(body, "\n") {
		if line != strings.TrimRight(line, " \t") {
			return false
		}
	}

	return true
}

// blockScalar renders body as a literal block scalar indented two columns past
// the header. keepNewline picks the chomping indicator: "|" keeps the single
// trailing newline the value ended with, "|-" strips it.
func blockScalar(indent, lead, body string, keepNewline bool) string {
	var b strings.Builder

	b.WriteString(indent)
	b.WriteString(lead)
	b.WriteString("|")

	if !keepNewline {
		b.WriteString("-")
	}

	pad := indent + "  "

	for _, line := range strings.Split(body, "\n") {
		b.WriteString("\n")

		// Empty lines stay empty rather than becoming trailing whitespace.
		if line != "" {
			b.WriteString(pad)
			b.WriteString(line)
		}
	}

	return b.String()
}

// quoteYAML renders s as a YAML double quoted scalar, which can carry any
// string on a single line.
func quoteYAML(s string) string {
	var b strings.Builder

	b.WriteString(`"`)

	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 || r == 0x7f {
				fmt.Fprintf(&b, `\x%02x`, r)

				continue
			}

			b.WriteRune(r)
		}
	}

	b.WriteString(`"`)

	return b.String()
}
