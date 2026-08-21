package gansivault

import "strings"

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
