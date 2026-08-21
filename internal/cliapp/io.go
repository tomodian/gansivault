package cliapp

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/tomodian/gansivault"
)

// stdioName is the conventional placeholder for standard input/output.
const stdioName = "-"

// defaultFileMode is used for files this tool creates itself.
const defaultFileMode os.FileMode = 0o600

// isTerminal reports whether f is attached to a terminal. It is a variable so
// tests can exercise both branches of the password prompt.
var isTerminal = func(f *os.File) bool {
	return termIsTerminal(int(f.Fd()))
}

// readPasswordNoEcho reads a line from a terminal with echo disabled.
var readPasswordNoEcho = func(f *os.File) ([]byte, error) {
	return termReadPassword(int(f.Fd()))
}

// createTemp is indirected so tests can hand back a file handle that is
// already closed, exercising the write failure path of editInTemp.
var createTemp = os.CreateTemp

// launchEditor runs an interactive editor over path. The editor string may
// carry arguments, e.g. "code --wait".
var launchEditor = func(ctx context.Context, editor, path string, in io.Reader, out, errOut io.Writer) error {
	fields := strings.Fields(editor)
	if len(fields) == 0 {
		return fmt.Errorf("gansivault: no editor configured; set $EDITOR")
	}

	cmd := exec.CommandContext(ctx, fields[0], append(fields[1:], path)...) // #nosec G204 -- the editor comes from the user's own $EDITOR
	cmd.Stdin = in
	cmd.Stdout = out
	cmd.Stderr = errOut

	return cmd.Run()
}

// editorCommand resolves the editor to use, following Ansible's preference for
// $EDITOR with a vi fallback.
func editorCommand() string {
	for _, key := range []string{"ANSIBLE_EDITOR", "EDITOR", "VISUAL"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			return v
		}
	}

	return "vi"
}

// newPrompt builds a PromptFunc that reads without echo when stdin is a
// terminal and falls back to a plain line read otherwise, so that piping a
// password into the tool works in CI.
func newPrompt(in io.Reader, out io.Writer) gansivault.PromptFunc {
	return func(prompt string) ([]byte, error) {
		_, _ = fmt.Fprint(out, prompt)

		if f, ok := in.(*os.File); ok && isTerminal(f) {
			pw, err := readPasswordNoEcho(f)
			_, _ = fmt.Fprintln(out)

			return pw, err
		}

		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && err != io.EOF {
			return nil, err
		}

		return []byte(strings.TrimRight(line, "\r\n")), nil
	}
}

// readInput loads a named file, or standard input for "" and "-".
func (a *App) readInput(name string) ([]byte, error) {
	if name == "" || name == stdioName {
		return io.ReadAll(a.Stdin)
	}

	data, err := os.ReadFile(name) // #nosec G304 -- operating on the file the user named
	if err != nil {
		return nil, fmt.Errorf("gansivault: %w", err)
	}

	return data, nil
}

// writeOutput writes data to a named file, or to standard output for "" and
// "-". mode is used only when creating a new file.
func (a *App) writeOutput(name string, data []byte, mode os.FileMode) error {
	if name == "" || name == stdioName {
		_, err := a.Stdout.Write(data)

		return err
	}

	if err := os.WriteFile(name, data, mode); err != nil {
		return fmt.Errorf("gansivault: %w", err)
	}

	return nil
}

// fileMode returns the permissions of an existing file, falling back to
// defaultFileMode when the file is absent or is standard input.
func fileMode(name string) os.FileMode {
	if name == "" || name == stdioName {
		return defaultFileMode
	}

	info, err := os.Stat(name)
	if err != nil {
		return defaultFileMode
	}

	return info.Mode().Perm()
}

// ensureTrailingNewline appends a newline if data does not already end with
// one, matching how ansible-vault writes vault files.
func ensureTrailingNewline(data []byte) []byte {
	if len(data) > 0 && data[len(data)-1] == '\n' {
		return data
	}

	return append(append([]byte{}, data...), '\n')
}

// readAllStdin drains standard input.
func (a *App) readAllStdin() ([]byte, error) {
	var buf bytes.Buffer

	if _, err := io.Copy(&buf, a.Stdin); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
