// Command gansivault is an ansible-vault compatible encryption tool.
//
//	gansivault encrypt --vault-password-file ~/.vault_pass secrets.yml
//	gansivault decrypt --vault-password-file ~/.vault_pass secrets.yml
//	gansivault view    --vault-id prod@~/.vault_prod       secrets.yml
package main

import (
	"context"
	"os"

	"github.com/tomodian/gansivault/internal/cliapp"
)

// osExit is indirected so the entry point itself stays testable.
var osExit = os.Exit

func main() {
	osExit(cliapp.Main(context.Background(), os.Args, os.Stdin, os.Stdout, os.Stderr))
}
