package cliapp

import "golang.org/x/term"

// termIsTerminal and termReadPassword isolate the only two calls this tool
// makes into golang.org/x/term, keeping the terminal dependency out of the
// library package entirely.
var (
	termIsTerminal   = term.IsTerminal
	termReadPassword = term.ReadPassword
)
