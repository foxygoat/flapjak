// Command flapjak is a very lightweight (featherweight) LDAP server that
// serves static records read-only.
//
//	Usage: flapjak [flags]
//
//	flapjak is a simple server of static LDAP records.
//
//	Flags:
//	  -h, --help       Show context-sensitive help.
//	  -V, --version    Print program version
package main

import "github.com/alecthomas/kong"

var version string = "v0.0.0" // overridden in Makefile with `git describe` output.

const description = `
flapjak is a simple server of static LDAP records.
`

type CLI struct {
	Version kong.VersionFlag `short:"V" help:"Print program version"`
}

func main() {
	cli := &CLI{}
	kctx := kong.Parse(cli,
		kong.Description(description),
		kong.Vars{"version": version},
	)
	err := kctx.Run(cli)
	kctx.FatalIfErrorf(err)
}
