// Command flapjak is a very lightweight (featherweight) LDAP server that
// serves static records read-only.
//
//	Usage: flapjak --entries=STRING [flags]
//
//	flapjak is a simple server of static LDAP records.
//
//	Flags:
//	  -h, --help                   Show context-sensitive help.
//	      --entries=STRING         Name of jsonnet file containing LDAP entries
//	  -J, --jpath=dir              Add a library search dir
//	      --max-stack=500          Number of allowed stack frames of jsonnet VM
//	      --max-trace=20           Maximum number of stack frames output on error
//	  -V, --ext-str=var[=str]      Set extVar string (str from env if omitted)
//	      --ext-str-file=var[=filename]
//	                               Set extVar string from a file (filename from env
//	                               if omitted)
//	      --ext-code=var[=code]    Set extVar code (code from env if omitted)
//	      --ext-code-file=var[=filename]
//	                               Set extVar code from a file (filename from env if
//	                               omitted)
//	  -A, --tla-str=var[=str]      Set top-level arg string (str from env if
//	                               omitted)
//	      --tla-str-file=var[=filename]
//	                               Set top-level arg string from a file (filename
//	                               from env if omitted)
//	      --tla-code=var[=code]    Set top-level arg code (code from env if omitted)
//	      --tla-code-file=var[=filename]
//	                               Set top-level arg code from a file (filename from
//	                               env if omitted)
//	      --listen=":10389"        Listen address
//	      --version                Print program version
package main

import (
	"fmt"
	"log/slog"
	"strings"

	jnxkong "foxygo.at/jsonnext/kong"
	"github.com/alecthomas/kong"
)

var version string = "v0.0.0" // overridden in Makefile with `git describe` output.

const description = `
flapjak is a simple server of static LDAP records.
`

type CLI struct {
	Entries string           `required:"" help:"Name of jsonnet file containing LDAP entries"`
	Jnx     jnxkong.Config   `embed:""`
	Listen  string           `default:":10389" help:"Listen address"`
	Version kong.VersionFlag `help:"Print program version"`
}

func main() {
	cli := &CLI{
		Jnx: *jnxkong.NewConfig(),
	}
	kctx := kong.Parse(cli,
		kong.Description(description),
		kong.Vars{"version": version},
	)
	err := kctx.Run(cli)
	kctx.FatalIfErrorf(err)
}

func (cli *CLI) Run() error {
	vm := cli.Jnx.MakeVM("FLAPJAK_PATH")
	jsonEntries, err := vm.EvaluateFile(cli.Entries)
	if err != nil {
		return fmt.Errorf("could not read entries: %w", err)
	}
	slog.Info("Loading entries", "filename", cli.Entries)
	entries, err := ReadJSON(strings.NewReader(jsonEntries))
	if err != nil {
		return fmt.Errorf("could not load entries: %w", err)
	}

	db := NewDB()
	if err := db.AddEntries(entries); err != nil {
		return fmt.Errorf("could not add entries to db: %w", err)
	}

	slog.Info("Entries loaded", "count", len(entries))

	s, err := NewServer(db)
	if err != nil {
		return err
	}
	return s.Run(cli.Listen)
}
