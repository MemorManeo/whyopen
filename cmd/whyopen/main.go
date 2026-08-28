// Command whyopen reports which ports on this host are reachable from the
// internet and which nftables rules decide that. It never modifies state.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/MemorManeo/whyopen/internal/collect"
	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/MemorManeo/whyopen/internal/report"
)

const usage = `whyopen: what is actually reachable from the internet, and why.

Usage:
  whyopen collect [-o FILE]        snapshot this host into a facts document
  whyopen check [-facts FILE] [-explain PORT]
                                    report what is reachable, and why

whyopen is read-only. It never creates, changes or deletes a rule.
`

// Exit codes, per docs/superpowers/specs/2026-08-28-whyopen-design.md.
const (
	exitOK    = 0
	exitError = 3
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(exitError)
	}
	switch os.Args[1] {
	case "collect":
		os.Exit(runCollect(os.Args[2:]))
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(exitError)
	}
}

func runCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	out := fs.String("o", "-", "write the facts document here, or - for stdout")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Print(usage)
			return exitOK
		}
		// ContinueOnError already printed the parse error to fs.Output().
		return exitError
	}

	f, err := collect.All(collect.Options{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "collect: %v\n", err)
		return exitError
	}

	w := os.Stdout
	var file *os.File
	if *out != "-" {
		file, err = os.Create(*out)
		if err != nil {
			fmt.Fprintf(os.Stderr, "create %s: %v\n", *out, err)
			return exitError
		}
		w = file
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil {
		fmt.Fprintf(os.Stderr, "encode: %v\n", err)
		if file != nil {
			file.Close()
		}
		return exitError
	}
	if file != nil {
		if err := file.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "close %s: %v\n", *out, err)
			return exitError
		}
	}
	return exitOK
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	factsPath := fs.String("facts", "", "evaluate this facts document instead of collecting one")
	explain := fs.Int("explain", 0, "print the full rule path for this port")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Print(usage)
			return exitOK
		}
		// ContinueOnError already printed the parse error to fs.Output().
		return exitError
	}

	var (
		f   facts.Facts
		err error
	)
	if *factsPath != "" {
		b, readErr := os.ReadFile(*factsPath)
		if readErr != nil {
			fmt.Fprintf(os.Stderr, "read %s: %v\n", *factsPath, readErr)
			return exitError
		}
		if err = json.Unmarshal(b, &f); err != nil {
			fmt.Fprintf(os.Stderr, "parse %s: %v\n", *factsPath, err)
			return exitError
		}
		if f.SchemaVersion != facts.SchemaVersion {
			fmt.Fprintf(os.Stderr, "facts schema version %d, this build understands %d\n",
				f.SchemaVersion, facts.SchemaVersion)
			return exitError
		}
	} else {
		f, err = collect.All(collect.Options{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "collect: %v\n", err)
			return exitError
		}
	}

	verdicts := model.Evaluate(f, model.InternetZone())

	if *explain != 0 {
		for _, v := range verdicts {
			if int(v.Endpoint.Port) == *explain {
				report.Explain(os.Stdout, v)
			}
		}
		return exitOK
	}
	report.Table(os.Stdout, verdicts, f.Warnings)
	return exitOK
}
