// Command whyopen reports which ports on this host are reachable from the
// internet and which nftables rules decide that. It never modifies state.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime/debug"

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
  whyopen version                  print the build version

whyopen is read-only. It never creates, changes or deletes a rule.
`

// Exit codes, per docs/superpowers/specs/2026-08-28-whyopen-design.md.
const (
	exitOK    = 0
	exitError = 3
)

// The values a build reports when the linker injected nothing. Named
// because resolveVersion recognises them as "not set" and fills them in.
const (
	defaultVersion = "dev"
	defaultCommit  = "none"
	defaultDate    = "unknown"
)

// Set by the linker at release time.
var (
	version = defaultVersion
	commit  = defaultCommit
	date    = defaultDate
)

// versionInfo is the triple `whyopen version` prints.
type versionInfo struct {
	Version string
	Commit  string
	Date    string
}

// defaultVersionInfo returns what the linker injected, or the defaults
// above where it injected nothing.
func defaultVersionInfo() versionInfo {
	return versionInfo{Version: version, Commit: commit, Date: date}
}

// resolveVersion fills in what the linker did not. A binary from
// `go install module@version` carries no -X values at all and would
// otherwise call itself "dev", but the go command embeds the module
// version it installed, and for a build from a checkout the VCS revision
// and commit time as well. Whatever the linker did inject wins: a release
// build is told its own tag, which is more precise than either.
func resolveVersion(v versionInfo, info *debug.BuildInfo, ok bool) versionInfo {
	if !ok || info == nil {
		return v
	}
	// "(devel)" is what a build from a checkout records, and it names no
	// version at all, so it is no better than the default it would replace.
	if v.Version == defaultVersion && info.Main.Version != "" && info.Main.Version != "(devel)" {
		v.Version = info.Main.Version
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if v.Commit == defaultCommit {
				v.Commit = s.Value
			}
		case "vcs.time":
			if v.Date == defaultDate {
				v.Date = s.Value
			}
		}
	}
	return v
}

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
	case "version":
		os.Exit(runVersion())
	case "-h", "--help", "help":
		fmt.Print(usage)
		os.Exit(exitOK)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n%s", os.Args[1], usage)
		os.Exit(exitError)
	}
}

func runVersion() int {
	info, ok := debug.ReadBuildInfo()
	v := resolveVersion(defaultVersionInfo(), info, ok)
	fmt.Printf("whyopen %s (commit %s, built %s)\n", v.Version, v.Commit, v.Date)
	return exitOK
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
	} else {
		report.Table(os.Stdout, verdicts, f.Warnings)
	}

	// One shared decision for every output mode: whatever check just
	// printed (table, explain, or a future mode), the exit code is what
	// cron and CI actually read, and a verdict built on an unreadable
	// ruleset is a tool error, not a clean run, no matter how it was
	// displayed.
	return checkExitCode(f)
}

func checkExitCode(f facts.Facts) int {
	if f.Ruleset.ReadFailed {
		fmt.Fprintln(os.Stderr, "the nftables ruleset could not be read, so every verdict above is unknown; re-run as root")
		return exitError
	}
	return exitOK
}
