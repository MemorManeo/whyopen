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
	"github.com/MemorManeo/whyopen/internal/policy"
	"github.com/MemorManeo/whyopen/internal/report"
)

const usage = `whyopen: what is actually reachable from the internet, and why.

Usage:
  whyopen collect [-o FILE]        snapshot this host into a facts document
  whyopen check [-facts FILE] [-explain PORT] [-policy FILE] [-json]
                                    report what is reachable, and why
  whyopen policy init [-o FILE]    write a policy from what is reachable now
  whyopen version                  print the build version

whyopen is read-only. It never creates, changes or deletes a rule.
`

// Exit codes, per docs/superpowers/specs/2026-08-28-whyopen-design.md.
const (
	exitOK        = 0
	exitViolation = 1
	exitUnknown   = 2
	exitError     = 3
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
// currentVersion is what this build reports about itself, resolved once
// for the two callers that need it.
func currentVersion() versionInfo {
	info, ok := debug.ReadBuildInfo()
	return resolveVersion(defaultVersionInfo(), info, ok)
}

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
	case "policy":
		os.Exit(runPolicy(os.Args[2:]))
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

func runPolicy(args []string) int {
	if len(args) == 0 || args[0] != "init" {
		fmt.Fprint(os.Stderr, "usage: whyopen policy init [-o FILE] [-facts FILE]\n")
		return exitError
	}
	fs := flag.NewFlagSet("policy init", flag.ContinueOnError)
	factsPath := fs.String("facts", "", "generate from this facts document instead of collecting one")
	out := fs.String("o", "-", "write the policy here, or - for stdout")
	if err := fs.Parse(args[1:]); err != nil {
		if err == flag.ErrHelp {
			fmt.Print(usage)
			return exitOK
		}
		// ContinueOnError already printed the parse error to fs.Output().
		return exitError
	}

	f, code := loadFacts(*factsPath)
	if code != exitOK {
		return code
	}
	// Every verdict from an unreadable ruleset is unknown, so the allow
	// list would come out empty and adopting it would fail every port on
	// the host for a reason that has nothing to do with the host.
	if f.Ruleset.ReadFailed {
		fmt.Fprintln(os.Stderr, "the nftables ruleset could not be read, so nothing is known to be reachable and the generated policy would allow nothing; re-run as root")
		return exitError
	}

	p, unresolved := policy.Init(model.Evaluate(f, model.InternetZone()))
	b := policy.Marshal(p, unresolved)

	if *out == "-" {
		os.Stdout.Write(b)
		return exitOK
	}
	// A policy file carries edits a human made, which regenerating it
	// would silently throw away. A facts document is disposable; this is
	// not.
	if _, err := os.Stat(*out); err == nil {
		fmt.Fprintf(os.Stderr, "%s already exists; policy init will not overwrite it\n", *out)
		return exitError
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", *out, err)
		return exitError
	}
	return exitOK
}

func runVersion() int {
	v := currentVersion()
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
	policyPath := fs.String("policy", "", "check the verdicts against this policy file")
	jsonOut := fs.Bool("json", false, "write the verdict set as a JSON document instead of a table")
	explain := fs.Int("explain", 0, "print the full rule path for this port")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Print(usage)
			return exitOK
		}
		// ContinueOnError already printed the parse error to fs.Output().
		return exitError
	}

	var pol policy.Policy
	if *policyPath != "" {
		var err error
		pol, err = loadPolicy(*policyPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "policy %s: %v\n", *policyPath, err)
			return exitError
		}
	}

	f, code := loadFacts(*factsPath)
	if code != exitOK {
		return code
	}

	zone := model.InternetZone()
	verdicts := model.Evaluate(f, zone)

	// The policy is checked against the whole verdict set before anything
	// is printed, so every output mode reports the same judgement and the
	// same exit code regardless of what it chose to show.
	var res *policy.Result
	if *policyPath != "" {
		r := policy.Check(pol, verdicts)
		res = &r
	}

	if *jsonOut {
		shown := verdicts
		if *explain != 0 {
			shown = onPort(verdicts, *explain)
		}
		err := report.JSON(os.Stdout, shown, report.JSONOptions{
			Version:      currentVersion().Version,
			Hostname:     f.Host.Hostname,
			Zone:         zone.Name,
			Warnings:     f.Warnings,
			Policy:       res,
			PolicySource: *policyPath,
			WithPath:     *explain != 0,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "write json: %v\n", err)
			return exitError
		}
		return checkExitCode(f, res)
	}

	if *explain != 0 {
		for _, v := range onPort(verdicts, *explain) {
			report.Explain(os.Stdout, v)
		}
	} else {
		report.Table(os.Stdout, verdicts, f.Warnings)
	}

	// The policy block prints in every text mode, including --explain, so
	// an exit code the policy produced always has a visible reason.
	if res != nil {
		report.Policy(os.Stdout, *res, *policyPath)
	}

	// One shared decision for every output mode: whatever check just
	// printed (table, explain, or a future mode), the exit code is what
	// cron and CI actually read, and a verdict built on an unreadable
	// ruleset is a tool error, not a clean run, no matter how it was
	// displayed.
	return checkExitCode(f, res)
}

// onPort narrows a verdict set to one port, which is what --explain asks
// for. Both families of it are kept: they are separate verdicts and can
// disagree.
func onPort(vs []model.Verdict, port int) []model.Verdict {
	var out []model.Verdict
	for _, v := range vs {
		if int(v.Endpoint.Port) == port {
			out = append(out, v)
		}
	}
	return out
}

// checkExitCode ranks the ways a run can end, worst first. An unreadable
// ruleset outranks everything because it makes every other conclusion
// void. A violation then outranks an unknown: one is something whyopen
// concluded, the other is something it could not.
func checkExitCode(f facts.Facts, res *policy.Result) int {
	if f.Ruleset.ReadFailed {
		fmt.Fprintln(os.Stderr, "the nftables ruleset could not be read, so every verdict above is unknown; re-run as root")
		return exitError
	}
	if res == nil {
		return exitOK
	}
	if len(res.Violations) > 0 {
		return exitViolation
	}
	if res.FailOnUnknown && len(res.Unknown) > 0 {
		return exitUnknown
	}
	return exitOK
}

// loadFacts reads a facts document, or collects one from this host when
// no path is given. The int is an exit code, already reported to stderr.
func loadFacts(path string) (facts.Facts, int) {
	var f facts.Facts
	if path == "" {
		f, err := collect.All(collect.Options{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "collect: %v\n", err)
			return f, exitError
		}
		return f, exitOK
	}
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		return f, exitError
	}
	if err := json.Unmarshal(b, &f); err != nil {
		fmt.Fprintf(os.Stderr, "parse %s: %v\n", path, err)
		return f, exitError
	}
	if f.SchemaVersion != facts.SchemaVersion {
		fmt.Fprintf(os.Stderr, "facts schema version %d, this build understands %d\n",
			f.SchemaVersion, facts.SchemaVersion)
		return f, exitError
	}
	// Only documents from outside this process are validated. One whyopen
	// just collected is structurally sound by construction, and refusing
	// to run against a live host over a collector bug would be a worse
	// failure than the one this prevents.
	if err := facts.Validate(f); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
		return f, exitError
	}
	// A snapshot from an older build may carry payloads this build can
	// decode and that one could not. Say so rather than quietly answering
	// differently from what the document itself records.
	if n := collect.Redecode(&f); n > 0 {
		fmt.Fprintf(os.Stderr, "re-decoded %d expression(s) this build understands and the collecting build did not\n", n)
	}
	return f, exitOK
}

func loadPolicy(path string) (policy.Policy, error) {
	file, err := os.Open(path)
	if err != nil {
		return policy.Policy{}, err
	}
	defer file.Close()
	return policy.Load(file)
}
