// Package policy compares a verdict set against what the operator said
// they wanted, which is what turns `whyopen check` from a report into a
// guardrail cron and CI can act on.
package policy

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/goccy/go-yaml"
)

// Version is the policy file schema this build understands. A file
// naming any other version is refused rather than read on a guess, the
// same posture facts documents take.
const Version = 1

// zoneName is the only zone whyopen models, and it matches
// model.InternetZone().Name. A policy naming any other zone is refused:
// silently ignoring a zone the operator wrote would turn their rules into
// a false green.
const zoneName = "internet"

// Entry is one allowed port, as written in the policy file: "22/tcp". It
// carries no address family, so it allows the port over IPv4 and IPv6
// alike.
type Entry struct {
	Port  uint16
	Proto string // tcp | udp
}

func (e Entry) String() string { return fmt.Sprintf("%d/%s", e.Port, e.Proto) }

// Policy is a parsed whyopen.yaml.
type Policy struct {
	Allow         []Entry
	FailOnUnknown bool
}

// document mirrors the file's shape. It is separate from Policy because
// the file is a surface humans type into and every field of it needs
// validating, while Policy is what the rest of the program may trust.
type document struct {
	Version       *int               `yaml:"version"`
	Zones         map[string]zoneDoc `yaml:"zones"`
	FailOnUnknown bool               `yaml:"fail_on_unknown"`
}

// Allow is []any rather than []string so that `- 22`, which YAML reads as
// an integer, reaches parseEntry as text and is refused there by name,
// instead of failing as a type error that says nothing useful.
type zoneDoc struct {
	Allow []any `yaml:"allow"`
}

// Load reads and validates a policy file. Every malformed or unrecognised
// thing in it is an error: a policy decides whether a run passes, so a key
// whyopen does not understand must stop the run rather than be ignored.
func Load(r io.Reader) (Policy, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return Policy{}, err
	}
	var doc document
	if err := yaml.UnmarshalWithOptions(b, &doc, yaml.Strict()); err != nil {
		return Policy{}, err
	}
	if doc.Version == nil {
		return Policy{}, fmt.Errorf("policy file has no version key; this build understands version %d", Version)
	}
	if *doc.Version != Version {
		return Policy{}, fmt.Errorf("policy version %d, this build understands %d", *doc.Version, Version)
	}

	p := Policy{FailOnUnknown: doc.FailOnUnknown}
	seen := map[Entry]bool{}
	for name, z := range doc.Zones {
		if name != zoneName {
			return Policy{}, fmt.Errorf("policy names zone %q, but this build models only %q", name, zoneName)
		}
		for _, raw := range z.Allow {
			e, err := parseEntry(fmt.Sprint(raw))
			if err != nil {
				return Policy{}, err
			}
			if seen[e] {
				continue
			}
			seen[e] = true
			p.Allow = append(p.Allow, e)
		}
	}
	sortEntries(p.Allow)
	return p, nil
}

// sortEntries puts an entry list in a stable order, so a parsed policy and
// a generated one can be compared and a generated file does not churn.
func sortEntries(es []Entry) {
	sort.Slice(es, func(i, j int) bool {
		if es[i].Port != es[j].Port {
			return es[i].Port < es[j].Port
		}
		return es[i].Proto < es[j].Proto
	})
}

func parseEntry(s string) (Entry, error) {
	port, proto, ok := strings.Cut(s, "/")
	if !ok {
		return Entry{}, fmt.Errorf("allow entry %q: want PORT/PROTO, for example 22/tcp", s)
	}
	if proto != "tcp" && proto != "udp" {
		return Entry{}, fmt.Errorf("allow entry %q: whyopen models tcp and udp, not %q", s, proto)
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 {
		return Entry{}, fmt.Errorf("allow entry %q: %q is not a port between 1 and 65535", s, port)
	}
	return Entry{Port: uint16(n), Proto: proto}, nil
}
