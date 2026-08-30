package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/MemorManeo/whyopen/internal/probe"
)

// probeRunner is how check reaches another machine. It is a variable so
// the wiring around it can be tested without an ssh server; nothing but a
// test ever replaces it.
var probeRunner probe.Runner = probe.SSHRunner{}

func runProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ContinueOnError)
	target := fs.String("target", "", "the address to probe")
	ports := fs.String("ports", "", "ports to probe, e.g. 22,80,8000-8100")
	timeout := fs.Duration("timeout", 2*time.Second, "how long to wait for an answer")
	asJSON := fs.Bool("json", false, "write the results as a JSON document")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			fmt.Print(usage)
			return exitOK
		}
		// ContinueOnError already printed the parse error to fs.Output().
		return exitError
	}
	if *target == "" {
		fmt.Fprintln(os.Stderr, "probe: -target is required")
		return exitError
	}
	list, err := probe.ParsePorts(*ports)
	if err != nil {
		fmt.Fprintf(os.Stderr, "probe: %v\n", err)
		return exitError
	}

	results := probe.Run(context.Background(), probe.Options{
		Target: *target, Ports: list, Timeout: *timeout,
	})

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(probe.Document{
			SchemaVersion: probe.DocumentVersion, Target: *target, Results: results,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "probe: %v\n", err)
			return exitError
		}
		return exitOK
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PORT\tSTATE\tDETAIL")
	for _, r := range results {
		fmt.Fprintf(tw, "%d/%s\t%s\t%s\n", r.Port, r.Proto, r.State, r.Detail)
	}
	tw.Flush()
	return exitOK
}

// probeThisHost asks another machine to probe every TCP port this one is
// listening on, one global address per family, and folds what it found
// into the verdict set.
//
// A probe that could not run is a tool error, not a quiet fall back to the
// model: the run was asked to check the model against reality, and a run
// that silently did not would look exactly like one that did.
func probeThisHost(source string, f facts.Facts, vs []model.Verdict) ([]model.Verdict, []probe.Disagreement, error) {
	host, err := probe.ParseSSHTarget(source)
	if err != nil {
		return vs, nil, err
	}

	var all []probe.Disagreement
	probed := 0
	for _, family := range []string{"ip", "ip6"} {
		addr, ok := globalAddr(f, family)
		if !ok {
			continue
		}
		ports := tcpPorts(vs, family)
		if len(ports) == 0 {
			continue
		}
		res, err := probe.Remote(context.Background(), probeRunner, host, addr, ports)
		if err != nil {
			return vs, nil, err
		}
		var dis []probe.Disagreement
		vs, dis = probe.Reconcile(vs, res, family, addr)
		all = append(all, dis...)
		probed++
	}
	if probed == 0 {
		return vs, nil, fmt.Errorf("nothing to probe: this host has no global address with a listening tcp port")
	}
	return vs, all, nil
}

// globalAddr is the address the internet would reach this host on, which
// is the one worth asking another machine to try.
func globalAddr(f facts.Facts, family string) (string, bool) {
	for _, i := range f.Host.Interfaces {
		if !i.Up {
			continue
		}
		for _, a := range i.Addresses {
			if a.Family == family && a.Scope == "global" {
				return a.IP, true
			}
		}
	}
	return "", false
}

func tcpPorts(vs []model.Verdict, family string) []uint16 {
	seen := map[uint16]bool{}
	var out []uint16
	for _, v := range vs {
		if v.Endpoint.Proto != "tcp" || v.Family != family || seen[v.Endpoint.Port] {
			continue
		}
		seen[v.Endpoint.Port] = true
		out = append(out, v.Endpoint.Port)
	}
	return out
}
