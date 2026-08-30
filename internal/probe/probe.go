// Package probe sends real TCP connections at a host and reports what came
// back. It is the counterweight to the rest of whyopen: everything else
// concludes what the kernel would do with a packet by reading rules, and
// this one finds out by sending one.
//
// It is for auditing a host you run, from a vantage point you choose. It
// probes the ports it is given, in one pass, with a bounded amount of
// concurrency and no retries, and refuses a spec large enough to be a
// scan of something else.
package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// maxPorts bounds one run. A host audit names the ports it cares about,
// or the ports something is listening on; a spec past this size is asking
// for something whyopen is not.
const maxPorts = 4096

type State string

const (
	// StateOpen is a completed TCP handshake: the packet reached a
	// listening socket.
	StateOpen State = "open"
	// StateClosed is a reset: the packet reached the host's TCP stack, or
	// a rule that rejects rather than drops, and was answered. Not the
	// same as no answer at all.
	StateClosed State = "closed"
	// StateFiltered is no answer before the timeout: something dropped it.
	StateFiltered State = "filtered"
	// StateError is anything that stopped whyopen from finding out, such
	// as no route to the target. It is never read as evidence about the
	// port.
	StateError State = "error"
)

type Result struct {
	Port   uint16 `json:"port"`
	Proto  string `json:"proto"`
	State  State  `json:"state"`
	Detail string `json:"detail,omitempty"`
}

type Options struct {
	Target  string
	Ports   []uint16
	Timeout time.Duration
	// Concurrency bounds the connections in flight. Zero picks a modest
	// default rather than opening one per port at once.
	Concurrency int
}

// ParsePorts reads "22,80,8000-8100" into a sorted, deduplicated list.
// Anything it cannot read exactly is an error: this decides what whyopen
// sends packets to.
func ParsePorts(spec string) ([]uint16, error) {
	if strings.TrimSpace(spec) == "" {
		return nil, errors.New("no ports given; want something like 22,80,8000-8100")
	}
	seen := map[uint16]bool{}
	var out []uint16
	add := func(p uint16) {
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		lo, hi, isRange := strings.Cut(part, "-")
		start, err := parsePort(lo)
		if err != nil {
			return nil, fmt.Errorf("port spec %q: %w", part, err)
		}
		if !isRange {
			add(start)
			continue
		}
		end, err := parsePort(hi)
		if err != nil {
			return nil, fmt.Errorf("port spec %q: %w", part, err)
		}
		if end < start {
			return nil, fmt.Errorf("port spec %q: the range ends below where it starts", part)
		}
		if int(end)-int(start)+1 > maxPorts {
			return nil, fmt.Errorf("port spec %q covers more than %d ports, which is more than whyopen probes in one run", part, maxPorts)
		}
		for p := int(start); p <= int(end); p++ {
			add(uint16(p))
		}
	}
	if len(out) > maxPorts {
		return nil, fmt.Errorf("%d ports, which is more than the %d whyopen probes in one run", len(out), maxPorts)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil {
		return 0, fmt.Errorf("%q is not a port number between 1 and 65535", strings.TrimSpace(s))
	}
	if n == 0 {
		return 0, errors.New("0 is not a port whyopen probes")
	}
	return uint16(n), nil
}

// Run probes every port once and returns the results in the order the
// ports were given, so the output is stable regardless of which answer
// came back first.
func Run(ctx context.Context, opt Options) []Result {
	if opt.Timeout <= 0 {
		opt.Timeout = 2 * time.Second
	}
	if opt.Concurrency <= 0 {
		opt.Concurrency = 16
	}

	results := make([]Result, len(opt.Ports))
	sem := make(chan struct{}, opt.Concurrency)
	done := make(chan int, len(opt.Ports))
	for i, port := range opt.Ports {
		go func(i int, port uint16) {
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = probeOne(ctx, opt.Target, port, opt.Timeout)
			done <- i
		}(i, port)
	}
	for range opt.Ports {
		<-done
	}
	return results
}

func probeOne(ctx context.Context, target string, port uint16, timeout time.Duration) Result {
	r := Result{Port: port, Proto: "tcp"}
	d := net.Dialer{Timeout: timeout}
	addr := net.JoinHostPort(target, strconv.Itoa(int(port)))
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err == nil {
		conn.Close()
		r.State = StateOpen
		return r
	}
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		r.State = StateClosed
	case isTimeout(err):
		r.State = StateFiltered
	default:
		// No route, a DNS failure, a local resource limit. None of these
		// say anything about the port, so none of them are reported as if
		// they did.
		r.State = StateError
		r.Detail = err.Error()
	}
	return r
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
