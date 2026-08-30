package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os/exec"
	"strconv"
	"strings"
)

// DocumentVersion is the version of the document `whyopen probe -json`
// writes and Remote reads back. It is what lets two whyopen builds on two
// machines agree about what a probe found, so it is checked rather than
// assumed.
const DocumentVersion = 1

// Document is what `whyopen probe -json` writes.
type Document struct {
	SchemaVersion int      `json:"schema_version"`
	Target        string   `json:"target"`
	Results       []Result `json:"results"`
}

// Runner runs a command on another machine and returns its stdout.
type Runner interface {
	Run(ctx context.Context, host string, args []string) ([]byte, error)
}

// SSHRunner runs the command over ssh. It adds no options of its own: the
// user's ssh config decides the key, the port and the rest, which is the
// only sane place for that to live.
type SSHRunner struct {
	// Binary is the ssh command, "ssh" when empty.
	Binary string
}

func (r SSHRunner) Run(ctx context.Context, host string, args []string) ([]byte, error) {
	bin := r.Binary
	if bin == "" {
		bin = "ssh"
	}
	cmd := exec.CommandContext(ctx, bin, append([]string{host}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if ok := asExitError(err, &ee); ok && len(ee.Stderr) > 0 {
			return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(ee.Stderr)))
		}
		return out, err
	}
	return out, nil
}

func asExitError(err error, target **exec.ExitError) bool {
	ee, ok := err.(*exec.ExitError)
	if ok {
		*target = ee
	}
	return ok
}

// ParseSSHTarget reads "ssh://user@host:port" into the destination ssh
// itself takes. The scheme is required: a bare hostname would be
// ambiguous with the other things --probe-from could grow to mean.
func ParseSSHTarget(s string) (string, error) {
	rest, ok := strings.CutPrefix(s, "ssh://")
	if !ok {
		return "", fmt.Errorf("probe source %q: want ssh://[user@]host[:port]", s)
	}
	if rest == "" || strings.ContainsAny(rest, " \t'\"$`;&|<>()\\") {
		return "", fmt.Errorf("probe source %q: not a host ssh would accept", s)
	}
	return rest, nil
}

// Remote asks another machine to probe this one and returns what it found.
//
// The target and the ports end up in a command that machine's shell runs,
// so both are checked here rather than quoted and hoped for: the target
// must parse as an IP address and the ports are rendered from numbers.
func Remote(ctx context.Context, r Runner, host, target string, ports []uint16) ([]Result, error) {
	if _, err := netip.ParseAddr(target); err != nil {
		return nil, fmt.Errorf("probe target %q is not an IP address", target)
	}
	if len(ports) == 0 {
		return nil, nil
	}
	spec := make([]string, 0, len(ports))
	for _, p := range ports {
		spec = append(spec, strconv.Itoa(int(p)))
	}

	out, err := r.Run(ctx, host, []string{"whyopen", "probe", "-target", target, "-ports", strings.Join(spec, ","), "-json"})
	if err != nil {
		return nil, fmt.Errorf("probe from %s: %w", host, err)
	}

	var doc Document
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("probe from %s: could not read what it wrote back (%v); is whyopen installed there?", host, err)
	}
	if doc.SchemaVersion != DocumentVersion {
		return nil, fmt.Errorf("probe from %s: document version %d, this build reads %d", host, doc.SchemaVersion, DocumentVersion)
	}
	return doc.Results, nil
}
