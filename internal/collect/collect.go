//go:build linux

package collect

import (
	"time"

	"github.com/MemorManeo/whyopen/internal/facts"
)

type Options struct {
	ProcRoot     string // "/proc"
	DockerSocket string // DefaultDockerSocket
}

func (o Options) withDefaults() Options {
	if o.ProcRoot == "" {
		o.ProcRoot = "/proc"
	}
	if o.DockerSocket == "" {
		o.DockerSocket = DefaultDockerSocket
	}
	return o
}

// All snapshots the host. Every sub-collector degrades to a warning rather
// than an error, because a partial snapshot still yields useful verdicts and
// the warnings are carried into the report.
func All(opts Options) (facts.Facts, error) {
	opts = opts.withDefaults()

	f := facts.Facts{SchemaVersion: facts.SchemaVersion, CapturedAt: time.Now().UTC()}

	host, warns := Host(opts.ProcRoot)
	f.Host = host
	f.Warnings = append(f.Warnings, warns...)

	socks, warns := Sockets(opts.ProcRoot)
	f.Sockets = socks
	f.Warnings = append(f.Warnings, warns...)

	rs, warns, err := Ruleset()
	f.Warnings = append(f.Warnings, warns...)
	if err != nil {
		f.Warnings = append(f.Warnings, facts.Warning{
			Source:  "ruleset",
			Message: err.Error() + " (whyopen needs CAP_NET_ADMIN, try running as root)",
		})
	}
	f.Ruleset = rs

	dk, warns := DockerFromSocket(opts.DockerSocket)
	f.Docker = dk
	f.Warnings = append(f.Warnings, warns...)

	return f, nil
}
