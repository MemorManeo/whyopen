package report

import (
	"encoding/json"
	"io"

	"github.com/MemorManeo/whyopen/internal/facts"
	"github.com/MemorManeo/whyopen/internal/model"
	"github.com/MemorManeo/whyopen/internal/policy"
	"github.com/MemorManeo/whyopen/internal/probe"
)

// SchemaVersion is the version of the verdict document JSON writes. It is
// deliberately its own number, not facts.SchemaVersion: that one describes
// what was collected, this one describes what was concluded, and the two
// change for different reasons.
const SchemaVersion = 1

// JSONOptions is everything the document carries beyond the verdicts
// themselves. All of it is optional: a field nothing was given for is
// absent from the output rather than present and empty, so a consumer can
// tell "no policy was consulted" from "a policy found nothing".
type JSONOptions struct {
	Version      string
	Hostname     string
	Zone         string
	Warnings     []facts.Warning
	Policy       *policy.Result
	PolicySource string
	// WithPath includes the ordered rule path of every verdict. It is the
	// expensive half of the document and only --explain asks for it.
	WithPath bool
	// ProbeSource and Disagreements describe a probe run. The
	// disagreements are the part a reader cannot derive from the verdicts,
	// because they are about the verdicts being wrong.
	ProbeSource   string
	Disagreements []probe.Disagreement
}

// The output types are separate from the model's own. A verdict schema
// that is just internal structs marshalled would change shape whenever
// they were refactored, and this one is a promise to whatever consumes it.
type jsonDoc struct {
	SchemaVersion int             `json:"schema_version"`
	Whyopen       string          `json:"whyopen,omitempty"`
	Hostname      string          `json:"hostname,omitempty"`
	Zone          string          `json:"zone,omitempty"`
	Verdicts      []jsonVerdict   `json:"verdicts"`
	Warnings      []facts.Warning `json:"warnings,omitempty"`
	Policy        *jsonPolicy     `json:"policy,omitempty"`
	Probe         *jsonProbe      `json:"probe,omitempty"`
}

type jsonProbe struct {
	Source        string             `json:"source"`
	Disagreements []jsonDisagreement `json:"disagreements"`
}

type jsonDisagreement struct {
	Port      uint16 `json:"port"`
	Proto     string `json:"proto"`
	Family    string `json:"family"`
	Modelled  string `json:"modelled"`
	Probed    string `json:"probed"`
	Diagnosis string `json:"diagnosis"`
}

type jsonVerdict struct {
	Port   uint16    `json:"port"`
	Proto  string    `json:"proto"`
	Family string    `json:"family"`
	Result string    `json:"result"`
	Reason string    `json:"reason,omitempty"`
	Owner  string    `json:"owner,omitempty"`
	BindIP string    `json:"bind_ip,omitempty"`
	Kind   string    `json:"kind,omitempty"`
	DNAT   *jsonDNAT `json:"dnat,omitempty"`
	Path   []jsonHit `json:"path,omitempty"`
}

type jsonDNAT struct {
	IP   string `json:"ip"`
	Port uint16 `json:"port"`
}

type jsonHit struct {
	Family   string `json:"family"`
	Table    string `json:"table"`
	Chain    string `json:"chain"`
	Hook     string `json:"hook,omitempty"`
	Priority int32  `json:"priority"`
	Handle   uint64 `json:"handle"`
	Action   string `json:"action"`
	// Rule is the nft-like rendering, so a consumer can show a human what
	// matched without reassembling it from the facts document.
	Rule string `json:"rule"`
}

type jsonPolicy struct {
	Source        string        `json:"source,omitempty"`
	FailOnUnknown bool          `json:"fail_on_unknown"`
	Violations    []jsonVerdict `json:"violations"`
	Stale         []jsonStale   `json:"stale"`
	Unknown       []jsonVerdict `json:"unknown"`
	// Unreadable is what fail_on_unknown fails the run on besides the
	// unknown verdicts: what never became a verdict at all, today a
	// destination rewrite whose forwarded ports whyopen cannot name. The
	// same warnings are in the document's own warnings list; they are
	// repeated here because this is where the exit code is explained.
	Unreadable []facts.Warning `json:"unreadable,omitempty"`
}

type jsonStale struct {
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
	// Found says what turned up in place of the reachable verdict the
	// policy expected: a result name, or "nothing-listening". Spelled out
	// rather than left empty, so a consumer never has to read an absent
	// value as a meaning.
	Found string `json:"found"`
}

// JSON writes the verdict set as a versioned document.
func JSON(w io.Writer, vs []model.Verdict, opt JSONOptions) error {
	doc := jsonDoc{
		SchemaVersion: SchemaVersion,
		Whyopen:       opt.Version,
		Hostname:      opt.Hostname,
		Zone:          opt.Zone,
		Verdicts:      jsonVerdicts(worstFirst(vs), opt.WithPath),
		Warnings:      opt.Warnings,
	}
	if opt.Policy != nil {
		doc.Policy = &jsonPolicy{
			Source:        opt.PolicySource,
			FailOnUnknown: opt.Policy.FailOnUnknown,
			Violations:    jsonVerdicts(opt.Policy.Violations, false),
			Unknown:       jsonVerdicts(opt.Policy.Unknown, false),
			Unreadable:    opt.Policy.Unreadable,
			Stale:         make([]jsonStale, 0, len(opt.Policy.Stale)),
		}
		for _, s := range opt.Policy.Stale {
			found := s.Found
			if found == "" {
				found = "nothing-listening"
			}
			doc.Policy.Stale = append(doc.Policy.Stale, jsonStale{Port: s.Entry.Port, Proto: s.Entry.Proto, Found: found})
		}
	}

	if opt.ProbeSource != "" {
		doc.Probe = &jsonProbe{Source: opt.ProbeSource, Disagreements: make([]jsonDisagreement, 0, len(opt.Disagreements))}
		for _, d := range opt.Disagreements {
			doc.Probe.Disagreements = append(doc.Probe.Disagreements, jsonDisagreement{
				Port: d.Port, Proto: d.Proto, Family: d.Family,
				Modelled: d.Modelled, Probed: string(d.Probed), Diagnosis: d.Diagnosis,
			})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func jsonVerdicts(vs []model.Verdict, withPath bool) []jsonVerdict {
	out := make([]jsonVerdict, 0, len(vs))
	for _, v := range vs {
		jv := jsonVerdict{
			Port:   v.Endpoint.Port,
			Proto:  v.Endpoint.Proto,
			Family: v.Family,
			Result: v.Result,
			Reason: v.Reason,
			Owner:  v.Endpoint.Owner,
			BindIP: v.Endpoint.BindIP,
			Kind:   v.Endpoint.Kind,
		}
		if v.DNAT != nil {
			jv.DNAT = &jsonDNAT{IP: v.DNAT.IP.String(), Port: v.DNAT.Port}
		}
		if withPath {
			for _, h := range v.Path {
				jv.Path = append(jv.Path, jsonHit{
					Family: h.Family, Table: h.Table, Chain: h.Chain, Hook: h.Hook,
					Priority: h.Priority, Handle: h.Handle, Action: h.Action,
					Rule: RenderRule(h.Rule),
				})
			}
		}
		out = append(out, jv)
	}
	return out
}
