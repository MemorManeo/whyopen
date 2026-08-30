package probe

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type fakeRunner struct {
	gotHost string
	gotArgs []string
	out     []byte
	err     error
}

func (f *fakeRunner) Run(_ context.Context, host string, args []string) ([]byte, error) {
	f.gotHost, f.gotArgs = host, args
	return f.out, f.err
}

func TestRemoteAsksTheOtherMachineToProbeThisOne(t *testing.T) {
	f := &fakeRunner{out: []byte(`{"schema_version":1,"target":"203.0.113.10","results":[{"port":22,"proto":"tcp","state":"open"}]}`)}
	res, err := Remote(context.Background(), f, "vantage.example", "203.0.113.10", []uint16{22, 443})
	if err != nil {
		t.Fatalf("Remote: %v", err)
	}
	if f.gotHost != "vantage.example" {
		t.Errorf("host = %q", f.gotHost)
	}
	joined := strings.Join(f.gotArgs, " ")
	for _, want := range []string{"whyopen", "probe", "203.0.113.10", "22,443", "-json"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %q missing %q", joined, want)
		}
	}
	if len(res) != 1 || res[0].State != StateOpen {
		t.Fatalf("results = %+v, want the remote's answer", res)
	}
}

// The target and the ports go into a command another machine's shell
// runs, so anything that is not an address and a list of numbers is
// refused here rather than quoted and hoped for.
func TestRemoteRefusesATargetThatIsNotAnAddress(t *testing.T) {
	f := &fakeRunner{}
	if _, err := Remote(context.Background(), f, "vantage.example", "203.0.113.10; rm -rf /", []uint16{22}); err == nil {
		t.Fatal("Remote accepted a target that is not an address")
	}
	if f.gotHost != "" {
		t.Error("Remote ran something before checking the target")
	}
}

func TestRemoteReportsWhatTheRemoteCommandFailedWith(t *testing.T) {
	f := &fakeRunner{err: errors.New("ssh: connect to host vantage.example port 22: Connection refused")}
	_, err := Remote(context.Background(), f, "vantage.example", "203.0.113.10", []uint16{22})
	if err == nil {
		t.Fatal("Remote hid a failure of the remote command")
	}
	if !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("error = %q, want the remote failure in it", err)
	}
}

// A remote whyopen of another generation may write a document this build
// cannot read. Refusing is the only safe answer: a half-read probe would
// silently overrule the model.
func TestRemoteRefusesAnUnreadableDocument(t *testing.T) {
	for _, out := range []string{
		`{"schema_version":99,"results":[]}`,
		`not json at all`,
		`whyopen: command not found`,
	} {
		f := &fakeRunner{out: []byte(out)}
		if _, err := Remote(context.Background(), f, "h", "203.0.113.10", []uint16{22}); err == nil {
			t.Errorf("Remote accepted %q", out)
		}
	}
}

func TestParseSSHTarget(t *testing.T) {
	cases := map[string]string{
		"ssh://vantage.example":      "vantage.example",
		"ssh://user@vantage.example": "user@vantage.example",
		"ssh://user@host:2222":       "user@host:2222",
	}
	for in, want := range cases {
		got, err := ParseSSHTarget(in)
		if err != nil {
			t.Errorf("ParseSSHTarget(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseSSHTarget(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"vantage.example", "http://host", "ssh://", ""} {
		if _, err := ParseSSHTarget(bad); err == nil {
			t.Errorf("ParseSSHTarget(%q) = nil error, want a refusal", bad)
		}
	}
}
