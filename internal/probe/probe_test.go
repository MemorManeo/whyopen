package probe

import (
	"context"
	"net"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestParsePorts(t *testing.T) {
	cases := map[string][]uint16{
		"22":          {22},
		"22,80,443":   {22, 80, 443},
		"20-23":       {20, 21, 22, 23},
		"80,20-22,80": {20, 21, 22, 80}, // sorted, deduped
		" 22 , 80 ":   {22, 80},
		"65535":       {65535},
	}
	for spec, want := range cases {
		got, err := ParsePorts(spec)
		if err != nil {
			t.Errorf("ParsePorts(%q): %v", spec, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ParsePorts(%q) = %v, want %v", spec, got, want)
		}
	}
}

// A probe spec decides what whyopen sends packets to, so anything it
// cannot read exactly is refused rather than approximated.
func TestParsePortsRefusals(t *testing.T) {
	for _, spec := range []string{"", "0", "70000", "ssh", "22-", "-22", "23-22", "22,,80", "1-65536"} {
		if _, err := ParsePorts(spec); err == nil {
			t.Errorf("ParsePorts(%q) = nil error, want a refusal", spec)
		}
	}
}

// A range that would expand to more ports than whyopen will probe in one
// run is refused rather than silently truncated: this is a tool for
// auditing a host you run, not a scanner.
func TestParsePortsRefusesAnUnreasonableRange(t *testing.T) {
	if _, err := ParsePorts("1-40000"); err == nil {
		t.Error("ParsePorts accepted 40000 ports, want a refusal naming the limit")
	}
}

func TestRunFindsAListeningPortOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	res := Run(context.Background(), Options{
		Target: "127.0.0.1", Ports: []uint16{uint16(port)}, Timeout: 2 * time.Second,
	})
	if len(res) != 1 {
		t.Fatalf("got %d results, want 1", len(res))
	}
	if res[0].State != StateOpen {
		t.Fatalf("state = %q (%s), want open", res[0].State, res[0].Detail)
	}
}

// A refused connection means the packet reached the host's TCP stack and
// something answered with a reset. That is not the same as no answer at
// all, and the two must not be reported as one thing.
func TestRunReportsARefusedPortAsClosed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	ln.Close() // nothing is listening there now

	res := Run(context.Background(), Options{
		Target: "127.0.0.1", Ports: []uint16{uint16(port)}, Timeout: 2 * time.Second,
	})
	if res[0].State != StateClosed {
		t.Fatalf("state = %q (%s), want closed", res[0].State, res[0].Detail)
	}
}

func TestRunProbesEveryPortItIsGiven(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)

	ports := []uint16{uint16(port), uint16(port) + 1, uint16(port) + 2}
	res := Run(context.Background(), Options{Target: "127.0.0.1", Ports: ports, Timeout: time.Second})
	if len(res) != len(ports) {
		t.Fatalf("got %d results, want %d", len(res), len(ports))
	}
	for i, r := range res {
		if r.Port != ports[i] {
			t.Errorf("result %d is for port %d, want %d in the order asked for", i, r.Port, ports[i])
		}
	}
}
