//go:build linux

package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/MemorManeo/whyopen/internal/facts"
)

// DefaultDockerSocket is where the daemon listens on a stock install.
const DefaultDockerSocket = "/var/run/docker.sock"

type dockerContainer struct {
	ID    string   `json:"Id"`
	Names []string `json:"Names"`
	Ports []struct {
		IP          string `json:"IP"`
		PrivatePort uint16 `json:"PrivatePort"`
		PublicPort  uint16 `json:"PublicPort"`
		Type        string `json:"Type"`
	} `json:"Ports"`
	NetworkSettings struct {
		Networks map[string]struct {
			IPAddress string `json:"IPAddress"`
		} `json:"Networks"`
	} `json:"NetworkSettings"`
}

// DockerFromSocket lists running containers and their published ports. An
// unreachable daemon is a warning, never an error: the ruleset still carries
// the DNAT rules, so verdicts remain possible, just less well attributed.
func DockerFromSocket(socketPath string) (facts.Docker, []facts.Warning) {
	client := &http.Client{
		Timeout: 3 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", socketPath)
			},
		},
	}

	resp, err := client.Get("http://docker/containers/json")
	if err != nil {
		return facts.Docker{}, []facts.Warning{{
			Source:  "docker",
			Message: fmt.Sprintf("daemon unreachable at %s (%v), container names and publishes are unknown", socketPath, err),
		}}
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return facts.Docker{}, []facts.Warning{{
			Source:  "docker",
			Message: fmt.Sprintf("daemon returned %s listing containers", resp.Status),
		}}
	}

	var raw []dockerContainer
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return facts.Docker{}, []facts.Warning{{
			Source: "docker", Message: fmt.Sprintf("decode container list: %v", err),
		}}
	}

	out := facts.Docker{Available: true}
	for _, c := range raw {
		fc := facts.Container{ID: c.ID, Name: containerName(c.Names)}
		ip := firstNetworkIP(c)
		for _, p := range c.Ports {
			if p.PublicPort == 0 {
				continue // exposed inside the network only, never published
			}
			hostIP := p.IP
			if hostIP == "" {
				hostIP = "0.0.0.0"
			}
			fc.Publishes = append(fc.Publishes, facts.Publish{
				HostIP: hostIP, HostPort: p.PublicPort,
				ContainerIP: ip, ContainerPort: p.PrivatePort,
				Proto: p.Type,
			})
		}
		out.Containers = append(out.Containers, fc)
	}
	return out, nil
}

func containerName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return strings.TrimPrefix(names[0], "/")
}

func firstNetworkIP(c dockerContainer) string {
	// Sort network names to ensure deterministic iteration order across runs.
	// Go randomizes map iteration, so without this a container with multiple
	// networks would produce different ContainerIP on each collection.
	var names []string
	for name := range c.NetworkSettings.Networks {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		if c.NetworkSettings.Networks[name].IPAddress != "" {
			return c.NetworkSettings.Networks[name].IPAddress
		}
	}
	return ""
}
