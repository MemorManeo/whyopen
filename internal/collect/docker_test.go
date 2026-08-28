//go:build linux

package collect

import (
	"net"
	"net/http"
	"path/filepath"
	"testing"
)

const containersJSON = `[
 {"Id":"abc123def456","Names":["/urizen-web-1"],
  "Ports":[{"IP":"127.0.0.1","PrivatePort":3000,"PublicPort":3000,"Type":"tcp"},
           {"PrivatePort":9229,"Type":"tcp"}],
  "NetworkSettings":{"Networks":{"urizen_default":{"IPAddress":"172.27.0.5"}}}}
]`

func TestDockerFromSocket(t *testing.T) {
	dir := t.TempDir()
	sock := filepath.Join(dir, "docker.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/containers/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(containersJSON))
	})
	srv := &http.Server{Handler: mux}
	go srv.Serve(ln)
	defer srv.Close()

	got, warns := DockerFromSocket(sock)
	if len(warns) != 0 {
		t.Fatalf("unexpected warnings: %+v", warns)
	}
	if !got.Available || len(got.Containers) != 1 {
		t.Fatalf("got %+v", got)
	}
	c := got.Containers[0]
	if c.Name != "urizen-web-1" || c.ID != "abc123def456" {
		t.Fatalf("container = %+v", c)
	}
	// Only the published port counts; the unpublished 9229 must be dropped.
	if len(c.Publishes) != 1 {
		t.Fatalf("publishes = %+v, want only the published port", c.Publishes)
	}
	p := c.Publishes[0]
	if p.HostIP != "127.0.0.1" || p.HostPort != 3000 || p.ContainerIP != "172.27.0.5" || p.ContainerPort != 3000 {
		t.Fatalf("publish = %+v", p)
	}
}

func TestDockerMissingSocketIsAWarningNotAnError(t *testing.T) {
	got, warns := DockerFromSocket(filepath.Join(t.TempDir(), "absent.sock"))
	if got.Available {
		t.Fatalf("expected unavailable")
	}
	if len(warns) == 0 {
		t.Fatalf("expected a warning explaining that publishes are unknown")
	}
}
