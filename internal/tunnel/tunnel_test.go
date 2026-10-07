package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary double as a fake ssh: when invoked with
// EIMER_FAKE_SSH=1 it parses -L local:remote, listens locally and proxies TCP to remote.
func TestMain(m *testing.M) {
	if os.Getenv("EIMER_FAKE_SSH") == "" {
		os.Exit(m.Run())
	}
	var forward, via, jumps string
	for i, a := range os.Args {
		if a == "-L" && i+1 < len(os.Args) {
			forward = os.Args[i+1]
		}
		if a == "-J" && i+1 < len(os.Args) {
			jumps = os.Args[i+1]
		}
		via = a
	}
	if via == "down" {
		fmt.Fprintln(os.Stderr, "ssh: connect to host down port 22: Connection refused")
		os.Exit(255)
	}
	if want := os.Getenv("EIMER_FAKE_SSH_EXPECT_JUMPS"); want != "" && jumps != want {
		fmt.Fprintf(os.Stderr, "fake ssh: expected -J %q, got %q (last hop %q)\n", want, jumps, via)
		os.Exit(255)
	}
	// forward is 127.0.0.1:port:host:port
	parts := strings.SplitN(forward, ":", 3)
	local, remote := parts[0]+":"+parts[1], parts[2]
	l, err := net.Listen("tcp", local)
	if err != nil {
		os.Exit(1)
	}
	for {
		c, err := l.Accept()
		if err != nil {
			os.Exit(0)
		}
		go func() {
			r, err := net.Dial("tcp", remote)
			if err != nil {
				_ = c.Close()
				return
			}
			go func() { _, _ = io.Copy(r, c) }()
			_, _ = io.Copy(c, r)
			_ = r.Close()
			_ = c.Close()
		}()
	}
}

func useFakeSSH(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	prev := sshCommand
	sshCommand = exe
	t.Setenv("EIMER_FAKE_SSH", "1")
	t.Cleanup(func() { sshCommand = prev })
}

func TestOpenForwardsToTheEndpoint(t *testing.T) {
	useFakeSSH(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "hello via tunnel")
	}))
	defer srv.Close()

	tun, err := Open(context.Background(), "bastion", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()

	local, err := tun.Rewrite(srv.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(local, "http://127.0.0.1:") || !strings.HasSuffix(local, "/x") || strings.Contains(local, srv.Listener.Addr().String()) {
		t.Fatalf("rewrite: %q", local)
	}
	resp, err := http.Get(local)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "hello via tunnel" {
		t.Fatalf("body %q", body)
	}
	tun.Close()
	if _, err := net.DialTimeout("tcp", tun.Local, 300*time.Millisecond); err == nil {
		t.Fatal("tunnel still listening after Close")
	}
}

func TestOpenChainsHopsWithJ(t *testing.T) {
	useFakeSSH(t)
	t.Setenv("EIMER_FAKE_SSH_EXPECT_JUMPS", "edge,core")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { fmt.Fprint(w, "ok") }))
	defer srv.Close()
	tun, err := Open(context.Background(), "edge, core ,bastion", srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	tun.Close()
	if got := Hops(" a,,b "); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("hops: %v", got)
	}
	if _, err := Open(context.Background(), " , ", srv.URL); err == nil {
		t.Fatal("empty via accepted")
	}
}

func TestOpenReportsSSHFailure(t *testing.T) {
	useFakeSSH(t)
	_, err := Open(context.Background(), "down", "http://10.0.0.1:9000")
	if err == nil || !strings.Contains(err.Error(), "Connection refused") {
		t.Fatalf("got %v", err)
	}
}

func TestOpenRejectsBadEndpoint(t *testing.T) {
	if _, err := Open(context.Background(), "b", "not a url"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := Open(context.Background(), "b", "http://"); err == nil {
		t.Fatal("expected error")
	}
}

func TestDefaultPorts(t *testing.T) {
	useFakeSSH(t)
	// The fake proxies to host:443, which nothing serves, but Open only needs the local
	// side to accept; it must still pick 443 for https without a port.
	tun, err := Open(context.Background(), "bastion", "https://store.internal")
	if err != nil {
		t.Fatal(err)
	}
	defer tun.Close()
	if tun.Remote != "store.internal:443" {
		t.Fatalf("remote %q", tun.Remote)
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		t.Log("real ssh not on PATH; the production default would fail with a clear error")
	}
}
