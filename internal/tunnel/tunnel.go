// Package tunnel opens an ssh port forward to a store that is only reachable from a
// bastion, so eimer can run on the operator's machine and keep keys and reports local.
//
// It runs the user's own ssh binary rather than a Go ssh client, so ~/.ssh/config
// aliases, agents, jump hosts and host key policies apply unchanged.
package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// sshCommand is replaced in tests.
var sshCommand = "ssh"

// Tunnel is a live port forward. Close ends the ssh process.
type Tunnel struct {
	Local  string // 127.0.0.1:port
	Remote string // host:port as seen from the bastion
	kill   func()
	once   sync.Once
	stderr *bytes.Buffer
}

// Stderr returns what ssh has written so far, for diagnosing a forward that accepts
// locally but cannot connect on the far side.
func (t *Tunnel) Stderr() string {
	if t == nil || t.stderr == nil {
		return ""
	}
	return strings.TrimSpace(t.stderr.String())
}

// Open forwards a local port to the endpoint's host and port through via: one ssh host
// (an alias, user@host, an address) or a comma-separated chain of hops, where the forward
// is opened on the last hop and the earlier ones become ssh -J jump hosts. It returns once
// the port accepts connections.
func Open(ctx context.Context, via, endpoint string) (*Tunnel, error) {
	hops := Hops(via)
	if len(hops) == 0 {
		return nil, errors.New("tunnel: --via needs at least one ssh host")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("tunnel: endpoint %q is not a URL", endpoint)
	}
	host, port := u.Hostname(), u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" {
			port = "443"
		}
	}
	local, err := freePort()
	if err != nil {
		return nil, err
	}
	t := &Tunnel{Local: fmt.Sprintf("127.0.0.1:%d", local), Remote: net.JoinHostPort(host, port)}

	args := []string{
		"-N",                  // no remote command
		"-o", "BatchMode=yes", // never hang on a password prompt
		"-o", "ServerAliveInterval=30",
		// A plain foreground connection this process owns, not a multiplexed session on a
		// ControlMaster that outlives it. Forwards from the user's config still apply; if
		// one of them cannot bind, ssh only warns, and ours is on a port picked free.
		"-o", "ControlMaster=no",
		"-o", "ControlPath=none",
		"-L", t.Local + ":" + t.Remote,
	}
	last := hops[len(hops)-1]
	if len(hops) > 1 {
		args = append(args, "-J", strings.Join(hops[:len(hops)-1], ","))
	}
	cmd := exec.CommandContext(ctx, sshCommand, append(args, last)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	t.stderr = &stderr
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("tunnel: start ssh: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()
	t.kill = func() { _ = cmd.Process.Kill(); <-exited }

	deadline := time.Now().Add(20 * time.Second)
	for {
		select {
		case err := <-exited:
			msg := strings.TrimSpace(stderr.String())
			if err == nil {
				return nil, fmt.Errorf("tunnel: ssh %s exited before the forward came up (ForkAfterAuthentication in ssh config?): %s", via, msg)
			}
			return nil, fmt.Errorf("tunnel: ssh %s exited: %w: %s", via, err, msg)
		default:
		}
		if c, err := net.DialTimeout("tcp", t.Local, 500*time.Millisecond); err == nil {
			_ = c.Close()
			return t, nil
		}
		if time.Now().After(deadline) {
			t.kill()
			return nil, fmt.Errorf("tunnel: port forward through %s did not come up in 20s: %s", via, bytes.TrimSpace(stderr.Bytes()))
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Close ends the ssh process. Safe on nil.
func (t *Tunnel) Close() {
	if t != nil && t.kill != nil {
		t.once.Do(t.kill)
	}
}

// Rewrite returns the endpoint URL pointed at the local side of the tunnel.
func (t *Tunnel) Rewrite(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	u.Host = t.Local
	return u.String(), nil
}

// Hops splits a via value on commas and trims blanks.
func Hops(via string) []string {
	var out []string
	for _, h := range strings.Split(via, ",") {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	return out
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("tunnel: no free local port: %w", err)
	}
	defer func() { _ = l.Close() }()
	addr, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		return 0, errors.New("tunnel: unexpected listener address")
	}
	return addr.Port, nil
}
