// Package update replaces the running eimer binary with the latest GitHub release,
// verified against the release's checksums. It only ever runs when asked: eimer never
// checks for versions on its own, because "nothing phones home" is a promise.
package update

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Options configures one update.
type Options struct {
	Current  string       // running version, e.g. v0.3.0, 0.3.0, dev
	Exe      string       // path to replace; "" means os.Executable()
	BaseURL  string       // "" means github.com; tests point it at a fake
	APIURL   string       // "" means api.github.com; tests point it at a fake
	HTTP     *http.Client // nil: a 60 second client
	OS, Arch string       // "" means runtime values
}

// Release is what the check found.
type Release struct {
	Current string `json:"current"`
	Latest  string `json:"latest"`
	Newer   bool   `json:"newer"`
}

const repo = "morrieinmaas/eimer"

func (o *Options) fill() {
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	if o.BaseURL == "" {
		o.BaseURL = "https://github.com/" + repo + "/releases/download"
	}
	if o.APIURL == "" {
		o.APIURL = "https://api.github.com/repos/" + repo + "/releases/latest"
	}
	if o.OS == "" {
		o.OS = runtime.GOOS
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
}

// Check asks GitHub for the latest release tag and compares it with the running version.
func Check(ctx context.Context, o Options) (*Release, error) {
	o.fill()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, o.APIURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := o.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("check latest release: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("check latest release: GitHub answered %s", resp.Status)
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("check latest release: %w", err)
	}
	latest := strings.TrimPrefix(body.TagName, "v")
	if latest == "" {
		return nil, errors.New("check latest release: no tag in response")
	}
	current := strings.TrimPrefix(o.Current, "v")
	return &Release{Current: current, Latest: latest, Newer: Newer(latest, current)}, nil
}

// Apply downloads the latest release for this OS and architecture, verifies it against
// checksums.txt, and replaces the executable atomically. It returns the installed version.
func Apply(ctx context.Context, o Options) (string, error) {
	o.fill()
	rel, err := Check(ctx, o)
	if err != nil {
		return "", err
	}
	exe := o.Exe
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return "", err
		}
		if exe, err = filepath.EvalSymlinks(exe); err != nil {
			return "", err
		}
	}

	archive := fmt.Sprintf("eimer_%s_%s_%s.tar.gz", rel.Latest, o.OS, o.Arch)
	base := o.BaseURL + "/v" + rel.Latest + "/"
	data, err := fetch(ctx, o.HTTP, base+archive)
	if err != nil {
		return "", fmt.Errorf("no release %s for %s/%s: %w", rel.Latest, o.OS, o.Arch, err)
	}
	sums, err := fetch(ctx, o.HTTP, base+"checksums.txt")
	if err != nil {
		return "", fmt.Errorf("checksums.txt for %s: %w", rel.Latest, err)
	}
	want := checksumFor(string(sums), archive)
	if want == "" {
		return "", fmt.Errorf("%s is not listed in checksums.txt", archive)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return "", fmt.Errorf("checksum mismatch for %s: expected %s, got %s", archive, want, got)
	}
	bin, err := extract(data, "eimer")
	if err != nil {
		return "", err
	}

	// Write beside the target and rename: readers see either the old or the new file.
	tmp, err := os.CreateTemp(filepath.Dir(exe), ".eimer-update-*")
	if err != nil {
		return "", fmt.Errorf("cannot write next to %s (try sudo, or reinstall with install.sh): %w", exe, err)
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(bin); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, exe); err != nil {
		return "", fmt.Errorf("replace %s: %w", exe, err)
	}
	return rel.Latest, nil
}

func fetch(ctx context.Context, hc *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

func checksumFor(sums, name string) string {
	for _, line := range strings.Split(sums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == name {
			return fields[0]
		}
	}
	return ""
}

func extract(archive []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(strings.NewReader(string(archive)))
	if err != nil {
		return nil, fmt.Errorf("archive: %w", err)
	}
	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil, fmt.Errorf("archive has no %s", name)
		}
		if err != nil {
			return nil, fmt.Errorf("archive: %w", err)
		}
		if filepath.Base(hdr.Name) == name && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(io.LimitReader(tr, 256<<20))
		}
	}
}

// Newer reports whether a is a higher release than b. Non-numeric versions such as
// "dev" or snapshots count as older than any release, so an update always applies.
func Newer(a, b string) bool {
	pa, oka := parts(a)
	pb, okb := parts(b)
	if !okb {
		return oka
	}
	if !oka {
		return false
	}
	for i := 0; i < 3; i++ {
		if pa[i] != pb[i] {
			return pa[i] > pb[i]
		}
	}
	return false
}

func parts(v string) ([3]int, bool) {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexAny(v, "-+"); i >= 0 {
		return out, false // pre-release or snapshot
	}
	fields := strings.Split(v, ".")
	if len(fields) != 3 {
		return out, false
	}
	for i, f := range fields {
		n, err := strconv.Atoi(f)
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}
