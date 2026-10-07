package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Estate is the JSON document eimer writes: one or more endpoint reports with a
// generation timestamp, so a file on disk is self-describing evidence.
type Estate struct {
	Tool        string    `json:"tool"`
	Version     string    `json:"version"`
	GeneratedAt time.Time `json:"generated_at"`
	Reports     []*Report `json:"reports"`
}

// Worst is the highest severity across every report.
func (e *Estate) Worst() Severity {
	w := Info
	for _, r := range e.Reports {
		if s := r.Worst(); s > w {
			w = s
		}
	}
	return w
}

// WriteJSON renders the estate as indented JSON.
func (e *Estate) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(e)
}

// WriteText renders every report, separated by a rule when there are several.
func (e *Estate) WriteText(w io.Writer) error {
	for i, r := range e.Reports {
		if i > 0 {
			fmt.Fprintln(w, "\n"+"────────────────────────────────────────────────────────────────────────")
		}
		if err := r.WriteText(w); err != nil {
			return err
		}
	}
	return nil
}

// Save writes the JSON document to path plus a path.sha256 sidecar and returns the
// hex digest, which is what an auditor files next to the report.
func (e *Estate) Save(path string) (string, error) {
	var buf []byte
	buf, err := json.MarshalIndent(e, "", "  ")
	if err != nil {
		return "", err
	}
	buf = append(buf, '\n')
	if err := os.WriteFile(path, buf, 0o600); err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf)
	digest := hex.EncodeToString(sum[:])
	sidecar := fmt.Sprintf("%s  %s\n", digest, path)
	if err := os.WriteFile(path+".sha256", []byte(sidecar), 0o600); err != nil {
		return "", err
	}
	return digest, nil
}

// Load reads a document written by Save or by --json.
func Load(path string) (*Estate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var e Estate
	if err := json.Unmarshal(data, &e); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if e.Tool != "eimer" {
		return nil, fmt.Errorf("%s: not an eimer report", path)
	}
	return &e, nil
}
