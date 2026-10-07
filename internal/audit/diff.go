package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Change is one difference between two reports of the same endpoint.
type Change struct {
	Kind    string `json:"kind"` // bucket_added, bucket_removed, finding_new, finding_resolved, config, inventory
	Bucket  string `json:"bucket,omitempty"`
	Detail  string `json:"detail"`
	Worsens bool   `json:"worsens"` // true when the change is in the wrong direction
}

// Diff compares two estate documents report by report, matched on name, falling
// back to endpoint. It is what "drift since the last audit" means in practice.
type Diff struct {
	Endpoint string   `json:"endpoint"`
	Changes  []Change `json:"changes"`
}

// Compare returns one Diff per endpoint present in either document.
func Compare(old, cur *Estate) []Diff {
	key := func(r *Report) string {
		if r.Name != "" {
			return r.Name
		}
		return r.Endpoint
	}
	oldBy := map[string]*Report{}
	for _, r := range old.Reports {
		oldBy[key(r)] = r
	}
	seen := map[string]bool{}
	var out []Diff
	for _, r := range cur.Reports {
		k := key(r)
		seen[k] = true
		if o, ok := oldBy[k]; ok {
			out = append(out, Diff{Endpoint: k, Changes: compareReports(o, r)})
		} else {
			out = append(out, Diff{Endpoint: k, Changes: []Change{{Kind: "endpoint_added", Detail: "endpoint is new in this report"}}})
		}
	}
	for k := range oldBy {
		if !seen[k] {
			out = append(out, Diff{Endpoint: k, Changes: []Change{{Kind: "endpoint_removed", Detail: "endpoint missing from this report", Worsens: true}}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Endpoint < out[j].Endpoint })
	return out
}

func compareReports(old, cur *Report) []Change {
	var ch []Change
	oldB, curB := map[string]*Bucket{}, map[string]*Bucket{}
	for i := range old.Buckets {
		oldB[old.Buckets[i].Name] = &old.Buckets[i]
	}
	for i := range cur.Buckets {
		curB[cur.Buckets[i].Name] = &cur.Buckets[i]
	}
	for _, name := range sortedKeys(curB) {
		o, ok := oldB[name]
		if !ok {
			ch = append(ch, Change{Kind: "bucket_added", Bucket: name, Detail: "new bucket"})
			continue
		}
		ch = append(ch, compareBuckets(o, curB[name])...)
	}
	for _, name := range sortedKeys(oldB) {
		if _, ok := curB[name]; !ok {
			ch = append(ch, Change{Kind: "bucket_removed", Bucket: name, Detail: "bucket gone", Worsens: true})
		}
	}

	findingKey := func(f Finding) string { return f.ID + "\x00" + f.Bucket }
	oldF, curF := map[string]Finding{}, map[string]Finding{}
	for _, f := range old.Findings {
		oldF[findingKey(f)] = f
	}
	for _, f := range cur.Findings {
		curF[findingKey(f)] = f
	}
	for _, k := range sortedKeys(curF) {
		if _, ok := oldF[k]; !ok {
			f := curF[k]
			ch = append(ch, Change{Kind: "finding_new", Bucket: f.Bucket, Detail: fmt.Sprintf("[%s] %s: %s", f.Severity, f.ID, f.Message), Worsens: true})
		}
	}
	for _, k := range sortedKeys(oldF) {
		if _, ok := curF[k]; !ok {
			f := oldF[k]
			ch = append(ch, Change{Kind: "finding_resolved", Bucket: f.Bucket, Detail: fmt.Sprintf("[%s] %s", f.Severity, f.ID)})
		}
	}
	return ch
}

func compareBuckets(o, c *Bucket) []Change {
	var ch []Change
	cfg := func(what, before, after string) {
		if before != after {
			ch = append(ch, Change{Kind: "config", Bucket: c.Name, Detail: fmt.Sprintf("%s: %s -> %s", what, orDash(before), orDash(after))})
		}
	}
	cfg("versioning", o.Versioning.Status, c.Versioning.Status)
	cfg("object lock", lockCell(o.ObjectLock), lockCell(c.ObjectLock))
	cfg("policy", docHash(o.Policy.Document), docHash(c.Policy.Document))
	cfg("acl", aclCell(o.ACL), aclCell(c.ACL))
	cfg("anonymous access", exposureCell(o.Exposure), exposureCell(c.Exposure))
	cfg("encryption", o.Encryption.Algorithm, c.Encryption.Algorithm)
	cfg("lifecycle rules", fmt.Sprint(len(o.Lifecycle.Rules)), fmt.Sprint(len(c.Lifecycle.Rules)))
	cfg("replication rules", fmt.Sprint(o.Replication.Rules), fmt.Sprint(c.Replication.Rules))
	cfg("notification targets", fmt.Sprint(o.Notification.Targets), fmt.Sprint(c.Notification.Targets))

	if o.Inventory.Error == "" && c.Inventory.Error == "" && (o.Inventory.Objects != c.Inventory.Objects || o.Inventory.Bytes != c.Inventory.Bytes) {
		ch = append(ch, Change{Kind: "inventory", Bucket: c.Name, Detail: fmt.Sprintf("objects %s -> %s, size %s -> %s",
			countCell(o.Inventory), countCell(c.Inventory), sizeCell(o.Inventory), sizeCell(c.Inventory))})
	}
	return ch
}

func docHash(doc string) string {
	if strings.TrimSpace(doc) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(doc))
	return "sha256:" + hex.EncodeToString(sum[:6])
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Changed reports whether any diff carries a change.
func Changed(diffs []Diff) bool {
	for _, d := range diffs {
		if len(d.Changes) > 0 {
			return true
		}
	}
	return false
}

// WriteDiff renders diffs for humans.
func WriteDiff(w io.Writer, diffs []Diff) {
	if !Changed(diffs) {
		fmt.Fprintln(w, "no changes")
		return
	}
	for _, d := range diffs {
		if len(d.Changes) == 0 {
			fmt.Fprintf(w, "%s: no changes\n", d.Endpoint)
			continue
		}
		fmt.Fprintf(w, "%s: %d change(s)\n", d.Endpoint, len(d.Changes))
		for _, c := range d.Changes {
			marker := " "
			if c.Worsens {
				marker = "!"
			}
			scope := c.Bucket
			if scope == "" {
				scope = "endpoint"
			}
			fmt.Fprintf(w, "  %s %-17s %-30s %s\n", marker, c.Kind, scope, c.Detail)
		}
	}
}
