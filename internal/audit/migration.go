package audit

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"unicode/utf8"
)

// CarryOver is one bucket feature in use on the audited estate and whether each
// candidate target engine can take it over. Only features in use are reported.
type CarryOver struct {
	Feature string            `json:"feature"`
	Buckets []string          `json:"buckets"`
	Support map[string]string `json:"support"` // engine -> native | partial: why | none
}

// Engines lists the migration targets in the order the text report prints them.
var Engines = []string{"RustFS", "Garage", "SeaweedFS", "Ceph RGW"}

// support is the engine capability table, verified against each project's own
// documentation and repository on 2026-10-07 (sources: docs/engine-support.md). It is
// deliberately a flat literal: when an engine ships a feature, change one string and
// send a pull request with the source.
var support = map[string]map[string]string{
	"versioning": {
		"RustFS": "native", "Garage": "none", "SeaweedFS": "native", "Ceph RGW": "native",
	},
	"object lock": {
		"RustFS": "native", "Garage": "none", "SeaweedFS": "native: set at bucket creation", "Ceph RGW": "native",
	},
	"bucket policy": {
		"RustFS": "native", "Garage": "none: per-key grants instead", "SeaweedFS": "native", "Ceph RGW": "native",
	},
	"ACL grants": {
		"RustFS": "partial: canned headers only, not enforced", "Garage": "none", "SeaweedFS": "partial: canned only, grants not persisted", "Ceph RGW": "native",
	},
	"lifecycle": {
		"RustFS": "native", "Garage": "partial: expiration and abort-MPU only", "SeaweedFS": "partial: no transition rules", "Ceph RGW": "native",
	},
	"replication": {
		"RustFS": "native: target registered via admin API", "Garage": "none: cluster-internal only", "SeaweedFS": "partial: filer.sync, not the S3 API", "Ceph RGW": "partial: across multisite zones only",
	},
	"event notifications": {
		"RustFS": "native: queue targets only", "Garage": "none", "SeaweedFS": "partial: filer-wide, not per bucket", "Ceph RGW": "native: topics via SNS",
	},
	"default encryption": {
		"RustFS": "native: needs a KMS backend", "Garage": "none: encrypt the disks", "SeaweedFS": "native: needs KEK or KMS", "Ceph RGW": "native: needs Vault or KMIP",
	},
	"bucket tags": {
		"RustFS": "native", "Garage": "none", "SeaweedFS": "native", "Ceph RGW": "native",
	},
	"CORS": {
		"RustFS": "native", "Garage": "native", "SeaweedFS": "native", "Ceph RGW": "native",
	},
	"access logging": {
		"RustFS": "partial: config stored, delivery planned", "Garage": "none", "SeaweedFS": "none", "Ceph RGW": "native",
	},
}

// featureOrder keeps the matrix stable between runs.
var featureOrder = []string{
	"versioning", "object lock", "bucket policy", "ACL grants", "lifecycle", "replication",
	"event notifications", "default encryption", "bucket tags", "CORS", "access logging",
}

// featuresInUse names the configured features of a bucket.
func featuresInUse(b *Bucket) []string {
	var out []string
	use := func(ok bool, name string) {
		if ok {
			out = append(out, name)
		}
	}
	use(b.Versioning.OK() && b.Versioning.Status != "", "versioning")
	use(b.ObjectLock.OK() && b.ObjectLock.Enabled, "object lock")
	use(b.Policy.OK() && b.Policy.Document != "", "bucket policy")
	use(b.ACL.OK() && b.ACL.Grants > 1, "ACL grants")
	use(b.Lifecycle.OK() && len(b.Lifecycle.Rules) > 0, "lifecycle")
	use(b.Replication.OK() && b.Replication.Rules > 0, "replication")
	use(b.Notification.OK() && b.Notification.Targets > 0, "event notifications")
	use(b.Encryption.OK() && b.Encryption.Algorithm != "", "default encryption")
	use(b.Tagging.OK() && len(b.Tagging.Tags) > 0, "bucket tags")
	use(b.CORS.OK() && b.CORS.Rules > 0, "CORS")
	use(b.Logging.OK() && b.Logging.TargetBucket != "", "access logging")
	return out
}

// Migration builds the carry-over matrix for the features the buckets actually use.
func Migration(buckets []Bucket) []CarryOver {
	users := map[string][]string{}
	for i := range buckets {
		for _, f := range featuresInUse(&buckets[i]) {
			users[f] = append(users[f], buckets[i].Name)
		}
	}
	var out []CarryOver
	for _, f := range featureOrder {
		if names := users[f]; len(names) > 0 {
			sort.Strings(names)
			out = append(out, CarryOver{Feature: f, Buckets: names, Support: support[f]})
		}
	}
	return out
}

func writeMigration(w io.Writer, rows []CarryOver) {
	fmt.Fprintln(w, "migration carry-over (features in use, per target engine)")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "FEATURE\tBUCKETS\t%s\n", strings.Join(Engines, "\t"))
	for _, row := range rows {
		cells := make([]string, 0, len(Engines))
		for _, e := range Engines {
			cells = append(cells, row.Support[e])
		}
		fmt.Fprintf(tw, "%s\t%d\t%s\n", row.Feature, len(row.Buckets), strings.Join(cells, "\t"))
	}
	_ = tw.Flush()
}

// nonPortableKey explains why other engines or tools may reject an object key,
// or returns "" when the key is unremarkable. Folder markers are not flagged here.
func nonPortableKey(key string) string {
	switch {
	case key == "":
		return "empty key"
	case len(key) > 1024:
		return "longer than 1024 bytes"
	case !utf8.ValidString(key):
		return "not valid UTF-8"
	case strings.HasPrefix(key, "/"):
		return "leading slash"
	case strings.Contains(key, "//"):
		return "empty path segment"
	case strings.Contains(key, "\\"):
		return "backslash"
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return "control character"
		}
	}
	for _, seg := range strings.Split(key, "/") {
		if seg == "." || seg == ".." {
			return "dot path segment"
		}
	}
	return ""
}
