package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/morrieinmaas/eimer/internal/minio"
)

func healthyMinIO() *minio.Info {
	return &minio.Info{
		Available: true, BuildDate: time.Date(2025, 7, 23, 0, 0, 0, 0, time.UTC),
		Servers:  []minio.Server{{Endpoint: "a", State: "online", OnlineDrives: 4}},
		Services: minio.Services{KMS: "Online", AuditTargets: []string{"webhook"}},
		Account:  "alice", AccountIsUser: true,
		Layout:          minio.Layout{Nodes: 4, Drives: 16, Sets: 1, DrivesPerSet: 16, Parity: 4, DrivesPerNodePerSet: 4, ToleratesNodeLoss: true, RawTotal: 1000, RawUsed: 500, UsedPercent: 50},
		SiteReplication: minio.SiteReplication{Checked: true, Enabled: true, Sites: []string{"a", "b"}},
		IAM: minio.IAM{
			Users:    []minio.User{{Name: "alice", Status: "enabled", Policies: []string{"readwrite"}}},
			Policies: []minio.PolicyDoc{{Name: "readwrite", BuiltIn: true, Wildcard: true, Attached: 1}},
		},
	}
}

func TestEvaluateMinIOHealthyOnlyFlagsArchive(t *testing.T) {
	fs := evaluateMinIO(&Report{MinIO: healthyMinIO()})
	if len(fs) != 1 || fs[0].ID != "MINIO_ARCHIVED" || !strings.Contains(fs[0].Message, "2025-07-23") {
		t.Fatalf("got %+v", fs)
	}
	if fs := evaluateMinIO(&Report{}); fs != nil {
		t.Fatalf("no adapter must mean no findings, got %+v", fs)
	}
}

func TestEvaluateMinIORules(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*minio.Info)
		want   string
		sev    Severity
	}{
		{"server offline", func(m *minio.Info) { m.Servers[0].State = "offline" }, "SERVER_OFFLINE", High},
		{"drives offline", func(m *minio.Info) { m.Servers[0].OfflineDrives = 2 }, "DRIVES_OFFLINE", High},
		{"backend offline count", func(m *minio.Info) { m.Backend.OfflineDrives = 1 }, "DRIVES_OFFLINE", High},
		{"healing", func(m *minio.Info) { m.Servers[0].HealingDrives = 1 }, "DRIVES_HEALING", Low},
		{"no audit", func(m *minio.Info) { m.Services.AuditTargets = nil }, "AUDIT_LOG_OFF", Medium},
		{"no kms", func(m *minio.Info) { m.Services.KMS = "" }, "KMS_OFF", Info},
		{"root credential", func(m *minio.Info) { m.AccountIsUser = false }, "ROOT_CREDENTIAL_IN_USE", Low},
		{"iam unreadable", func(m *minio.Info) { m.IAM.Error = "boom"; m.AccountIsUser = false }, "IAM_UNREADABLE", Info},
		{"custom wildcard policy", func(m *minio.Info) {
			m.IAM.Policies = append(m.IAM.Policies, minio.PolicyDoc{Name: "god", Wildcard: true, Attached: 2})
		}, "IAM_POLICY_WILDCARD", Medium},
		{"admin users", func(m *minio.Info) { m.IAM.Users[0].Policies = []string{"consoleAdmin"} }, "IAM_ADMIN_USERS", Medium},
		{"admin via custom policy", func(m *minio.Info) {
			m.IAM.Policies = append(m.IAM.Policies, minio.PolicyDoc{Name: "ops", AdminAPI: true})
			m.IAM.Users[0].Policies = []string{"ops"}
		}, "IAM_ADMIN_USERS", Medium},
		{"user without policy", func(m *minio.Info) { m.IAM.Users[0].Policies = nil }, "IAM_USERS_WITHOUT_POLICY", Low},
		{"disabled user", func(m *minio.Info) { m.IAM.Users[0].Status = "disabled" }, "IAM_USERS_DISABLED", Info},
		{"capacity high", func(m *minio.Info) { m.Layout.UsedPercent = 88 }, "CAPACITY_HIGH", Medium},
		{"capacity critical", func(m *minio.Info) { m.Layout.UsedPercent = 97 }, "CAPACITY_CRITICAL", High},
		{"node loss", func(m *minio.Info) { m.Layout.ToleratesNodeLoss = false }, "NODE_LOSS_NOT_TOLERATED", High},
		{"parity low", func(m *minio.Info) { m.Layout.Parity = 2 }, "PARITY_LOW", Medium},
		{"site replication off", func(m *minio.Info) { m.SiteReplication.Enabled = false }, "SITE_REPLICATION_OFF", Info},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := healthyMinIO()
			tc.mutate(m)
			var found []Finding
			for _, f := range evaluateMinIO(&Report{MinIO: m}) {
				if f.ID != "MINIO_ARCHIVED" {
					found = append(found, f)
				}
			}
			if len(found) != 1 || found[0].ID != tc.want || found[0].Severity != tc.sev {
				t.Fatalf("got %+v, want %s/%s", found, tc.want, tc.sev)
			}
		})
	}
}

func TestMaskKey(t *testing.T) {
	for in, want := range map[string]string{"": "none", "ab": "a…", "sigmatoshi": "sigm…", "eimeradmin": "eime…"} {
		if got := maskKey(in); got != want {
			t.Errorf("maskKey(%q) = %q, want %q", in, got, want)
		}
	}
	m := healthyMinIO()
	m.AccountIsUser, m.Account = false, "sigmatoshi"
	for _, f := range evaluateMinIO(&Report{MinIO: m}) {
		if f.ID == "ROOT_CREDENTIAL_IN_USE" && strings.Contains(f.Message, "sigmatoshi") {
			t.Fatalf("full key leaked into finding: %s", f.Message)
		}
	}
}

func TestEvaluateMinIOUnavailable(t *testing.T) {
	fs := evaluateMinIO(&Report{MinIO: &minio.Info{Error: "admin API refused"}})
	if len(fs) != 1 || fs[0].ID != "ADMIN_API_UNAVAILABLE" {
		t.Fatalf("got %+v", fs)
	}
}

func TestApplyUsage(t *testing.T) {
	buckets := []Bucket{{Name: "a", Inventory: Inventory{Objects: 10, Truncated: true}}, {Name: "b", Inventory: Inventory{Objects: 3}}}
	applyUsage(buckets, &minio.Usage{Buckets: map[string]minio.BucketUsage{"a": {Objects: 5000, Bytes: 42, Versions: 5001}}})
	if a := buckets[0].Inventory; !a.Exact || a.Truncated || a.Objects != 5000 || a.Bytes != 42 || a.Versions != 5001 {
		t.Fatalf("a: %+v", a)
	}
	if b := buckets[1].Inventory; b.Exact || b.Objects != 3 {
		t.Fatalf("b: %+v", b)
	}
	applyUsage(buckets, nil)
}
