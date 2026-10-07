package audit

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/morrieinmaas/eimer/internal/minio"
)

// minioArchived is the day the upstream repository was archived. Builds before it
// are the last community releases; nothing newer will come from upstream.
var minioArchived = time.Date(2026, 4, 25, 0, 0, 0, 0, time.UTC)

// applyUsage replaces capped inventory numbers with the server's exact counters.
func applyUsage(buckets []Bucket, u *minio.Usage) {
	if u == nil {
		return
	}
	for i := range buckets {
		bu, ok := u.Buckets[buckets[i].Name]
		if !ok {
			continue
		}
		inv := &buckets[i].Inventory
		inv.Objects, inv.Bytes, inv.Versions = int64(bu.Objects), int64(bu.Bytes), int64(bu.Versions)
		inv.Exact, inv.Truncated = true, false
	}
}

func evaluateMinIO(r *Report) []Finding {
	m := r.MinIO
	if m == nil {
		return nil
	}
	var out []Finding
	add := func(id string, sev Severity, msg string) {
		out = append(out, Finding{ID: id, Severity: sev, Message: msg})
	}
	if !m.Available {
		add("ADMIN_API_UNAVAILABLE", Info, "MinIO admin API not readable with this credential, so server health and IAM were not audited: "+m.Error)
		return out
	}

	if !m.BuildDate.IsZero() {
		add("MINIO_ARCHIVED", Medium, fmt.Sprintf(
			"running MinIO built %s; upstream archived the project on %s, so this build receives no fixes",
			m.BuildDate.Format("2006-01-02"), minioArchived.Format("2006-01-02")))
	}
	offline, healing := 0, 0
	for _, s := range m.Servers {
		offline += s.OfflineDrives
		healing += s.HealingDrives
		if s.State != "online" {
			add("SERVER_OFFLINE", High, fmt.Sprintf("server %s is %s", s.Endpoint, s.State))
		}
	}
	if offline == 0 {
		offline = m.Backend.OfflineDrives
	}
	if offline > 0 {
		add("DRIVES_OFFLINE", High, fmt.Sprintf("%d drive(s) offline; parity is %d per set", offline, m.Backend.Parity))
	}
	if healing > 0 {
		add("DRIVES_HEALING", Low, fmt.Sprintf("%d drive(s) healing", healing))
	}
	l := m.Layout
	switch {
	case l.UsedPercent >= 95:
		add("CAPACITY_CRITICAL", High, fmt.Sprintf("raw capacity %.0f%% used (%s of %s)", l.UsedPercent, humanBytes(int64(l.RawUsed)), humanBytes(int64(l.RawTotal))))
	case l.UsedPercent >= 85:
		add("CAPACITY_HIGH", Medium, fmt.Sprintf("raw capacity %.0f%% used (%s of %s)", l.UsedPercent, humanBytes(int64(l.RawUsed)), humanBytes(int64(l.RawTotal))))
	}
	if l.Nodes > 1 && l.DrivesPerNodePerSet > 0 && !l.ToleratesNodeLoss {
		add("NODE_LOSS_NOT_TOLERATED", High, fmt.Sprintf(
			"parity %d per set of %d drives over %d nodes: one node holds up to %d drives of a set, so a single node outage takes data offline",
			l.Parity, l.DrivesPerSet, l.Nodes, l.DrivesPerNodePerSet))
	}
	if l.DrivesPerSet >= 8 && l.Parity > 0 && l.Parity < 4 {
		add("PARITY_LOW", Medium, fmt.Sprintf("parity %d on %d-drive sets; MinIO's own default for sets this size is 4", l.Parity, l.DrivesPerSet))
	}
	if m.SiteReplication.Checked && !m.SiteReplication.Enabled {
		add("SITE_REPLICATION_OFF", Info, "no site replication: the store holds the only copy of its data unless something external copies it out")
	}
	if len(m.Services.AuditTargets) == 0 {
		add("AUDIT_LOG_OFF", Medium, "no audit log target configured: API calls leave no evidence trail")
	}
	if m.Services.KMS == "" {
		add("KMS_OFF", Info, "no KMS configured: server-side encryption cannot be enabled")
	}
	if m.Account != "" && !m.AccountIsUser && m.IAM.Error == "" {
		add("ROOT_CREDENTIAL_IN_USE", Low, fmt.Sprintf("this audit ran as %s, which is not a managed user: likely the root credential", maskKey(m.Account)))
	}

	iam := m.IAM
	if iam.Error != "" {
		add("IAM_UNREADABLE", Info, "IAM inventory not readable: "+iam.Error)
		return out
	}
	for _, p := range iam.Policies {
		if p.Wildcard && !p.BuiltIn && p.Attached > 0 {
			add("IAM_POLICY_WILDCARD", Medium, fmt.Sprintf("custom policy %q allows everything and is attached %d time(s)", p.Name, p.Attached))
		}
	}
	admins, noPolicy, disabled := 0, 0, 0
	for _, u := range iam.Users {
		if u.Status == "disabled" {
			disabled++
			continue
		}
		if len(u.Policies) == 0 && len(u.Groups) == 0 {
			noPolicy++
		}
		for _, p := range u.Policies {
			if p == "consoleAdmin" || hasAdminAPI(iam.Policies, p) {
				admins++
				break
			}
		}
	}
	if admins > 0 {
		add("IAM_ADMIN_USERS", Medium, fmt.Sprintf("%d user(s) hold admin API rights directly", admins))
	}
	if noPolicy > 0 {
		add("IAM_USERS_WITHOUT_POLICY", Low, fmt.Sprintf("%d enabled user(s) have no policy and no group", noPolicy))
	}
	if disabled > 0 {
		add("IAM_USERS_DISABLED", Info, fmt.Sprintf("%d disabled user(s) still exist", disabled))
	}
	return out
}

func hasAdminAPI(policies []minio.PolicyDoc, name string) bool {
	for _, p := range policies {
		if p.Name == name {
			return p.AdminAPI
		}
	}
	return false
}

func writeMinIO(w io.Writer, m *minio.Info) {
	fmt.Fprintln(w, "minio admin")
	if !m.Available {
		fmt.Fprintf(w, "  not available: %s\n", m.Error)
		return
	}
	fmt.Fprintf(w, "  version %s   mode %s   backend %s parity %d   buckets %d   objects %d   usage %s\n",
		m.Version, m.Mode, m.Backend.Type, m.Backend.Parity, m.Totals.Buckets, m.Totals.Objects, humanBytes(int64(m.Totals.Bytes)))
	if l := m.Layout; l.Drives > 0 {
		tol := "NOT tolerated"
		if l.ToleratesNodeLoss {
			tol = "tolerated"
		}
		fmt.Fprintf(w, "  layout %d node(s), %d drive(s), %d set(s) of %d, parity %d: any %d drive(s) per set may fail, node loss %s\n",
			l.Nodes, l.Drives, l.Sets, l.DrivesPerSet, l.Parity, l.Parity, tol)
		fmt.Fprintf(w, "  raw capacity %s, used %s (%.0f%%)\n", humanBytes(int64(l.RawTotal)), humanBytes(int64(l.RawUsed)), l.UsedPercent)
	}
	switch sr := m.SiteReplication; {
	case !sr.Checked:
		fmt.Fprintln(w, "  site replication: not readable")
	case sr.Enabled:
		fmt.Fprintf(w, "  site replication: on, sites %s\n", strings.Join(sr.Sites, ", "))
	default:
		fmt.Fprintln(w, "  site replication: off")
	}
	fmt.Fprintf(w, "  kms %s   ldap %s   audit targets %s   logger targets %s   notification targets %d\n",
		orNone(m.Services.KMS), orNone(m.Services.LDAP), orNone(strings.Join(m.Services.AuditTargets, ",")),
		orNone(strings.Join(m.Services.LoggerTargets, ",")), m.Services.Notifications)
	if m.Usage != nil {
		fmt.Fprintf(w, "  scanner updated %s", m.Usage.LastUpdate.UTC().Format(time.RFC3339))
		if m.Usage.Capacity > 0 { // older builds do not report capacity
			fmt.Fprintf(w, "   capacity %s   used %s", humanBytes(int64(m.Usage.Capacity)), humanBytes(int64(m.Usage.Used)))
		}
		fmt.Fprintln(w)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  SERVER\tSTATE\tVERSION\tUPTIME\tDRIVES OK\tOFFLINE\tHEALING\tRAW\tUSED")
	for _, s := range m.Servers {
		var total, used uint64
		for _, d := range m.Drives {
			if d.Server == s.Endpoint {
				total += d.Total
				used += d.Used
			}
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\t%s\n", s.Endpoint, s.State, s.Version,
			(time.Duration(s.UptimeSeconds) * time.Second).Truncate(time.Hour), s.OnlineDrives, s.OfflineDrives, s.HealingDrives,
			humanBytes(int64(total)), humanBytes(int64(used)))
	}
	_ = tw.Flush()
	if len(m.Sets) > 0 {
		tw = tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SET\tNODES\tDRIVES OK\tOFFLINE\tHEALING\tRAW\tUSED\tOBJECTS")
		for _, s := range m.Sets {
			fmt.Fprintf(tw, "  %d/%d\t%d\t%d\t%d\t%d\t%s\t%s\t%d\n", s.Pool, s.Set, len(s.Nodes), s.OnlineDrives, s.OfflineDrives, s.HealingDrives,
				humanBytes(int64(s.RawCapacity)), humanBytes(int64(s.RawUsage)), s.Objects)
		}
		_ = tw.Flush()
	}
	if m.IAM.Error != "" {
		fmt.Fprintf(w, "  iam: %s\n", m.IAM.Error)
		return
	}
	svc := 0
	for _, n := range m.IAM.ServiceAccounts {
		svc += n
	}
	fmt.Fprintf(w, "  iam: %d user(s), %d group(s), %d polic(ies), %d service account(s); audit ran as %s\n",
		len(m.IAM.Users), len(m.IAM.Groups), len(m.IAM.Policies), svc, maskKey(m.Account))
}

// maskKey keeps enough of an access key to recognise it and no more; MinIO user
// names are access keys, and the text report may end up in a chat or a ticket.
func maskKey(key string) string {
	if key == "" {
		return "none"
	}
	if len(key) <= 4 {
		return key[:1] + "…"
	}
	return key[:4] + "…"
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
