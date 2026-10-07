// Package minio reads the MinIO admin API, read-only, to see what the S3 API cannot:
// server health, exact usage, and the IAM inventory a migration has to carry over.
//
// It talks the wire protocol directly rather than importing MinIO's AGPL client
// library, which an Apache 2.0 tool cannot embed. Paths and shapes follow the
// madmin-go v3 API as shipped in the last community releases.
package minio

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
)

// Options configures one collection run.
type Options struct {
	Endpoint  string
	Region    string
	AccessKey string
	SecretKey string
	HTTP      *http.Client
	Now       time.Time // zero: time.Now()
}

// Info is everything collected from the admin API.
type Info struct {
	Available bool   `json:"available"` // admin API reachable with this credential
	Error     string `json:"error,omitempty"`

	Mode         string    `json:"mode,omitempty"`
	DeploymentID string    `json:"deployment_id,omitempty"`
	Version      string    `json:"version,omitempty"`
	BuildDate    time.Time `json:"build_date,omitempty"`
	Servers      []Server  `json:"servers,omitempty"`
	Backend      Backend   `json:"backend"`
	Totals       Totals    `json:"totals"`
	Services     Services  `json:"services"`

	Drives          []Drive         `json:"drives,omitempty"`
	Sets            []SetInfo       `json:"erasure_sets,omitempty"`
	Layout          Layout          `json:"layout"`
	SiteReplication SiteReplication `json:"site_replication"`

	Usage *Usage `json:"usage,omitempty"`
	IAM   IAM    `json:"iam"`
	// Account is the identity the audit ran as, "" when the admin API refused.
	Account       string `json:"account,omitempty"`
	AccountIsUser bool   `json:"account_is_user"` // false: root or an external identity
}

// Server is one node of the deployment.
type Server struct {
	Endpoint      string `json:"endpoint"`
	State         string `json:"state"`
	Version       string `json:"version"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	OnlineDrives  int    `json:"online_drives"`
	OfflineDrives int    `json:"offline_drives"`
	HealingDrives int    `json:"healing_drives"`
}

// Drive is one physical drive as the server sees it.
type Drive struct {
	Server  string `json:"server"`
	Path    string `json:"path,omitempty"`
	State   string `json:"state"`
	Healing bool   `json:"healing"`
	Total   uint64 `json:"total_bytes"`
	Used    uint64 `json:"used_bytes"`
	Avail   uint64 `json:"available_bytes"`
	Pool    int    `json:"pool"`
	Set     int    `json:"set"`
	Index   int    `json:"index"`
}

// SetInfo is one erasure set: the unit that fails together.
type SetInfo struct {
	Pool          int      `json:"pool"`
	Set           int      `json:"set"`
	Nodes         []string `json:"nodes,omitempty"`
	OnlineDrives  int      `json:"online_drives"`
	OfflineDrives int      `json:"offline_drives"`
	HealingDrives int      `json:"healing_drives"`
	RawCapacity   uint64   `json:"raw_capacity_bytes"`
	RawUsage      uint64   `json:"raw_usage_bytes"`
	Usage         uint64   `json:"usage_bytes"`
	Objects       uint64   `json:"objects"`
}

// Layout is the redundancy picture derived from the erasure configuration.
type Layout struct {
	Nodes               int     `json:"nodes"`
	Drives              int     `json:"drives"`
	Sets                int     `json:"sets"`
	DrivesPerSet        int     `json:"drives_per_set"`
	Parity              int     `json:"parity"`
	DrivesPerNodePerSet int     `json:"drives_per_node_per_set"` // worst case across sets
	ToleratesNodeLoss   bool    `json:"tolerates_node_loss"`
	RawTotal            uint64  `json:"raw_total_bytes"`
	RawUsed             uint64  `json:"raw_used_bytes"`
	UsedPercent         float64 `json:"used_percent"`
}

// SiteReplication is multi-site replication, the only store-level backup MinIO offers.
type SiteReplication struct {
	Checked bool     `json:"checked"` // false when the endpoint refused or is unknown
	Enabled bool     `json:"enabled"`
	Sites   []string `json:"sites,omitempty"`
}

// Backend is the erasure layout.
type Backend struct {
	Type          string `json:"type,omitempty"`
	OnlineDrives  int    `json:"online_drives"`
	OfflineDrives int    `json:"offline_drives"`
	Parity        int    `json:"parity"`
	Sets          []int  `json:"sets,omitempty"`
	DrivesPerSet  []int  `json:"drives_per_set,omitempty"`
}

// Totals are the deployment-wide counters the server keeps.
type Totals struct {
	Buckets  uint64 `json:"buckets"`
	Objects  uint64 `json:"objects"`
	Versions uint64 `json:"versions"`
	Bytes    uint64 `json:"bytes"`
}

// Services summarises the integrations that matter for evidence.
type Services struct {
	KMS           string   `json:"kms,omitempty"` // status string, "" when unconfigured
	LDAP          string   `json:"ldap,omitempty"`
	AuditTargets  []string `json:"audit_targets,omitempty"`
	LoggerTargets []string `json:"logger_targets,omitempty"`
	Notifications int      `json:"notification_targets"`
}

// Usage is the scanner's last data-usage snapshot: exact counts without a listing.
type Usage struct {
	LastUpdate time.Time              `json:"last_update"`
	Capacity   uint64                 `json:"capacity_bytes,omitempty"`
	Used       uint64                 `json:"used_bytes,omitempty"`
	Buckets    map[string]BucketUsage `json:"buckets"`
}

// BucketUsage is one bucket's server-side counters.
type BucketUsage struct {
	Objects       uint64 `json:"objects"`
	Versions      uint64 `json:"versions"`
	DeleteMarkers uint64 `json:"delete_markers"`
	Bytes         uint64 `json:"bytes"`
	LockedActive  uint64 `json:"locked_versions_active"`
	LockedExpired uint64 `json:"locked_versions_expired"`
	LegalHold     uint64 `json:"legal_hold_versions"`
}

// IAM is the identity inventory.
type IAM struct {
	Error           string            `json:"error,omitempty"`
	Users           []User            `json:"users,omitempty"`
	Groups          []Group           `json:"groups,omitempty"`
	Policies        []PolicyDoc       `json:"policies,omitempty"`
	ServiceAccounts map[string]int    `json:"service_accounts,omitempty"` // parent user -> count
	Attached        map[string]int    `json:"policy_attachments,omitempty"`
	Documents       map[string]string `json:"-"`
}

// User is one managed identity.
type User struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Policies []string `json:"policies,omitempty"`
	Groups   []string `json:"groups,omitempty"`
}

// Group is one group with its members and policies.
type Group struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"`
	Members  []string `json:"members,omitempty"`
	Policies []string `json:"policies,omitempty"`
}

// PolicyDoc is a canned policy reduced to what an access review asks.
type PolicyDoc struct {
	Name      string `json:"name"`
	BuiltIn   bool   `json:"built_in"`
	Wildcard  bool   `json:"wildcard"` // Allow on s3:* or admin:* against every resource
	AdminAPI  bool   `json:"admin_api"`
	Attached  int    `json:"attached"` // users plus groups referencing it
	Statement int    `json:"statements"`
}

var builtInPolicies = map[string]bool{"consoleAdmin": true, "readonly": true, "readwrite": true, "writeonly": true, "diagnostics": true}

const adminPrefix = "/minio/admin/v3"

// Collect reads the admin API. A credential without admin rights yields
// Available=false and an Error, never a failed audit.
func Collect(ctx context.Context, o Options) *Info {
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	if o.HTTP == nil {
		o.HTTP = &http.Client{Timeout: 60 * time.Second}
	}
	c := client{o: o, signer: v4.NewSigner()}
	info := &Info{}

	var raw infoMessage
	if err := c.getJSON(ctx, "/info", nil, &raw); err != nil {
		info.Error = err.Error()
		if strings.Contains(info.Error, "AccessDenied") {
			info.Error = "admin API refused: credential has no admin rights"
		}
		return info
	}
	info.Available = true
	info.fromInfo(&raw)

	var du dataUsage
	if err := c.getJSON(ctx, "/datausageinfo", url.Values{"capacity": {"true"}}, &du); err == nil {
		info.Usage = du.toUsage()
	}

	var acct struct {
		AccountName string `json:"accountName"`
	}
	if err := c.getJSON(ctx, "/accountinfo", nil, &acct); err == nil {
		info.Account = acct.AccountName
	}

	var sr struct {
		Enabled bool `json:"enabled"`
		Sites   []struct {
			Name     string `json:"name"`
			Endpoint string `json:"endpoint"`
		} `json:"sites"`
	}
	if err := c.getJSON(ctx, "/site-replication/info", nil, &sr); err == nil {
		info.SiteReplication.Checked = true
		info.SiteReplication.Enabled = sr.Enabled
		for _, site := range sr.Sites {
			label := site.Name
			if site.Endpoint != "" {
				label += " (" + site.Endpoint + ")"
			}
			info.SiteReplication.Sites = append(info.SiteReplication.Sites, label)
		}
	}

	info.IAM = c.collectIAM(ctx)
	info.AccountIsUser = slices.ContainsFunc(info.IAM.Users, func(u User) bool { return u.Name == info.Account })
	return info
}

type client struct {
	o      Options
	signer *v4.Signer
}

func (c client) get(ctx context.Context, path string, query url.Values) ([]byte, error) {
	u := strings.TrimRight(c.o.Endpoint, "/") + adminPrefix + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	hash := hex.EncodeToString(sha256.New().Sum(nil)) // empty body
	req.Header.Set("X-Amz-Content-Sha256", hash)
	creds := aws.Credentials{AccessKeyID: c.o.AccessKey, SecretAccessKey: c.o.SecretKey}
	if err := c.signer.SignHTTP(ctx, creds, req, hash, "s3", c.o.Region, c.o.Now); err != nil {
		return nil, err
	}
	resp, err := c.o.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("admin %s: %s", path, apiError(resp.StatusCode, body))
	}
	return body, nil
}

func (c client) getJSON(ctx context.Context, path string, query url.Values, v any) error {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// getEncryptedJSON reads a response MinIO encrypts with the caller's secret key.
func (c client) getEncryptedJSON(ctx context.Context, path string, query url.Values, v any) error {
	body, err := c.get(ctx, path, query)
	if err != nil {
		return err
	}
	plain, err := decrypt(c.o.SecretKey, body)
	if err != nil {
		return fmt.Errorf("admin %s: %w", path, err)
	}
	return json.Unmarshal(plain, v)
}

var codeRe = regexp.MustCompile(`<Code>([^<]+)</Code>`)

func apiError(status int, body []byte) string {
	if m := codeRe.FindSubmatch(body); m != nil {
		return string(m[1])
	}
	var j struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if json.Unmarshal(body, &j) == nil && j.Code != "" {
		return j.Code
	}
	return http.StatusText(status)
}

// Wire shapes, trimmed to the fields used.

type infoMessage struct {
	Mode         string `json:"mode"`
	DeploymentID string `json:"deploymentID"`
	Buckets      struct {
		Count uint64 `json:"count"`
	} `json:"buckets"`
	Objects struct {
		Count uint64 `json:"count"`
	} `json:"objects"`
	Versions struct {
		Count uint64 `json:"count"`
	} `json:"versions"`
	Usage struct {
		Size uint64 `json:"size"`
	} `json:"usage"`
	Services struct {
		KMS struct {
			Status string `json:"status"`
		} `json:"kms"`
		LDAP struct {
			Status string `json:"status"`
		} `json:"ldap"`
		Logger        []map[string]json.RawMessage `json:"logger"`
		Audit         []map[string]json.RawMessage `json:"audit"`
		Notifications []map[string]json.RawMessage `json:"notifications"`
	} `json:"services"`
	Backend struct {
		Type         string `json:"backendType"`
		Online       int    `json:"onlineDisks"`
		Offline      int    `json:"offlineDisks"`
		Parity       int    `json:"standardSCParity"`
		Sets         []int  `json:"totalSets"`
		DrivesPerSet []int  `json:"totalDrivesPerSet"`
	} `json:"backend"`
	Servers []struct {
		State    string      `json:"state"`
		Endpoint string      `json:"endpoint"`
		Uptime   int64       `json:"uptime"`
		Version  string      `json:"version"`
		Drives   []wireDrive `json:"drives"`
	} `json:"servers"`
	Pools map[string]map[string]struct {
		Nodes        []string `json:"nodes"`
		OnlineDisks  int      `json:"onlineDisks"`
		OfflineDisks int      `json:"offlineDisks"`
		HealDisks    int      `json:"healDisks"`
		RawCapacity  uint64   `json:"rawCapacity"`
		RawUsage     uint64   `json:"rawUsage"`
		Usage        uint64   `json:"usage"`
		ObjectsCount uint64   `json:"objectsCount"`
	} `json:"pools"`
}

type wireDrive struct {
	Endpoint string `json:"endpoint"`
	Path     string `json:"path"`
	State    string `json:"state"`
	Healing  bool   `json:"healing"`
	Total    uint64 `json:"totalspace"`
	Used     uint64 `json:"usedspace"`
	Avail    uint64 `json:"availspace"`
	Pool     int    `json:"pool_index"`
	Set      int    `json:"set_index"`
	Index    int    `json:"disk_index"`
}

var releaseRe = regexp.MustCompile(`RELEASE\.(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)`)

func (i *Info) fromInfo(m *infoMessage) {
	i.Mode, i.DeploymentID = m.Mode, m.DeploymentID
	i.Totals = Totals{Buckets: m.Buckets.Count, Objects: m.Objects.Count, Versions: m.Versions.Count, Bytes: m.Usage.Size}
	i.Backend = Backend{Type: m.Backend.Type, OnlineDrives: m.Backend.Online, OfflineDrives: m.Backend.Offline,
		Parity: m.Backend.Parity, Sets: m.Backend.Sets, DrivesPerSet: m.Backend.DrivesPerSet}
	i.Services = Services{KMS: m.Services.KMS.Status, LDAP: m.Services.LDAP.Status, Notifications: len(m.Services.Notifications)}
	for _, t := range m.Services.Audit {
		i.Services.AuditTargets = append(i.Services.AuditTargets, keys(t)...)
	}
	for _, t := range m.Services.Logger {
		i.Services.LoggerTargets = append(i.Services.LoggerTargets, keys(t)...)
	}
	for _, s := range m.Servers {
		srv := Server{Endpoint: s.Endpoint, State: s.State, Version: s.Version, UptimeSeconds: s.Uptime}
		for _, d := range s.Drives {
			switch {
			case d.Healing:
				srv.HealingDrives++
			case d.State == "ok":
				srv.OnlineDrives++
			default:
				srv.OfflineDrives++
			}
			i.Drives = append(i.Drives, Drive{Server: s.Endpoint, Path: d.Path, State: d.State, Healing: d.Healing,
				Total: d.Total, Used: d.Used, Avail: d.Avail, Pool: d.Pool, Set: d.Set, Index: d.Index})
			i.Layout.RawTotal += d.Total
			i.Layout.RawUsed += d.Used
		}
		i.Servers = append(i.Servers, srv)
		if i.Version == "" && s.Version != "" {
			i.Version = s.Version
			i.BuildDate = buildDate(s.Version)
		}
	}
	sort.Slice(i.Servers, func(a, b int) bool { return i.Servers[a].Endpoint < i.Servers[b].Endpoint })
	sort.Slice(i.Drives, func(a, b int) bool {
		if i.Drives[a].Server != i.Drives[b].Server {
			return i.Drives[a].Server < i.Drives[b].Server
		}
		return i.Drives[a].Path < i.Drives[b].Path
	})

	for pool, sets := range m.Pools {
		for set, info := range sets {
			si := SetInfo{Pool: atoi(pool), Set: atoi(set), Nodes: info.Nodes, OnlineDrives: info.OnlineDisks, OfflineDrives: info.OfflineDisks,
				HealingDrives: info.HealDisks, RawCapacity: info.RawCapacity, RawUsage: info.RawUsage, Usage: info.Usage, Objects: info.ObjectsCount}
			sort.Strings(si.Nodes)
			i.Sets = append(i.Sets, si)
		}
	}
	sort.Slice(i.Sets, func(a, b int) bool {
		if i.Sets[a].Pool != i.Sets[b].Pool {
			return i.Sets[a].Pool < i.Sets[b].Pool
		}
		return i.Sets[a].Set < i.Sets[b].Set
	})
	i.Layout = deriveLayout(i.Layout, len(i.Servers), len(i.Drives), m.Backend.Sets, m.Backend.DrivesPerSet, m.Backend.Parity, i.Sets)
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

// deriveLayout works out what the erasure configuration survives. A set spreads its
// drives over its nodes; losing a node removes drivesPerSet/nodes drives from every set
// it touches, which the parity must cover for the set to stay readable.
func deriveLayout(l Layout, nodes, drives int, sets, drivesPerSet []int, parity int, setInfo []SetInfo) Layout {
	l.Nodes, l.Drives, l.Parity = nodes, drives, parity
	for _, n := range sets {
		l.Sets += n
	}
	if len(drivesPerSet) > 0 {
		l.DrivesPerSet = drivesPerSet[0]
	}
	worst := 0
	for _, s := range setInfo {
		n := len(s.Nodes)
		if n == 0 || l.DrivesPerSet == 0 {
			continue
		}
		if per := (l.DrivesPerSet + n - 1) / n; per > worst {
			worst = per
		}
	}
	if worst == 0 && nodes > 0 && l.DrivesPerSet > 0 { // no per-set node list: assume an even spread
		worst = (l.DrivesPerSet + nodes - 1) / nodes
	}
	l.DrivesPerNodePerSet = worst
	l.ToleratesNodeLoss = nodes > 1 && worst > 0 && parity >= worst
	if l.RawTotal > 0 {
		l.UsedPercent = 100 * float64(l.RawUsed) / float64(l.RawTotal)
	}
	return l
}

// buildDate parses both forms MinIO uses: "2025-07-23T15:54:02Z" in /info and
// "RELEASE.2025-07-23T15-54-02Z" in binaries and image tags.
func buildDate(version string) time.Time {
	if t, err := time.Parse(time.RFC3339, version); err == nil {
		return t
	}
	if m := releaseRe.FindStringSubmatch(version); m != nil {
		t, _ := time.Parse("2006-01-02T15-04-05Z", m[1])
		return t
	}
	return time.Time{}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

type dataUsage struct {
	LastUpdate time.Time `json:"lastUpdate"`
	Capacity   uint64    `json:"capacity"`
	Used       uint64    `json:"usedCapacity"`
	Buckets    map[string]struct {
		Size          uint64 `json:"size"`
		Objects       uint64 `json:"objectsCount"`
		Versions      uint64 `json:"versionsCount"`
		DeleteMarkers uint64 `json:"deleteMarkersCount"`
		LockActive    uint64 `json:"lockActiveRetentionVersions"`
		LockExpired   uint64 `json:"lockExpiredRetentionVersions"`
		LegalHold     uint64 `json:"lockLegalHoldVersions"`
	} `json:"bucketsUsageInfo"`
}

func (d *dataUsage) toUsage() *Usage {
	u := &Usage{LastUpdate: d.LastUpdate, Capacity: d.Capacity, Used: d.Used, Buckets: map[string]BucketUsage{}}
	for name, b := range d.Buckets {
		u.Buckets[name] = BucketUsage{Objects: b.Objects, Versions: b.Versions, DeleteMarkers: b.DeleteMarkers, Bytes: b.Size,
			LockedActive: b.LockActive, LockedExpired: b.LockExpired, LegalHold: b.LegalHold}
	}
	return u
}

// maxServiceAccountLookups bounds the per-user calls on large IAM databases.
const maxServiceAccountLookups = 50

func (c client) collectIAM(ctx context.Context) IAM {
	var iam IAM
	users := map[string]struct {
		PolicyName string   `json:"policyName"`
		Status     string   `json:"status"`
		MemberOf   []string `json:"memberOf"`
	}{}
	if err := c.getEncryptedJSON(ctx, "/list-users", nil, &users); err != nil {
		iam.Error = err.Error()
		return iam
	}
	iam.Attached = map[string]int{}
	for name, u := range users {
		policies := splitPolicies(u.PolicyName)
		for _, p := range policies {
			iam.Attached[p]++
		}
		iam.Users = append(iam.Users, User{Name: name, Status: u.Status, Policies: policies, Groups: u.MemberOf})
	}
	sort.Slice(iam.Users, func(a, b int) bool { return iam.Users[a].Name < iam.Users[b].Name })

	var groups []string
	if err := c.getJSON(ctx, "/groups", nil, &groups); err == nil {
		for _, g := range groups {
			var desc struct {
				Name    string   `json:"name"`
				Status  string   `json:"status"`
				Members []string `json:"members"`
				Policy  string   `json:"policy"`
			}
			if err := c.getJSON(ctx, "/group", url.Values{"group": {g}}, &desc); err != nil {
				continue
			}
			policies := splitPolicies(desc.Policy)
			for _, p := range policies {
				iam.Attached[p]++
			}
			iam.Groups = append(iam.Groups, Group{Name: g, Status: desc.Status, Members: desc.Members, Policies: policies})
		}
	}

	docs := map[string]json.RawMessage{}
	if err := c.getJSON(ctx, "/list-canned-policies", nil, &docs); err == nil {
		iam.Documents = map[string]string{}
		for name, doc := range docs {
			iam.Documents[name] = string(doc)
			wildcard, admin, n := inspectPolicy(doc)
			iam.Policies = append(iam.Policies, PolicyDoc{Name: name, BuiltIn: builtInPolicies[name], Wildcard: wildcard,
				AdminAPI: admin, Attached: iam.Attached[name], Statement: n})
		}
		sort.Slice(iam.Policies, func(a, b int) bool { return iam.Policies[a].Name < iam.Policies[b].Name })
	}

	iam.ServiceAccounts = map[string]int{}
	for i, u := range iam.Users {
		if i == maxServiceAccountLookups {
			break
		}
		var resp struct {
			Accounts []json.RawMessage `json:"accounts"`
		}
		if err := c.getEncryptedJSON(ctx, "/list-service-accounts", url.Values{"user": {u.Name}}, &resp); err == nil && len(resp.Accounts) > 0 {
			iam.ServiceAccounts[u.Name] = len(resp.Accounts)
		}
	}
	return iam
}

func splitPolicies(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// inspectPolicy reports whether a policy grants everything (s3:* or admin:* on every
// resource), whether it touches the admin API at all, and how many statements it has.
func inspectPolicy(doc json.RawMessage) (wildcard, admin bool, statements int) {
	var p struct {
		Statement json.RawMessage `json:"Statement"`
	}
	if json.Unmarshal(doc, &p) != nil {
		return false, false, 0
	}
	type stmt struct {
		Effect   string          `json:"Effect"`
		Action   json.RawMessage `json:"Action"`
		Resource json.RawMessage `json:"Resource"`
	}
	var stmts []stmt
	if json.Unmarshal(p.Statement, &stmts) != nil {
		var one stmt
		if json.Unmarshal(p.Statement, &one) != nil {
			return false, false, 0
		}
		stmts = []stmt{one}
	}
	for _, s := range stmts {
		if s.Effect != "Allow" {
			continue
		}
		actions, resources := stringList(s.Action), stringList(s.Resource)
		for _, a := range actions {
			if strings.HasPrefix(a, "admin:") {
				admin = true
			}
		}
		allActions := slices.ContainsFunc(actions, func(a string) bool { return a == "*" || a == "s3:*" || a == "admin:*" })
		allResources := len(resources) == 0 || slices.ContainsFunc(resources, func(r string) bool { return r == "*" || r == "arn:aws:s3:::*" })
		if allActions && allResources {
			wildcard = true
		}
	}
	return wildcard, admin, len(stmts)
}

func stringList(raw json.RawMessage) []string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return []string{s}
	}
	var list []string
	_ = json.Unmarshal(raw, &list)
	return list
}
