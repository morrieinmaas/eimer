package minio

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const secret = "eimersecret"

func encryptedJSON(t *testing.T, id byte, v any) []byte {
	t.Helper()
	plain, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	salt := bytes.Repeat([]byte{0x5a}, saltSize)
	nonce := bytes.Repeat([]byte{0x11}, nonceSize)
	out, err := encrypt(secret, id, salt, nonce, plain)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func fakeAdmin(t *testing.T, cipher byte) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=eimeradmin/") {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`<Error><Code>AccessDenied</Code></Error>`))
			return
		}
		path := strings.TrimPrefix(r.URL.Path, adminPrefix)
		switch path {
		case "/info":
			_, _ = w.Write([]byte(`{"mode":"online","deploymentID":"d-1","buckets":{"count":72},"objects":{"count":204000000},"versions":{"count":204000001},"usage":{"size":123456789012},
				"services":{"kms":{},"ldap":{},"logger":[{"console":{"status":"Online"}}],"audit":[],"notifications":[]},
				"backend":{"backendType":"Erasure","onlineDisks":19,"offlineDisks":1,"standardSCParity":2,"totalSets":[1],"totalDrivesPerSet":[20]},
				"servers":[{"state":"online","endpoint":"10.0.0.12:9000","uptime":100,"version":"2025-07-23T15:54:02Z","drives":[{"state":"ok","path":"/d1","totalspace":100,"usedspace":90,"availspace":10,"pool_index":0,"set_index":0,"disk_index":0},{"state":"offline","path":"/d2","totalspace":100}]},
				           {"state":"online","endpoint":"10.0.0.11:9000","uptime":200,"version":"2025-07-23T15:54:02Z","drives":[{"state":"ok","path":"/d1","totalspace":100,"usedspace":90},{"state":"ok","healing":true,"path":"/d2","totalspace":100,"usedspace":90}]}],
				"pools":{"0":{"0":{"id":0,"nodes":["10.0.0.11:9000","10.0.0.12:9000"],"onlineDisks":19,"offlineDisks":1,"healDisks":1,"rawCapacity":400,"rawUsage":270,"usage":135,"objectsCount":5}}}}`))
		case "/site-replication/info":
			_, _ = w.Write([]byte(`{"enabled":true,"name":"nl","sites":[{"name":"nl","endpoint":"http://a"},{"name":"de","endpoint":"http://b"}]}`))
		case "/datausageinfo":
			_, _ = w.Write([]byte(`{"lastUpdate":"2026-10-07T00:00:00Z","capacity":500,"usedCapacity":120,"bucketsUsageInfo":{"corpora":{"size":1000,"objectsCount":10,"versionsCount":10,"lockActiveRetentionVersions":3}}}`))
		case "/accountinfo":
			_, _ = w.Write([]byte(`{"accountName":"eimeradmin","policy":{}}`))
		case "/list-users":
			_, _ = w.Write(encryptedJSON(t, cipher, map[string]any{
				"alice": map[string]any{"policyName": "readwrite,custom-admin", "status": "enabled", "memberOf": []string{"ops"}},
				"bob":   map[string]any{"policyName": "", "status": "disabled"},
			}))
		case "/groups":
			_, _ = w.Write([]byte(`["ops"]`))
		case "/group":
			_, _ = w.Write([]byte(`{"name":"ops","status":"enabled","members":["alice"],"policy":"readonly"}`))
		case "/list-canned-policies":
			_, _ = w.Write([]byte(`{"readonly":{"Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]},
				"custom-admin":{"Statement":[{"Effect":"Allow","Action":["admin:*","s3:*"],"Resource":["arn:aws:s3:::*"]}]},
				"readwrite":{"Statement":{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::*"}}}`))
		case "/list-service-accounts":
			if r.URL.Query().Get("user") == "alice" {
				_, _ = w.Write(encryptedJSON(t, cipher, map[string]any{"accounts": []map[string]string{{"accessKey": "svc1"}, {"accessKey": "svc2"}}}))
				return
			}
			_, _ = w.Write(encryptedJSON(t, cipher, map[string]any{"accounts": []string{}}))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestCollect(t *testing.T) {
	for _, cipher := range []byte{idArgon2AESGCM, idArgon2ChaCha20, idPBKDF2AESGCM} {
		srv := fakeAdmin(t, cipher)
		info := Collect(context.Background(), Options{Endpoint: srv.URL, Region: "us-east-1", AccessKey: "eimeradmin", SecretKey: secret, HTTP: srv.Client()})
		srv.Close()

		if !info.Available || info.Error != "" {
			t.Fatalf("cipher %d: %+v", cipher, info)
		}
		if info.Version != "2025-07-23T15:54:02Z" || info.BuildDate.Year() != 2025 || info.Totals.Objects != 204000000 || info.Backend.OfflineDrives != 1 {
			t.Errorf("info: %+v", info)
		}
		if len(info.Servers) != 2 || info.Servers[0].Endpoint != "10.0.0.11:9000" || info.Servers[0].HealingDrives != 1 || info.Servers[1].OfflineDrives != 1 {
			t.Errorf("servers: %+v", info.Servers)
		}
		if len(info.Services.AuditTargets) != 0 || info.Services.LoggerTargets[0] != "console" || info.Services.KMS != "" {
			t.Errorf("services: %+v", info.Services)
		}
		if len(info.Drives) != 4 || info.Drives[0].Server != "10.0.0.11:9000" || info.Drives[0].Path != "/d1" || info.Drives[3].State != "offline" {
			t.Errorf("drives: %+v", info.Drives)
		}
		if len(info.Sets) != 1 || info.Sets[0].OfflineDrives != 1 || len(info.Sets[0].Nodes) != 2 || info.Sets[0].Objects != 5 {
			t.Errorf("sets: %+v", info.Sets)
		}
		if l := info.Layout; l.Nodes != 2 || l.Drives != 4 || l.Sets != 1 || l.DrivesPerSet != 20 || l.Parity != 2 || l.RawTotal != 400 || l.RawUsed != 270 || l.ToleratesNodeLoss {
			t.Errorf("layout: %+v", l)
		}
		if sr := info.SiteReplication; !sr.Checked || !sr.Enabled || len(sr.Sites) != 2 || sr.Sites[1] != "de (http://b)" {
			t.Errorf("site replication: %+v", sr)
		}
		if info.Usage == nil || info.Usage.Buckets["corpora"].Objects != 10 || info.Usage.Buckets["corpora"].LockedActive != 3 || info.Usage.Capacity != 500 {
			t.Errorf("usage: %+v", info.Usage)
		}
		if info.Account != "eimeradmin" || info.AccountIsUser {
			t.Errorf("account: %q user=%v", info.Account, info.AccountIsUser)
		}
		iam := info.IAM
		if iam.Error != "" || len(iam.Users) != 2 || iam.Users[0].Name != "alice" || len(iam.Users[0].Policies) != 2 || iam.Users[1].Status != "disabled" {
			t.Errorf("users: %+v", iam)
		}
		if len(iam.Groups) != 1 || iam.Groups[0].Policies[0] != "readonly" || iam.Attached["readonly"] != 1 || iam.Attached["custom-admin"] != 1 {
			t.Errorf("groups/attachments: %+v %+v", iam.Groups, iam.Attached)
		}
		byName := map[string]PolicyDoc{}
		for _, p := range iam.Policies {
			byName[p.Name] = p
		}
		if !byName["custom-admin"].Wildcard || !byName["custom-admin"].AdminAPI || byName["custom-admin"].BuiltIn {
			t.Errorf("custom-admin: %+v", byName["custom-admin"])
		}
		if !byName["readwrite"].Wildcard || !byName["readwrite"].BuiltIn || byName["readonly"].Wildcard {
			t.Errorf("built-ins: %+v %+v", byName["readwrite"], byName["readonly"])
		}
		if iam.ServiceAccounts["alice"] != 2 || iam.ServiceAccounts["bob"] != 0 {
			t.Errorf("service accounts: %+v", iam.ServiceAccounts)
		}
	}
}

func TestCollectWithoutAdminRights(t *testing.T) {
	srv := fakeAdmin(t, idArgon2AESGCM)
	defer srv.Close()
	info := Collect(context.Background(), Options{Endpoint: srv.URL, AccessKey: "nobody", SecretKey: "x", HTTP: srv.Client()})
	if info.Available || !strings.Contains(info.Error, "no admin rights") {
		t.Fatalf("%+v", info)
	}
}

func TestDecryptRejectsWrongKeyAndGarbage(t *testing.T) {
	data := encryptedJSON(t, idArgon2AESGCM, map[string]int{"a": 1})
	if _, err := decrypt("wrong", data); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err := decrypt(secret, data[:10]); err == nil {
		t.Fatal("short input accepted")
	}
	data[saltSize] = 0x09
	if _, err := decrypt(secret, data); err == nil {
		t.Fatal("unknown id accepted")
	}
}

func TestBuildDateParsing(t *testing.T) {
	want := time.Date(2025, 7, 23, 15, 54, 2, 0, time.UTC)
	for _, v := range []string{"RELEASE.2025-07-23T15-54-02Z", "2025-07-23T15:54:02Z"} {
		if got := buildDate(v); !got.Equal(want) {
			t.Errorf("buildDate(%q) = %v", v, got)
		}
	}
	if !buildDate("garbage").IsZero() {
		t.Error("garbage should give zero time")
	}
}

func TestDeriveLayout(t *testing.T) {
	// 5 nodes, sets of 14 drives spread over all 5: one node holds 3 drives of a set, parity 2 cannot cover it.
	sets := []SetInfo{{Nodes: []string{"a", "b", "c", "d", "e"}}}
	l := deriveLayout(Layout{RawTotal: 1000, RawUsed: 900}, 5, 70, []int{5}, []int{14}, 2, sets)
	if l.Sets != 5 || l.DrivesPerSet != 14 || l.DrivesPerNodePerSet != 3 || l.ToleratesNodeLoss || l.UsedPercent != 90 {
		t.Fatalf("%+v", l)
	}
	// parity 4 covers 3 drives per node
	if l := deriveLayout(Layout{}, 5, 70, []int{5}, []int{14}, 4, sets); !l.ToleratesNodeLoss {
		t.Fatalf("%+v", l)
	}
	// 4 nodes x 4 drives, sets of 16 with parity 4: exactly one node per set is tolerated
	if l := deriveLayout(Layout{}, 4, 16, []int{1}, []int{16}, 4, nil); l.DrivesPerNodePerSet != 4 || !l.ToleratesNodeLoss {
		t.Fatalf("%+v", l)
	}
	// single node: node loss is never tolerated and never claimed
	if l := deriveLayout(Layout{}, 1, 4, []int{1}, []int{4}, 2, nil); l.ToleratesNodeLoss {
		t.Fatalf("%+v", l)
	}
}
