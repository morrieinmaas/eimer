# eimer: S3 estate compliance audit CLI

Date: 2026-10-07. Status: approved in-session (user asked to plan and implement in one go).

## Purpose

One static binary that points at any S3-compatible endpoint (MinIO, RustFS, Garage, SeaweedFS,
Ceph RGW) and prints an object-lock / WORM / versioning / policy audit report. Offline, read-only,
nothing phones home. It is the free, self-qualifying lead tool for the Traect sovereign storage
control plane: whoever runs it has an estate and cares about compliance.

Dogfood target: a production MinIO cluster (five nodes, about 200 million objects) ahead of its migration to RustFS.

## Non-goals (v1)

- No writes of any kind. No PUT, DELETE, or configuration changes, ever.
- No per-engine admin APIs (MinIO `admin`, Garage RPC). S3 API only, so it stays vendor neutral.
- No multi-endpoint estate view, no HTML report, no scheduling. Later, and in the plane.

## CLI

```
eimer audit --endpoint https://s3.example.org [--bucket name]... [--region r] [--json] [--sample N] [--insecure]
eimer version
```

Credentials: `--access-key` / `--secret-key` flags, else the standard AWS chain
(`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_PROFILE`, `~/.aws/credentials`).

Exit codes: 0 ran clean, 1 usage or connection error, 3 at least one high-severity finding
(`--fail-on` is not in v1; the fixed threshold is enough for CI gating).

## Architecture

```
cmd/eimer/main.go          flag parsing, output, exit code
internal/audit/
  inspect.go               S3 reads: ListBuckets + per-bucket config probes + object sample
  rules.go                 pure function: BucketState -> []Finding
  report.go                Report types, text and JSON rendering
```

`inspect` produces facts. `rules` produces findings from facts. They never mix, so rules are
unit-tested with struct literals and inspect is tested against an httptest S3 fake.

### Facts collected per bucket

versioning status and MFA delete, object lock configuration (enabled, default mode, default
period), bucket policy document, lifecycle rules, default encryption, logging target, replication
configuration, and for locked buckets a sample of up to N objects with their retention and legal
hold. Each probe records one of: value, `not supported` (engine returned NotImplemented or
MethodNotAllowed), or an error string. Unsupported is not an error: Garage legitimately lacks most
of these APIs and the report should say so, not crash.

Endpoint-level facts: engine name from the `Server` header of an unauthenticated GET on `/`, TLS
on or off.

### Rules (v1)

| id | severity | condition |
|---|---|---|
| PLAINTEXT_ENDPOINT | medium | endpoint scheme is http |
| VERSIONING_OFF | medium | versioning never enabled |
| VERSIONING_SUSPENDED | medium | versioning suspended |
| LOCK_OFF | info | object lock not enabled (can only be set at bucket creation on most engines) |
| LOCK_NO_DEFAULT_RETENTION | high | object lock enabled, no default retention rule |
| LOCK_GOVERNANCE_MODE | low | default retention mode is GOVERNANCE (bypassable with a permission) |
| LOCK_UNLOCKED_OBJECTS | high | locked bucket, sampled objects with neither retention nor legal hold |
| POLICY_PUBLIC | high | bucket policy has an Allow statement with wildcard principal |
| LIFECYCLE_EXPIRES_WITHIN_RETENTION | medium | lifecycle expiration days shorter than default retention |
| ENCRYPTION_OFF | low | no default server-side encryption configuration |

## Testing

- `rules_test.go`: table tests, one per rule, plus a clean bucket producing nothing.
- `inspect_test.go`: httptest server serving canned XML for the probes, including NotImplemented.
- `report_test.go`: JSON round trip, text renderer smoke.
- `just smoke`: docker MinIO with a locked bucket, run the binary, eyeball the report.
- Live run: cross-compile linux/amd64, scp to a bastion on the storage LAN, run with the cluster credentials.

## Tooling

`justfile` with build, test, lint (golangci-lint), fmt, vet, smoke, release (goreleaser later).
GitHub Actions CI runs test + lint on push. Apache 2.0 licence.
