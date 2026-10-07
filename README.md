# eimer

Offline compliance audit for S3-compatible object stores. One static binary: point it at an
endpoint and get back the posture of every bucket, which is object lock and WORM, versioning,
exposure, encryption, inventory, and what will survive a migration to another engine.

Works against MinIO, RustFS, Garage, SeaweedFS, Ceph RGW and anything else that speaks S3.
Read-only by construction. Nothing phones home: the only network traffic is S3 reads to the
endpoint you name.

## Install

Linux and macOS, amd64 and arm64:

```sh
curl -fsSL https://raw.githubusercontent.com/morrieinmaas/eimer/main/install.sh | sh
```

The script downloads the release archive for your machine, verifies it against the published
`checksums.txt`, and installs `eimer` into `/usr/local/bin` if that is writable, else into
`~/.local/bin`. `EIMER_INSTALL_DIR` and `EIMER_VERSION` override those choices. To read the
script first: `curl -fsSL .../install.sh > install.sh`, look, then `sh install.sh`.

The archives are also on the [releases page](https://github.com/morrieinmaas/eimer/releases)
for a manual install, and Go users can build from source with
`go install github.com/morrieinmaas/eimer/cmd/eimer@latest`.

## Quick start

```sh
export AWS_ACCESS_KEY_ID=...  AWS_SECRET_ACCESS_KEY=...
eimer audit --endpoint https://s3.example.org:9000
```

Add `--out today.json` to keep the evidence file, and later run
`eimer diff last-month.json today.json` to see what changed.

This is the report from `just smoke`, which audits a throwaway RustFS with one WORM bucket and
one public bucket. It exits 3 because a bucket is readable without credentials:

```
eimer v0.3.0 audit of http://127.0.0.1:19000
engine: RustFS (probable)   tls: no   region: us-east-1   buckets: 2   started: 2026-10-07T12:25:40Z   took: 0.0s

BUCKET  VERSIONING  OBJECT LOCK     POLICY  ACL      ANONYMOUS  ENCRYPTION  SAMPLE
plain   off         off             PUBLIC  private  READ       off         -
worm    enabled     compliance 30d  none    private  denied     off         1/1 locked

BUCKET  OBJECTS  SIZE  OLDEST      NEWEST      LIFECYCLE  REPLICATION  NOTIFY  MULTIPART
plain   1        22 B  2026-10-07  2026-10-07  0 rule(s)  none         none    none
worm    1        22 B  2026-10-07  2026-10-07  0 rule(s)  none         none    none

migration carry-over (features in use, per target engine)
FEATURE        BUCKETS  RustFS  Garage                        SeaweedFS                       Ceph RGW
versioning     1        native  none                          native                          native
object lock    1        native  none                          native: set at bucket creation  native
bucket policy  1        native  none: per-key grants instead  native                          native

7 finding(s)
  [high  ] POLICY_PUBLIC                      bucket policy allows a wildcard principal
            plain
  [high  ] ANON_READ                          an unauthenticated client can read objects (proven by fetching one byte of "x.txt")
            plain
  [medium] PLAINTEXT_ENDPOINT                 endpoint is plain http: credentials and data travel unencrypted
            endpoint
  [medium] VERSIONING_OFF                     versioning is off: overwrites and deletes are unrecoverable
            plain
  [low   ] ENCRYPTION_OFF                     no default server-side encryption configured
            plain, worm
  [info  ] LOCK_OFF                           object lock is not enabled (most engines only allow enabling it at bucket creation)
            plain
```

Against a MinIO deployment the report grows a section from the admin API: build date against
the April 2026 archive, server, drive and erasure-set health, whether a node outage is
survivable, capacity, audit log and KMS targets, site replication, exact per-bucket usage, and
the IAM inventory (users, groups, policies, service accounts).

### Try it without an estate

The repository ships a smoke test that starts a throwaway RustFS in docker, creates the two
buckets above, audits them, changes one, and diffs the two reports. It needs `docker` and
[`just`](https://github.com/casey/just):

```sh
git clone https://github.com/morrieinmaas/eimer && cd eimer
just smoke
```

### A real run from a bastion

Most self-hosted stores sit on a LAN. Install eimer on a host that can reach it, then pipe the
keys in on stdin so they never land on a command line or a remote disk:

```sh
ssh -o ServerAliveInterval=30 bastion \
  'eimer audit --env-file /dev/stdin --endpoint http://10.0.0.11:9000 -v --out /tmp/estate.json' \
  < .env
scp 'bastion:/tmp/estate.json*' ./evidence/
```

`--env-file /dev/stdin` reads the keys from the piped dotenv file. A large estate takes a minute
or two per hundred buckets; `-v` prints each bucket with its slowest call as it goes, and the
report is saved before it is printed, so a dropped session loses only the screen output.
`just smoke-remote HOST ENDPOINT` does the same from a checkout: copies the binary over, runs
it, fetches the report into `evidence/`, and removes everything from the bastion again.

## Commands

```
eimer audit --endpoint URL [--bucket NAME]... [--region R] [--env-file FILE] [--config FILE]
            [--sample N] [--list-max N] [--parallel N] [--timeout SECONDS] [-v]
            [--json] [--out FILE] [--insecure]
eimer diff OLD.json NEW.json
eimer version
```

Exit codes: 0 clean, 1 usage or connection error, 3 at least one high-severity finding,
4 `diff` found changes. Either one gates a CI job directly.

## Configuration

Every setting can come from a flag, an environment variable, or a TOML file. Precedence is
flags, then environment, then file, then defaults. The file is `--config PATH`, else
`./eimer.toml`, else `~/.config/eimer/config.toml`; a missing default file is fine.
[`eimer.example.toml`](eimer.example.toml) lists every key with its default.

| setting | flag | environment | default |
|---|---|---|---|
| endpoint | `--endpoint` | `EIMER_ENDPOINT`, `MINIO_URL`, `S3_ENDPOINT`, `AWS_ENDPOINT_URL` | required |
| region | `--region` | `EIMER_REGION`, `AWS_REGION`, `AWS_DEFAULT_REGION`, `MINIO_REGION` | `us-east-1`, then whatever the server asks for |
| access key | `--access-key` | `EIMER_ACCESS_KEY`, `AWS_ACCESS_KEY_ID`, `MINIO_ACCESS_KEY`, `MINIO_ACCESSKEY`, `MINIO_ROOT_USER` | AWS profile chain |
| secret key | `--secret-key` | `EIMER_SECRET_KEY`, `AWS_SECRET_ACCESS_KEY`, `MINIO_SECRET_KEY`, `MINIO_SECRETKEY`, `MINIO_ROOT_PASSWORD` | AWS profile chain |
| env file | `--env-file` | `EIMER_ENV_FILE` | none |
| buckets | `--bucket` (repeatable) | `EIMER_BUCKETS` (comma separated) | all listed |
| sample | `--sample` | `EIMER_SAMPLE` | `20` |
| list max | `--list-max` | `EIMER_LIST_MAX` | `200` |
| parallel | `--parallel` | `EIMER_PARALLEL` | `8` |
| timeout | `--timeout` | `EIMER_TIMEOUT` | `30` seconds per call |
| verbose | `-v` | `EIMER_VERBOSE` | `false` |
| insecure | `--insecure` | `EIMER_INSECURE` | `false` |
| json | `--json` | `EIMER_JSON` | `false` |
| out | `--out` | `EIMER_OUT` | none |
| config file | `--config` | `EIMER_CONFIG` | see above |

In each environment column the first variable that is set wins, so credentials already in a
shell for `mc` or the AWS CLI are picked up without renaming. `--env-file` reads a dotenv file
(comments, quotes and `export` are fine) whose variables take precedence over the environment.
Keep secrets in the environment or a gitignored env file, not in the TOML.

Several endpoints go in one file as `[[estate]]` tables, each with a name, its own endpoint
and region, and `access_key_env` / `secret_key_env` naming the variables that hold its keys.
One `eimer audit` then produces one report per estate in a single document.

## What it checks

**Per bucket, over the S3 API.** Versioning, object-lock configuration, bucket policy, ACL,
lifecycle, default encryption, access logging, replication, event notifications, tags, CORS,
in-progress multipart uploads, and a capped object listing that yields counts, sizes, age,
size bands, folder markers and keys other engines may reject. For object-locked buckets a
sample of objects is checked for actual retention or legal hold.

**Exposure, empirically.** Policy and ACL say what should happen. eimer also asks the store
without credentials for a listing and for one byte of one object, and reports what did happen.

**Per endpoint.** Engine fingerprint, TLS version and certificate expiry, clock skew, and the
region the server actually wants.

**MinIO, over the admin API.** Only when the credential has admin rights; otherwise the report
says so and carries on. Build date, server and drive state, erasure sets with the nodes they
span and a derived verdict on whether a node outage is survivable, raw capacity, audit and KMS
targets, site replication, exact usage, users, groups, policies and service accounts. The
encrypted admin responses are decoded with a clean-room implementation of MinIO's format; no
MinIO code is linked.

**Migration carry-over.** Every feature in use is listed against RustFS, Garage, SeaweedFS and
Ceph RGW as `native`, `partial` or `none`. The table is one Go literal in
`internal/audit/migration.go`, verified against each engine's own documentation on
2026-10-07 with sources in [`docs/engine-support.md`](docs/engine-support.md). Corrections
are a one-line pull request that cites a page.

Every probe records one of three outcomes: a value, "not supported" (the engine answered
NotImplemented, which Garage does for most of these) or an error. Unsupported is not a failure
and never produces a finding.

### Findings

| id | severity | meaning |
|---|---|---|
| `ANON_READ`, `ANON_LIST` | high | an unauthenticated client read an object or listed the bucket |
| `POLICY_PUBLIC` | high | an Allow statement names a wildcard principal |
| `ACL_PUBLIC_READ`, `ACL_PUBLIC_WRITE` | high | the ACL grants everyone access |
| `LOCK_NO_DEFAULT_RETENTION` | high | object lock is on, but nothing protects objects unless each write sets retention |
| `LOCK_UNLOCKED_OBJECTS` | high | object lock is on, sampled objects have neither retention nor legal hold |
| `NODE_LOSS_NOT_TOLERATED` | high | parity cannot cover the drives one node contributes to an erasure set |
| `DRIVES_OFFLINE`, `SERVER_OFFLINE`, `CAPACITY_CRITICAL`, `TLS_CERT_EXPIRED` | high | the store is degraded, nearly full, or its certificate is dead |
| `VERSIONING_OFF`, `VERSIONING_SUSPENDED` | medium | overwrites and deletes are unrecoverable |
| `BUCKET_NAME_INVALID` | medium | the name is not DNS-compatible; path-style clients cannot reach it and it must be renamed before migrating |
| `LIFECYCLE_EXPIRES_WITHIN_RETENTION` | medium | a lifecycle expiry is shorter than the default retention |
| `PLAINTEXT_ENDPOINT`, `TLS_OLD_VERSION`, `TLS_CERT_EXPIRING`, `CLOCK_SKEW` | medium | transport hygiene |
| `MINIO_ARCHIVED` | medium | the build predates the upstream archive and will never see a fix |
| `AUDIT_LOG_OFF` | medium | no audit log target: API calls leave no evidence trail |
| `PARITY_LOW`, `CAPACITY_HIGH` | medium | parity below MinIO's own default for the set size, or raw usage above 85 percent |
| `IAM_POLICY_WILDCARD`, `IAM_ADMIN_USERS` | medium | custom policies that allow everything, users holding admin rights |
| `LOCK_GOVERNANCE_MODE` | low | default retention can be bypassed with one permission |
| `ENCRYPTION_OFF`, `MULTIPART_STALE`, `KEYS_NONPORTABLE`, `DRIVES_HEALING`, `IAM_USERS_WITHOUT_POLICY`, `ROOT_CREDENTIAL_IN_USE` | low | worth a look before an auditor finds it |
| `LOCK_OFF`, `KMS_OFF`, `SITE_REPLICATION_OFF`, `IAM_USERS_DISABLED`, `ADMIN_API_UNAVAILABLE`, `IAM_UNREADABLE` | info | context, not a defect |

## Working with the JSON

`--json` prints one document per run: `{tool, version, generated_at, reports: [...]}`, with
one entry in `reports` per endpoint audited. Pipe it into `jq`:

```sh
eimer audit --endpoint https://s3.example.org --json > today.json

jq '.reports[0] | keys' today.json                      # what a report contains
jq '.reports[0].findings[] | select(.severity == "high")' today.json
jq '[.reports[0].findings[] | select(.id == "VERSIONING_OFF") | .bucket]' today.json
jq '.reports[0].findings | group_by(.id) | map({id: .[0].id, buckets: length}) | sort_by(-.buckets)' today.json
jq '.reports[0].buckets[] | {name, objects: .inventory.objects, tb: (.inventory.bytes / 1e12)}' today.json
jq '.reports[0].buckets[] | select(.exposure.anonymous_read) | .name' today.json
jq '.reports[0].migration' today.json                   # the carry-over matrix
jq '.reports[0].minio | {layout, site_replication}' today.json
jq -r '.reports[0].minio.erasure_sets[]? | "\(.pool)/\(.set) nodes=\(.nodes | length) offline=\(.offline_drives) healing=\(.healing_drives)"' today.json
```

Straight from a bastion, without a file on either side:

```sh
ssh -o ServerAliveInterval=30 bastion \
  'eimer audit --env-file /dev/stdin --endpoint http://10.0.0.11:9000 --json' < .env \
  | jq '.reports[0].findings | group_by(.id) | map({id: .[0].id, severity: .[0].severity, buckets: length})'
```

Progress from `-v` goes to stderr, so it never disturbs the pipe.

## Evidence and drift

`--out FILE` writes the JSON document and a `FILE.sha256` sidecar next to it. The document
carries the generation time, the tool version and every fact the text report was rendered
from, so it is the thing to file, not the screen output.

`eimer diff OLD.json NEW.json` lists, per endpoint and bucket, what changed between two runs:
buckets added or removed, configuration that moved (versioning, lock, policy hash, ACL,
anonymous access, encryption, rule counts), inventory growth, and findings that appeared or
were resolved. Lines marked `!` moved in the wrong direction. Exit code 4 means something
changed, which is the signal a scheduled job wants.

## What it does not do

- **Write.** There is no code path that creates, changes or deletes anything on the store.
  The only non-GET request is the anonymous one-byte object read used to prove exposure.
- **Phone home.** No telemetry, no update check, no DNS lookups beyond the endpoint you name.
- **Admin APIs for engines other than MinIO.** RustFS, Garage, SeaweedFS and Ceph are audited
  over the S3 API only. Their health and IAM need their own adapters, which is the next step.
- **Claim more than it has seen.** The MinIO adapter has been exercised against one production
  cluster of five nodes and about 200 million objects. The migration table was checked against
  each engine's documentation on a stated date; it is a checklist to argue with, not a verdict.
- **Walk the whole estate.** Counts and sizes come from a capped listing unless an engine adapter
  supplies exact totals, and the per-object lock sample is the first page of keys, not a spread.
- **Windows.** The code may well run there, but nothing is tested and the examples assume a
  Unix shell, so there are no Windows builds.

## Development

```
just                  # list recipes
just check            # lint + test + build
just smoke            # throwaway RustFS in docker: audit, change, diff
just smoke-remote HOST ENDPOINT [ENVFILE]
just build-linux      # static linux/amd64 binary in ./bin
just release-snapshot # build every release archive locally, publish nothing
```

Releases are built by goreleaser when a `v*` tag is pushed.

## Why

MinIO's open-source repository was archived in April 2026 and its images are gone from the
public registries. The estates it left behind are moving to RustFS, Garage and SeaweedFS, and
the people running them still owe auditors evidence about WORM, retention and access. The S3
data path is portable between engines. The control path is not. This tool is the smallest
useful piece of that gap: a report that reads the same whatever engine is underneath, and a
migration checklist that falls out of it.

It is built by [Traect](https://traect.dev) as the first piece of a vendor-neutral operations
and compliance plane for self-hosted object storage. If you run a mixed estate and want the
rest of that, say hello at mo [at] traect [dot] dev.

## Licence

Apache 2.0.
