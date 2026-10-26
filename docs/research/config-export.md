# Config export: destinations, and how comparable tools do it

Research for [#16](https://github.com/lcleveland/network-mcp/issues/16). Checked 2026-10-26.

`network-mcp` is general-purpose ([#2 resolution](https://github.com/lcleveland/network-mcp/issues/2)): the user picks where fetched configs go. This note covers how existing tools store and ship configs, then recommends an interface and a v1 sink set.

## Answer

- **Interface**: one small `Sink` interface. The server fetches, **redacts by default**, and hands each sink a finished artifact (device name, kind, bytes, SHA-256, fetch time, redaction flag). Sinks are configured as **named destinations**, and every credential is a credential ref, as for devices.
- **Trigger**: **on-demand only** in v1 (an export action on the config tool, or a `network_config_export` tool). No scheduler: scheduled backup is Oxidized/RANCID territory, and the map already puts it out of scope. A systemd timer or the user's agent can call the tool on a schedule.
- **History and diffs**: come from the destination (a git sink commits only on change), not from server-side storage. The server keeps no config store.
- **v1 sinks**: `dir` (local directory), `git` (local repo with optional push over SSH or HTTPS, via **go-git v5**), `s3` (any S3-compatible store, via **aws-sdk-go-v2/service/s3** built without `LoadDefaultConfig`).
- **Later**: `http` (POST JSON, the Oxidized pattern) and `sftp` (`pkg/sftp`). **Not** syslog: it is a log channel, not a file transport.
- All three v1 libraries build with `CGO_ENABLED=0` on Go 1.26.10 from nixpkgs and need no external binaries (no `git`, no `aws` CLI).

## How comparable tools do it

| Tool | Where configs go | Remote / push | Secret redaction | Schedule vs on-demand | Sink credentials |
|---|---|---|---|---|---|
| **Oxidized** | Output backends `file`, `git`, `gitcrypt`, `http` ([Outputs.md](https://github.com/ytti/oxidized/blob/master/docs/Outputs.md)) | **Not an output.** It is the `githubrepo` **hook** on `post_store` that pushes the local repo to `remote_repo` ([Hooks.md](https://github.com/ytti/oxidized/blob/master/docs/Hooks.md)) | Global `vars: remove_secret: true` runs each model's `cmd :secret` substitutions. The docs warn it "reduces the usefulness as a full configuration backup" ([Configuration.md](https://github.com/ytti/oxidized/blob/master/docs/Configuration.md)) | `interval` (seconds); oxidized-web `GET/PUT /node/next/<node>` moves a node to the front of the queue, e.g. on a config-change syslog | `http` output: `user`/`password`/`headers` in plain config, `ssl_verify` **defaults to false**. `githubrepo`: password, or SSH key that must be **legacy PEM**, passphrase from `OXIDIZED_SSH_PASSPHRASE` env, or ssh-agent |
| **RANCID** | A local VCS: `RCSSYS` = `cvs` (default), `svn` or `git` ([rancid.conf.sample](https://github.com/haussli/rancid/blob/master/etc/rancid.conf.sample.in)) | Not built in. The sample says to create repos locally, move them to the remote, and edit each group's `.git/config` | `FILTER_PWDS` (`NO`/`YES`/`ALL`), `NOCOMMSTR` strips SNMP communities, `FILTER_OSC` for oscillating data | cron runs `rancid-run` | Mail diffs to per-group aliases (`MAILSPLIT` for big diffs) |
| **Unimus** | Its own store. Export is an external **shell script** that reads the Unimus API (`backup_type` `latest` or `all`) and writes to `fs` or commits and pushes to git over HTTP(S) or SSH ([Unimus Backup Exporter](https://blog.unimus.net/unimus-backup-exporter/)) | Git push from the script | Not covered by the exporter | cron, run after Unimus's own backups. Staff say FTP export is **not planned**; S3 is "use the AWS CLI" ([forum](https://forum.unimus.net/viewtopic.php?p=3996)) | `git_password` in an env file, or an SSH key already on the host |
| **netbox-config-backup** (NetBox plugin) | A local git repo at `repository`, with `committer`/`author` ([README](https://github.com/DanSheps/netbox-config-backup)) | None. "Allow github repositories" is on its future list | Not mentioned | Django RQ job, `frequency` in seconds (1800 or 3600 suggested). Shows only backups with changes, plus diffs | NAPALM device credentials only |

**What this says.**
1. **Git is the universal history layer.** Every tool either stores in a VCS or exports to one. None of them builds its own diff store on top of git.
2. **"Store" and "ship" are separate steps.** Oxidized commits locally, then a hook pushes. RANCID and the NetBox plugin have no push at all. Unimus bolts push on with a script. Users of all four ask for S3/SFTP/FTP and get told to script it.
3. **Redaction is per platform, opt-in, and lossy.** Oxidized and RANCID both filter with per-model regex rules and both default to keeping secrets. For an MCP whose output also lands in an LLM context, **on by default** is the right choice. Opting out should happen per destination and be explicit.
4. **Credential handling in these tools is weak.** It is mostly plaintext config, environment variables, or ambient files (`~/.aws/credentials` for the Oxidized `awssns` hook). Our credential-ref model is already stricter. Keep sinks inside it.

## Recommended interface

```go
type Artifact struct {
    Device    string    // inventory name, sanitized for paths
    Kind      string    // "running", "startup", "meraki-<resource>"
    Ext       string    // "txt" or "json"
    Body      []byte    // already redacted unless the destination opted out
    SHA256    string
    FetchedAt time.Time
    Redacted  bool
}

type Sink interface {
    Put(ctx context.Context, a []Artifact, reason string) (Receipt, error)
}

type Receipt struct {
    Destination string
    Changed     bool   // false when content matched what was already there
    Ref         string // commit hash, object key + version ID, or file path
}
```

- **Batch per call.** One export call becomes one git commit (message carries `reason` and the session ID) or one set of object puts. That matches how Oxidized commits per node and keeps history readable.
- **Layout.** `<device>/<kind>.<ext>`, the same in all sinks. Device names come from inventory. Reject `/`, `..` and control characters so a hostile inventory name cannot escape the root. Never put IPs in paths.
- **Change detection.** Compare SHA-256 with what is there (the file, the git tree entry, or S3 object metadata). Write nothing when they match, and report `Changed: false`. This gives the Oxidized/netbox-config-backup "only changes" behaviour for free.
- **Audit.** Every export is audit-logged like a write: destination, devices, kinds, hashes, receipt ref and `reason`. Never log the body.
- **Config shape (illustrative).**
  ```
  destinations:
    archive: { type: git, path: /var/lib/network-mcp/configs, remote: ssh://..., credential: git-push, known_hosts: /etc/network-mcp/git_known_hosts }
    bucket:  { type: s3, endpoint: https://..., bucket: ..., prefix: configs/, path_style: true, credential: s3-export }
    local:   { type: dir, path: /var/lib/network-mcp/export }
  ```
  If no destination is configured, the export capability is stripped from the tool schema, the same rule as other disabled capabilities.

## Redaction

- Done **once, in the server, before any sink**, so no sink can forget it. Per-platform rule sets, modelled on Oxidized's `cmd :secret` and RANCID's `FILTER_PWDS`/`NOCOMMSTR`. IOS-XE / NX-OS: `enable secret|password`, `username ... secret|password`, `snmp-server community`, `key` / `key-string`, `tacacs`/`radius` server keys, `crypto ... key`, pre-shared keys, `ppp ... password`. Type-5/8/9 hashes are redacted too, because they can be cracked offline.
- Replace with a fixed marker (`<redacted>`) that keeps the line, so diffs still show that a secret changed position but not its value. To show *that* a secret changed, an optional per-line HMAC with a server-held key could come later. Not in v1.
- Meraki JSON: redact by key name (`psk`, `secret`, `sharedSecret`, `password`, `apiKey`, RADIUS `secret`), applied recursively.
- Generic SSH devices have no rule set, so the default for them should be a conservative catch-all (`password|secret|community|key`) or a refusal to export unredacted.
- `redact: false` is a per-destination setting, off by default, and logged on every export.

## Sink libraries

| Sink | Library | Version (2026-10) | Status | Notes |
|---|---|---|---|---|
| git | `github.com/go-git/go-git/v5` | v5.19.3 (2026-10-04); `go 1.26.0` | Apache-2.0, ~7.8k stars, active (push 2026-10-23), 268 open issues. v6 is at `v6.0.0-beta.1`: stay on v5 | Pure Go, so no `git` binary is needed at runtime. SSH auth via `transport/ssh` (`PublicKeys` from bytes fits credential refs). Host keys: `NewKnownHostsCallback(files...)` reads `SSH_KNOWN_HOSTS` or `~/.ssh/known_hosts` **only when given no files**, so always pass the pinned file explicitly. HTTPS: `transport/http.BasicAuth` with a token. 19 non-std modules (incl. `ProtonMail/go-crypto`, `cloudflare/circl`, `skeema/knownhosts`) |
| s3 | `github.com/aws/aws-sdk-go-v2/service/s3` | v1.114.5 (2026-10-22); core v1.47.4 | Apache-2.0, AWS-owned, pushed daily | Build `s3.Options` directly with `credentials.NewStaticCredentialsProvider` from the credential ref, `BaseEndpoint`, `UsePathStyle`. **Do not** call `config.LoadDefaultConfig`: it reads env vars and `~/.aws`, which breaks the no-env credential rule. The SDK defaults `RequestChecksumCalculation` to **WhenSupported** (`config/resolve.go`), which some S3-compatible stores reject, so make it a per-destination setting defaulting to `WhenRequired` for non-AWS endpoints. 11 non-std modules for `service/s3` |
| s3 (alternative) | `github.com/minio/minio-go/v7` | v7.4.1 (2026-10-12); `go 1.26.0` | Apache-2.0, active (push 2026-10-25), 9 open issues | Also pure Go and S3-compatible-first, 19 non-std modules. Passed over because the **MinIO server repo is archived** (`minio/minio`, archived, last push 2026-04-24), which puts the client's long-term direction in question. The AWS SDK has no such dependency. Either works behind the interface |
| sftp (later) | `github.com/pkg/sftp` | v1.13.12 (2026-10-23); `go 1.25.0` | BSD-2-Clause, active | Runs over `x/crypto/ssh`, which we already have from scrapligo; reuse the known_hosts pinning. 3 non-std modules |
| dir | standard library | n/a | n/a | Write to a temp file in the same directory, `fsync`, then `rename`, so readers never see half a config |
| http (later) | `net/http` | n/a | n/a | POST JSON (the Oxidized `http` output shape). Unlike Oxidized, **verify TLS by default** and take the auth header from a credential ref |

**Build check.** A throwaway module importing `go-git/v5` (+ `transport/ssh`, `transport/http`), `aws-sdk-go-v2/config`, `aws-sdk-go-v2/service/s3`, `minio-go/v7` and `pkg/sftp` built with `go1.26.10 linux/amd64` from nixpkgs at `CGO_ENABLED=0`, and `go vet` passed. `go list -deps` found no non-standard packages with cgo files. All are ordinary modules, so they vendor under `buildGoModule` with a `vendorHash`.

## Effects on the map

- The out-of-scope line "Config backup storage or history (Oxidized/RANCID territory); only on-demand `get`" still holds for the **server**. Export adds "on-demand send to a user-chosen destination", and history lives in that destination. Suggested wording: "No scheduled backup and no server-side config store. On-demand export to user-configured destinations (dir, git, S3), redacted by default."
- The git and sftp sinks need SSH host-key pinning for the *destination*, the same as for devices. The NixOS module needs a second known_hosts path (or a shared one).
- Writable state: `dir` and the local repo for `git` need a `StateDirectory` under the hardened systemd unit.

## Method

- Tool behaviour comes from each project's own docs: Oxidized `docs/Outputs.md`, `docs/Hooks.md` and `docs/Configuration.md` on `master`; RANCID `etc/rancid.conf.sample.in`; the netbox-config-backup README; the Unimus blog post on its backup exporter and Unimus staff answers on its forum. The Unimus wiki page for export was not reachable (404).
- Library versions come from `proxy.golang.org/<module>/@latest`. Repo status comes from the GitHub REST API (`/repos/<owner>/<repo>`).
- Source was read from the module cache: go-git `plumbing/transport/ssh/auth_method.go` (known_hosts lookup), aws-sdk-go-v2 `config/resolve.go` (checksum default).
- Not checked: go-git performance on large, long-lived repos (Oxidized notes that `git gc` is needed for its libgit2 repos; go-git's own gc/repack support was not evaluated). Run it in a prototype if a git sink will hold years of history.
