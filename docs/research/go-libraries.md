# Go libraries for the SSH, SNMP and Meraki clients

Research for [#4](https://github.com/lcleveland/network-mcp/issues/4). Checked 2026-10-26.

## Answer

| Client | Use | Why |
|---|---|---|
| SSH (IOS-XE, NX-OS, generic) | `github.com/scrapli/scrapligo` **v1.4.x** with the **`standard` transport** | Pure Go on `x/crypto/ssh`; strict known_hosts is the default; embedded IOS-XE / NX-OS platform definitions; maintained on `maintenance-1.4.x`. Avoid **v2**: it loads a Zig shared library that it downloads at runtime. |
| SNMP | `github.com/gosnmp/gosnmp` v1.47.0 | Active, BSD-3, v2c and v3 (SHA-2 auth, AES-256 privacy), `BulkWalk`, `Context`, timeouts and retries. No MIB support, which is expected. |
| MIB names | `github.com/sleepinggenius2/gosmi` v0.4.4 over **embedded** MIB files (start with net-snmp's IETF set) | Pure Go, forward and reverse lookup work on Go 1.26, `SetFS` takes an `embed.FS`. The library is dormant, so keep it behind a small interface. A pre-compiled OID table is the fallback. |
| Meraki | **Thin `net/http` client** (no SDK) | The official Go SDK is 18 API minors behind (1.57.0 against 1.75.1), takes no `context.Context`, and its option constructor writes the API key into the process environment. |

All four build together on **Go 1.26.10** (the `go` in nixpkgs) with `CGO_ENABLED=0`, and `go vet` passes. `go list -deps` finds no cgo packages. Everything vendors under `buildGoModule` with a `vendorHash`. None of them is packaged in nixpkgs as a library, but Go libraries never are, so nothing is lost.

## Method

- Versions and `go.mod` files come from `proxy.golang.org` (`@latest`, `@v/list`, `.mod`). Repo status comes from the GitHub REST API (`/repos/...`, `/releases`, `/commits`).
- Source was read from the module zips in the Go module cache.
- Build check: a throwaway module that imports `scrapligo/driver/generic`, `scrapligo/platform`, `gosnmp`, `gosmi` and `dashboard-api-go/v5/sdk`, built with `go1.26.10 linux/amd64` from nixpkgs, `CGO_ENABLED=0`, then `go vet`. The cgo check ran `go list -deps -f '{{if .CgoFiles}}...'` with cgo enabled. It found nothing outside the standard library.
- gosmi was also run against the MIBs that nixpkgs `net-snmp` 5.9.5.2 ships (`share/snmp/mibs`, 65 files).

## SSH: scrapligo

**Status.** MIT licence, 307 stars, not archived, 0 open issues, last push 2026-10-21 ([repo](https://github.com/scrapli/scrapligo)). There are two release lines ([releases](https://github.com/scrapli/scrapligo/releases)):

- **v1.4.x** on branch `maintenance-1.4.x`: v1.4.1 (2026-08-07, race and panic fixes in `Channel.Close`), v1.4.2 (2026-09-27, quadratic matching fix in `SendWithCallbacks`), v1.4.3 (2026-10-21). `go.mod`: `go 1.20`. Direct dependencies: `creack/pty`, `go-cmp`, `sirikothe/gotextfsm`, `golang.org/x/crypto v0.26.0`, `yaml.v3`.
- **v2** (`github.com/scrapli/scrapligo/v2`, v2.0.0 on 2026-10-03, now v2.0.2): a rewrite over **libscrapli**, a Zig shared library loaded through `ebitengine/purego`. `go.mod`: `go 1.26.0`.

**Why not v2.** It has no cgo, but it is not pure Go in practice (`ffi/ffi.go`):

- `EnsureLibscrapli` looks for `libscrapli-<arch>-linux-<gnu|musl>.so.<ver>` in the user cache directory. If the file is missing, it **downloads it over HTTP from the libscrapli GitHub releases at runtime, with no checksum check**. If the version is a commit hash, it runs `docker run ghcr.io/scrapli/libscrapli/builder:latest` instead.
- `LIBSCRAPLI_PATH` can point at a pre-built `.so`. Nix would then have to build libscrapli from Zig source itself. `libscrapli` is not in nixpkgs, and the binary would need a dynamic loader, so it could not be fully static.
- It panics on any OS other than Linux or macOS.

That conflicts with hermetic builds, the hardened systemd service and the no-runtime-fetch posture. Stay on v1 and review this again if v1 maintenance stops.

**v1 against the standing decisions.**

| Need | v1.4.3 | Source |
|---|---|---|
| IOS-XE / NX-OS platforms | Embedded YAML in `assets/platforms/` (`cisco_iosxe`, `cisco_nxos`, plus `cisco_iosxr`, `arista_eos`, `aruba_wlc`, `hp_comware`, `juniper_junos`, ...). There is **no `cisco_ios` (classic)** definition. Its `>` / `#` / `(config)#` prompts match the `cisco_iosxe` patterns. TP-Link has no definition. | `platform/definition.go` `GetPlatformNames`, `assets/platforms/*.yaml` |
| Generic driver | `driver/generic` with `SendCommand(s)` and `SendInteractive`. The default prompt pattern is `(?im)^[a-z\d.\-@()/:_]{1,48}[#>$]\s*$`, and `options.WithPromptPattern` overrides it. Privilege-level handling (`driver/network`) exists only for platform drivers. | `channel/channel.go`, `driver/options/channel.go` |
| Host-key pinning | `StrictKey` **defaults to true** (`transport/transport.go`). The `standard` transport uses `x/crypto/ssh/knownhosts.New(file)` and **errors when strict mode has no known_hosts file**. Use `options.WithSSHKnownHostsFile(path)` and never `WithAuthNoStrictKey`. | `transport/standard.go` `openBase`, `driver/options/transportssh.go` |
| Transport | The default is **`system`**: it execs the `ssh` binary on a pty (`creack/pty`). Set `options.WithTransportType("standard")` so that no `openssh` runtime dependency exists and no secrets reach child processes. `telnet` exists but should not be used. | `transport/transport.go` (`DefaultTransport = "system"`), `transport/system.go` |
| Private keys | `WithAuthPrivateKey(path, pass)`. `WithStandardTransportPrivateKeyBytes` takes keys from memory, which fits credential refs. | `driver/options/transportstandard.go` |
| In-process test server | No SSH test server is included. The `file` transport replays a byte file into the channel and says it is for testing only. The plan is an in-process `x/crypto/ssh` server (that package has the server half) that replays sanitized transcripts to the `standard` transport. | `transport/file.go` |
| Parsing | TextFSM through `gotextfsm` (`response.TextFsmParse`) if wanted. | `util/parse.go` |

**Gaps and cautions.**
- `platform.NewPlatform(string)` falls back to **reading a file path or fetching a URL** when the name is not an embedded asset (`loadPlatformDefinition` uses `util.ResolveAtFileOrURL`). Pass only constants or `[]byte`. Never pass a string from config or the network.
- v1 pins `x/crypto v0.26.0` (2024). Our `go.mod` should require a current `golang.org/x/crypto` (latest v0.58.0). MVS will then use it. Run `govulncheck` in CI.
- v1 work happens on a maintenance branch, and no release note commits to how long v1 will be supported. Watch for an end-of-life notice.
- The command allowlist, newline rejection, `debug` denial and pipe filtering are all ours to build. scrapligo just sends what it is given.

## SNMP: gosnmp

**Status.** BSD-3-Clause, about 1.26k stars, not archived, 31 open issues, last push 2026-10-26 ([repo](https://github.com/gosnmp/gosnmp)). v1.47.0 came out on 2026-10-23, after a steady stream of minor releases (v1.43 to v1.47). `go.mod`: `go 1.24.0`. Its only runtime dependency is the standard library. `golang/mock`, `testify` and `yaml` are used only by tests.

| Need | gosnmp v1.47.0 | Source |
|---|---|---|
| v2c / v3 | `Version2c`, `Version3`. USM auth: MD5, SHA, SHA224/256/384/512. Privacy: DES, AES, AES192/256 (Blumenthal) and AES192C/256C (Reeder, the Cisco-style key extension). | `v3_usm.go` |
| Walks | `Walk`/`WalkAll` (GETNEXT), `BulkWalk`/`BulkWalkAll` (GETBULK). `MaxRepetitions` defaults to 50. `MaxOids` defaults to 60 per `Get`. The `WalkFunc` callback lets us stop at the row or byte cap. | `gosnmp.go`, `walk.go` |
| Timeouts | `Timeout` defaults to 2 s per request. `Retries` defaults to 3. `ExponentialTimeout` is available. A `Context` field allows overall deadlines and cancellation. | `gosnmp.go` (`Default`) |
| Read-only | `Set` and the trap listener exist. We simply never call them. | |

**Gaps.** No MIB handling, so names have to be resolved before calls. One `*GoSNMP` per target, with no sharing across goroutines, because it holds the connection and request IDs. The `AppOpts "c"` option (skip the increasing-OID check) can loop forever on broken agents, so leave it unset. There is no agent simulator. For tests, `github.com/slayercat/GoSNMPServer` (v0.5.2, 2024) is a pure-Go option to evaluate in the testing ticket. A small UDP fake that answers fixed PDUs is another.

## MIB-name resolution

| Option | Verdict |
|---|---|
| **gosmi** (`sleepinggenius2/gosmi` v0.4.4) | **Use it.** MIT. Native Go since v0.2.0 (a SMIv1/v2 parser and a libsmi-compatible `smi` package). Its only dependencies are `alecthomas/participle` and `repr`. `gosmi.SetFS(gosmi.NamedFS(name, embedFS))` loads MIBs from an `embed.FS` (`cmd/embed`). Verified on Go 1.26: after loading IF-MIB, SNMPv2-MIB, HOST-RESOURCES-MIB and IP-MIB from nixpkgs net-snmp, `GetNode("ifDescr")` returned `IF-MIB::ifDescr 1.3.6.1.2.1.2.2.1.2`, and `GetNodeByOID(...2.1.2.5)` resolved the instance OID back to `IF-MIB::ifDescr`. **Cautions:** dormant (last release 2022-02, last push 2024-04, 17 open issues). The state is global and has no locks, so load all modules once at startup and treat it as read-only after that. |
| **net-snmp MIB tree** | Use it as a **source of MIB files**, not as a library. nixpkgs `net-snmp` ships 65 IETF/IANA/net-snmp MIBs. Using the C library would need cgo, so no. Cisco MIBs are not included. They would have to be vendored, and their licence notices checked before they are committed to a public repo. |
| **Pre-compiled OID table** | **Fallback.** A `go generate` step (using gosmi or `snmptranslate`) emits a `map[name]OID` plus sorted OIDs for reverse longest-prefix lookup. This avoids the runtime parser and the dormant-library risk, but loses types and enums unless they are emitted too. Switch to it if gosmi breaks, or if startup parse time matters. |
| `hallidave/mibtool` | Rejected. v0.2.0, 2019, unmaintained. |

## Meraki: dashboard-api-go vs a thin client

**SDK status.** MIT, 21 stars, 9 open issues ([repo](https://github.com/meraki/dashboard-api-go)). Latest is `v5.0.8`, tagged 2025-09-11 (the CHANGELOG dates it 2025-08-10). The last commit was 2025-11-07, and it only touched the README. v5 targets **Dashboard API 1.57.0** (README compatibility matrix). Meanwhile the [OpenAPI spec](https://github.com/meraki/openapi/releases) is at **v1.75.1** (2026-10-16). Dependencies: `go-resty/resty/v2 v2.11.0` (current is v2.17.2), `juju/ratelimit`, `google/go-querystring`. It is generated, with 916 functions in a 3.6 MB `sdk/` directory.

**Problems found in `sdk/api_client.go` (v5.0.8):**
- `NewClientWithOptions` / `SetOptions` call **`os.Setenv(MERAKI_DASHBOARD_API_KEY, key)`**, and `NewClient()` reads the key, base URL and debug flag from the environment. That breaks the "never env" credential rule and leaks the key to any child process. The workaround is `NewClient()` followed by `SetAuthToken`, which still reads the environment.
- **No `context.Context`** on any service method (for example `GetOrganizationDevices(orgID, params)`), so MCP cancellation and per-call deadlines cannot reach the HTTP request.
- Rate limiting uses a token bucket (`SetRequestsPerSecond`). 429 retry with backoff arrived only in v5.0.4 (`SetBackoff`). Link-header pagination is supported.
- The generated structs lag the API and have needed type fixes in patch releases (v5.0.5 to v5.0.7: IMEI float to string, port `*int` to string).

**Thin `net/http` client.** It needs `Authorization: Bearer <key>`, base URL `https://api.meraki.com/api/v1` (configurable for regional clouds and `httptest`), `Retry-After`-aware 429 handling, `Link: rel=next` pagination with a row cap, and `context.Context` throughout. Responses can be decoded into small hand-written structs, or returned as `json.RawMessage` and filtered, for the handful of read endpoints the Meraki tools need. That is a few hundred lines, uses the standard library only, and tests directly against `httptest`. **Recommend this.** The SDK's size, API lag and environment-variable credential handling outweigh its typed structs for a read-only v1.

## Build and packaging summary

| Module | Version | go.mod `go` | cgo | Builds on 1.26.10 | Notes |
|---|---|---|---|---|---|
| scrapligo | v1.4.3 | 1.20 | none (`creack/pty` is pure Go, used only by the `system` transport) | yes | Bump `x/crypto`. |
| scrapligo/v2 | v2.0.2 | 1.26.0 | none, but **purego + runtime-downloaded `.so`** | not tried (rejected) | Not hermetic. |
| gosnmp | v1.47.0 | 1.24.0 | none | yes | |
| gosmi | v0.4.4 | 1.16 | none | yes, and runs | Dormant. |
| dashboard-api-go/v5 | v5.0.8 | 1.21.5 | none | yes | Not recommended. |

For `buildGoModule`, all of these vendor normally with `vendorHash`. Embed MIB files with `//go:embed` so the package needs no runtime `MIBDIRS`. Set `CGO_ENABLED=0` explicitly.

## Open items for later tickets

- Which Cisco or vendor MIBs to embed beyond the IETF set, and whether their licences allow committing them to this public repo.
- The design of the in-process SSH fake server (`x/crypto/ssh` server side) belongs to the testing ticket.
- Prompt patterns for classic IOS and TP-Link under the generic driver are to be confirmed against sanitized transcripts.
