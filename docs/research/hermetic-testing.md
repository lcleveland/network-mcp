# Hermetic testing for SSH, SNMP and Meraki drivers

Research for [#8](https://github.com/lcleveland/network-mcp/issues/8) (map: [#1](https://github.com/lcleveland/network-mcp/issues/1)).
Sources checked 2026-10-26. Versions: scrapligo v2.0.2 / v1.4.3, gliderlabs/ssh v0.3.8, gosnmp v1.47.0, snmpsim (lextudio) 1.2.2, net-snmp 5.9.5.2, dashboard-api-go v5.0.8. nixpkgs is the local flake registry pin (`.version` 26.11).

## Answer

Use three layers, all driven by one set of sanitized fixtures:

| Layer | SSH | SNMP | Meraki | Runs in |
|---|---|---|---|---|
| 1. Unit (no sockets) | scrapligo's own replay transport over a recorded byte stream | handler tests over an in-memory OID table | `httptest.Server` | `go test`, so the package's `checkPhase` |
| 2. In-process loopback | fake SSH server on `127.0.0.1:0` built on `golang.org/x/crypto/ssh`. It answers commands from transcripts and prints a prompt | fake UDP agent built on gosnmp's exported decode/marshal | (same as layer 1) | `go test` |
| 3. NixOS VM | `services.openssh` with a test user whose login shell is the same fake CLI, built as a binary | `services.snmpd` (net-snmp) with fixture OIDs from `override` lines | optional static fake | `checks.<system>.vm-network` |

Don't depend on snmpsim (it isn't in nixpkgs) or on gliderlabs/ssh (it adds little over `x/crypto/ssh`). Keep fixtures in snmpsim's `.snmprec` text format anyway, because it's simple and well documented. Every fixture goes through a `sanitize` step, and a guard test fails CI if a fixture contains anything outside the documentation ranges.

## Findings

### SSH: how scrapligo tests itself

- **scrapligo v2 is now an FFI wrapper over libscrapli (Zig).** `go.mod` depends on `github.com/ebitengine/purego`, and `ffi/ffi.go` `EnsureLibscrapli` **downloads a prebuilt `libscrapli-<ver>-linux-<abi>.so` from GitHub at runtime** into a cache dir. You can override this with `LIBSCRAPLI_PATH`, `LIBSCRAPLI_CACHE_PATH` or `LIBSCRAPLI_VERSION` (`constants/ffi.go`; the pinned version is `LibScrapliVersion = "0.0.6"` in `constants/versions.go`). libscrapli is **not in nixpkgs** (`nix search nixpkgs libscrapli` finds nothing). In a Nix sandbox (no network), v2 tests and the binary itself need a Nix-built libscrapli passed through `LIBSCRAPLI_PATH`. v2.0.0 was released 2026-10-03, and v1.4.3 (pure Go) still got a commit on 2026-10-21.
  Sources: https://github.com/scrapli/scrapligo/blob/main/ffi/ffi.go, https://github.com/scrapli/scrapligo/blob/main/constants/ffi.go, https://github.com/scrapli/scrapligo/blob/main/go.mod
- **v2 unit tests replay a raw session byte stream.** `cli/cli_test.go` `getCli` either records (`-record`, which sets `WithSessionRecorderPath(f)` against a live device) or replays (`WithTransportTest()`, `WithTestTransportF(f)`, `WithReadSize(1)`). Fixtures in `cli/fixtures/*` are the whole recorded session: login banner, prompts, echo and output. Results are compared to `golden/*` files, which are refreshed with `-update` (`testhelper/flags.go`). There are no sockets and no server. One test comment warns that `$` in the output can be mistaken for a prompt because the test transport reads one byte at a time.
  Sources: https://github.com/scrapli/scrapligo/blob/main/cli/cli_test.go, https://github.com/scrapli/scrapligo/blob/main/cli/send_input_test.go, https://github.com/scrapli/scrapligo/blob/main/testhelper/flags.go
- **v1 has the same idea in pure Go.** `transport/file.go` `File` transport: `Open` reads the whole file, `Read` returns one byte per call, and writes are captured in `Writes [][]byte`. `channel/test-fixtures/golden/*-in.txt` / `*-out.txt` assert both what the driver sent and what it returned.
  Sources: https://github.com/scrapli/scrapligo/blob/v1.3.3/transport/file.go, https://github.com/scrapli/scrapligo/tree/v1.4.3/channel/test-fixtures
- **scrapligo's own "dummy SSH server" is plain `x/crypto/ssh`, not gliderlabs.** `build/dummy_ssh_server/main.go` takes an `ssh.ServerConfig` with a `PasswordCallback`, generates an ed25519 host key per run, listens on TCP and serves a canned `show version`. Its `go.mod` requires only `golang.org/x/crypto`. v2 uses it for concurrency tests over both `bin` (system `ssh` binary) and `ssh2` (libssh2 in libscrapli).
  Source: https://github.com/scrapli/scrapligo/blob/main/build/dummy_ssh_server/main.go
- **scrapligo's sanitizer is minimal.** `testhelper/cli.go` `CleanCliOutput` replaces only `user@host`, weekday-month timestamps and `password ...` lines. Its own committed fixture `cli/fixtures/send-input-simple` still has a `Last login: ... from <private IPv4>` line. That's a real-world example of what a regex-only cleaner misses.
  Sources: https://github.com/scrapli/scrapligo/blob/main/testhelper/cli.go, https://github.com/scrapli/scrapligo/blob/main/cli/fixtures/send-input-simple

### SSH: gliderlabs/ssh vs `x/crypto/ssh`

- gliderlabs/ssh: last release v0.3.8 on 2024-12-13, last push 2025-01-27, not archived. It wraps `x/crypto/ssh` with `Session`, `Pty()`, window-change parsing (`util.go` `parsePtyRequest`, `parseWinchRequest`) and handler sugar.
  Source: https://github.com/gliderlabs/ssh
- A fake server only needs `pty-req`, `shell` and (optionally) `exec` channel requests, and the scrapligo team does that in about 100 lines of `x/crypto/ssh`. **Recommendation: use `x/crypto/ssh` directly.** It is already a dependency of any Go SSH stack, so there's one less module and nothing stale. Take gliderlabs only if the fake grows real PTY or window-size semantics.

### SSH: recommended fake (layer 2)

- `sshfake.Start(t, transcripts)` listens on `127.0.0.1:0`, generates an ed25519 host key, and writes a `known_hosts` line to `t.TempDir()`. That exercises the "pinned known_hosts, no TOFU" decision on every test, and a sibling test asserts that a different key is rejected.
- The engine is driven by **prompt matching rather than strict byte replay**. It prints the banner and prompt, reads a line, looks the command up in a `command → output` map built from sanitized transcripts, then writes the echo, the output and the prompt. An unknown command returns a vendor-style `% Invalid input detected` error. This survives reordering and lets the allowlist tests (`debug`, newline injection, redirect pipes) assert that the command **never reached the server**: the fake logs every line it received.
- Knobs for failure tests: the delay before the prompt (timeouts), a paging prompt (`--More--`) until the platform's paging-off command (`terminal length 0` or its equivalent) is sent, an auth-failure user, a dropped connection mid-output, and oversized output (the 60 KiB cap).
- Build the same engine into a tiny `cmd/fakecli` binary (stdin/stdout) for the VM (layer 3). This is test-only, so keep it out of the shipped package's `subPackages` or use a separate derivation.
- Layer 1 (scrapligo replay transport) stays useful for prompt-detection edge cases. Its API depends on the scrapligo major version chosen (v1 `transport.File` vs v2 `WithTransportTest`). That choice belongs to the SSH-library ticket, but note the libscrapli-download constraint above.

### SNMP

- **gosnmp's own tests:** CI installs `snmpd` with apt, runs `snmp_users.sh`, binds it to loopback and runs `make test` with `GOSNMP_TARGET=127.0.0.1` (`.github/workflows/ci.yml`; `generic_e2e_test.go`). For v3 it also has an **in-process scripted UDP/TCP agent** (`v3_testagent_test.go`). It parses each request, checks the HMAC, logs the request and replies through the library's own marshalling or committed libsnmp-generated bytes.
  Sources: https://github.com/gosnmp/gosnmp/blob/master/.github/workflows/ci.yml, https://github.com/gosnmp/gosnmp/blob/master/v3_testagent_test.go
- **The building blocks are exported:** `(*GoSNMP).SnmpDecodePacket([]byte)` (gosnmp.go: "exposes SNMP packet parsing to external callers") and `(*SnmpPacket).MarshalMsg()` (marshal.go). A fake v2c agent for layer 2 is therefore a UDP loop: decode, answer Get / GetNext / GetBulk from a sorted OID table, marshal. The guard rails worth testing all live there: row/byte caps, bulkwalk `max-repetitions`, `endOfMibView`, out-of-order OIDs (gosnmp's `walk_test.go` covers a "response decreases" case) and timeouts. Leave SNMPv3 crypto to the VM layer, against real net-snmp.
  Sources: https://github.com/gosnmp/gosnmp/blob/master/gosnmp.go, https://github.com/gosnmp/gosnmp/blob/master/marshal.go, https://github.com/gosnmp/gosnmp/blob/master/walk_test.go
- Off-the-shelf Go agent: `slayercat/GoSNMPServer` (v0.5.2, 2024-03-27; about 130 stars). It could replace the hand-rolled fake, but it is small and slow-moving, so it's not recommended as a dependency.
- **snmpsim** (now maintained at lextudio/snmpsim, 1.2.2, `pysnmp>=7.1.26,<8`). Fixtures are `.snmprec` lines of `OID|TYPE|VALUE` with numeric BER tags (`4` OCTET STRING, `6` OID, `67` TimeTicks, `x` suffix for hex). It can record from a live agent or from snmpwalk output. **It isn't in nixpkgs** (`nix search nixpkgs snmpsim`: no match). nixpkgs does have `python3Packages.pysnmp` 7.1.27 and `pysmi` 2.0.2, so packaging it would be possible, but it would add a Python test dependency to a Go-only project. **Adopt the `.snmprec` format, not the tool.**
  Source: https://github.com/lextudio/snmpsim (README, pyproject.toml)
- **net-snmp in nixpkgs:** `net-snmp` 5.9.5.2 (provides `snmpd`, `snmpwalk`, `snmpbulkwalk`, `net-snmp-create-v3-user`, …). The NixOS module is `services.snmpd` (`nixos/modules/services/monitoring/snmpd.nix`), with options `enable`, `package`, `listenAddress`, `port`, `openFirewall`, `configText` and `configFile`. It runs `snmpd -f -Lo -c <file> <addr>:<port>`. The upstream VM test `nixos/tests/snmpd.nix` is just `rocommunity public` plus `snmpwalk -v 2c -c public localhost`.
- **Fixture MIB tree in snmpd** (`man snmpd.conf`, source `man/snmpd.conf.5.def`):
  - `override [-rw] OID TYPE VALUE` serves a fixed value at an OID. Generate these lines in Nix from the same `.snmprec` file.
  - `pass_persist [-p priority] MIBOID PROG` hands a whole subtree to a long-running program over a stdin/stdout protocol (starts with `PING`). It fits table-shaped fixtures (ifTable, vendor tables) when GETNEXT ordering matters.
  - `rouser` / `createUser` set up v3 users, so the VM can test auth/priv against a reference implementation.
  - The VM's own MIB-II is also served. That's fine: it's VM-local, not environment data.
  Source: https://github.com/net-snmp/net-snmp/blob/master/man/snmpd.conf.5.def
- Other SNMP packages in nixpkgs, for reference: `prometheus-snmp-exporter` 0.30.1, `librenms`, `braa`, `onesixtyone`, `snmpcheck`. None is needed.

### Meraki

- `net/http/httptest.Server` serving recorded, sanitized JSON per path, covering `Link:` header pagination, `429` + `Retry-After`, and `401`/`404`.
- **Caveat on the official Go SDK** (`meraki/dashboard-api-go` v5.0.8): `sdk/api_client.go` `SetOptions` (called by `NewClientWithOptions`) does `os.Setenv(MERAKI_DASHBOARD_API_KEY, dashboardApiKey)` and `os.Setenv(MERAKI_BASE_URL, …)`. That puts the key into the process environment, which conflicts with the standing "never argv or env" credentials decision. Because the base URL is global env, two clients in one test process can't safely point at different fakes. A thin own client over `net/http` is easier to test and to keep compliant. That is for the Meraki-driver ticket to decide.
  Source: https://github.com/meraki/dashboard-api-go/blob/main/sdk/api_client.go

### NixOS VM test (house style)

netbox-mcp's `tests/vm-netbox.nix` uses `pkgs.testers.runNixOSTest`, imports `self.nixosModules.<name>`, uses fixed test secrets through `environment.etc`, and has a Python `testScript` that speaks MCP JSON-RPC over curl with `subtest`s. `flake.nix` wires it in as `checks.<system>.vm-<name>`, next to the `package` check (the Go tests in `checkPhase`) and `tests/eval.nix`. Mirror that shape:

```nix
# tests/vm-network.nix (sketch, not verified)
{ pkgs, self }:
let keys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs; in
pkgs.testers.runNixOSTest {
  name = "network-mcp-vm";
  nodes.device = {                     # fake SSH + SNMP device
    services.openssh.enable = true;    # pin a fixed host key (keys.snakeOilEd25519*), not a generated one
    users.users.fake = { isNormalUser = true; shell = fakecli; /* password or key from a test file */ };
    services.snmpd = { enable = true; configText = ''
      rocommunity <test-community> 127.0.0.1   # placeholder; use a test value
      override 1.3.6.1.2.1.1.5.0 octet_str "dev1"
      ...'' ; };
  };
  nodes.server = { imports = [ self.nixosModules.network-mcp ]; /* known_hosts with the pinned key */ };
  testScript = '' ... MCP calls: network_show, allowlist rejections, network_snmp walk ... '';
}
```

- `nixos/tests/ssh-keys.nix` provides fixed RFC 9500 test keys (`snakeOilPrivateKey`, `snakeOilEd25519PrivateKey` / `PublicKey`) that many nixpkgs tests import. Use them to pre-seed the host key and the known_hosts pin.
- `services.openssh` has `hostKeys`, `extraConfig` (for `Match User fake` / `ForceCommand` if a login shell turns out awkward), and `knownHosts` (an alias of `programs.ssh.knownHosts`).
- Two nodes (device + server) exercise the management-prefix allowlist with real addresses inside the VM network. Inventory needs NetBox. Either reuse the netbox-mcp VM approach (slow, about 7 minutes of migrations) or have the server's inventory port accept a static/stub source in tests. **Open question for the inventory ticket.**

## Transcript sanitization (recommended step)

1. **Record** with the library's recorder (scrapligo `WithSessionRecorderPath` / `WithChannelLog`, or `snmpwalk -On -Ob` → `.snmprec`, or saved Dashboard JSON) into a **gitignored** `testdata/raw/` directory.
2. **Sanitize** with `go run ./cmd/sanitize raw/ → testdata/`. The tool is deterministic and keeps consistent per-file mappings, so the same real value always maps to the same fake one and prompts still match:
   - Device hostname or prompt → `dev1`, `dev2` (applied everywhere, including the prompt itself).
   - IPv4 → RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`). IPv6 → RFC 3849 `2001:db8::/32`. MAC → RFC 7042 `00:00:5e:00:53:xx`. Domains/FQDNs → RFC 2606 `example.com`/`.net`/`.org`.
   - Serials, chassis IDs, license keys, Meraki org/network/device IDs and names, usernames → stable placeholders.
   - Drop or blank: `Last login … from …`, banners/MOTD, `password`/`secret`/`key`/`community`/`snmp-server` lines, crypto blocks, uptime and timestamps (scrapligo's patterns).
   - Model and firmware strings → generic placeholders, per the public-repo rule.
3. **Guard** with a `TestFixturesAreSanitized` test, run in `checkPhase`. It scans `testdata/` and fails on any IPv4/IPv6/MAC outside the documentation ranges, any FQDN not under `example.*`, and any line matching the secret patterns. Add an optional **local, gitignored denylist** of the operator's real hostnames/domains, checked by a pre-commit hook, so the real names never have to be written into the repo.
4. A human reviews the diff before commit (the guard catches formats, not meaning).

## Nix availability (verified with `nix search`, nixpkgs 26.11 pin)

| Need | nixpkgs |
|---|---|
| net-snmp (`snmpd`, client tools) | `net-snmp` 5.9.5.2. NixOS module `services.snmpd`, upstream test `nixos/tests/snmpd.nix` |
| OpenSSH server/client | `openssh`. NixOS `services.openssh`. Test keys in `nixos/tests/ssh-keys.nix` |
| snmpsim | **not packaged** (`pysnmp` 7.1.27 and `pysmi` 2.0.2 are) |
| libscrapli (for scrapligo v2) | **not packaged** |
| VM test driver | `pkgs.testers.runNixOSTest` (as netbox-mcp) |

## Open points for other tickets

- scrapligo v1 (pure Go) vs v2 (purego FFI and a runtime `.so` download). This decides the layer-1 replay API and whether the Nix package must build libscrapli (Zig) itself.
- Running `snmpd` unprivileged inside `checkPhase` (high port, `-C`, a writable persistent dir) is untested here. The plan above keeps snmpd in the VM only, so nothing depends on it.
- Whether the VM's server node uses real NetBox or a stub inventory.
