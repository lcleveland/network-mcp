# network-mcp

An MCP server, written in Go, that reads network devices over SSH and SNMP. It is general-purpose: any SSH device works through the generic driver, IOS-XE and NX-OS have first-class drivers, and any SNMP v2c or v3 agent can be read. It can export configs and, when enabled, apply gated config changes to IOS-XE. It serves stdio or streamable HTTP and is packaged as a Nix flake with a NixOS module.

The server is read-only unless `--allow-config` enables config changes (below). Before anything reaches a device, it checks four things:
- the device is in the inventory and opted in;
- every address the device resolves to is inside `management_prefixes`;
- the device's SSH host key matches the `--known-hosts` file (no trust-on-first-use);
- free-form commands pass the read gate.

## Tools

| Group | Tool | What it does |
|---|---|---|
| core (always on) | `network_status` | Without `device`: version, enabled groups, inventory source health. With `device`: each connect check in order (prefix gate, TCP, host key, auth, prompt), then an SNMP `sysUpTime.0` read if the device has SNMP. Runs no CLI command. |
| core (always on) | `network_inventory` | `list` (filters `name` glob, `platform`, `driver`, `tag`; `fields`; `limit` 50, max 200) or `get` (`name`: merged record, provenance, credential ref names, and gate verdicts `opt_in`, `in_prefix`, `host_key_pinned`, `reachable_reason`). Contacts no device. |
| cli | `network_show` | `device` and exactly one of `getter` or `command`; filters `include`, `exclude`, `section`. Raw text, or JSON in `data` on NX-OS. |
| cli | `network_config` | `action: get`, `device`, `source: running\|startup`; the same filters. Always redacted. |
| snmp | `network_snmp` | `get` (`device`, up to 16 `oids`), `walk` / `bulkwalk` (`device`, root `oid`, `after`, `max_rows` 500/max 5000), `resolve` (`oids`, name ↔ OID offline). Rows `{oid, name, type, value}`. |
| export | `network_export` | `devices` (at most 50), `kinds: [running, startup]`, `destination`, `reason`. Writes `<device>/<kind>.txt` to a configured destination; returns per device and kind `ref`, `changed`, `sha256` or an error, never config text. Absent without `destinations`. |
| change | `network_change` | Only with `--allow-config`. `plan`: `device`, `lines` (≤200), `reason`; returns `plan_id`, the lines as a `+` diff, `pre_hash`, `expires`. `apply`: `plan_id`, `revert_minutes` (2–15, default 5), `reason`; IOS-XE only; returns `change_id`, `deadline`, `post_hash` and the device diff. `confirm` / `rollback`: `change_id`, `reason`. `save`: `device`, `reason`, only with `--allow-save`. `status`: this session's plans and pending changes, and the counts. |

**Export.** On demand only; history lives in the destination. Configs are redacted before any sink unless the destination sets `redact: false`, which is logged on every export. A device is written whole or not at all, an identical config is not rewritten (`changed: false`), and every export is audit-logged (destination, devices, kinds, hashes, refs, `redact`, reason, session) before anything is written; if the audit line cannot be written the export is refused. Device names with `/`, `\`, `..`, control characters or a leading `.`, and IP literals, are refused. The `dir` sink writes a temp file, fsyncs and renames, confined to its root. The `git` sink (go-git, no `git` binary) commits a batch only when the tree changed, author `network-mcp`, message the reason and MCP session; `ref` is the commit. With a `remote` it pushes after every export, also when nothing changed; a failed push keeps the commit and reports the error. An ssh:// remote's host key is pinned by `known_hosts`, never trusted on first use, and `~/.ssh` is never read. The `s3` sink stores the body's SHA-256 as object metadata and skips the put when it matches; `ref` is the key, plus `?versionId=` when the bucket versions. Its client is built from the credential ref alone: no environment variable, `~/.aws` file or instance metadata.

**Change plans.** A plan is for one IOS-XE or NX-OS device with a `write_ref` (classic IOS, generic SSH and ad-hoc devices are refused; the `read_ref` is never used). Lines are printable ASCII without `?` or `|`; `do`, `end`, `exit` and `configure` are refused. The server reads the unredacted running config with the write ref, hashes it (SHA-256 after dropping volatile lines, CR, ANSI, trailing spaces and blank lines; the text never leaves the server) and refuses the whole plan if any line matches the management-plane denylist: each typed token is compared as a prefix of the entry's token, so abbreviations match, after stripping a leading `no`/`default`. Compiled-in entries: `aaa`, `username`, `enable`, `line`, `ip ssh`, `crypto`, `snmp-server`, `boot`, `reload`, `erase`, `config-register`, `alias`, `event manager`, `kron`, `archive`, `parser`, `configuration mode`, `privilege`, `banner`, `macro`, `ip http`, `restconf`, `netconf-yang`, `ip scp`/`ftp`/`tftp`, `logging`, `license`, `key`, `tacacs`, `radius`, `radius-server`, `service internal`, `gnxi`, `checkpoint`, `rollback`, `feature`; `write_deny` adds more. From the running config it also denies the ACLs named by `access-class`, `snmp-server` or the connect interface's filters, the management VRF (`vrf context management`, `vrf definition Mgmt-*`, the connect interface's VRF) and its routes, and the interface that owns the address the server dials. The plan is kept in memory for 10 minutes, bound to the MCP session, the device address, its pinned host key, driver, lines, hash, write ref and reason, and is single-use; a restart voids it. Plans, denials, refusals and expiries are audit-logged; if the audit line cannot be written the plan is refused. The device's config is not touched.

**Writes.** Off by default. This path is **unvalidated on hardware**: it was built against Cisco's documentation and a fake device, never a lab switch, so trial it on a non-critical IOS-XE device first. NX-OS plans work, NX-OS apply does not yet.
- **Before apply**, the operator must configure `archive` / `path` on the device; the server never does, and refuses without it.
- **apply** uses up the plan and takes the device's slot: a second apply on the device, or more than `--max-pending-changes` at once, is refused, not queued (reads are never blocked). On a fresh SSH session with the write ref, the prompt must be privileged (`#`; the server never runs `enable`), and the server refuses unless `archive path` is set, `show archive config rollback timer` shows nothing pending, `show configuration lock` is clear and the running config still hashes to `pre_hash`. It then sends `configure terminal revert timer <revert_minutes>`, each line, and `end`. Any reply line starting with `%` sends `configure revert now`. Otherwise it records `post_hash` and `show archive config differences` (redacted, in `_untrusted`) and keeps the session open until the deadline.
- **confirm** must come before the deadline from the same MCP session. It dials a **new** SSH session (proving the device is still reachable), checks the running config hashes to `post_hash`, sends `configure confirm` and checks no timer is left. If the new session's confirm is refused (IOS-XE may tie it to the session that started the timer), it is retried on the apply session. Any failure means no confirm, and the device timer reverts the change.
- **rollback** sends `configure revert now` and checks the running config hashes to `pre_hash`.
- **Deadline check.** One minute after the deadline, an unconfirmed change frees its slot and the server dials once more and audits `reverted`, `not_reverted` or `unreachable`. If the server dies first, the device timer still reverts.
- **save** (`--allow-save`) runs `copy running-config startup-config` only when nothing is pending on the device (in this process, or a revert timer from any) and the running config hashes to the `post_hash` of the last change this server confirmed there. Records do not survive a restart, so after one, save by hand. Confirm never saves.
- Every step needs a `reason`. Each audit line carries the change fields (`change_id`, `pre_hash`, `post_hash`, `revert_minutes`, `deadline`, redacted commands, truncated device error). A `started` line is written before anything reaches the device; if it cannot be written, the step is refused, and if apply's final line cannot be written, the change is reverted.
- Not lab-checked: the reply texts parsed (`No Rollback Confirmed Change pending`, `Owner PID`, `[OK]`), whether a new session may confirm, whether a timed revert leaves a stale lock, how long the revert takes, and whether config-mode prompts keep the whole hostname.

**Config reads.** `network_config` sends a command the server picks, never user text, so it skips the read gate's deny list (which blocks config dumps in `network_show`). IOS, IOS-XE and NX-OS use `show running-config` and `show startup-config`; any other platform needs `platforms.<value>.config.running` / `.startup`, which must stay inside the read gate's character set, and is refused until set. Redaction patterns are Cisco-shaped; elsewhere only the catch-all (`password`, `secret`, `key`, `community`, `psk`, `passphrase`) is likely to match, so give the server a read-only device account.

**SNMP.** Only v2c and v3 authPriv, with version and credentials from the device's `snmp` rule (`{version, ref, port?}`, port 161 by default), never from arguments. v1, noAuth and authNoPriv refuse startup; a device with no `snmp` rule is refused. The SNMP address passes the same prefix gate as SSH. The server never sends a SET and listens for no traps. Walks stop at the end of the subtree, `endOfMibView`, `max_rows` or about 60 KiB, and `_truncation.hint` then says `use after: <oid>`; an agent whose OIDs do not increase ends the walk with an error. The community and USM subtrees (`1.3.6.1.6.3.18`, `1.3.6.1.6.3.15`) are refused on request and withheld from answers. Printable octet strings come back as sanitized text, others as `0x` hex, missing objects as `null` with a warning. Names resolve offline through gosmi over net-snmp's IETF/IANA MIBs, built in; `--mib-dir` adds vendor MIBs, and numeric OIDs always work.

**Platforms.** The device's `platform` value picks the driver and getter profile, ignoring case:

| Platform values | Driver | Getters |
|---|---|---|
| `ios-xe`, `iosxe`, `cisco_iosxe`, `cisco-ios-xe` | `iosxe` | `iosxe` |
| `nx-os`, `nxos`, `cisco_nxos`, `cisco-nx-os` | `nxos` | `nxos` |
| `ios`, `cisco_ios`, `cisco-ios` | `generic_ssh` | `ios` |
| anything else or missing | `generic_ssh` | none |

The `iosxe` and `nxos` drivers use scrapligo's embedded platform definitions and send only the session-only `terminal width` and `terminal length 0` before the first command. They never run `enable`: an account that lands at `>` reads at exec level. Getters use NAPALM names (`facts`, `inventory`, `environment`, `interfaces`, `interfaces_ip`, `vlans`, `lldp_neighbors`, `cdp_neighbors`, `arp_table`, `mac_address_table`, `routes`, `bgp_neighbors`) and return raw output; each maps to one command that passes the read gate. On NX-OS the server appends ` | json` after the gate: valid JSON comes back in `data` with `parsed: true` (keys such as `community` or `password` are redacted), and anything else, or JSON over 60 KiB or with a filter, comes back as text with `parsed: false`.

Results are JSON built by the server. Device text appears only in the fields listed in `_untrusted`, and device-side failures appear in `device_error`.

**Read gate.** A command must:
- use only letters, digits, spaces and `. / : _ , -`, so pipes, `;`, `?`, quotes and newlines are refused;
- be at most 256 bytes;
- start with the full keyword `show`, `display`, `dir`, `ping` or `traceroute` (abbreviations are refused);
- avoid a compiled-in deny list (`debug`, `terminal`, `configure`, `show running`, `show tech`, …). Matching works on token prefixes, so `sh run` and `conf t` are caught too.

`ping` and `traceroute` take a target, at most 6 tokens, and no `repeat`, `count`, `size`, `timeout` or `sweep`. Every refusal is audit-logged.

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--config` | `NETWORK_MCP_CONFIG` | required |
| `--credentials-dir` | `CREDENTIALS_DIRECTORY` | required |
| `--known-hosts` | `NETWORK_MCP_KNOWN_HOSTS` | required if any device uses SSH |
| `--tool-groups` | | all (`cli`, `snmp`, `export`, `change`; `core` is always on; `snmp` is dropped when no rule sets `snmp`) |
| `--mib-dir` (repeatable) | | none; extra MIB modules, a parse error refuses startup |
| `--allow-adhoc` | | off; needs `adhoc_prefixes` |
| `--allow-config` | | off; registers `network_change` and refuses startup unless every rule's `write_ref` file exists with no group or world access |
| `--max-pending-changes` | | 1; applied but unconfirmed changes at once, across devices |
| `--allow-save` | | off; adds `network_change` `save`; needs `--allow-config` |
| `--request-timeout`, `--log-level` | `NETWORK_MCP_LOG_LEVEL` | `30s`, `info` |
| `--stdio` / `--http` | | stdio |
| `--addr`, `--path` | | `127.0.0.1:8232`, `/mcp` |
| `--http-auth-token-file` | `NETWORK_MCP_HTTP_AUTH_TOKEN_FILE` | the credential `http-auth-token` if present; a non-loopback listener requires a token |

**HTTP.** Clients send `Authorization: Bearer <token>`, compared in constant time. The server refuses to start on a non-loopback `--addr` without a token, and never logs it. `/healthz` stays open.

The config file holds structure only, never secrets:

```yaml
management_prefixes: [192.0.2.0/24]   # empty or missing refuses startup
adhoc_prefixes: [192.0.2.128/25]      # optional, inside management_prefixes; used only with --allow-adhoc
resolve_names: false                   # true: DNS-resolve a device no source gives an address
sources:                               # merged in this order; see Inventory
  - {name: file, type: file, path: /etc/network-mcp/devices.yaml}
  - name: netbox
    type: netbox                       # read-only
    url: https://netbox.example.com
    token_ref: netbox-token            # credential ref holding {"token": …}
    opt_in_tag: network-mcp            # only devices with this tag are opted in
    address_order: [primary_ip4, primary_ip6, oob_ip]  # the default
    filters: {site: dc1}               # optional extra /api/dcim/devices/ filters
rules:                                 # credentials and SNMP; never from a source
  - {match: default,          read_ref: ssh-read}
  - {match: {platform: nxos}, read_ref: nxos-read, write_ref: nxos-write}
  - {match: {tag: core},      snmp: {version: v3, ref: snmp-core}}
  - {match: {device: dev1},   read_ref: dev1-read}
  - {match: adhoc,            read_ref: adhoc-read}
platforms:                             # optional; keys match the platform value, ignoring case
  c9k: {driver: iosxe, profile: iosxe} # nothing is inferred: set both
  aos:
    getters: {clients: show clients}   # name -> command; overrides a profile getter of the same name
    read_allow: [who]                  # extra first keywords
    read_deny: [show clients detail]   # extra deny entries
    config: {running: show running-config, startup: show startup-config} # for network_config
destinations:                          # optional; none means no network_export
  local: {type: dir, path: /var/lib/network-mcp/export}  # redact: false is allowed, off by default
  repo:                                # one commit per export; remote optional (ssh:// or https://)
    {type: git, path: /var/lib/network-mcp/repo, branch: main, remote: 'ssh://git@git.example.com/configs.git',
     credential: git-push, known_hosts: /etc/network-mcp/git_known_hosts}  # known_hosts required for ssh://
  bucket:                              # endpoint for non-AWS stores; checksum when_required|when_supported
    {type: s3, endpoint: 'https://s3.example.com', region: us-east-1, bucket: configs, prefix: net/, path_style: true, credential: s3-export}
write_deny: [spanning-tree]            # optional; adds to the network_change denylist, never removes
```

Getter commands pass the same read gate. Allow and deny entries only add: none removes a compiled-in deny or widens the character set, and an unknown driver or profile, or a getter command the gate refuses, stops startup.

The device file is a list. Names are unique and case-insensitive, and every device listed is opted in. Only `name` is required, so the file can patch a field NetBox lacks:

```yaml
- {name: dev1, address: 192.0.2.10}
- {name: dev2, address: dev2.example.net, port: 2222, platform: cisco_ios, tags: [core]}
```

**Inventory.** Sources merge by device name, field by field: the first source in `sources` that sets a field wins, and `provenance` records which one. A device in one source only is kept. Each source's list is cached for 60 s; a failed source contributes nothing (no stale data) and `network_status` shows its error. NetBox is queried with `?tag=<opt_in_tag>`, and the tag is checked again on every object because NetBox ignores filters it does not know. A device with no address (and `resolve_names` off) or with neither a `read_ref` nor an `snmp` rule is refused with the reason. A device with only an `snmp` rule is SNMP-only: `network_snmp` reads it, the SSH tools refuse it and `network_status` skips the SSH checks. A platform the table does not know gets `generic_ssh`.

**Rules.** `read_ref`, `write_ref` and `snmp` resolve separately, default < platform (the platform value or its driver) < tag < device; among rules of one level the first listed wins. `write_ref` never falls back to `read_ref`.

**Ad-hoc addresses.** With `--allow-adhoc`, a `device` that is an IP literal no source knows is accepted if it is inside `adhoc_prefixes`: `generic_ssh`, credentials from the `adhoc` rule only, host key still pinned. Without the flag it is refused.

**Credential refs.** A ref is the file `$CREDENTIALS_DIRECTORY/<ref>`. It holds JSON, either `{"username": …, "password": …}` or `{"username": …, "private_key": …}`; an SNMP ref holds `{"community": …}` for v2c or `{"username", "auth_protocol", "auth_password", "priv_protocol", "priv_password"}` for v3 (auth `MD5`, `SHA`, `SHA224`–`SHA512`; priv `DES`, `AES`, `AES192`, `AES256`, `AES192C`, `AES256C`). An export `credential` holds `{"username"?, "private_key"}` for a git ssh:// remote, `{"username"?, "token"}` for https:// (username defaults to `git`), or `{"access_key_id", "secret_access_key", "session_token"?}` for s3. The server reads it on every connect and never caches or logs it. No secret is ever taken from a flag or an environment variable.

**Host keys.** The server dials the resolved IP address, so pin each device's key in the `--known-hosts` file under its IP (`[ip]:port` for a port other than 22).

**Audit.** One JSON line per event goes to stderr, which lands in journald under systemd.

## Nix

```nix
{
  inputs.network-mcp.url = "github:lcleveland/network-mcp";

  outputs = { nixpkgs, network-mcp, ... }: {
    nixosConfigurations.host = nixpkgs.lib.nixosSystem {
      modules = [
        network-mcp.nixosModules.default
        {
          services.network-mcp = {
            enable = true;
            settings = {
              management_prefixes = [ "192.0.2.0/24" ];
              sources = [ { name = "file"; type = "file"; path = "/etc/network-mcp/devices.yaml"; } ];
              rules = [ { match = "default"; read_ref = "ssh-read"; } ];
            };
            # ref name -> runtime path, e.g. from sops-nix or agenix
            credentials.ssh-read = "/run/secrets/network-mcp-ssh-read"; # config.sops.secrets.<name>.path
            # credentials.ssh-read = config.age.secrets.network-mcp-ssh-read.path;
            knownHostsFile = "/etc/network-mcp/known_hosts";
            bearerTokenFile = "/run/secrets/network-mcp-bearer";
          };
        }
      ];
    };
  };
}
```

The module:
- renders `settings` to the `--config` file (or takes `configFile`); it holds structure and ref names only;
- passes each credential and the bearer token through systemd `LoadCredential`, so no secret reaches the Nix store, argv or the environment, and refuses paths inside the store;
- serves streamable HTTP on `127.0.0.1:8232` as a hardened DynamicUser, and refuses a non-loopback `listenAddress` without `bearerTokenFile`;
- refuses empty `settings.management_prefixes`;
- gives the unit `StateDirectory=network-mcp`, the only place it can write: export destination paths must live under `/var/lib/network-mcp/`, and the module refuses a `settings.destinations` path elsewhere.
- passes each of `mibDirs` as `--mib-dir`.

`overlays.default` adds `pkgs.network-mcp`. To install only the CLI for stdio use on a workstation, set `services.network-mcp.installCli = true;` and leave `enable` off.

## Clients

Claude Code over stdio:

```json
{
  "mcpServers": {
    "network": {
      "command": "network-mcp",
      "args": ["--config", "/etc/network-mcp/config.yaml", "--known-hosts", "/etc/network-mcp/known_hosts"],
      "env": {"CREDENTIALS_DIRECTORY": "/run/secrets/network-mcp"}
    }
  }
}
```

Over HTTP, to the NixOS service:

```sh
claude mcp add --transport http network http://127.0.0.1:8232/mcp \
  --header "Authorization: Bearer $(cat ~/.config/network-mcp/bearer)"
```

## Development

`nix develop` gives you Go, gopls, govulncheck and nixfmt. `nix flake check` builds the package and runs every test (the fixture guard included), the module evaluation checks and the VM test. `nix fmt` formats the Nix files.

The tests are hermetic: an in-process SSH server (`internal/sshfake`) replays fixture output on loopback, and an in-process SNMP v2c agent (`internal/snmpfake`) answers from the hand-made `.snmprec` files in `testdata/snmp`. There is no vendor image and no lab. The VM test (`nix build .#checks.x86_64-linux.vm-network -L`, under a minute with KVM) runs the module against a real OpenSSH server whose login shell is `cmd/fakecli`, a test-only build of the same fake that is never shipped, and against net-snmp `snmpd` serving the same `.snmprec` fixtures over v2c and v3 authPriv (SHA-256/AES).

## Public repo rule

This repository is public. Fixtures, docs and issues must never contain real hostnames, IPs, MACs, domains, serials, device counts, models or firmware versions. Use only:
- documentation values: RFC 5737 / 3849 / 7042 addresses, RFC 2606 names;
- `dev1`-style hostnames.

`TestFixturesAreSanitized` scans every file under `testdata/` and fails on anything else, and it runs in `nix flake check`. In `.snmprec` files it scans comments and values (hex decoded), not OIDs, so an address inside an OID index must be checked by hand. LibreNMS walks are GPL-3.0: use them for shape only.

## Fixtures

1. Put the capture in `testdata/raw/`, which is gitignored and skipped by the guard.
2. Sanitize it: `go run ./cmd/sanitize < testdata/raw/x.txt > testdata/<dir>/x.txt`. It replaces hostnames with `dev1`, `dev2`, …, addresses and domains with documentation values, and serials, usernames, model and firmware strings with placeholders. It drops login lines, banners, secret lines and timestamps. It prints nothing if the result still fails the guard.
3. Review the diff by hand: the guard catches formats, not meaning.
4. Commit only what `go test ./internal/fixtures` passes.

Third-party fixtures go under `testdata/third_party/<source>/` with the upstream `LICENSE`, a `SOURCE` file (URL, commit SHA, upstream path of each file) and, for Apache-2.0, a `NOTICE` that lists each file changed. They are sanitized like any other fixture. `cmd/sanitize` is a dev tool, not part of the shipped package.

## Licence

MIT. The embedded MIB modules in `internal/mib/mibs` keep their own IETF/IANA notices; see `NOTICE`.
