# network-mcp

An MCP server, written in Go, that reads network devices over SSH. It is general-purpose: any SSH device works through the generic driver, and IOS-XE and NX-OS have first-class drivers. SNMP, config export and gated writes come in later releases. It serves stdio or streamable HTTP and is packaged as a Nix flake with a NixOS module.

The server is read-only. Before anything reaches a device, it checks four things:
- the device is in the inventory and opted in;
- every address the device resolves to is inside `management_prefixes`;
- the device's SSH host key matches the `--known-hosts` file (no trust-on-first-use);
- free-form commands pass the read gate.

## Tools

| Group | Tool | What it does |
|---|---|---|
| core (always on) | `network_status` | Without `device`: version, enabled groups, inventory source health. With `device`: each connect check in order (prefix gate, TCP, host key, auth, prompt). Runs no CLI command. |
| cli | `network_show` | `device` and exactly one of `getter` or `command`; filters `include`, `exclude`, `section`. Raw text, or JSON in `data` on NX-OS. |
| cli | `network_config` | `action: get`, `device`, `source: running\|startup`; the same filters. Always redacted. |
| export | `network_export` | `devices` (at most 50), `kinds: [running, startup]`, `destination`, `reason`. Writes `<device>/<kind>.txt` to a configured destination; returns per device and kind `ref`, `changed`, `sha256` or an error, never config text. Absent without `destinations`. |

**Export.** On demand only; history lives in the destination. Configs are redacted before any sink unless the destination sets `redact: false`, which is logged on every export. A device is written whole or not at all, an identical config is not rewritten (`changed: false`), and every export is audit-logged (destination, devices, kinds, hashes, refs, `redact`, reason, session) before anything is written; if the audit line cannot be written the export is refused. Device names with `/`, `\`, `..`, control characters or a leading `.`, and IP literals, are refused. The `dir` sink writes a temp file, fsyncs and renames, confined to its root.

**Config reads.** `network_config` sends a command the server picks, never user text, so it skips the read gate's deny list (which blocks config dumps in `network_show`). IOS, IOS-XE and NX-OS use `show running-config` and `show startup-config`; any other platform needs `platforms.<value>.config.running` / `.startup`, which must stay inside the read gate's character set, and is refused until set. Redaction patterns are Cisco-shaped; elsewhere only the catch-all (`password`, `secret`, `key`, `community`, `psk`, `passphrase`) is likely to match, so give the server a read-only device account.

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
| `--tool-groups` | | all (`cli`, `export`; `core` is always on) |
| `--allow-adhoc` | | off; needs `adhoc_prefixes` |
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
```

Getter commands pass the same read gate. Allow and deny entries only add: none removes a compiled-in deny or widens the character set, and an unknown driver or profile, or a getter command the gate refuses, stops startup.

The device file is a list. Names are unique and case-insensitive, and every device listed is opted in. Only `name` is required, so the file can patch a field NetBox lacks:

```yaml
- {name: dev1, address: 192.0.2.10}
- {name: dev2, address: dev2.example.net, port: 2222, platform: cisco_ios, tags: [core]}
```

**Inventory.** Sources merge by device name, field by field: the first source in `sources` that sets a field wins, and `provenance` records which one. A device in one source only is kept. Each source's list is cached for 60 s; a failed source contributes nothing (no stale data) and `network_status` shows its error. NetBox is queried with `?tag=<opt_in_tag>`, and the tag is checked again on every object because NetBox ignores filters it does not know. A device with no address (and `resolve_names` off) or no `read_ref` is refused with the reason. A platform the table does not know gets `generic_ssh`.

**Rules.** `read_ref`, `write_ref` and `snmp` resolve separately, default < platform (the platform value or its driver) < tag < device; among rules of one level the first listed wins. `write_ref` never falls back to `read_ref`.

**Ad-hoc addresses.** With `--allow-adhoc`, a `device` that is an IP literal no source knows is accepted if it is inside `adhoc_prefixes`: `generic_ssh`, credentials from the `adhoc` rule only, host key still pinned. Without the flag it is refused.

**Credential refs.** A ref is the file `$CREDENTIALS_DIRECTORY/<ref>`. It holds JSON, either `{"username": …, "password": …}` or `{"username": …, "private_key": …}`. The server reads it on every connect and never caches or logs it. No secret is ever taken from a flag or an environment variable.

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

The tests are hermetic: an in-process SSH server (`internal/sshfake`) replays fixture output on loopback. There is no vendor image and no lab. The VM test (`nix build .#checks.x86_64-linux.vm-network -L`, under a minute with KVM) runs the module against a real OpenSSH server whose login shell is `cmd/fakecli`, a test-only build of the same fake that is never shipped.

## Public repo rule

This repository is public. Fixtures, docs and issues must never contain real hostnames, IPs, MACs, domains, serials, device counts, models or firmware versions. Use only:
- documentation values: RFC 5737 / 3849 / 7042 addresses, RFC 2606 names;
- `dev1`-style hostnames.

`TestFixturesAreSanitized` scans every file under `testdata/` and fails on anything else, and it runs in `nix flake check`.

## Fixtures

1. Put the capture in `testdata/raw/`, which is gitignored and skipped by the guard.
2. Sanitize it: `go run ./cmd/sanitize < testdata/raw/x.txt > testdata/<dir>/x.txt`. It replaces hostnames with `dev1`, `dev2`, …, addresses and domains with documentation values, and serials, usernames, model and firmware strings with placeholders. It drops login lines, banners, secret lines and timestamps. It prints nothing if the result still fails the guard.
3. Review the diff by hand: the guard catches formats, not meaning.
4. Commit only what `go test ./internal/fixtures` passes.

Third-party fixtures go under `testdata/third_party/<source>/` with the upstream `LICENSE`, a `SOURCE` file (URL, commit SHA, upstream path of each file) and, for Apache-2.0, a `NOTICE` that lists each file changed. They are sanitized like any other fixture. `cmd/sanitize` is a dev tool, not part of the shipped package.

## Licence

MIT.
