# network-mcp

An MCP server, written in Go, that reads network devices over SSH. It is general-purpose: any SSH device works through the generic driver. First-class IOS-XE and NX-OS drivers, SNMP, config export and gated writes come in later releases. It is packaged as a Nix flake.

The server is read-only. Before anything reaches a device, it checks four things:
- the device is in the inventory and opted in;
- every address the device resolves to is inside `management_prefixes`;
- the device's SSH host key matches the `--known-hosts` file (no trust-on-first-use);
- free-form commands pass the read gate.

## Tools

| Group | Tool | What it does |
|---|---|---|
| core (always on) | `network_status` | Without `device`: version, enabled groups, inventory source health. With `device`: each connect check in order (prefix gate, TCP, host key, auth, prompt). Runs no CLI command. |
| cli | `network_show` | `device`, `command`: one read command, raw text. |

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
| `--tool-groups` | | all (`cli`; `core` is always on) |
| `--request-timeout`, `--log-level` | `NETWORK_MCP_LOG_LEVEL` | `30s`, `info` |
| `--stdio` | | the only transport so far |

The config file holds structure only, never secrets:

```yaml
management_prefixes: [192.0.2.0/24]   # empty or missing refuses startup
sources:
  - {name: file, type: file, path: /etc/network-mcp/devices.yaml}
credentials:
  default: {read_ref: ssh-read}
```

The device file is a list. Names are unique and case-insensitive, and every device listed is opted in:

```yaml
- {name: dev1, address: 192.0.2.10}
- {name: dev2, address: dev2.example.net, port: 2222, platform: cisco_ios, tags: [core]}
```

**Credential refs.** A ref is the file `$CREDENTIALS_DIRECTORY/<ref>`. It holds JSON, either `{"username": …, "password": …}` or `{"username": …, "private_key": …}`. The server reads it on every connect and never caches or logs it. No secret is ever taken from a flag or an environment variable.

**Host keys.** The server dials the resolved IP address, so pin each device's key in the `--known-hosts` file under its IP (`[ip]:port` for a port other than 22).

**Audit.** One JSON line per event goes to stderr, which lands in journald under systemd.

## Claude Code (stdio)

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

## Development

`nix develop` gives you Go, gopls, govulncheck and nixfmt. `nix flake check` builds the package and runs every test, the fixture guard included. `nix fmt` formats the Nix files.

The tests are hermetic: an in-process SSH server (`internal/sshfake`) replays fixture output on loopback. There is no vendor image and no lab.

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
