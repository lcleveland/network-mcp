# What to borrow from existing network MCP servers and automation tools

Research for [#3](https://github.com/lcleveland/network-mcp/issues/3) (map [#1](https://github.com/lcleveland/network-mcp/issues/1)).
Read on 2026-10-26 from each project's default branch (source code and README), not from write-ups. Each project is linked where it is first named; file paths are relative to that repo. Star counts are a rough maturity signal only.
Related: the Go library choice is in `research/go-libraries` (#4), and the IOS-XE / NX-OS rollback commands are in `research/cisco-rollback-and-apis` (#5).

## Answer in brief

- **No existing server matches our safety model.** Most have no global write switch, and two "rollbacks" (pyATS_MCP and plain Junos `commit`) are not real auto-reverts. Our map decisions are stricter than all of them. Nothing found argues for loosening one.
- **Best single source for the generic SSH gate: [ktbyers/netmiko_mcp](https://github.com/ktbyers/netmiko_mcp)** (written by Netmiko's author). It uses an allowlist of *characters* checked before the command allowlist, anchored exact/glob matching with deny-wins, a pipe-modifier allowlist with one pipe at most, and a fail-closed audit log.
- **Best single source for the IOS-XE write path: [anderson-jason573/cisco-iosxe-mcp](https://github.com/anderson-jason573/cisco-iosxe-mcp)** (new, 0 stars, but carefully reasoned). Apply takes only a preview id. It refuses when `archive` is missing, applies under `configure terminal revert timer`, checks reachability on a **new** SSH session and only then confirms. It rejects `do`, bare `end` and nested `configure` inside a config block.
- **Three gaps in the map that these projects expose:** (1) the management-plane denylist has to match **abbreviated** keywords (Juniper's server does this); (2) config reads should **redact secrets** by default (Oxidized and NAPALM both carry ready-made Cisco regex sets); (3) whether a confirmed change is also **saved to startup-config** is undecided (NAPALM saves it, cisco-iosxe-mcp makes it a separate gated tool).
- **Skip:** free-form `sh -c`, re-pasting a snapshot as "rollback", SNMP communities passed as tool arguments, fail-open allowlists (empty list = allow all), embedding-based API search, and per-vendor tool sprawl (58 tools in one server).

## Projects checked

| Project | Exists? | Language, licence | Stars | Notes |
|---|---|---|---|---|
| [automateyournetwork/pyATS_MCP](https://github.com/automateyournetwork/pyATS_MCP) | Yes | Python, MIT | 90 | The "pyATS_MCP" in the ticket. |
| [Juniper/junos-mcp-server](https://github.com/Juniper/junos-mcp-server) | Yes | Python, Apache-2.0 | 109 | Vendor-official. |
| [CiscoDevNet/cisco-meraki-mcp-official](https://github.com/CiscoDevNet/cisco-meraki-mcp-official) | Yes (added) | Python, Apache-2.0 | 15 | Vendor-official, beta. Also hosted at `mcp.meraki.com`. |
| [WYRE-AI/meraki-mcp](https://github.com/WYRE-AI/meraki-mcp) | Yes | TypeScript, Apache-2.0 | 1 | The "wyre meraki-mcp" in the ticket. |
| [Avinash-Amudala/MCP-Telecom](https://github.com/Avinash-Amudala/MCP-Telecom) | Yes | Python, MIT | 1 | The "mcp-telecom" in the ticket. Netmiko-based. |
| [netboxlabs/netbox-mcp-server](https://github.com/netboxlabs/netbox-mcp-server) | Yes | Python, Apache-2.0 | 249 | Vendor-official, read-only. |
| [ktbyers/netmiko_mcp](https://github.com/ktbyers/netmiko_mcp) | Yes (added) | Python, Apache-2.0 | 19 | Generic SSH MCP by Netmiko's author. |
| [anderson-jason573/cisco-iosxe-mcp](https://github.com/anderson-jason573/cisco-iosxe-mcp) | Yes (added) | Python, Apache-2.0 | 0 | scrapli-based IOS-XE MCP with a revert-timer write path. Single commit (2026-08-17). |
| [acato/snmp-mcp](https://github.com/acato/snmp-mcp) | Yes (added) | Python, Apache-2.0 | 0 | Read-only SNMP, with a thorough `DESIGN.md`. |
| [sdempsay/snmp-mcp](https://github.com/sdempsay/snmp-mcp) | Yes (added) | Python | 0 | net-snmp subprocess wrapper. |
| [classfang/ssh-mcp-server](https://github.com/classfang/ssh-mcp-server) | Yes (added) | TypeScript | 978 | The most popular generic SSH MCP; aimed at Linux hosts. |
| [uarlouski/ssh-mcp-server](https://github.com/uarlouski/ssh-mcp-server) | Yes (added) | TypeScript | 37 | Generic SSH, Linux-oriented. |
| [napalm-automation/napalm](https://github.com/napalm-automation/napalm) | Yes | Python, Apache-2.0 | 2.5k | Getter set and config-replace logic. |
| [ktbyers/netmiko](https://github.com/ktbyers/netmiko) | Yes | Python, MIT | 4.3k | `generic` and `tplink_jetstream` drivers. |
| [scrapli/scrapligo](https://github.com/scrapli/scrapligo) | Yes | Go, MIT | 307 | Covered in depth in #4; v1.4.x only. |
| [ytti/oxidized](https://github.com/ytti/oxidized) | Yes | Ruby, Apache-2.0 | 3.6k | Around 200 model files in `lib/oxidized/model/`. |

Seen but not read in depth (thin or duplicate): several other pyATS, Junos, Meraki, Nornir and Netmiko MCPs found by GitHub search. Almost all have fewer than 20 stars; the exception is automateyournetwork/MCPyATS (70), which bundles pyATS_MCP with other servers. No SNMP MCP with real adoption exists. Both SNMP servers above have 0 stars.

## Per project: tool shape, safety model, output

### pyATS_MCP

- **Tools** (`pyats_mcp_server.py`, 26): `pyats_run_show_command` (and multi/pcall fan-out variants), `pyats_show_running_config`, `pyats_learn_feature`, `pyats_diff_learned_snapshots`, `pyats_configure_device`, `pyats_configure_with_diff`, `pyats_rollback_config`, `pyats_run_linux_command`, `pyats_run_dynamic_test` (runs LLM-written Python), `pyats_run_blitz`, `pyats_run_robot` and others.
- **Safety:** `validate_show_command` requires a `show` prefix, blocks `|`, `>`, `<` and the tokens `copy delete erase reload write configure conf`. Config goes through a regex denylist (`write erase`, `erase`, `reload`, `delete`, `format`). **No global write flag**: config tools are always listed. `pyats_rollback_config` re-applies a saved `show running-config` as config lines. That is a merge: lines added since the snapshot stay, so it is not a rollback. `pyats_run_linux_command` wraps commands containing `|` or `>` in `sh -c`.
- **Output:** tries a Genie parser first, then falls back to raw text with ANSI and non-printables stripped (`clean_output`). Structured JSON envelope `{status, device, command, output, parsed}`. No size cap.
- **Borrow:** parse-then-raw fallback with a `parsed: bool` flag; ANSI stripping; diff of running-config before and after a change returned with the apply result. **Skip:** snapshot re-paste "rollback", `sh -c`, LLM-authored test scripts, and denylist-only gating.

### Juniper/junos-mcp-server

- **Tools** (`jmcp.py` `TOOL_HANDLERS`): `execute_junos_command`, `execute_junos_command_batch`, `get_junos_config`, `junos_config_diff`, `render_and_apply_j2_template`, `gather_device_facts`, `get_router_list`, `load_and_commit_config`, `execute_junos_pfe_command`.
- **Safety:** denylists in plain files. `block.cmd` lists `request system reboot/halt/power-off/zeroize`; `block.cfg` lists root-authentication and user authentication lines. The matcher (`_matches_blocklist_tokens`) compares **token by token and accepts abbreviations**: a typed token matches if the pattern's literal keyword *starts with* it. The blocklist fails closed if the file is missing or unreadable. The write path takes a config **lock**, `load`s, `diff`s, returns "No configuration changes detected" when empty, and runs plain `commit`, **not** `commit confirmed`. On error it rolls back the candidate and unlocks. If unlock fails, it drops the transport so a locked session is not reused. No write flag. Streamable HTTP refuses to start without bearer tokens unless `--allow-unauthenticated-http` is set, and that flag is allowed on loopback only.
- **Output:** plain text with request arguments in content annotations. Per-router connection pool with idle timeout and a per-router lock. Progress notifications for batches.
- **Borrow:** token-prefix denylist matching (abbreviation-aware); fail closed when the policy file is unreadable; lock → load → diff → empty-diff short-circuit; drop the session when cleanup fails; per-device lock plus idle-timeout pool; HTTP refuses to start unauthenticated. **Skip:** commit without confirm; no write flag.

### Meraki: CiscoDevNet/cisco-meraki-mcp-official

- **Tools:** two. `semantic_search` (vector search over the Dashboard OpenAPI spec, local `fastembed` model) and `execute_api(capability_id, parameters)`. Only GET operations are indexed (`providers/openapi.py` hard-codes `method="GET"`), and the client refuses non-GET SDK methods (`providers/meraki_client.py`).
- **Safety:** read-only by construction, plus server instructions telling the agent to deny writes. The README warns that the agent may call the API directly with the same key, so it says to use a read-only Dashboard key. `reject_total_pages_parameter` and `reject_traversal_parameters` reject multi-page fetches and path-traversal values. Tools carry `readOnlyHint=True`. A `RiskClassifier` maps GET → SAFE, POST/PUT/PATCH → ELEVATED, DELETE → DESTRUCTIVE.
- **Output:** **one page only**, by design ("can bloat the agent's context and stall on large orgs"). Typed success and error models with a `recovery_suggestion`.
- **Borrow:** one-page default with an explicit "not the complete dataset" note; traversal check on path parameters; `readOnlyHint` annotations; error results that carry a recovery hint; the method → risk-tier table if a Meraki raw-GET escape hatch is ever added. **Skip:** the embedding index (a heavy dependency; curated intent tools fit our design better).

### Meraki: WYRE-AI/meraki-mcp

- **Tools:** curated `meraki_<domain>_<verb>` (organizations, networks, devices, clients, wireless, switch, appliance) plus `meraki_navigate`, `meraki_status` and a `meraki_raw_request` escape hatch.
- **Safety:** `READ_ONLY_MODE` is on by default. Write tools are **listed but rejected** in the handler; our map strips them from the schema, which is stronger. High-blast-radius tools also need `confirm_destructive_action: true`, and confirmation never bypasses read-only. The README spells out that `appliance_firewall_l3_update` **replaces the whole rule set** and that an SSID PSK change drops every client. `meraki_raw_request` is classified by HTTP method. HTTP mode refuses to start without an HMAC service secret, refuses known placeholder secrets, and binds `127.0.0.1` unless a secret is set. Credentials are carried per request through `AsyncLocalStorage` and never cached globally (`src/utils/client.ts`).
- **Borrow:** loopback-by-default and refuse-to-start-insecure for streamable HTTP; per-request credential scoping if multi-org is ever supported; the replace-semantics warnings for any future Meraki writes. **Skip:** list-but-reject gating.

### MCP-Telecom

- **Tools:** 58 (`src/mcp_telecom/server.py`): one per show intent (`show_bgp_summary`, `show_interfaces`, ...), `run_command`, `run_vendor_operation`, NETCONF, gNMI telemetry, SNMP, topology, compliance, containerlab, and even `start_dashboard`.
- **Safety:** `safety.py` requires a prefix (`show display monitor ping traceroute tracepath`) and rejects a regex denylist (`configure`, `set`, `delete`, `commit`, `reload`, `clear`, `debug`, ...). It does **not** check `|`, newlines or redirects. Every call goes to a JSONL audit log (device, command, tool, success, output length).
- **Output:** raw text, no cap. `snmp_get` takes `community` as a **tool argument, default `public`**.
- **Borrow:** the `VENDOR_COMMANDS` table shape (intent → per-platform command, `vendors/mappings.py`) for `network_show` intents. **Skip:** tool sprawl, credentials as tool arguments, and prefix-plus-denylist without pipe or newline checks.

### netboxlabs/netbox-mcp-server

- **Tools:** `netbox_get_objects`, `netbox_get_object_by_id`, `netbox_get_changelogs`, `netbox_search_objects`. Read-only.
- **Output control:** `fields` projection (passed as NetBox `?fields=`), `brief`, `limit` default **5**, max 100, `offset`, `ordering`. Tool descriptions push the model hard to request only the fields it needs. `validate_filters` rejects filters NetBox would **silently ignore** (`__in`, multi-hop `a__b__c`).
- **Borrow:** small default page and field projection for `network_inventory`. Lesson for our inventory gate: NetBox silently ignores unknown filters, so the **opt-in tag and management-prefix check must be done on the returned objects in Go, not trusted to a query filter**.

### ktbyers/netmiko_mcp

- **Tools:** `list_groups`, `list_devices`, `send_show_command(device, command, use_textfsm, save_output)`, `send_show_command_to_group`, `list_device_outputs`, `read_device_output(offset, limit)`, `ping`.
- **Safety** (`security.py`, `docs/commands.md`): **default deny** (empty allowlist = nothing allowed). The order is (1) collapse whitespace, including `\n` and `\t`, to single spaces; (2) **character allowlist** `a-zA-Z0-9 ./:_-,"` that rejects Unicode look-alikes and `; & ' \` $ ! \\`; (3) deny list, which wins; (4) allow list with exact match or glob (`"show ip *"` needs a further word, `"show ip*"` does not), anchored and case-insensitive; (5) pipes off by default; when on, at most one pipe and the modifier must be in `pipe_modifiers` (`include exclude section begin count`). Abbreviations are **not** expanded (`sh ver` ≠ `show version`). The audit log **fails closed**: if the file or syslog write fails, the tool call fails. It logs every attempt with verdict, reason and correlation id, and can optionally keep channel transcripts. HTTP auth is on by default; HTTP is stateless by default. The README says the MCP gate is best-effort and recommends a read-only AAA account as the real control.
- **Output:** optional TextFSM parsing. Output over 1000 lines is saved to disk and paged with `read_device_output`.
- **Borrow:** almost all of the gate (see the borrow list). **Skip:** writing outputs to disk (our server keeps no device data at rest).

### anderson-jason573/cisco-iosxe-mcp

- **Tools:** 19 in all. Reads are built from fixed templates with validated arguments (there is no free-form command tool). They include `get_archive_status`, `get_revert_timer`, `preview_config_change`, and three `write_` tools: `write_apply_config_block`, `write_save_config`, `write_reload_device`. `cancel_reload` is deliberately ungated.
- **Safety** (`server.py`): `preview_config_change` validates the block and reads back the sections it touches, then stores it with a `preview_id` (TTL 1800 s). `write_apply_config_block` takes **only** the id, so it cannot apply text that was not previewed. Validation rejects lines over a maximum length, NUL/CR, `do <cmd>` (an exec escape from config mode), a bare `end` (later lines would run as exec), and nested `configure` (it would escape the revert timer). Apply runs `archive config` → `configure terminal revert timer N` → block → reconnect on a **new** session → `configure confirm` only if that works → `show archive config differences`. It **refuses** when `archive` is not configured. The header documents that it did **not** build a "trial apply to harvest a real diff", because that would make unapproved config live. The MCP endpoint itself has no auth (stated in the README).
- **Borrow:** the whole apply sequence, the config-block validators, preview-id TTL, the "refuse without archive" check, and the save-to-startup decision kept separate from apply.

### SNMP MCPs: acato/snmp-mcp and sdempsay/snmp-mcp

- **acato** (`DESIGN.md`): `snmp_get`, `snmp_walk`, `snmp_bulk_walk(max_repetitions=25)`, `snmp_table`, plus MIB wrappers (`system_info`, `interfaces_list`, `host_resources`, `printer_status`, `device_detect`). Every result uses one envelope, `{ok, host, data, warnings, error:{category, message}}`. `noSuchInstance`/`noSuchObject` become `value: null` plus a warning; `endOfMibView` ends a walk cleanly; a walk stops when the OID leaves the subtree. v3 auth failures are never retried. Credential fields are masked in `repr` and never returned. No SET code path at all. **No row or byte cap** on walks.
- **sdempsay:** `snmp_get`, `snmp_walk`, `icmp_ping`, shelling out to net-snmp `snmpwalk`, with `max_walk_results` defaulting to 1000.
- **Borrow:** the envelope and the per-varbind null-plus-warning handling, the subtree-exit check, no retry on auth failure, and warnings such as "ifSpeed saturated, used ifHighSpeed". **Skip:** credentials from per-host env vars (we use credential refs), and shelling out.

### Generic SSH MCPs: classfang and uarlouski

- Both target Linux hosts over an exec channel (`execute-command`, upload/download, background jobs). classfang matches regex white/blacklists against the full command and, when a whitelist is set, rejects `; & | \` $() > <` and newlines. No host-key verification setting was found in its source. In uarlouski, **an empty `allowedCommands` disables validation** (fail-open).
- **Borrow:** classfang's byte-range `read-file` with a `next offset` header is a model for continuation if 60 KiB truncation proves too blunt (not needed for v1). **Skip:** exec-channel design (many network CLIs need an interactive shell, which is why we use scrapligo), fail-open allowlists, and missing host-key pinning.

### NAPALM (getter set and config handling)

- **Getters** (`napalm/base/base.py`): `get_facts`, `get_interfaces`, `get_interfaces_counters`, `get_interfaces_ip`, `get_lldp_neighbors(_detail)`, `get_arp_table`, `get_mac_address_table`, `get_route_to`, `get_bgp_neighbors(_detail)`, `get_bgp_config`, `get_environment`, `get_ntp_*`, `get_snmp_information`, `get_users`, `get_optics`, `get_vlans`, `get_network_instances`, `get_ipv6_neighbors_table`, `get_config(retrieve, full, sanitized)`, `ping`, `traceroute`, `cli`, `compliance_report`.
- **Config:** `load_merge_candidate` / `load_replace_candidate` → `compare_config` → `commit_config(revert_in)` → `confirm_commit` / `rollback`. IOS (`napalm/ios/ios.py`) checks `show archive` before honouring `revert_in` (1–120 min), refuses when `show archive config rollback timer` shows a pending commit, uses `configure replace ... revert timer` for replace and `configure terminal revert timer` then `copy <file> running-config` for merge, saves to startup on confirm, and only lets the same user confirm. **NX-OS** (`napalm/nxos/nxos.py`) raises `NotImplementedError` for `revert_in`. It uses a checkpoint plus replace, then **copies running to startup on every commit**. NAPALM does not use NX-OS `configure replace ... commit-timeout`, which #5 documents.
- `get_config(sanitized=True)` applies `CISCO_SANITIZE_FILTERS` (`napalm/base/constants.py`).
- **Borrow:** getter names and return shapes as the vocabulary for normalized `network_show` intents (facts, interfaces, interfaces_ip, lldp_neighbors, arp_table, mac_address_table, bgp_neighbors, environment, vlans); the pending-commit and archive pre-checks; the sanitize filters. **Skip:** NX-OS commit without auto-revert, and implicit save to startup.

### Netmiko generic driver

- `netmiko/ssh_dispatcher.py` maps `generic` → `GenericSSH` and `tplink_jetstream` → `TPLinkJetStreamSSH`. The base connection's job is `session_preparation` (find prompt, `disable_paging`, `set_terminal_width`), echo verification (`cmd_verify`), ANSI stripping and per-call `read_timeout`.
- **Borrow:** the session-preparation checklist for our generic driver: find prompt, disable paging, widen the terminal, check the echoed command, strip ANSI, and use per-command read timeouts. Library mechanics themselves come from scrapligo v1.4.x (#4).

### Oxidized model files

- A model (`lib/oxidized/model/ios.rb`, `nxos.rb`, `tplink.rb`, ...) declares a `prompt` regex, `expect` pager handlers, `post_login` commands (`terminal length 0`, `terminal width 0`), `cmd :all` cleanup, `cmd :secret` redaction (active when `remove_secret` is on), and `cmd :significant_changes`, which drops volatile lines such as `! Last configuration change at`.
- **TP-Link** (`tplink.rb`) is a good example of a quirky generic-SSH target: it needs `\r\n` newlines, has a `Press any key to continue (Q to quit)` pager, and needs an extra `\r` when a line does not end in a prompt character.
- **Borrow** (Apache-2.0, keep attribution): prompt regexes and pager patterns as **seed data** for generic-SSH platform profiles; the IOS/NX-OS `:secret` regex sets for config redaction; the volatile-line filters for **running-config hashing**, so the "config changed since plan" check does not trip on timestamps.

## Borrow / skip list against the map's decisions

| # | Borrow | From | Map decision it serves |
|---|---|---|---|
| B1 | Character allowlist checked **before** command matching (rejects Unicode look-alikes and shell metacharacters) | netmiko_mcp `security.py` | Generic SSH allowlist |
| B2 | Anchored, case-insensitive exact/glob matching; deny beats allow; empty allowlist = deny all | netmiko_mcp | Generic SSH allowlist |
| B3 | Pipes off by default; if on, one pipe and a modifier allowlist (`include exclude section begin count`). Simpler still: allow no device-side pipes on generic SSH and rely on our server-side filters | netmiko_mcp | Generic SSH "redirect/tee/append" rule. A modifier allowlist beats a denylist of bad pipes |
| B4 | **Abbreviation-aware** token-prefix matching for denylists | Junos `_matches_blocklist_tokens` | Management-plane denylist (IOS accepts `userna`, `cryp`, `line v`) |
| B5 | Config-block validators: reject `do`, bare `end`, nested `configure`, NUL/CR, overlong lines | cisco-iosxe-mcp | "No free-form config mode", plan → apply |
| B6 | Apply takes only a plan id; plans expire (TTL) | cisco-iosxe-mcp | Plan token |
| B7 | Pre-checks: refuse when `archive` is missing or a revert timer is already pending (`show archive config rollback timer`) | cisco-iosxe-mcp, NAPALM IOS | Platform auto-revert |
| B8 | Confirm only after a **new** SSH session reaches the device | cisco-iosxe-mcp | Platform auto-revert, explicit confirm |
| B9 | Config lock → diff → empty-diff short-circuit; drop the session if unlock fails | Junos | Apply path |
| B10 | Secret redaction on config reads by default | Oxidized `:secret`, NAPALM `CISCO_SANITIZE_FILTERS` | Output / untrusted text (**new**: not in the map yet) |
| B11 | Volatile-line filters before hashing running-config | Oxidized `significant_changes`, IOS `post` | Running-config hash check |
| B12 | Fail-closed audit; also log **denied** attempts with reason and a correlation id | netmiko_mcp `audit.py` | Audit log |
| B13 | Streamable HTTP: refuse to start without auth; loopback unless configured; refuse placeholder secrets | Junos, WYRE, netmiko_mcp | Streamable HTTP |
| B14 | Small default pages, field projection; check inventory policy on the returned objects, not via filters | netbox-mcp-server | `network_inventory`, opt-in tag / prefix gate |
| B15 | Intent → per-platform command table; NAPALM getter names as the intent vocabulary | MCP-Telecom `mappings.py`, NAPALM | `network_show` intent tools |
| B16 | Parsed-or-raw result with a `parsed` flag; ANSI stripping | pyATS_MCP, Netmiko | Output |
| B17 | SNMP result envelope, per-varbind null plus warning, subtree-exit check, no retry on v3 auth failure | acato/snmp-mcp | `network_snmp` |
| B18 | Meraki: one page by default with an "incomplete" note, path-traversal check, `readOnlyHint` | Meraki official | Meraki resource tools |
| B19 | Session prep: find prompt, disable paging, widen terminal, verify echo; TP-Link `\r\n` and pager quirks | Netmiko, Oxidized `tplink.rb` | Generic SSH driver |

| # | Skip | Seen in | Why |
|---|---|---|---|
| S1 | Write tools always present, no global flag | pyATS_MCP, Junos, cisco-iosxe-mcp | Map: `--allow-config`, stripped from schema |
| S2 | Writes listed but rejected | WYRE | Weaker than stripping |
| S3 | "Rollback" = re-pasting a running-config snapshot | pyATS_MCP | A merge, not a revert |
| S4 | Commit without confirm / auto-revert | Junos, NAPALM NX-OS | Map requires platform auto-revert |
| S5 | Implicit save to startup on commit | NAPALM IOS and NX-OS | Makes a change outlive a reload without a separate decision |
| S6 | Prefix + regex denylist without pipe or newline checks | MCP-Telecom, pyATS_MCP | Bypassable |
| S7 | Fail-open allowlist (empty = allow all) | uarlouski | Must fail closed |
| S8 | Credentials as tool arguments (SNMP community default `public`) | MCP-Telecom | Map: credential refs only |
| S9 | `sh -c` wrapping, LLM-authored test scripts | pyATS_MCP | Arbitrary execution |
| S10 | Embedding search over an API spec | Meraki official | Heavy; curated intent tools fit better |
| S11 | Tool-per-command sprawl (58 tools) | MCP-Telecom | Map: few intent-based tools |
| S12 | Writing device output to disk | netmiko_mcp | Keeps device data at rest |
| S13 | "Trial apply" to get a device-computed diff | (rejected by cisco-iosxe-mcp itself) | Makes unapproved config live |

## Open points for grilling

- **Save to startup.** Does a confirmed apply also run `copy running-config startup-config`, is that a separate gated step, or is it left to the operator? IOS `configure confirm` does not save (#5). NAPALM saves; cisco-iosxe-mcp gates saving separately.
- **Pipes on generic SSH.** Ban device-side pipes entirely (server-side filters already cover include/section) or allow a modifier allowlist (B3)?
- **Abbreviations.** Normalize abbreviations, or reject anything that is not a full keyword? netmiko_mcp rejects them by never expanding them; the denylist must still catch them (B4).
- **Redaction default.** B10 means `network_config` get redacts secrets by default. Decide whether an unredacted read exists at all, and behind which flag.

## Method

- Repos found with `gh search repos` ("pyats mcp", "junos mcp", "meraki mcp", "mcp-telecom", "netbox mcp", "snmp mcp", "ssh mcp server", "netmiko mcp", "napalm mcp", "nornir mcp", "cisco ios mcp", "nxos mcp"), then source tarballs of each default branch read locally on 2026-10-26.
- scrapligo v1.4.3 files were read through the GitHub contents API at tag `v1.4.3` (`transport/standard.go`, `transport/transport.go`: strict host-key checking is the default and fails without a known_hosts file). Library choice itself: see #4.
- Not done: running any of these servers against a device. Behaviour claims come from reading code and READMEs.
