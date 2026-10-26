# Inventory sources for a general-purpose network MCP

Research for [#15](https://github.com/lcleveland/network-mcp/issues/15). Framing from [#2](https://github.com/lcleveland/network-mcp/issues/2): `network-mcp` is general-purpose. NetBox is one source among several, and its data can have gaps (missing primary IPs or platforms).

## Answer

- Define one internal **device record**: name, address, platform, driver, credential refs, SNMP settings, opt-in flag, and provenance. Every source fills it, and no source gets special treatment.
- **v1 sources**: a **static file** (YAML), **NetBox** (read-only REST), and **ad-hoc address** (off by default, read-only drivers only, prefix-guarded).
- **Compose** them in an ordered list and merge **field by field** by device name. A source higher in the list wins any field it sets. Each field records the source it came from, and `network_inventory` shows that. The static file, listed first, then patches NetBox gaps without editing NetBox.
- **Credentials and SNMP** come from **rules**, not from the sources: global default < platform < tag/group < device. This follows Oxidized's and Nornir's inheritance. Sources only ever carry credential *ref names*, never secrets.
- **Platform → driver** is a config mapping table, as in Nautobot's `network_driver_mappings`. Unknown or missing platform → the generic read-only SSH driver, never a first-class or write-capable one.
- **Safety gates run after the merge, at connect time**: opt-in, then the resolved address inside the allowed prefixes. No source can bypass them.
- **Later**: Nautobot, and Ansible inventory via `ansible-inventory --list` JSON. Oxidized/RANCID files are not worth a native source, since they carry no platform → driver data we can trust and little else.

## What each source provides

| Source | Address | Platform/driver | Credentials | SNMP | Gaps / missing data |
|---|---|---|---|---|---|
| NetBox | `primary_ip`, `primary_ip4`, `primary_ip6`, `oob_ip` | `platform` (slug); no driver field | none (out of scope for NetBox) | none native; config context or custom field | missing primary IP or platform is common |
| Nautobot | primary IP (same model) | `platform.network_driver` + `network_driver_mappings` | none | config context / custom field | same as NetBox |
| Nornir SimpleInventory | `hostname` | `platform` | `username`/`password` inherited host > groups > defaults | free-form `data` | `hostname` falls back to name in NetBox plugin |
| Ansible | `ansible_host` | `ansible_network_os` + `ansible_connection` | `ansible_user`, vault | vars | merged by precedence; last source wins |
| Oxidized | `ip` (optional; DNS lookup of `name` if absent) | `model` | node > group-model > group > model > global | n/a | name is the only mandatory field |
| RANCID `router.db` | name only (must resolve) | `device_type` | separate `.cloginrc` | n/a | only `up` rows are collected |
| Existing network MCP servers | static TOML/YAML `hostname` | netmiko `device_type` | `[default]` section or env-var expansion | n/a | none of them read NetBox |

### NetBox

- A device "may designate one primary IPv4 address and/or one primary IPv6 address for management purposes". NetBox prefers IPv6 by default, and `PREFER_IPV4` changes that. A device may also designate an out-of-band IP. ([Device model](https://netboxlabs.com/docs/netbox/en/stable/models/dcim/device/))
  - We should therefore let the operator choose the address order (for example `[oob_ip, primary_ip4, primary_ip6]`), not rely on `primary_ip`.
- The current Platform model lists Parent, Name, Slug, Manufacturer and Configuration Template. It has **no driver field**. ([Platform model](https://netboxlabs.com/docs/netbox/en/stable/models/dcim/platform/))
  - We need our own slug → driver map. Older NetBox had `napalm_driver`, and the nornir_netbox plugin still reads it ([source](https://github.com/wvandeun/nornir_netbox/blob/master/nornir_netbox/plugins/inventory/netbox.py)).
- Config context can be assigned by region, site group, site, location, device type, role, platform, tenant and **tag**. Contexts merge by weight, and local context data "will *always* take precedence". ([Context data](https://netboxlabs.com/docs/netbox/en/stable/features/context-data/))
  - Config context is the natural place for per-device SNMP version or a credential-ref *name*.
- As of NetBox v4.7, config context is pre-rendered and "always returned for devices and virtual machines", and `?exclude=config_context` "is silently ignored" ([same page](https://netboxlabs.com/docs/netbox/en/stable/features/context-data/)). List queries get heavier as a result, so filter server-side (by tag) and cache the result.
- Ansible's `netbox.netbox.nb_inventory` shows the patterns the community uses ([docs](https://docs.ansible.com/ansible/latest/collections/netbox/netbox/nb_inventory_inventory.html)):
  - `device_query_filters`, for example `has_primary_ip: 'true'`, to drop devices without a primary IP.
  - `oob_ip_as_primary_ip` and `ansible_host_dns_name` to pick the address.
  - `config_context` / `flatten_config_context` to expose context data.
  - `query_filters` with `tag:`.
- nornir_netbox `NetBoxInventory2` behaviour ([source](https://github.com/wvandeun/nornir_netbox/blob/master/nornir_netbox/plugins/inventory/netbox.py)):
  - Uses the primary IP (prefix stripped) as `hostname`, and falls back to the device **name** (so DNS) when there is none.
  - Uses the platform **name** unless `use_platform_slug` or `use_platform_napalm_driver` is set.

### Nautobot

- A Platform has `network_driver`, "a generic string that corresponds loosely to a Netmiko driver name". Nautobot uses netutils to derive `network_driver_mappings` per library (Ansible collection, pyATS OS, Scrapli platform, NAPALM). Operators can override the mapping with the `NETWORK_DRIVERS` setting. ([Platform](https://docs.nautobot.com/projects/core/en/stable/user-guide/core-data-model/dcim/platform/))
- This is the model to copy: one canonical driver string per platform, plus a mapping table that config can override.

### Nornir

- Inventory = hosts, groups and defaults. A host has `hostname`, `port`, `username`, `password`, `platform`, `groups`, `data` and `connection_options`.
- Values resolve host → parent groups (recursively) → defaults, and raise `KeyError` if still unset. ([Inventory tutorial](https://nornir.readthedocs.io/en/latest/tutorial/inventory.html))
- Plugins implement `load()` returning an `Inventory` and register through the `nornir.plugins.inventory` entry point or `InventoryPluginRegister.register`.
- **Transform functions** run per host after loading, "independently of which inventory plugin was used". They are the documented hook for filling credentials from the environment or a secret store. ([Plugins](https://nornir.readthedocs.io/en/latest/plugins/index.html))
  - This matches our split: sources describe devices, and a separate rule layer attaches credentials.

### Ansible

- Precedence is all < parent group < child group < host. Same-level groups merge alphabetically, and `ansible_group_priority` can change the order.
- With multiple `-i` sources, they merge "in the order given" and **the last one wins**. Directory sources load alphabetically. ([Inventory guide](https://docs.ansible.com/ansible/latest/inventory_guide/intro_inventory.html))
- `ansible_host` is "the resolvable name or IP of the host to connect to" when it differs from the alias.
- `ansible-inventory --list` emits JSON for any inventory plugin. A future source could read that JSON (not run Ansible) to reuse an existing Ansible inventory.

### Oxidized and RANCID

- Oxidized sources are CSV, JSON file, SQL and HTTP. Each uses a `map:` (with `name` mandatory) and a `vars_map:`. If `ip` is absent, "a DNS lookup will be done against `name`". ([Sources](https://github.com/ytti/oxidized/blob/master/docs/Sources.md))
- Oxidized option precedence, least to most important: global → model → group → model-within-group → node. "More important options overwrite less important ones if they are set." ([Configuration](https://github.com/ytti/oxidized/blob/master/docs/Configuration.md))
- RANCID `router.db` is `name;device_type;state[;comments]`. Only `up` devices are collected, and the name must resolve. ([router.db(5)](https://www.shrubbery.net/rancid/man/router.db.5.html))
- Both tools are config-backup territory, which the map puts out of scope. Their inventory files are thin, so the static file can replace them with a one-time conversion.

### Existing network MCP servers

- [upa/mcp-netmiko-server](https://github.com/upa/mcp-netmiko-server): a TOML file with a `[default]` section (`username`/`password`) that devices inherit, and netmiko `device_type` per device. It stores secrets in plaintext in the inventory.
- [ntunes/netmiko-mcp-server](https://github.com/ntunes/netmiko-mcp-server): a YAML inventory with groups and tags, and `${NETMIKO_PASSWORD}` env-var expansion.
- Neither reads a source of truth or guards addresses. Both offer a list-devices tool filtered by tag or type, and our `network_inventory` should do the same.

## Recommendation

### Device record (internal)

```
name            unique key across sources (case-insensitive)
address         host or IP; port optional
platform        source's own value (slug / model / device_type)
driver          resolved via mapping table; "generic_ssh" if unknown
cred_ref        read credential ref name (write ref chosen by rules only)
snmp            {version: v2c|v3, cred_ref}
tags            for opt-in, credential rules and filtering
opt_in          bool, computed (tag match or present in the static file)
provenance      field -> source name
```

### Source interface (Go)

```go
type Source interface {
    Name() string
    // List returns partial records; empty fields mean "unknown here".
    List(ctx context.Context) ([]Device, error)
}
```

- `List` with a short TTL cache is enough. A per-name `Lookup` is an optimisation we can add later.
- A source that fails returns an error. The merge then marks its fields stale or absent and does **not** fall back silently. `network_status` reports per-source health.

### Composition

1. Order comes from config (for example `sources: [file, netbox]`). The first source that sets a field wins, like Ansible's "last -i wins" but in a readable top-down order.
2. Merge by name field by field, so the file can set only `address` or `platform` for a device NetBox knows.
3. Devices that exist in only one source are kept.
4. Apply the **platform → driver** map:
   - Built-in defaults for the drivers we ship.
   - Overridable in config.
   - Keyed by the source's platform value.
5. Apply **credential/SNMP rules** in the order default < platform < tag < device. This uses Oxidized's order, minus the model-in-group level.
6. **Gates at connect time**:
   - Opt-in is required.
   - The address must resolve inside the allowed prefixes. If it is a name, resolve it first and check every resolved IP.
   - The write ref is loaded only when write flags are on.

### Gaps

| Missing | Behaviour |
|---|---|
| address | Use the next source. If no source has one, DNS-resolve the name only when `resolve_names: true`, and still apply the prefix check. Otherwise the device is listed as unreachable with the reason. |
| platform | `generic_ssh` (read-only) and SNMP only. Never a first-class or write driver. |
| cred_ref | Default rule. If there is no default, the device is unreachable with the reason. |
| SNMP version | Rule default. Otherwise SNMP is disabled for that device. |

### Ad-hoc addresses

- Off unless `allow_adhoc: true`. The address must be inside `adhoc_prefixes`, which is a subset of the allowed prefixes.
- Read-only drivers only (generic SSH, SNMP). Credentials come from a dedicated ad-hoc rule.
- Host-key pinning still applies, so a target missing from `known_hosts` fails.

### v1 set

- static file
- NetBox
- ad-hoc (flagged)

### Deferred

- Nautobot: same shape, and the driver comes free from `network_driver`.
- Ansible JSON
- Oxidized/RANCID import
