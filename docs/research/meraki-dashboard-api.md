# Meraki Dashboard API v1: facts for a read-only client

Research for [#6](https://github.com/lcleveland/network-mcp/issues/6) (map [#1](https://github.com/lcleveland/network-mcp/issues/1)).
Sources read October 2026. OpenAPI facts come from `meraki/openapi` `openapi/spec3.json`, version **v1.75.1**
(1,039 operations: 557 GET, 200 POST, 203 PUT, 79 DELETE; 180 GETs paginated).
No Meraki API was called; everything below is from documentation and the spec.

## Answer in brief

- Base URL `https://api.meraki.com/api/v1`, header `Authorization: Bearer <key>`.
- Budget: **10 req/s per organization** (+10 burst in the first second), **100 req/s per source IP**. A 429 carries `Retry-After`; honour it, never retry faster.
- Pagination: follow the RFC 5988 `Link` header (`first`/`prev`/`next`/`last`). Treat `startingAfter`/`endingBefore` as opaque; the spec says clients "should not" set them.
- An API key is **not** independently scopable: it carries its owner's admin rights in **every** org that admin can reach. Least privilege = a dedicated admin identity with org access `read-only` (or `none` plus `read-only` on specific networks/tags), and no `full` grant anywhere. Read-only admins get 403 on any non-GET.
- The MX read surface is broad and mostly org-wide (uplink statuses, VPN statuses, loss/latency, device statuses), which keeps calls per question low.
- Action batches are write-only, atomic, max 20 sync / 100 async actions, 5 concurrent per org. Not needed in v1.

## 1. Authentication and base URL

| Fact | Source |
|---|---|
| Base URL `https://api.meraki.com/api/v1`. The spec's `servers` entry is `https://api.meraki.com/{basePath}` with `basePath` default `api/v1`. | [Authentication](https://developer.cisco.com/meraki/api-v1/authorization/); spec3.json `servers` |
| v1 uses `Authorization: Bearer <API key>`. The v0 `X-Cisco-Meraki-API-Key` header "does not apply to v1" per the docs, yet spec3.json still lists it as an accepted security scheme. Use Bearer only. | [Authentication](https://developer.cisco.com/meraki/api-v1/authorization/); spec3.json `components.securitySchemes` |
| Clients such as cURL and Postman strip `Authorization` on HTTP redirect, producing 401 "Missing API key"; the docs tell clients to preserve the header on redirect. | [Authentication](https://developer.cisco.com/meraki/api-v1/authorization/) |
| Two access methods: admin-scoped API keys and app-scoped OAuth 2.0 (authorization-code grant, 60-minute tokens, auto-refresh). | [Authentication](https://developer.cisco.com/meraki/api-v1/authorization/) |
| OAuth scopes exist per product family and split config/telemetry and read/write, e.g. `sdwan:config:read`, `sdwan:telemetry:read` ("Secure SD-WAN (MX including MXIGZ)"), `dashboard:general:config:read`. | spec3.json `components.securitySchemes.oauth2` |

**Go implication.** `net/http` forwards `Authorization` on a redirect only when the target host equals or is a subdomain of the original. A redirect from `api.meraki.com` to another `*.meraki.com` host would drop it. Use a `CheckRedirect` that re-adds the header only for HTTPS targets under `meraki.com` and refuses anything else, so the key is never sent off-domain.

## 2. API key scoping and read-only admins

| Fact | Source |
|---|---|
| A key "inherits the same permissions as" the admin account that generated it, and reaches every organization that admin can access. | [Cisco Meraki Dashboard API](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Dashboard_API); [Authentication](https://developer.cisco.com/meraki/api-v1/authorization/) |
| Read-only admins can only send GET; anything else returns 403 Forbidden. | [Cisco Meraki Dashboard API](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Dashboard_API) |
| Up to **two** valid keys per identity at once, across all orgs. Keys **never expire** (unaffected by password expiry); they last until revoked. Shown once at creation. SAML/SSO admins cannot generate keys. | Both pages above |
| Org access values: `full`, `read-only`, `enterprise`, `none`. Network access: `full`, `read-only`, `guest-ambassador`, `monitor-only`, `switchport`, `switch-port-manager`. Tag access: `full`, `read-only`, `guest-ambassador`, `monitor-only`. Newer dashboard UI calls org read-only "Observer"; the API value is still `read-only`. | spec3.json `createOrganizationAdmin` request schema; [Managing Dashboard Administrators and Permissions](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Managing_Dashboard_Access/Managing_Dashboard_Administrators_and_Permissions) |
| Permissions are **additive**: the highest applicable grant wins. Org read-only plus Full on one network = Full on that network, so a key for that admin can write there. Same across tags. | [Managing Dashboard Administrators and Permissions](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/Managing_Dashboard_Access/Managing_Dashboard_Administrators_and_Permissions) |
| Org read-only admins can still run switch port cycles and cable tests in the UI. (Not an MX concern, but "read-only" is not strictly zero-effect.) | Same page |
| `getOrganizations` is exempt from an org's IP allow-list restrictions. | [Cisco Meraki Dashboard API](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Dashboard_API) |

**Implications for the standing "scope keys as narrowly as the Dashboard allows" decision.**
The narrowest available scope is the *admin identity*, not the key. Recommend a dedicated service identity per server with org `read-only` (or `none` + network/tag `read-only` if the server should see only some networks), no `full` grant anywhere, and no membership in unrelated orgs. Because one key spans every org of its owner, the server should also pin the allowed organization ID(s) in config and refuse others. Since keys never expire, rotation is an operator procedure (two-key overlap allows zero-downtime swap). OAuth with `*:read` scopes is the only way to get a capability-limited credential, but it needs a registered app and a refresh flow; out of scope for v1 unless grilling wants it.

## 3. Rate limits and 429

| Fact | Source |
|---|---|
| **10 requests/second per organization**, shared by every application using that org. Burst: 10 extra in the first second, so max 30 in two seconds. | [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |
| **100 requests/second per source IP**, shared by all clients on that IP. | [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |
| Exceeding either returns **429** with a **`Retry-After`** header giving the wait; body is `{"errors": ["API rate limit exceeded for organization"]}`-style. | [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |
| Advice: check every status, wait `Retry-After`, add backoff; prefer org-wide/network-wide endpoints over per-device calls; use `getOrganizationConfigurationChanges` instead of polling slow-changing config. | [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |
| Claim endpoints: 10 requests per 5 minutes per IP (write path, irrelevant to v1). | [Cisco Meraki Dashboard API](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Dashboard_API) |
| Usage is visible under Organization > API & Webhooks > API Analytics; `getOrganizationApiRequests` lists requests. | [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |
| No documented concurrency limit for plain requests. | [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |

**Recommendation.** A per-org token bucket in the client set *below* 10 req/s (the budget is shared with other integrations), honour `Retry-After` on 429 with a capped retry count, and surface "rate limited, retry after N s" to the MCP caller rather than blocking a tool call indefinitely. Cap pages per tool call so one walk cannot drain the shared budget.

## 4. Pagination

| Fact | Source |
|---|---|
| RFC 5988 Web Linking. Params `perPage`, `startingAfter`, `endingBefore`. | [Pagination](https://developer.cisco.com/meraki/api-v1/pagination/) |
| Response `Link` header: comma-separated, up to four links, `rel` = `first`, `prev`, `next`, `last`. Some operations return only three (unidirectional). On the last page, `next` can become `prev`. | [Pagination](https://developer.cisco.com/meraki/api-v1/pagination/); spec3.json 200 `headers.Link` |
| Tokens are "often a timestamp or an ID but ... not limited to those. This parameter should not be defined by client applications." | spec3.json parameter descriptions on `startingAfter`/`endingBefore` |
| No total-count header. | [Pagination](https://developer.cisco.com/meraki/api-v1/pagination/) |
| `perPage` range and default vary per operation, e.g. `getNetworkEvents` 3-1000 (default **10**), `getNetworkClients` 3-5000 (default **10**), `getOrganizationDevices` 3-5000, `getOrganizationApplianceUplinkStatuses` 3-1000 (default 1000), `getOrganizationApplianceVpnStatuses` 3-300 (default 300), `getOrganizationConfigurationChanges` 3-100000. | spec3.json |
| Array query params use bracket form: `networkIds[]=A&networkIds[]=B`. | spec3.json (`getOrganizationApplianceVpnStatuses` example) |

**Recommendation.** One generic pager: set `perPage` to the operation's max (from a small per-resource table), follow `rel="next"` from `Link` until absent or the page/byte cap hits, and reject any `next` URL whose host is not the API host. Low defaults (10) mean a client that forgets `perPage` burns budget fast.

## 5. Errors

| Code | Meaning (per [Errors](https://developer.cisco.com/meraki/api-v1/errors/)) |
|---|---|
| 400 | Bad request, often a missing required parameter (e.g. `productType` on events in multi-product networks) |
| 401 | Incorrect API key |
| 403 | No permission (e.g. read-only admin attempting non-GET) |
| 404 | Resource not found |
| 429 | Rate limited; back off |
| 500/502/503/504 | Server side; occasional ones are expected, likely never reached the dashboard |

Body: `{"errors": ["..."]}`.
Conflict: the [Cisco Meraki Dashboard API](https://documentation.meraki.com/Platform_Management/Dashboard_Administration/Operate_and_Maintain/How-Tos/Cisco_Meraki_Dashboard_API) article says a missing or incorrect key yields **404** (to hide resource existence); the developer hub says **401**. The client should treat both 401 and a 404 on `getOrganizations`/`getOrganization` as a likely credential problem in `network_status`.

## 6. MX-relevant read endpoints

All are GET; "max perPage" blank means not paginated. From spec3.json v1.75.1.

### Inventory and health (org-wide, cheapest)

| operationId | Path | Max perPage |
|---|---|---|
| getOrganizations | `/organizations` | 9000 |
| getOrganizationNetworks | `/organizations/{organizationId}/networks` | 100000 |
| getOrganizationDevices | `/organizations/{organizationId}/devices` | 5000 |
| getOrganizationDevicesStatuses | `/organizations/{organizationId}/devices/statuses` | 1000 |
| getOrganizationDevicesAvailabilities | `/organizations/{organizationId}/devices/availabilities` | 1000 |
| getOrganizationDevicesAvailabilitiesChangeHistory | `/organizations/{organizationId}/devices/availabilities/changeHistory` | 1000 |
| getOrganizationConfigurationChanges | `/organizations/{organizationId}/configurationChanges` | 100000 |

### Uplinks

| operationId | Path | Max perPage |
|---|---|---|
| getOrganizationApplianceUplinkStatuses | `/organizations/{organizationId}/appliance/uplink/statuses` | 1000 |
| getOrganizationApplianceUplinksStatusesOverview | `/organizations/{organizationId}/appliance/uplinks/statuses/overview` | |
| getOrganizationDevicesUplinksLossAndLatency | `/organizations/{organizationId}/devices/uplinksLossAndLatency` (window ≤ 5 min, ends ≥ 2 min ago, lookback 60 days) | |
| getOrganizationApplianceUplinksUsageByNetwork | `/organizations/{organizationId}/appliance/uplinks/usage/byNetwork` | |
| getNetworkApplianceUplinksUsageHistory | `/networks/{networkId}/appliance/uplinks/usageHistory` | |
| getDeviceApplianceUplinksSettings | `/devices/{serial}/appliance/uplinks/settings` | |
| getNetworkApplianceTrafficShapingUplinkSelection | `/networks/{networkId}/appliance/trafficShaping/uplinkSelection` | |
| getNetworkApplianceWarmSpare | `/networks/{networkId}/appliance/warmSpare` | |

### VPN

| operationId | Path | Max perPage |
|---|---|---|
| getOrganizationApplianceVpnStatuses | `/organizations/{organizationId}/appliance/vpn/statuses` | 300 |
| getOrganizationApplianceVpnStats | `/organizations/{organizationId}/appliance/vpn/stats` | 300 |
| getNetworkApplianceVpnSiteToSiteVpn | `/networks/{networkId}/appliance/vpn/siteToSiteVpn` | |
| getOrganizationApplianceVpnThirdPartyVPNPeers | `/organizations/{organizationId}/appliance/vpn/thirdPartyVPNPeers` | |
| getOrganizationApplianceVpnVpnFirewallRules | `/organizations/{organizationId}/appliance/vpn/vpnFirewallRules` | |
| getNetworkApplianceVpnBgp | `/networks/{networkId}/appliance/vpn/bgp` | |

### Firewall and NAT (per network)

`getNetworkApplianceFirewall{L3FirewallRules, L7FirewallRules, InboundFirewallRules, CellularFirewallRules, InboundCellularFirewallRules, OneToOneNatRules, OneToManyNatRules, PortForwardingRules, FirewalledServices, Settings}` under `/networks/{networkId}/appliance/firewall/...`. None paginated.

### Addressing and routing (per network)

`getNetworkApplianceVlans`, `getNetworkApplianceVlansSettings`, `getNetworkApplianceSingleLan`, `getNetworkApplianceStaticRoutes`, `getNetworkAppliancePorts`, `getDeviceApplianceDhcpSubnets`, `getNetworkApplianceSettings`. Org-wide: `getOrganizationApplianceDevicesInterfacesL3` (paged, 1000).

### Clients

| operationId | Path | Notes |
|---|---|---|
| getNetworkClients | `/networks/{networkId}/clients` | paged ≤ 5000, default 10; `timespan` ≤ 31 days (default 1 day); filters ip/mac/vlan/statuses |
| getNetworkClient | `/networks/{networkId}/clients/{clientId}` | |
| getDeviceClients | `/devices/{serial}/clients` | |
| getOrganizationClientsSearch | `/organizations/{organizationId}/clients/search` | by MAC; paged ≤ 5 |

### Events and security

| operationId | Path | Notes |
|---|---|---|
| getNetworkEvents | `/networks/{networkId}/events` | paged ≤ 1000, default 10; **`productType=appliance` required** for multi-product networks; filters include `includedEventTypes`, `deviceSerial`, `clientMac` |
| getNetworkEventsEventTypes | `/networks/{networkId}/events/eventTypes` | |
| getNetworkApplianceSecurityEvents | `/networks/{networkId}/appliance/security/events` | paged ≤ 1000 |
| getOrganizationApplianceSecurityEvents | `/organizations/{organizationId}/appliance/security/events` | paged ≤ 1000 |

Avoid in a read-only tool: endpoints under `/devices/{serial}/liveTools/...` create jobs via POST (ping, cable test, etc.) and are actions, not reads; `getOrganizationAdmins` and `/apiRequests` expose identity data that the management-plane denylist covers.

## 7. Action batches (write question only)

| Fact | Source |
|---|---|
| `POST /organizations/{organizationId}/actionBatches` with `confirmed`, `synchronous`, `actions`, `callback`. | [Action Batches](https://developer.cisco.com/meraki/api-v1/action-batches-overview/); spec3.json |
| All-or-nothing: "either all changes apply or none do"; actions run in order; mixed resource types allowed. | [Action Batches](https://developer.cisco.com/meraki/api-v1/action-batches-overview/) |
| Synchronous ≤ 20 actions; asynchronous ≤ 100 actions (poll for completion). At most 5 batches running concurrently. | Same |
| `confirmed: false` stores a batch that can be inspected, updated or deleted; unconfirmed batches auto-delete after one week. Confirmed batches cannot be deleted. | Same |
| One batch counts as one request against the rate limit. | Same; [Rate Limit](https://developer.cisco.com/meraki/api-v1/rate-limit/) |

Relevance: atomicity covers a *batch*, not *undo*. There is no rollback after success, so a future Meraki write path would still need its own captured "before" state to reverse a change. An unconfirmed batch is a natural plan/preview artefact for a plan → apply flow. Leave this to the "Meraki writes" open question.

## 8. Recommended resource table for the Meraki tools

One intent-based tool (e.g. `network_meraki`) with a `resource` enum, or a few resource tools; grilling decides the tool shape. Each row maps to a fixed operation so no free-form path ever reaches the API.

| resource | Scope arg | Operation(s) | Paged | Notes |
|---|---|---|---|---|
| `organizations` | none | getOrganizations | yes | Filter to configured allowed org IDs |
| `networks` | org | getOrganizationNetworks | yes | Filter by `productTypes` contains `appliance` |
| `devices` | org (+ `networkIds[]`, `productTypes[]=appliance`) | getOrganizationDevices | yes | Inventory/serials |
| `device_statuses` | org | getOrganizationDevicesStatuses | yes | Online/offline/alerting |
| `uplinks` | org (+ networkIds/serials) | getOrganizationApplianceUplinkStatuses | yes | WAN state, IPs, gateways |
| `uplink_loss_latency` | org (+ uplink, timespan ≤ 300 s) | getOrganizationDevicesUplinksLossAndLatency | no | Can be large; cap output |
| `uplink_usage` | network | getNetworkApplianceUplinksUsageHistory | no | |
| `vpn_status` | org (+ networkIds) | getOrganizationApplianceVpnStatuses | yes | Auto VPN + third-party peer reachability |
| `vpn_config` | network | getNetworkApplianceVpnSiteToSiteVpn | no | Hub/spoke, subnets |
| `vpn_third_party_peers` | org | getOrganizationApplianceVpnThirdPartyVPNPeers | no | **Redact `secret`/PSK fields** |
| `vpn_firewall` | org | getOrganizationApplianceVpnVpnFirewallRules | no | |
| `firewall_l3` / `firewall_l7` / `firewall_inbound` | network | getNetworkApplianceFirewall{L3,L7,Inbound}FirewallRules | no | |
| `nat` | network | OneToOneNat, OneToManyNat, PortForwarding rules | no | |
| `vlans` | network | getNetworkApplianceVlans (fallback getNetworkApplianceSingleLan) | no | 400 when VLANs disabled |
| `static_routes` | network | getNetworkApplianceStaticRoutes | no | |
| `ports` | network | getNetworkAppliancePorts | no | |
| `clients` | network (+ timespan, mac/ip/vlan filter) | getNetworkClients | yes | Set perPage high; cap rows |
| `events` | network (`productType=appliance`, eventTypes, t0/t1) | getNetworkEvents | yes | Paging is time-based |
| `security_events` | org or network (+ timespan) | get{Organization,Network}ApplianceSecurityEvents | yes | |
| `config_changes` | org (+ networkId, timespan) | getOrganizationConfigurationChanges | yes | Drift/audit view; may include admin emails, consider redaction |

Cross-cutting: every row goes through the shared rate limiter and pager, the 60 KiB output cap, and untrusted-text handling. `network_status` should call `getOrganizations` (or `getOrganization` for the configured ID) as its Meraki health probe.

## Open points for grilling

- Whether to pin the organization ID in config (recommended) and fail closed when the key can see other orgs.
- Whether a single `network_meraki` tool with a resource enum beats per-resource tools.
- Redaction list for secrets in config payloads (third-party VPN PSKs, RADIUS secrets if ever read).
- Whether OAuth with `sdwan:*:read` scopes is worth adding later as the only truly capability-scoped credential.
