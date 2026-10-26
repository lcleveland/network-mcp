# Aruba AP management planes, and how network-mcp would read each

Research for [#7](https://github.com/lcleveland/network-mcp/issues/7) (map [#1](https://github.com/lcleveland/network-mcp/issues/1)).
Generic research: no environment data.

## Answer in brief

An HPE Aruba AP is in exactly one of three management planes, set by the firmware family it runs:

1. **Instant AOS-8 (IAP)**: a cluster of APs, one of them the *virtual controller* (VC). It is locally managed (SSH CLI, a local REST API, SNMP) and may also be monitored or configured by Central.
2. **AOS-8 controller-managed (campus AP)**: the AP is a thin client of a Mobility Controller / Mobility Conductor. You read the **controller**, not the AP: SSH CLI, the AOS-8 REST API, SNMP.
3. **AOS-10**: cloud-managed only, by HPE Aruba Networking Central (Classic Central or the new GreenLake-based Central). It has no controller and no supported local management plane. You read it through the **Central REST API (OAuth2)**.

Planes 1 and 2 are covered by the generic SSH and SNMP tools that are already decided. Plane 3 is not: it needs a new HTTPS/OAuth2 cloud driver shaped like the Meraki one, or Aruba stays out of scope.

## Plane by plane

### 1. Instant AOS-8 (virtual controller cluster)

| Aspect | Finding |
|---|---|
| SSH CLI | The VC (cluster conductor) has an IOS-like CLI with `show` commands (`show aps`, `show clients`, `show ap bss-table`, ...). Privileged mode offers show/clear/ping/traceroute/commit. [Instant 8.x CLI Reference Guide][iap-cli] |
| REST API | HTTPS on port **4343**. It is **off by default** and turned on with `allow-rest-api` + `commit apply` on the conductor. In cluster mode **only the conductor IAP serves it**. `POST /rest/login` with JSON `{user, passwd}` returns a `sid` that every later call carries. Sessions expire after **15 minutes idle**. Monitoring is `GET /rest/show-cmd?iap_ip_addr=<ap>&cmd=<show ...>&sid=<sid>`, which wraps CLI show output. [Instant 8.12 REST API Guide][iap-rest] |
| REST caveat | A community report says a read-only management user got "Invalid opcode for current user" on `show-cmd`, and only a full-privilege user worked. **Unverified against the guide**, but if true it conflicts with the read-only credential decision. [Airheads thread][iap-rest-ro] |
| SNMP | SNMP v1/v2c/v3 agent on the VC, configured in the Instant UI or CLI. Instant-specific objects are in **AI-AP-MIB** (enterprise 14823, `1.3.6.1.4.1.14823.2.3.3.1`), e.g. `aiAccessPointTable`, `aiClientTable`. [Central SNMP-for-IAP settings][central-iap-snmp], [AI-AP-MIB listing][ai-ap-mib] |
| Central overlay | An IAP cluster can be managed by Classic Central. Since 8.4, `disable-local-management-when-remotely-managed` turns off WebUI/SSH/Telnet on Central-managed IAPs. If a site sets it, the local planes disappear and only Central is left. [Community article][iap-disable-local] |
| Generic tools enough? | **Yes.** SSH to the VC with the `show` allowlist, plus `network_snmp` with AI-AP-MIB. The local REST API adds nothing that `show` over SSH does not already give, and it needs a write-side config toggle (`allow-rest-api`). |

### 2. AOS-8 controller-managed (campus APs)

| Aspect | Finding |
|---|---|
| Where data lives | The AP has no supported management plane of its own. State is read from the Mobility Controller (MD) or Mobility Conductor (MCR): `show ap database`, `show ap active`, `show user-table`, etc. |
| SSH CLI | Controller CLI over SSH, IOS-like, `show` commands. [AOS-8 REST/CLI overview][aos8-rest] |
| REST API | Served by the Mobility Conductor, managed devices and standalone controllers on HTTPS **4343**. `GET /v1/api/login` (admin username/password) returns a **`UIDARUBA`** token, which is sent as a query parameter (and as the `SESSION` cookie) on every call. Monitoring: `GET /v1/configuration/showcommand?command=<show ...>&UIDARUBA=<tok>`, which returns **structured JSON** for most commands. Config: GET/POST on `/v1/configuration/object/...` + `write_memory`. [AOS-8 REST APIs][aos8-rest], [showcommand API][aos8-show], [login][aos8-login] |
| SNMP | Controller SNMP agent. AP state is in **WLSX-WLAN-MIB** (`wlsxWlanAccessPointInfoGroup`, e.g. the AP table under `1.3.6.1.4.1.14823.2.2.1.5.2.1.4`), with enums in ARUBA-TC. [WLSX-WLAN-MIB tables][wlsx-mib] |
| Generic tools enough? | **Yes**, for reads: SSH to the controller with the `show` allowlist, plus SNMP. The showcommand REST endpoint is the one real gain (JSON instead of screen-scraped text). It would be an optional per-platform transport later, like NX-API. |

### 3. AOS-10 (cloud-managed by Central)

| Aspect | Finding |
|---|---|
| Model | AOS-10 APs and gateways are managed and controlled from the cloud. APs no longer rely on controllers, and Mobility Conductor does not exist in AOS-10. AOS-10 hardware requires Central for management and monitoring. [AOS-10 architecture overview][aos10-arch], [AOS 8→10 migration planning][aos10-migrate] |
| Local CLI | An AP CLI exists for troubleshooting (`show ap bss-table`, `show ap association`, ...). The AOS-10 CLI guide says APs connected to Central must take **configuration only from Central**. [AOS-10 CLI Reference][aos10-cli], [AOS-10 troubleshooting][aos10-trbl] HPE community staff state there is "no on-device management with AOS-10". Direct SSH to an AOS-10 AP is **not a supported management plane**, so do not plan on it. |
| SNMP | **Unclear, and should be treated as unavailable.** Central's AOS-10 *System* settings page lists an SNMP section, and LogicMonitor polls AI-AP-MIB OIDs. A 2024 community thread reports that SNMP was configurable only for *Microbranch* AOS-10 APs, not standard ones, and HPE responders pointed users to the API. HPE techdocs could not be fetched to settle this (they return 403 to automated fetches). [AOS-10 AP system settings][aos10-systems], [community thread][aos10-snmp] |
| Classic Central API | HTTPS to a **regional API gateway** (e.g. `apigw-prod2.central.arubanetworks.com`). OAuth2: access token **2 h** (`expires_in: 7200`), renewed with a refresh token, which also returns a new refresh token. Scopes `read` or `all`. New tokens through the login/authcode flow are limited to **one per client ID per 30 min**, so refresh tokens are effectively mandatory and need to be persisted. Limits: **7 calls/s** and **5,000 calls/day** base (more per licensed device). AP monitoring: `GET /monitoring/v2/aps`, `/monitoring/v1/aps/{serial}`. [OAuth access token][central-oauth], [token management][central-token], [usage and rate limits][central-rate], [API spec mirror][central-aps] |
| New Central API (GreenLake) | OAuth2 **client credentials** against the GreenLake token endpoint `https://sso.common.cloud.hpe.com/as/token.oauth2` (client ID + secret, the workspace ID for GreenLake-scoped clients). The token lives about 2 h, and there is no refresh-token dance: you simply mint a new one. Base URL per cluster (e.g. `https://us5.api.central.arubanetworks.com`). Read paths: `network-monitoring/v1/aps`, `.../aps/{serial}` and trend sub-paths, plus `network-monitoring/v1/device-inventory`. Remote show commands are **async**: `POST network-troubleshooting/v1alpha1/aps/{serial}/showCommand` (400 unless the command starts with `show `), then poll `.../aps/showCommands/async-operations/{id}` for raw text. Some paths are still `v1alpha*`, and a community report says `v1alpha1/aps` is deprecated for `v1alpha2`/`v1`. [New Central authentication][nc-auth], [generating access tokens][nc-token], [token exchange][nc-token-exch], [run AP show command][nc-show], [get show result][nc-show-res], [PyCentral monitoring module][pycentral-mon] |
| Generic tools enough? | **No.** Neither SSH nor SNMP is a supported read path. Reading AOS-10 needs an HTTPS/OAuth2 cloud driver. Its shape matches the Meraki driver (one API, rate-limited, org/workspace-scoped key), but it has a token lifecycle that Meraki's static key does not. |

## Which platforms the Wi-Fi 6E (AP-6xx) and Wi-Fi 7 (AP-7xx) APs run

| Family | Instant AOS-8 | AOS-8 controller | AOS-10 |
|---|---|---|---|
| AP-6xx (Wi-Fi 6E) | Yes. Minimums vary by model: AP-635 from 8.9.0.0, AP-655 from 8.10.0.0, AP-615 from 8.11.0.0 | Yes (6 GHz support arrived in AOS-8 8.9) | Yes (AOS-10.7 notes list AP-635/655 among the 600-series 6 GHz MBSSID platforms) |
| AP-7xx (Wi-Fi 7) | **No** | **No** | **AOS-10 only** (AP-750 series from 10.7) |

Sources: [Central supported Instant APs][central-supp-aps], [Instant 8.11.1.0 release notes][iap-rn], [AOS-10.7 what's new][aos107], [AP-7xx AOS-10-only (HPE staff reply)][ap7xx].

So an AP-6xx fleet can be on **any** of the three planes. The model alone does not decide the plane: the human facts must name the firmware family. An AP-7xx fleet is **always** AOS-10.

## Decision table (apply once the human facts name the plane)

| Human fact: APs run... | Read path for network-mcp | New driver needed? | Writes | Credential / policy notes |
|---|---|---|---|---|
| Instant AOS-8, local management on | Generic SSH to the VC (`show` allowlist) + `network_snmp` with AI-AP-MIB | No | None (read-only, generic SSH) | NetBox needs the **VC/conductor** as the device (the VC address can float between APs). Leave `allow-rest-api` off. |
| Instant AOS-8, Central-managed with local management disabled | Same as AOS-10 (Classic Central API) | Yes (Central driver) | None | `disable-local-management-when-remotely-managed` removes SSH. SNMP may still answer, so check. |
| AOS-8 controller-managed | Generic SSH to the **controller** + `network_snmp` with WLSX-WLAN-MIB | No (optional later: AOS-8 `showcommand` REST for JSON, like NX-API) | None in v1 | AP data comes from the controller, so NetBox should tag the controller, not each AP. |
| AOS-10, Classic Central | Central REST driver (regional gateway, OAuth2 auth-code + **refresh-token persistence**) | Yes | None | The refresh token rotates on every refresh, so the server needs **writable state** for it. That clashes with read-only `LoadCredential` files. Use the `read` scope. Budget is 7/s and ~5k/day. |
| AOS-10, new Central (GreenLake) | Central REST driver (client-credentials token from GreenLake; `network-monitoring/v1`; async show via `network-troubleshooting`) | Yes | None | Fits the existing credential model (static client ID + secret through `LoadCredential`, token minted in memory). Several endpoints are still `v1alpha*`. |
| AOS-10, and no cloud API access allowed | **Out**: no supported local read plane | — | — | SNMP on AOS-10 is unconfirmed. Do not promise it. |

## Recommendation for the map

- If the fleet is **Instant or controller-managed AOS-8**, Aruba needs **no new code**: it is a generic-SSH + SNMP platform. Add the Aruba `show` commands to the per-platform allowlist and AI-AP-MIB / WLSX-WLAN-MIB to the bundled MIBs.
- If the fleet is **AOS-10** (always the case for AP-7xx), the only supported read path is the Central API. Prefer **new Central with client credentials**: it fits the existing credential decisions, while Classic Central's rotating refresh token does not. It would be a fourth first-class driver, read-only and Meraki-like. Whether that is in v1 is a scope call for grilling.

## Unverified or open

- HPE techdocs (`arubanetworking.hpe.com/techdocs/...`) return 403 to automated fetches. Claims sourced there come from search-indexed excerpts, not full-page reads. Spot-check the Instant REST guide and the AOS-10 SNMP page by hand before relying on them.
- Whether a read-only Instant management user can call `/rest/show-cmd` (community report says no).
- Whether standard (non-Microbranch) AOS-10 APs answer SNMP at all, and with which MIB.
- Classic Central's retirement timeline relative to new Central: no official date was found.
- Instant CLI paging behaviour for the generic SSH driver: not checked, so verify with a recorded transcript.

[iap-cli]: https://support.alcadis.nl/Support_files/Alcatel-Lucent//OmniAccess/OAW%20Instant/Manuals/AOS-W%20Instant%208.9.0.0/AOS-W%20Instant%208.x%20CLI%20Reference%20Guide.pdf
[iap-rest]: https://arubanetworking.hpe.com/techdocs/Aruba-Instant-8.x-Books/812/Aruba-Instant-8.12.0.0-REST-API-Guide.pdf
[iap-rest-ro]: https://airheads.hpe.com/discussion/rest-on-aruba-instant-86
[central-iap-snmp]: https://arubanetworking.hpe.com/techdocs/central/2.5.8/content/nms/access-points/cfg/log-servers/snmp.htm
[ai-ap-mib]: https://mibs.observium.org/mib/AI-AP-MIB/
[iap-disable-local]: https://community.arubanetworks.com/t5/Controller-less-WLANs/How-to-Disable-Local-Management-of-Instant-AP-when-Managed-by/ta-p/483077
[aos8-rest]: https://developer.arubanetworks.com/aos8/docs/rest-apis
[aos8-show]: https://developer.arubanetworks.com/aos8/docs/showcommand-api
[aos8-login]: https://developer.arubanetworks.com/aos8/docs/login
[wlsx-mib]: https://mibs.observium.org/mib/WLSX-WLAN-MIB/tables
[aos10-arch]: https://arubanetworking.hpe.com/techdocs/central/2.5.8/content/aos10x/aos10x-overview/architecture-overview-aos10.htm
[aos10-migrate]: https://arubanetworking.hpe.com/techdocs/VSG/docs/035-campus-migrate/esp-campus-migrate-040-planning-aos8/
[aos10-cli]: https://arubanetworking.hpe.com/techdocs/CLI-Bank/Content/landing-pages/aos10-home.htm
[aos10-trbl]: https://arubanetworking.hpe.com/techdocs/aos/wifi-design-deploy/security/modes/troubleshooting/
[aos10-systems]: https://arubanetworking.hpe.com/techdocs/central/latest/content/aos10x/cfg/aps/systems.htm
[aos10-snmp]: https://airheads.hpe.com/discussion/snmp-for-aos10-aps
[central-oauth]: https://developer.arubanetworks.com/central/docs/api-oauth-access-token
[central-token]: https://developer.arubanetworks.com/central/docs/access-token-management
[central-rate]: https://developer.arubanetworks.com/central/docs/usage-and-rate-limits
[central-aps]: https://apis.io/apis/aruba/aruba-monitoring-api/
[nc-auth]: https://developer.arubanetworks.com/new-central/docs/authentication
[nc-token]: https://developer.arubanetworks.com/new-central/docs/generating-and-managing-access-tokens
[nc-token-exch]: https://developer.arubanetworks.com/new-central/docs/token-exchange
[nc-show]: https://developer.arubanetworks.com/new-central/reference/runapshowcommand
[nc-show-res]: https://developer.arubanetworks.com/new-central/reference/getapshowcommandsresult
[pycentral-mon]: https://pycentral.readthedocs.io/en/v2/modules/new_monitoring/
[central-supp-aps]: https://arubanetworking.hpe.com/techdocs/central/latest/content/nms/access-points/supported-platforms/supported-aps.htm
[iap-rn]: https://arubanetworking.hpe.com/techdocs/Aruba-Instant-8.x-Books/Release-Notes/8111/Aruba-Instant-8.11.1.0-Release-Notes.pdf
[aos107]: https://arubanetworking.hpe.com/techdocs/central/latest/content/whats_new/aos107.htm
[ap7xx]: https://airheads.hpe.com/discussion/supported-versions-for-ap-7xx
