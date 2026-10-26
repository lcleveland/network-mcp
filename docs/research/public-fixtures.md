# Public fixtures: CLI transcripts, SNMP walks and API examples

Ticket #12, re-scoped: **no real devices.** This note finds public, licensed captures we can build and test against now. Once the MCP runs, the team replaces them with sanitized captures from its own devices.

Sources were read on 2026-10-26 at the commits listed under [Pinned revisions](#pinned-revisions). Sizes are bytes of the file as published. "Cap" means the 60 KiB (61,440 byte) output cap.

## Verdict

- **CLI (IOS-XE, NX-OS, classic IOS):** `ntc-templates` (Apache-2.0) and NAPALM's mocks (Apache-2.0) hold hundreds of real `show` outputs. We may commit them if each file keeps its Apache-2.0 licence and attribution. scrapligo's v1 goldens (MIT) are the only public **full session transcripts** for IOS-XE and NX-OS, with login, prompts and paging set-up. They come from lab devices, so they are small.
- **TP-Link:** no public `show` outputs or transcripts exist in these sources. Prompts and paging come only from netmiko's driver and TP-Link's CLI reference guide. TP-Link stays a gap until we have our own capture.
- **SNMP:** LibreNMS `tests/snmpsim` has the best walks (IOS, IOS-XE, NX-OS, JetStream), but it is **GPL-3.0: do not commit it** into this MIT repo. snmpsim's own data is BSD-2-Clause and fine to commit, but it holds only Linux and Windows walks, with no network devices. For committed SNMP fixtures, write small hand-made `.snmprec` files shaped like the LibreNMS walks.
- **Meraki and Aruba New Central:** their example responses carry **no open licence** (Meraki's spec repo has none; Aruba's spec says "HPE" licensing). Read them for the shape, then write our own JSON. They are also tiny (one item, about 0.3–1.5 KB), so they never exercise paging or the cap.
- **Over the cap, even in public data:** `show interfaces` on a switch with about 45 or more interfaces, and a full IF-MIB walk of a 48-port switch. `show running-config`, `show ip route` and `show lldp neighbors detail` stay small in every public sample. But all the public configs and route tables come from labs, so they say nothing about production sizes.

## Sources and licences

| Source | Licence | Commit with attribution? | What it has for us |
|---|---|---|---|
| [scrapli/scrapligo](https://github.com/scrapli/scrapligo) `maintenance-1.4.x` (v1, pure Go) | MIT | **Yes.** Keep the copyright notice. | `driver/network/test-fixtures/golden/functional-*-cisco_iosxe-*`, `*-cisco_nxos-*`: full session output of `show running-config` from a lab CSR1000v and an n9kv. `assets/platforms/cisco_iosxe.yaml` and `cisco_nxos.yaml` hold the prompt regexes and on-open commands. |
| scrapligo `main` (v2, libscrapli) | MIT | Yes | `cli/fixtures/*`: raw byte recordings. Only an Arista EOS one shows paging (`send-input-simple-requires-pagination`, 4,832 B). It is useful for the recording format, not for our platforms. |
| [networktocode/ntc-templates](https://github.com/networktocode/ntc-templates) `tests/<platform>/<command>/*.raw` | Apache-2.0 (licence text in the `LICENSE` file; GitHub reports it as NOASSERTION) | **Yes.** Keep the file's licence, add a copy of Apache-2.0 and a NOTICE, and mark any changes. | The largest public set of `show` outputs: `cisco_ios` (also used for IOS-XE), `cisco_nxos`. Command output only: no prompts, no `show running-config`. Nothing for TP-Link. |
| [napalm-automation/napalm](https://github.com/napalm-automation/napalm) `test/{ios,nxos_ssh,nxos}/mocked_data/**` | Apache-2.0 | **Yes**, with the same conditions as ntc-templates | Production-scale `show interfaces` (up to 308 KB), `show running-config` and `show lldp neighbors detail`. Output only, no prompts. |
| [ktbyers/netmiko](https://github.com/ktbyers/netmiko) | MIT | Yes, but there is little to take | No recorded outputs. `netmiko/tplink/tplink_jetstream.py` and `tests/etc/{commands,responses}.yml.example` describe TP-Link JetStream prompts and paging. |
| [scrapli/scrapli_community](https://github.com/scrapli/scrapli_community), [scrapli/scrapli_replay](https://github.com/scrapli/scrapli_replay) | MIT | Yes | No TP-Link platform. scrapli_replay is a pattern for record and replay, not a source of data. |
| TP-Link [T2600G CLI Reference Guide](https://static.tp-link.com/1910012273_T2600G_CLI.pdf) (2017) | TP-Link copyright, all rights reserved | **No.** Cite it, do not copy it. | Command modes, prompts and the `clipaging` command. |
| [lextudio/snmpsim](https://github.com/lextudio/snmpsim) `snmpsim/data/**` (fork of etingof/snmpsim) | BSD-2-Clause | **Yes.** Keep the notice. | The `.snmprec` format plus Linux and WinXP full walks (199 KB and 104 KB) and `mib2dev/*` samples. No switches or routers. |
| [librenms/librenms](https://github.com/librenms/librenms) `tests/snmpsim/*.snmprec` | GPL-3.0 (`LICENSE.txt`) | **No.** It is copyleft: the files would stay GPL inside an MIT repo. Use them as a reference only. | Real walks: IOS, IOS-XE (C9200L to C9600 SVL), NX-OS, JetStream, older TP-Link. Many are partial (only the OIDs LibreNMS polls). |
| [gosnmp/gosnmp](https://github.com/gosnmp/gosnmp) | BSD-2-Clause | Yes | Packet-level fixtures only (`testdata/v3_harness`, `netsnmp/testdata`). No walks. |
| [meraki/openapi](https://github.com/meraki/openapi) `openapi/spec3.json` (v1.75.1) | **None.** The repo has no LICENSE and `info.license` is null, so it defaults to all rights reserved. | **No.** Write our own JSON from the schema. | 1,039 operations, 951 of them with an example response |
| Aruba New Central API reference (e.g. [getDevicesV1](https://developer.arubanetworks.com/new-central/reference/getdevicesv1)) | The spec's `info.license` is "HPE" (points to hpe.com software licensing) | **No** | The spec is embedded inline in each page, with no download link. `DeviceListResponseV1` has an example of about 1 KB with one item. |
| [aruba/pycentral](https://github.com/aruba/pycentral) (branch `v2`) | MIT | Yes | Client code. I did not check it for recorded responses. |
| Cisco DevNet always-on sandboxes | Cisco DevNet terms | n/a | **Excluded.** They are live devices, which this re-scoped ticket rules out. |

## Prompts and paging

| Platform | Prompts | Paging and how to turn it off | Source |
|---|---|---|---|
| IOS-XE and classic IOS | exec `^[\w.\-@/:]{1,63}>$`; privileged `…#$`; config `…\(…\)#$`. Escalation prompt `^(?:enable\s){0,1}password:\s?$`. | `--More--`. On open, the driver sends `terminal width 512` and `terminal length 0`. Both are exec commands that last only for the session and are not config. | [scrapligo cisco_iosxe.yaml](https://github.com/scrapli/scrapligo/blob/maintenance-1.4.x/assets/platforms/cisco_iosxe.yaml) |
| NX-OS | exec `^[\w.\-]{1,63}>\s?$`; privileged `…#\s?$` (note the optional trailing space); config `…\(config…\)#\s?$` | `terminal width 511` and `terminal length 0` (session only). The failure strings add `% Invalid command` and `ERROR:`. | [scrapligo cisco_nxos.yaml](https://github.com/scrapli/scrapligo/blob/maintenance-1.4.x/assets/platforms/cisco_nxos.yaml) |
| TP-Link JetStream | `Name>` (User EXEC), `Name#` (Privileged EXEC), `Name(config)#`. Some firmware needs `enable` and then `enable-admin`. Line ending is `\r\n`. Netmiko turns off command echo verification because the terminal width cannot be set. | **`no clipaging`**, valid in Privileged EXEC and any config mode. Netmiko's own test checks for it with `show running-config \| include clipaging`, which suggests it is **saved in running-config, so it is a config change and not a session setting.** Netmiko's base class also sends `terminal length 0`. I found no evidence that JetStream accepts it. | [netmiko tplink_jetstream.py](https://github.com/ktbyers/netmiko/blob/develop/netmiko/tplink/tplink_jetstream.py), [netmiko responses.yml.example](https://github.com/ktbyers/netmiko/blob/develop/tests/etc/responses.yml.example), [T2600G CLI guide §2.8](https://static.tp-link.com/1910012273_T2600G_CLI.pdf) |

Consequences for the generic SSH driver, which is read-only:

- It must not send `no clipaging`. It should answer the pager prompt itself (by sending a space or a key and stripping the pager text) or accept paged output as it comes. The exact TP-Link pager string was **not found** in any public source. It needs one capture from our own device.
- Netmiko warns that TP-Link devices offering **only a DSA host key** do not work with current Paramiko. Check whether Go's `x/crypto/ssh` offers `ssh-dss` as a host-key algorithm by default (not checked here).
- The `{1,63}` hostname limit in the prompt regexes is worth keeping for the prompt detector.

## Output sizes (bytes)

| Output | IOS / IOS-XE | NX-OS | TP-Link | Over the 60 KiB cap? |
|---|---|---|---|---|
| `show running-config` | 1,423–2,233 (NAPALM mocks); 6,959 (scrapligo, lab CSR1000v) | 4,715 (scrapligo, lab n9kv); 14,499 (NAPALM `nxos_ssh`) | none found | **Not in public data.** Every sample is a lab or trimmed config. Production size is unknown until our own capture. |
| `show interfaces` / `show interface` | about **1.3–1.5 KB per interface**. 307,881 B for 207 interfaces (NAPALM `ios/test_get_vlans`); 74,247 B for 56 (ntc `cisco_ios_show_interfaces2.raw`, also NAPALM `alternate2`); median ntc 12 KB | about **0.8 KB per interface**. 244,119 B for 295 interfaces; 137,620 B for 178 (NAPALM `nxos_ssh`); NX-API JSON 409,115 B (NAPALM `nxos`) | none found | **Yes.** IOS passes 60 KiB at about 45 interfaces, so every 48-port IOS or IOS-XE switch exceeds it. NX-OS passes it at about 75 interfaces. |
| `show ip route` | 873–3,260 (ntc). About 60–100 B per route. | 753–6,476 (ntc). About 140 B per route, because entries span several lines. | none found | Not in public data, which comes from small labs. By estimate, a cap breach comes at about 600–1,000 routes (IOS) or about 450 (NX-OS). |
| `show lldp neighbors detail` | 546–9,869 (ntc and NAPALM). About 0.9–1.8 KB per neighbour. | 1,048–3,572. About 0.5 KB per neighbour. | none found | No. At these rates it needs roughly 35 (IOS) to 120 (NX-OS) neighbours. |
| Full IF-MIB walk (ifTable + ifXTable, `.snmprec` lines) | IOS-XE C9300 with 76 ifIndex: 81,844 B; C9400 with 125: 150,164 B; IOS 2960X stack with 146: 163,522 B (partial columns) | N9K-C93180YC-FX3 with 59: 68,072 B; N3K-3064PQ with 54: 62,553 B | JetStream T1600G-28TS with 34: 35,450 B; SG2218P with 20: 22,198 B; SG2008 with 11: 9,988 B | **Yes** for every Cisco switch sampled. TP-Link stays under the cap up to about 28 ports. These are LibreNMS walks, so text output with MIB names (`snmpwalk`) or JSON would be **larger**. |
| ENTITY-MIB walk | C9300 46,964; C9400 169,404; 2960X 108,629 | 80,295–93,302 | not in the samples | Usually yes. Stacks and chassis are far over. |
| LLDP-MIB walk | 1,973 (C3560) | 3,591 | 2,322 | No |
| SNMPv2-MIB `system` | 153–691 | | | No |

I measured the SNMP sizes by splitting the LibreNMS `.snmprec` files by OID prefix: `1.3.6.1.2.1.2` (ifTable), `1.3.6.1.2.1.31` (ifXTable and related), `1.3.6.1.2.1.47` (ENTITY-MIB), `1.0.8802.1.1.2` (LLDP-MIB) and `1.3.6.1.2.1.1` (system). `.snmprec` is `oid|type|value`, one varbind per line. It works out to about 34 varbinds and 1.1 KB per interface for IF-MIB.

Not measured: **IF-MIB walk timing.** Timing needs a live agent. It belongs with the own-device captures in the follow-up.

## Meraki and Aruba response shapes

- Meraki examples (`spec3.json`, v1.75.1) for the read paths we care about are each a **single-element array**: `getOrganizations` 509 B, `getOrganizationDevices` 594 B, `getOrganizationDevicesStatuses` 766 B, `getDeviceLldpCdp` 1,112 B, `getNetworkApplianceVlans` 1,511 B, `getNetworkApplianceFirewallL3FirewallRules` 287 B, `getOrganizationApplianceUplinkStatuses` 511 B. The examples do not show pagination (the `Link` header and `perPage`/`startingAfter`). Fixtures for paging must be built by hand.
- The Meraki examples use **non-documentation addresses** (`1.2.3.4`, `123.123.123.1`, `8.8.8.8`, `192.168.1.0/24`) and MAC `00:11:22:33:44:55`. Copied as they are, they would fail the `TestFixturesAreSanitized` guard that the hermetic-testing research proposes.
- Aruba New Central `getDevicesV1`: the example is about 1 KB, `{items:[…1 device…], count, total, next}`. `limit` is at most 1000 (default 1000), and `next` is a page number that is null on the last page. The docs call it a "cursor", but the schema treats it as a page number.

## Using these as fixtures

- **Commit-safe now:** ntc-templates and NAPALM outputs (Apache-2.0), scrapligo goldens (MIT), snmpsim data (BSD-2-Clause). Put them under `testdata/third_party/<source>/` with the upstream `LICENSE`, the upstream URL and the commit SHA. Apache-2.0 also needs a NOTICE and a note on any changed file.
- **Reference only:** LibreNMS walks (GPL-3.0), the Meraki spec, the Aruba spec and the TP-Link guide. Write our own minimal fixtures in the same shape.
- **Sanitization still applies:** the public fixtures contain RFC 1918 and other non-documentation addresses (for example, 129 distinct non-RFC 5737 IPv4 addresses across the four ntc IOS `show ip route` files and one NAPALM interface mock). Run them through the planned sanitizer or exempt `third_party/` from the guard on purpose.
- For cap tests: NAPALM's 308 KB IOS `show interfaces` and 244 KB NX-OS `show interface` are ready-made over-cap inputs for `network_show`. For `network_snmp`, a hand-made IF-MIB `.snmprec` for 76 interfaces (about 82 KB) does the same.

## Pinned revisions

| Repo | Ref | Commit |
|---|---|---|
| scrapli/scrapligo | maintenance-1.4.x | a61dc51bcadd |
| scrapli/scrapligo | main | 66814b5ec877 |
| networktocode/ntc-templates | master | d4f30da6077d |
| napalm-automation/napalm | develop | 820a06b2069e |
| ktbyers/netmiko | develop | 3e6861cac666 |
| lextudio/snmpsim | master | 16956e4958b7 |
| librenms/librenms | master | 6a0b87082040 |
| gosnmp/gosnmp | master | 9de0d2fa9266 |
| meraki/openapi | master | 23cd4b4ea6d0 |

## Open points

- TP-Link: the exact pager prompt, whether `terminal length 0` works, and real `show` output sizes. Each needs one capture from our own device.
- Production `show running-config` and `show ip route` sizes. No public source has them.
- IF-MIB walk timing (GETBULK, max-repetitions) against a real agent.
- Whether Go's `x/crypto/ssh` still accepts `ssh-dss` host keys for older TP-Link firmware.
