# Outbound attacks: your addresses attacking others (v1.1.0)

Shield also watches traffic **leaving** your network. When one of your own addresses sends attack
traffic to the outside, Shield opens an **outbound incident** naming that address and the outside
targets it is hitting. Typical causes:

- a customer VPS or server is compromised and part of a botnet (SYN, UDP, ICMP floods);
- a server runs an open service that attackers abuse as a reflector/amplifier (open DNS resolver,
  NTP with monlist, memcached, SSDP, CLDAP, ...);
- a machine is scanning the internet.

Providers act on these: they send abuse reports, and some shut ports. Finding the machine first is
the point of this feature.

## What counts as outbound

A flow is **outbound** when its source address is inside a protected prefix and its destination is
outside every protected prefix. Traffic between two of your own addresses is counted as inbound
(to the destination), as before.

## What Shield detects

Per local sender, every second, against the outbound thresholds (Settings, `outbound_*`):

| Vector | Meaning | Default threshold |
|---|---|---|
| `out_syn_flood` | TCP SYN flood sent by the address | `outbound_syn_pps` 10,000 pps |
| `out_udp_flood` | UDP flood sent by the address | `outbound_udp_pps` 30,000 pps |
| `out_icmp_flood` | ICMP flood | `outbound_icmp_pps` 10,000 pps |
| `dns_reflector`, `ntp_reflector`, ... | UDP sent **from** a reflection port (53, 123, 1900, 389, 11211, ...): the server answers spoofed requests and amplifies them at someone else | `outbound_reflect_pps` 5,000 pps |
| `out_scan` | Very many distinct outside targets per second | `outbound_scan_targets` 500 per second |
| `out_volumetric_pps` / `_bps` | Anything above the overall rate limits | `outbound_pps` 50,000 pps, `outbound_bps` 500 Mb/s |

The same rules as for inbound attacks decide *suspected* → *confirmed* → *ended* (3 of 5 seconds
hot, 80% of 20 s and confidence ≥ 70% to confirm, 120 quiet seconds to end). Set a threshold to
`0` to switch that check off; `outbound_detection = false` switches outbound detection off.

Scan detection counts the distinct targets **in the flow data**. With 1-in-1024 sampling, a scan
of thousands of addresses per second shows only a few targets per second, so `out_scan` mostly
fires with light or no sampling. Floods and reflection are detected reliably with sampling.

## What you see

- **Overview**: an orange banner when one of your addresses is attacking, the outbound rate and
  how many of your addresses are sending, and **Busiest senders right now (outbound)**.
- **Active attacks**: a separate section *Outbound: your addresses attacking others*.
- **Attack history**: filter *Outbound (from your addresses)*.
- **The incident page**: "Outbound attack from 163.5.191.77", the traffic it sends, the attack
  type, **Where it is sending to** (target addresses, networks and countries, CSV) and **What to do**.
- **Alerts**: "Outbound attack from …" for confirmed, escalated, unacknowledged and ended.
- **Reports**: *Outbound: attacks sent from your addresses* with the senders and their customers;
  the CSV has a `direction` column.

The attack counts, mitigation policies and reports for attacks **on** you do not include outbound
incidents.

## What Shield does not do

Shield never mitigates an outbound incident: its blackholes and filters protect your addresses from
incoming traffic, and blackholing your own sender would cut its incoming traffic, not stop what it
sends. Mitigation policies skip outbound incidents, and the mitigation API refuses them. The
incident page gives the steps instead: contact the customer or isolate the machine, close the open
service for a reflector, and if needed drop its traffic on the router by hand:

```routeros
/ip/firewall/raw add chain=prerouting src-address=163.5.191.77 action=drop comment="shield-manual: outbound attack"
```

Remove that rule when the machine is clean. (Its comment does not start with `shield:`, so Shield's
own clean-up commands leave it alone.)

## Router: export the outgoing traffic too

Shield can only see outgoing traffic if the router exports flows for it. The read-only setup
exports from the **upstream-facing** interfaces; add the **customer-facing** interfaces (the ones
your servers and VPS hosts are behind) to the same traffic-flow configuration:

```routeros
# Example: sfp-sfpplus10-12 face the upstreams, bridge-vps and sfp-sfpplus1 face your servers.
/ip traffic-flow set interfaces=sfp-sfpplus10,sfp-sfpplus11,sfp-sfpplus12,bridge-vps,sfp-sfpplus1
```

Then check on the Overview that *Outbound* shows a rate and *Busiest senders* lists your addresses.
If *Outbound* stays at "–", no outgoing flows are arriving.

Flows that pass two exported interfaces can be counted twice; the per-sender figures are still
right in shape, but rates may read up to twice as high. Raise the `outbound_*` thresholds if that
causes false alarms. On CCR2116/2216 with L3 hardware offloading, switched traffic bypasses
traffic-flow entirely (see docs/mikrotik.md).

## Storage

ClickHouse (applied by the installer, `003_outbound.sql`):

| Table | Content | Kept |
|---|---|---|
| `out_1s` | per local sender per second (same columns as `dst_1s`; `dst` = the sender) | 30 days |
| `out_targets_10s` | busiest outside targets per sender per 10 s (`dst` = sender, `src` = target) | 90 days |
| `out_asn_10s` | per target network | 90 days |

Postgres: `attack_incidents.direction` (`inbound` / `outbound`); one open incident per address and
direction, so a server can be attacked and attack others at the same time.

## Lab check

```bash
shield-flowgen -scenario out-syn-flood -victim 163.5.191.77 -duration 60s
shield-flowgen -scenario out-dns-reflector -victim 77.107.95.53 -prefix 77.107.95.0/24 -duration 60s
shield-flowgen -scenario out-scan -victim 163.5.191.78 -sampling 1 -duration 60s
```

(`shield-flowgen` only sends flow records to the local collector; it sends no traffic to anyone.)
