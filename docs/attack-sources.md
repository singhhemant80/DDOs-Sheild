# Attack history and attack sources

## How long things are kept

| What | Where | Kept |
|---|---|---|
| Incidents (target, type, severity, timeline, evidence, notes) | PostgreSQL | Indefinitely |
| Each incident's source summary (top addresses, networks, countries) | PostgreSQL, saved when the incident closes | Indefinitely |
| Per-second traffic per destination (attack graphs) | ClickHouse `dst_1s` | 30 days |
| One-minute traffic per destination (graphs of older attacks) | ClickHouse `dst_1m` | 180 days |
| Busiest sources and per-network totals, every 10 s | ClickHouse `src_10s`, `asn_10s` | 90 days |

Attack history (menu: Attack history) defaults to the last 30 days; choose up to *All time*.

## Where the traffic came from

Open an attack to see **Where the traffic came from**:

- **Networks (AS)**: the origin AS of the sources, with its name and country, and its share of the
  attack. These totals count every packet to the target, including sources not listed one by one.
- **Countries**: the same, by country.
- **Source addresses**: the busiest sources (20 per 10 seconds, up to 100 shown), with the
  protocol and ports they used. *Download CSV* exports them.

Attack history shows the two largest source networks of every closed attack.

**Read the addresses with care.** Floods such as SYN, ACK or plain UDP floods can carry forged
(spoofed) source addresses; for those the dashboard says so. In reflection attacks (DNS, NTP,
CLDAP, memcached, …) the sources are real, but they are the abused servers, not the attacker.

## How it works

- The flow collector keeps, per protected destination and 10-second window, the traffic of each
  source (up to 2,048 per destination) and totals per origin AS for all of them. It stores them
  for destinations above `sources.min_pps` (default 5,000 packets/s) and for every target of an
  open incident, whatever its rate. Settings are in `/etc/crapplet-shield/collector.json`:

  ```json
  "sources": {"enabled": true, "window_seconds": 10, "top": 20, "min_pps": 5000,
              "max_per_destination": 2048, "max_total": 1000000,
              "asn_db": "/var/lib/crapplet-shield/ip2asn-combined.tsv.gz"}
  ```

- The AS comes from the router's flow export when it sends one (NetFlow/IPFIX element 16).
  MikroTik does not, so Shield uses the public-domain [iptoasn.com](https://iptoasn.com) table,
  downloaded by the installer and refreshed daily (`shield-asn-update.timer`). To refresh by hand:
  `sudo systemctl start shield-asn-update`. The server needs HTTPS access to iptoasn.com; without
  the table, addresses are still listed but networks show as *Unknown*.
- When an incident closes, the detector saves its summary on the incident, so attack history keeps
  it after the 90-day per-source data has expired.
- Sources are counted when their flow record arrives; the per-destination graph spreads long
  flows over their duration, so a source's peak can look a little higher than the graph.
