# Local filtering on MikroTik (Phase 9)

Blackholing drops **all** traffic to an address. For many attacks that is more than needed: an
NTP reflection attack, for instance, is UDP from port 123, and nothing a normal server needs
looks like that. Local filtering drops only the attack traffic on your edge router and leaves
everything else to the address flowing.

## What Shield does on the router

- It adds drop rules to the firewall **raw** table (before connection tracking, the cheapest
  place to drop) in its own chain, `shield-filter`, for example:
  `chain=shield-filter action=drop dst-address=163.5.191.20/32 protocol=udp src-port=123 comment=shield:<action>:0`
- The first time, it adds one jump rule at the top of raw prerouting:
  `chain=prerouting action=jump jump-target=shield-filter comment=shield:jump`
- It removes its rules when the action ends (withdrawn, expired, rolled back) and every 30
  seconds checks the router: missing Shield rules are put back, Shield rules nothing asks for are
  removed, and the routers' drop counters are recorded ("Dropped so far" on the action page).
- It never edits or removes a rule without a `shield:` comment. The RouterOS client enforces
  this itself: it can only add drop rules in `shield-filter` with a specific destination (a /24 or
  smaller) and a protocol, port or fragment match, add the jump, and remove rule ids it has read
  with a `shield:` comment. Anything else is refused before it is sent.

## What gets dropped

From the attack type (or what you choose in the dialog):

| Attack | Rule |
|---|---|
| DNS, NTP, SSDP, CLDAP, memcached, chargen, SNMP, WS-Discovery, CoAP, ARD, portmap, NetBIOS reflection | UDP from that service's port (53, 123, 1900, 389, 11211, 19, 161, 3702, 5683, 3283, 111, 137) |
| Fragment flood | fragmented packets |
| ICMP flood | ICMP |
| UDP flood to one port | UDP to that port (you choose it) |
| SYN / ACK / RST floods, "high rate" only | **not filtered**: the packets look like real connections. Use SYN cookies on the server, or blackholing |

Shield refuses filters that would drop everything to an address (that is a blackhole) or all TCP.

## Limits, stated plainly

- Filtering happens on your router, **after** the traffic crossed your upstream link. If the link
  is full, the router cannot help: the planner warns when the attack is near your upstream
  capacity, and the provider has to drop it (upstream blackholing or scrubbing).
- On CCR2116/CCR2216 with layer-3 hardware offloading, packets routed in the switch chip bypass
  the firewall; the planner warns when Shield's router checks found offloading on.
- Raw drops cost router CPU per packet. The planner shows the router's CPU load.

## Setting it up

1. On the router, run `deploy/mikrotik/shield-filter-user.rsc` (after `shield-readonly.rsc`).
   It creates a separate account in a group with `read,write,api`, allowed only from Shield.
   RouterOS cannot limit an account to the firewall, so keep it separate from the read-only
   account and remove it when you stop filtering.
2. In Shield: Routers & upstreams → your router → Edit → **Filter account**. Then **Test filter
   account** on the router page (it only reads).
3. Protected prefixes → Edit → allow **filtering** for the prefixes it may be used on.
4. Settings → `filter_backend` = `routeros` (until then everything runs in simulation, and no
   router is changed).
5. On an attack: **Filter the attack traffic** → preview the suggested rules → propose → approve.
   Policies can also use "Filter the attack traffic on my routers" as their action.

## Tested

`backend/tests/test_local_filtering.py` (11 tests) runs the workflow against the simulated backend
and against the RouterOS protocol simulator over TLS with a pinned certificate and a separate write
account: the jump goes first, the operator's rules are unchanged, only Shield's drops are added and
removed, reconciliation restores a deleted Shield rule and removes an orphan while leaving a
similar-looking operator rule alone, a refused write fails and rolls back, and every refused
command (other tables, edits, reboots, broad or match-all rules, command injection) is blocked
before sending.

**Not yet verified on a real CCR2004/CCR2116.** Try it on a lab or test address first.
