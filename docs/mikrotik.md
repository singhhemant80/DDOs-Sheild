# MikroTik integration (Phase 5: read-only)

Shield reads from RouterOS 7 routers over the API (api-ssl, port 8729). In this phase it **cannot
change a router**: the client checks every command before sending it and refuses anything that is
not a `print`, and the account the templates create has no write policy either. Write access arrives
in phase 8, behind approvals and dry runs.

## What Shield reads

| Every | What | Used for |
|---|---|---|
| 10 s | identity, resource (version, uptime, CPU, memory), interface counters | Status, measured interface rates (`source: routeros`) for the live dashboard, topology and saturation alarms |
| 30 s | BGP connections and sessions (`/routing/bgp/connection`, `/routing/bgp/session`) | Session state, `bgp_down` / `bgp_up` events, the BGP page |
| 60 s | addresses, routes **for protected prefixes only**, traffic-flow settings and targets, services, switch L3 offload, Shield's own account and group | Configuration checks |

Shield never prints the full routing table: on an edge router with full tables that is close to a
million routes. Routes are read with queries per protected prefix, plus static blackholes.

Events recorded (Routers page, BGP page, and `{"type":"router_event"}` on the live WebSocket):
`unreachable` (after 3 failed polls, or at once for a login or certificate failure), `recovered`,
`bgp_down`, `bgp_up`, `reboot` (uptime went backwards), `version_change`.

## Setting up a router

1. Edit the variables at the top of [`deploy/mikrotik/shield-readonly.rsc`](../deploy/mikrotik/shield-readonly.rsc):
   Shield's address, the router's management address, the upstream-facing interfaces and a
   password of 16+ characters.
2. Upload it to the router (Files), open a terminal, press **Ctrl+X** for Safe Mode, and run
   `/import file-name=shield-readonly.rsc verbose=yes`. It creates:
   - group `shield-read` with `read,api,test` only, and user `shield-ro` allowed only from Shield's address;
   - a self-signed certificate `shield-api` for api-ssl; api-ssl limited to Shield's address and TLS 1.2+;
     the unencrypted `api` service disabled;
   - IPFIX export from the upstream interfaces to Shield, sampled 1 in 1024, 1-minute active timeout.

   It does not touch firewall rules, routing, BGP, winbox or ssh. Note the fingerprint it prints.
3. In Shield: **Routers & upstreams → Add router**, with the same username and password.
4. Open the router and choose **Test connection**. The first test fails on purpose with *certificate
   not trusted* and shows the fingerprint the router presented, before any password is sent. If it
   matches the one the script printed (`/certificate print detail where name=shield-api`), choose
   **Pin this certificate**. From then on Shield connects only if the router presents exactly that
   certificate.
5. Test again and work through the checks.

Undo with [`shield-remove.rsc`](../deploy/mikrotik/shield-remove.rsc).

### Checks and what to do

| Check | Meaning |
|---|---|
| `perm_write` (problem) | Shield's account can change the router. Use a group with only `read,api,test`. |
| `perm_any_address` | The account may log in from anywhere. Set its allowed address to Shield's. |
| `flow_disabled`, `flow_no_target`, `flow_wrong_target` (problem) | Shield receives no flows from this router. The expected target is the `collector_address` setting. |
| `flow_src` | The export source address is not the management address; the collector accepts listed exporters only. |
| `flow_v5` | NetFlow v5 cannot carry IPv6 or the sampling rate. Use IPFIX. |
| `flow_unsampled`, `flow_sampling_space` | Every packet is exported. During a large attack this can overload the router CPU and the collector. RouterOS samples `sampling-interval` packets then skips `sampling-space`; 1 in 1024 is `interval=1 space=1023`. |
| `flow_timeout` | Active timeout over 1 minute delays detection of long flows. |
| `flow_all_interfaces` | Traffic crossing two exporting interfaces is counted twice. |
| `l3hw` | CCR2116/2216 switch-chip routing bypasses traffic-flow. See below. |
| `api_plain`, `api_open` | The plain API is on, or api-ssl accepts any address. |
| `tls_unverified`, `tls_plain` | Shield is not verifying the router's certificate, or not using TLS. Pin it. |
| `read_*` | A section could not be read (older RouterOS, missing package, or a permission). The rest still works. |

### CCR2116: hardware offloading hides traffic

With L3 hardware offloading, packets routed by the switch chip never reach the CPU, so traffic-flow
does not see them. [`ccr2116-l3hw-check.rsc`](../deploy/mikrotik/ccr2116-l3hw-check.rsc) only prints
where offloading is on and lists the options. Turning it off on the upstream ports moves their
forwarding to the CPU, which carries far less than the switch chip; only do it if normal peak plus
headroom fits. The alternative is flow export from the provider or a device in front of the router.

A router cannot drop more traffic than its upstream links deliver. For attacks near link capacity,
mitigation must happen upstream (provider blackholing or scrubbing), whichever option is chosen.

## Security

- Passwords are encrypted with `SHIELD_CREDENTIAL_KEY` (Fernet) in PostgreSQL, decrypted only inside
  `shield-api` (test connection) and `shield-mikrotik`, never returned by the API or written to logs.
  The audit log records `router.test` with the outcome, never the credentials.
- api-ssl with a pinned certificate is the intended mode. "Verify certificate" without a pin needs a
  certificate from a CA the Shield server trusts, matching the management address. Unverified TLS
  and the plain API are possible for lab use and show as warnings.
- Test connection and Get certificate need the Network Engineer role. Viewing status needs any role.

## Commands

```bash
# One-off probe from the Shield server (prompts for the password; nothing is stored)
/opt/crapplet-shield/venv/bin/python -m app.mikrotik probe 10.255.0.1 --user shield-ro --collector 10.255.0.10
# Show the certificate a router presents (sends no credentials)
/opt/crapplet-shield/venv/bin/python -m app.mikrotik cert 10.255.0.1
# Service
systemctl status shield-mikrotik; journalctl -u shield-mikrotik -f
# Lab simulator (loopback only, for testing without a router)
python -m app.mikrotik simulate --port 18729 --tls
```

## Tested

Against `app.mikrotik.simulator` (RouterOS API protocol, RouterOS 7.16-shaped data): 26 client tests
(wire format, login, traps, TLS pinning, refused writes), 18 adapter/check tests, 9 poller tests
(events, rates, schedule, reboots, outages) and 4 API tests. In the lab, two simulated routers
(one correctly configured with a pinned certificate, one CCR2116 with deliberate misconfigurations)
were polled by the real service: all 11 misconfigurations were reported, a BGP flap produced
`bgp_down` then `bgp_up`, and a replaced certificate was refused until re-pinned.

**Not yet verified on hardware.** Before relying on it, run `probe` against a CCR2004 and a CCR2116
and compare with WinBox, especially BGP session fields and the L3HW properties, which differ between
RouterOS 7 releases.
