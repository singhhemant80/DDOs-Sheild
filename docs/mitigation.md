# Mitigation: blackholing (Phase 6, simulation)

Shield can blackhole an address under attack: announce a host route with the provider's
blackhole community so the provider drops all traffic to it (upstream RTBH), or tag it for your
own edge routers (internal RTBH).

**In this release everything runs against a simulated BGP speaker.** The whole workflow is real
(plans, checks, approvals, execution, verification, withdrawal, timers, reconciliation), but no
route is sent to any router or provider. Phase 7 adds an FRR speaker in a staging lab; phase 8
turns on real announcements.

## What blackholing does

Blackholing makes the address **unreachable**, legitimate traffic included. It protects
everything else: the link, the router and the other customers in the prefix. Use it when the attack
is bigger than the link or threatens the rest of the network, not as a first response to every
alert.

- **Upstream** blackholing stops the traffic before it reaches your links. It is the only option
  that helps when a link is saturated. Traffic arriving through an upstream that was not included
  still reaches the target.
- **Internal** blackholing drops traffic at your own edge after it has crossed the links. It
  protects the customer's server and your core, not the upstream links.

## The workflow

1. **Preview.** From the Mitigation center ("Blackhole an address") or an attack's page. Shield
   shows exactly what it would announce (`announce 163.5.191.20/32 to Upstream-A (AS174),
   communities 174:666, no-export`), every safety check, and the effect in plain words: who loses
   connectivity, which providers drop it, which do not, and the current traffic to the target.
2. **Propose.** Creates one action per upstream. The request carries an `Idempotency-Key`, so a
   double click or a retried request never creates a second blackhole.
3. **Approve or reject.** NOC operators and above. With *four-eyes approval* on, the proposer
   cannot approve their own request; with *require MFA for mitigation* on, only an MFA session can
   approve. All checks run again at approval.
4. **Execute.** The controller (`shield-mitigator`) runs the checks a third time, writes its intent
   to the database, announces, reads the route back from the speaker and compares every attribute.
   Only then is the action *active*. If the speaker refuses, or the route does not appear, it retries
   for 60 seconds, then marks the action *failed* and removes anything it announced (*rolled back*).
5. **Duration.** Each blackhole has a duration (default 60 minutes). When it ends, Shield extends it
   if the attack is still visible in flow data, otherwise withdraws it. Behind an upstream blackhole
   the attack usually is not visible any more (the provider drops it), so the route is withdrawn; if
   the attack comes back it is detected and proposed again.
6. **Withdraw.** Any time, by NOC operators and above. Withdrawal is verified on the speaker too.

Every step is in the action's timeline, the attack's timeline and the audit log, and appears live
on the dashboard.

## Safety checks

| Blocks the action | |
|---|---|
| Target outside every protected prefix, prefix disabled, ownership not verified, blackholing not allowed | Configured per prefix under Protected prefixes |
| Target broader than the prefix allows (default: single addresses only) | A /24 is never blackholed for one address without an explicit prefix setting |
| The target contains a router management address, a BGP session address or the collector | Shield never cuts off its own management |
| Customer opted out of blackholing | Per customer IP |
| Emergency stop on | Also stops approved actions that have not run yet |
| Upstream without an enabled, verified blackhole policy, or prefix length outside its limits | Policy taken from the provider's documentation |
| Upstream's route limit, or the global limit (`global_max_rtbh_routes`), would be exceeded | |
| The same address already has a live action | |
| Automatic actions only: automation off, infrastructure address, re-blackholing within the flap cooldown | A person can still do these, with a warning |

| Warns | |
|---|---|
| Not all upstreams included | Attack traffic through the others continues |
| Address was un-blackholed in the last 15 minutes | Risk of flapping |
| Infrastructure address (manual) | Other customers may depend on it |
| Internal blackholing | Does not relieve a saturated link |

## Policies

A policy turns a confirmed attack into a proposal: scope (prefix), attack types, minimum
confidence, how long it must have been confirmed, action, duration, minimum hold and how many
actions it may have at once. By default a policy only **proposes**; a person approves. A policy set
to act without approval does so only while *automatic mitigation* is switched on, and only roles
allowed to enable automation can save such a policy. When a policy cannot act (automation off,
limits, checks) the attack's timeline says why, once.

## Restarts and reconciliation

Only one controller acts at a time (PostgreSQL advisory lock); a second one waits as standby. On
start and every 30 seconds the controller compares the routes that should be announced with what
the speaker holds: missing routes are announced again, routes nobody wants any more are withdrawn,
and both are recorded. An action interrupted between "intent recorded" and "verified" simply
continues after a restart. A withdrawal only ever removes a route the speaker says belongs to the
same action, so an old action can never remove a newer one's route.

## Tested

30 automated tests (`backend/tests/test_mitigation.py`) cover the plans and checks, idempotency,
approvals (four-eyes, MFA), execution, speaker failures with rollback, withdrawal, expiry and
extension, policies, live events and restarts at both points of execution.

Lab run with the real collector, detector and controller (synthetic flow records to the loopback
collector only):

| Step | Result |
|---|---|
| UDP flood to 163.5.191.20 | Confirmed after 20 s; policy proposed blackholes at both upstreams 23 s later |
| Approve | Active and verified on the speaker within 1.1 s |
| Second controller started | Stood by |
| Controller killed with SIGKILL, one route removed from the speaker, a stray route added | On restart: missing route re-announced, stray route withdrawn, within 1 s |
| Same proposal sent twice with one Idempotency-Key | One action |
| Blackhole the whole /24 | Refused: broader than the prefix allows, outside both providers' accepted lengths |
| Manual blackhole, then withdraw | Withdrawn and verified; immediate re-proposal shows the flap warning |
| Speaker silently dropping announcements | Retried for 60 s, failed, rolled back |

## API

See [api.md](api.md): `/mitigation/preview`, `/mitigation/actions` (with `Idempotency-Key`),
`…/approve`, `…/reject`, `…/withdraw`, `…/extend`, `/mitigation/routes`, `/mitigation/status`,
`/mitigation/policies`.
