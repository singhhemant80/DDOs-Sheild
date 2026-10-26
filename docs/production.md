# Controlled live mitigation (Phase 8)

Phase 8 lets Shield announce blackholes to your **production** routers and providers. It adds no
new kind of mitigation: the same approved, verified `/32` (or `/128`) blackholes as in staging, sent
over production sessions, behind four extra safeguards.

| Safeguard | What it does |
|---|---|
| Production switch | Production sessions are configured in FRR only while **Settings → Production BGP** is on. Turning it on needs an administrator signed in with two-factor, the FRR speaker and no emergency stop. Turning it off is allowed for everyone who can use the emergency stop. |
| Acceptance run, per peer | Until a run passes, a production session carries **only the run's test address** (its own route-map `SHIELD-ACC-<peer>`), never your real blackholes, and the planner refuses to use it. |
| Safety interlock | After every announcement and every 30 s, Shield compares what each session advertises with what approved, active actions allow. Anything else is removed at once and the emergency stop is engaged. |
| Rollback | **Withdraw all** in the Mitigation center withdraws every blackhole and cancels everything pending. Switching production off does the same and also removes the production sessions. |

The existing layers stay: the planner's checks, the database trigger, the speaker's own
authorisation of every route, and the import filter on your router (see [bgp.md](bgp.md)).

## Going live, step by step

1. **On each production router**, install the generated import filter on the session from Shield
   (BGP sessions → Router filter) and route the discard next hop to null. Check both on your
   RouterOS version in Safe Mode: the RouterOS filter (`set blackhole yes`) has been tested only
   on FRR lab routers so far.
2. **Add the session** in Shield (BGP sessions → Add session) with environment *production*, a
   small route limit, and TCP-MD5 if your router uses it.
3. **Switch production on** (Settings → Production BGP). The session comes up; the router
   receives nothing yet.
4. **Run an acceptance test** (BGP sessions → Acceptance runs → Test). Pick one address inside a
   protected prefix that nothing uses, and confirm that it is unused. The run:
   1. records a baseline: what every session advertises, and the protected routes on each router
      Shield reads;
   2. blackholes the test address over that peer only;
   3. checks that it is advertised on the peer's sessions and nowhere else, and that nothing else
      Shield sends changed;
   4. where Shield reads the router (MikroTik), waits for the router to show the blackhole and
      checks that its other protected routes are unchanged;
   5. withdraws it and checks that every session is back to its baseline.

   Any failure, or a step running out of time (2–3 minutes), fails the run, withdraws the test
   address, and leaves the session unaccepted.
5. When the run passes, the session starts carrying the peer's real blackholes, including any that
   are already active.

Changing a production session (port, multihop, address, password, route limit, environment) or
the provider's blackhole policy resets its acceptance; run the test again.

## What "unaffected" is checked against

- **Shield's side**: FRR's advertised routes for every session, before, during and after the run.
  During the run only the test address may be added, and only on the tested peer's sessions.
- **Router side** (when Shield reads the router): the router's routes inside your protected
  prefixes, from the read-only poller (refreshed every 60 s). During the run only the test
  address may change, and it must appear as a blackhole.

## If something goes wrong

- The status strip shows **Safety interlock removed …** in red, and the Mitigation center explains
  what was removed. New blackholes stay stopped until someone checks Shield's FRR
  (`vtysh -c "show bgp ipv4 unicast"`) and turns automation back on under Settings.
- **Withdraw all** or **Switch off and withdraw all** returns everything to how it was before
  mitigation.

## Tested

`backend/tests/test_production_acceptance.py` runs Shield's FRR against two FRR routers, a lab
router (staging) and a "production" router, with real BGP sessions (9 tests, also in CI):

- production can be switched on only by an administrator with an MFA session; a NOC operator can
  switch it off, which withdraws everything;
- an unaccepted production router receives **nothing**, not even a blackhole already active on
  staging; ordinary proposals over it are refused;
- the acceptance run passes, and the lab router's routes are identical before, during and after;
  once accepted, the production router gets the existing and new blackholes;
- with the production session down, the run fails and leaves nothing announced;
- a protected route on the router changing during the run fails it;
- a route injected straight into Shield's FRR is removed by the interlock, the emergency stop is
  engaged, and the authorised route is untouched;
- withdraw all, and production off, leave both routers empty;
- editing a production session resets its acceptance; customer addresses can't be test addresses.
