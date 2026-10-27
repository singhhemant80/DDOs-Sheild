# Selective upstream steering (Phase 9 part 2)

Blackholing and filtering drop traffic. Steering drops nothing: it changes **which upstream the
traffic arrives over**, for example to move an attacked /24 onto the upstream that has DDoS
protection, or away from a link that is filling up.

Inbound traffic follows what you announce, so Shield changes what your edge router announces to
one upstream, for one exact prefix (the /24, or /48, holding the attacked address):

| Change | Rule Shield adds | Effect |
|---|---|---|
| Stop announcing | `if (dst == 163.5.191.0/24) { reject; }` | The internet reaches the /24 over your other upstreams only |
| Prepend N (1-5) | `if (dst == 163.5.191.0/24) { set bgp-path-prepend 3; }` | The path through that upstream looks longer; most, not all, traffic moves |
| Action communities | `if (dst == 163.5.191.0/24) { append bgp-communities 174:990; }` | Whatever that provider documents for those communities (e.g. "do not announce to X") |

## On the router

- Each upstream gets a Shield chain in `/routing/filter/rule`, `shield-steer-<upstream id>`,
  entered by one rule at the top of that upstream's BGP **output** chain:
  `jump shield-steer-<id>` (comment `shield:steer-jump:<id>`). The jump is removed again when the
  last steering rule for that upstream goes.
- Shield's rules never `accept`: after a Shield rule, your own output filter still runs (so your
  community clean-up and prefix limits still apply). A withhold `reject`s, which only ever removes
  the one prefix.
- Shield refuses to add its jump to an output chain that has no rules of its own, and refuses
  sessions without an output chain: it adds in front of your filter, it never creates one.
- It uses the router's **filter account** (see [local-filtering.md](local-filtering.md)); the
  RouterOS client accepts only these rule shapes, for one prefix /8-/24 (/16-/48), and removes only
  rules it has read with a `shield:` comment.
- Every 30 seconds Shield re-adds missing Shield rules and removes Shield rules nothing asks for.

## Safety checks before anything changes

- The protected prefix must allow **steering** (Protected prefixes → Edit).
- At least two upstreams must be linked to your routers (Routers & upstreams → Edit upstream →
  Edge router), and Shield must see the router's BGP session to each one (it reads them).
- **Never unreachable:** Shield refuses any steering, together with what is already active, that
  would stop announcing the prefix to every upstream.
- It warns when the traffic to the prefix is near the capacity left on the remaining upstreams,
  when it cannot see a route for exactly that prefix on the router (steering only changes an
  announcement of exactly that prefix), and that action communities are the provider's to define.
- Without a choice, Shield suggests moving the prefix onto your DDoS-protected upstream(s) by
  withholding it from the others (mark upstreams "Provider offers DDoS protection").

## Setting it up

1. Make sure each upstream's BGP session on the router has an **output filter chain**
   (`/routing/bgp/connection print` → `output.filter-chain`). Most setups have one.
2. Link each upstream to the router and mark the protected one(s) under Routers & upstreams.
3. Add the filter account to the router (same account as local filtering).
4. Allow steering on the protected prefix.
5. Settings → `steering_backend` = `routeros` (simulated until then: no router changes).
6. On an attack: **Steer away from an upstream** → preview → propose → approve.

## Not yet verified on hardware

Tested against the RouterOS protocol simulator. On your router, check once, on a test prefix, that:
the rule syntax is accepted on your RouterOS version; the router re-advertises after a filter
change (RouterOS 7 normally does; otherwise a session refresh is needed); and the upstream stops
receiving the prefix (their looking glass, or bgp.tools).
