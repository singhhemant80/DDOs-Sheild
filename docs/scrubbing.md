# Scrubbing-centre adapter (Phase 9 part 3)

An on-demand scrubbing service takes over the traffic for an attacked prefix, drops the attack in
its own network and sends the clean traffic back to you, usually over a GRE tunnel or a direct
interconnect you set up with the provider in advance. It is the answer when an attack is larger
than your links: blackholing would cut the address off, filtering on your router cannot help a
full link, and steering only moves the load between your own upstreams.

Shield does not contain any one provider's integration. It is generic and follows what your
provider documents:

| Method | What Shield does |
|---|---|
| **API** | Calls the provider's HTTPS API to start (`activate`) and stop (`deactivate`) diversion of the /24, with your API token; optionally polls a `status` request and reads a JSON field to confirm the diversion is active |
| **Manual** | Records the diversion and its steps; someone triggers it with the provider (portal, phone) and stops it again when the action is withdrawn |

## Configuring a provider (Routers & upstreams → Scrubbing providers)

- **Requests**: method, URL and an optional JSON body. Placeholders `{prefix}`, `{target}`,
  `{action_id}`, `{incident_id}` are filled in after being validated (prefixes, addresses and
  UUIDs only), e.g. `https://api.example-scrubber.net/v1/prefixes/{prefix}/divert`.
- **Token**: the header name (e.g. `Authorization`) and value (e.g. `Bearer …`). Stored
  encrypted, never shown again, and removed from any error message.
- **Limits**: the prefix lengths the provider accepts (normally /24 only) and how many prefixes
  your contract allows at once.
- **Verify**: after checking the settings against the provider's documentation (enter its URL),
  **Mark as verified**. Any change to the requests or token clears the verification.
- **Test** calls only the status request for a prefix you choose; it never starts a diversion.

Safety: only `https` URLs to public addresses are called (not private, loopback or link-local, checked
again at each call), redirects are not followed, and requests time out after 15 seconds.

## Using it

1. Allow **scrubbing** on the protected prefix (Protected prefixes → Edit).
2. Set up the return path with the provider and test it before an attack.
3. Settings → `scrubbing_backend` = `live` (simulated until then: no provider is called).
4. On an attack: **Divert to scrubbing** → preview → propose → approve. Shield diverts the whole
   /24 holding the address. Withdrawing the action (or its duration ending without the attack)
   stops the diversion.

The controller checks every 30 seconds: if the provider stops reporting an active diversion that
should be active, Shield requests it again. A provider refusing a request (HTTP 4xx) fails the
action at once; network errors and 5xx are retried for a minute.

## Tested

`backend/tests/test_scrubbing.py` (10 tests): URLs to internal addresses and plain HTTP refused,
the token never returned or logged, changes reset verification, a full diversion against a mock
provider API (activate, status confirmation, deactivate), refusal and retry behaviour, the simulated
backend calling nothing, and manual providers.

**Not tested against a real provider.** Run the status test first, then divert a test prefix
the provider agrees to, during a maintenance window.
