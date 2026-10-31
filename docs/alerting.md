# Alerts and reports (Phase 10)

## Alerts

Menu: **Alerts**. A channel is an e-mail address list (SMTP), a Telegram chat (bot) or a webhook
(Shield's JSON, or Slack/Mattermost/Teams-compatible text). Each channel chooses:

- **Send**: the minimum severity (e.g. only high and critical for the on-call phone);
- **Events**: which kinds of alert (none ticked = all);
- **Quiet period**: the same alert is not repeated within it (repeats are listed as suppressed);
- **Escalation**: confirmed attacks nobody has acknowledged after N minutes are sent again as
  *critical* (once per attack);
- **Summary report**: daily (08:00 server time) or weekly (Monday 08:00).

| Alert | Default severity |
|---|---|
| Attack confirmed / severity increased | the attack's severity |
| Attack ended | info |
| Attack not acknowledged (escalation) | critical |
| Mitigation waiting for approval, active, withdrawn, failed | medium / medium / info / high |
| Safety interlock tripped | critical |
| Emergency stop engaged | high |
| BGP session down / up, router unreachable / back, router rebooted | high / info / high / info / medium |
| Upstream link near capacity (measured interface rate against the upstream's capacity and alarm level) | high |
| No flow data from any router | high |

Secrets (SMTP password, Telegram bot token, webhook signing key) are stored encrypted and never
returned. Webhooks with a signing key carry `X-Shield-Signature: sha256=<HMAC of the body>`.
Delivery is retried with back-off (5 attempts); failures are shown under *Recently sent* and make
the *Alerts* component on System health show as degraded.

Set **Settings → dashboard_url** (e.g. `https://162.4.12.101`) so alerts link to the attack.

The alerts are sent by `shield-notifier.service`.

## Reports

Menu: **Reports**: attacks per day, by severity and type, time under attack, the largest attack,
the most attacked addresses (with customer), the main source networks, and the mitigations taken
and their outcome, for 24 hours up to a year. **Attacks as CSV** exports every incident in the
period with its customer, timings, peak, top source networks and mitigations.

API: `GET /api/v1/reports/summary?days=30`, `GET /api/v1/reports/incidents.csv?days=30`.
