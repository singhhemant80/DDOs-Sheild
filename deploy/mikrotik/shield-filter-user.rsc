# Crapplet DDoS Shield - filter account for local filtering (Phase 9), RouterOS 7
#
# What this does (and nothing else):
#   a user group "shield-filter" (read,write,api) and a user for Shield, allowed only from the
#   Shield server's address. Shield uses this account only to add and remove its OWN drop rules in
#   /ip firewall raw (chain "shield-filter", comments starting "shield:"), plus one jump rule at
#   the top of raw prerouting (comment "shield:jump"); and, for steering, its own rules in
#   /routing filter rule chains "shield-steer-<n>" plus one jump at the top of an upstream's BGP
#   output chain (comment "shield:steer-jump:<n>"). Shield's own client refuses every other change.
#
# Be aware: RouterOS cannot limit an account to the firewall. A "write" account can change any
# configuration, so keep this password safe, allow it from the Shield server only, and keep it
# separate from the read-only polling account (shield-ro). Remove it when you stop using filtering.
#
# Before running: run shield-readonly.rsc first (api-ssl is needed), set the variables, Safe Mode.
# Run:   /import file-name=shield-filter-user.rsc verbose=yes
# Undo:  see the end of this file
{
:local shieldAddress "10.255.0.10"
:local filterUser "shield-fw"
# At least 16 characters. Enter it in Shield (Routers & upstreams -> Edit -> Filter account), then
# clear it from this file.
:local filterPassword ""

:if ([:len $filterPassword] < 16) do={ :error "Set filterPassword (16+ characters) before running" }
:if ([:len [/user group find name="shield-filter"]] = 0) do={
  /user group add name="shield-filter" policy="read,write,api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api" comment="Crapplet Shield: local filtering"
}
:if ([:len [/user find name=$filterUser]] = 0) do={
  /user add name=$filterUser group="shield-filter" address=($shieldAddress . "/32") password=$filterPassword comment="Crapplet Shield filter account"
} else={
  /user set [find name=$filterUser] group="shield-filter" address=($shieldAddress . "/32") password=$filterPassword
}
:put "Filter account ready. In Shield: Routers & upstreams -> Edit -> Filter account, then Test filter account."
}

# ---- Undo (copy into the terminal) ------------------------------------------------------------
# /ip firewall raw remove [find where comment~"^shield:"]
# /ipv6 firewall raw remove [find where comment~"^shield:"]
# /routing filter rule remove [find where comment~"^shield:"]
# /user remove [find name="shield-fw"]
# /user group remove [find name="shield-filter"]
