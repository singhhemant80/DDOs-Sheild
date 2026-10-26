# Crapplet DDoS Shield - read-only access and flow export for RouterOS 7 (CCR2004 / CCR2116)
#
# What this does (and nothing else):
#   1. a user group that can only read (read,api,test) and a user for Shield, allowed only from
#      the Shield server's address
#   2. a self-signed certificate for the api-ssl service; api-ssl restricted to the Shield server
#      and TLS 1.2+; the plain api service disabled
#   3. traffic-flow (IPFIX) export from the upstream-facing interfaces to the Shield collector,
#      sampled 1 in 1024, 1 minute active timeout
#
# It does not touch firewall rules, routing, BGP, winbox, ssh or any other service.
#
# Before running:
#   * read it, and set the variables below
#   * run it in Safe Mode (Ctrl+X in the terminal) so it is undone if you lose the session
#   * if api-ssl is already used by something else, its address list is replaced below: check
#     /ip service print first
#
# Run:   /import file-name=shield-readonly.rsc verbose=yes
# Undo:  /import file-name=shield-remove.rsc
{
:local shieldAddress "10.255.0.10"
:local routerMgmtAddress "10.255.0.1"
:local upstreamInterfaces "sfp-sfpplus1,sfp-sfpplus2"
:local collectorPort 4739
:local shieldUser "shield-ro"
# At least 16 characters. Enter the same password in Shield when adding the router, then clear it
# from this file.
:local shieldPassword ""

:if ([:len $shieldPassword] < 16) do={ :error "Set shieldPassword (16+ characters) before running" }
:if ([:len [/ip address find where address~("^" . $routerMgmtAddress . "/")]] = 0) do={
  :error "routerMgmtAddress is not an address of this router"
}

# ---- 1. read-only account --------------------------------------------------------------
:if ([:len [/user group find name="shield-read"]] = 0) do={
  /user group add name="shield-read" policy="read,api,test,!local,!telnet,!ssh,!ftp,!reboot,!write,!policy,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api" comment="Crapplet Shield: read only"
}
:if ([:len [/user find name=$shieldUser]] = 0) do={
  /user add name=$shieldUser group="shield-read" address=($shieldAddress . "/32") password=$shieldPassword comment="Crapplet Shield"
} else={
  /user set [find name=$shieldUser] group="shield-read" address=($shieldAddress . "/32") password=$shieldPassword
}

# ---- 2. api-ssl with its own certificate ----------------------------------------------------
:if ([:len [/certificate find name="shield-api"]] = 0) do={
  /certificate add name="shield-api" common-name=$routerMgmtAddress subject-alt-name=("IP:" . $routerMgmtAddress) key-type=ec key-size=prime256v1 days-valid=825 key-usage=digital-signature,key-agreement,tls-server
  /certificate sign "shield-api"
  :delay 3s
}
/ip service set api-ssl certificate="shield-api" tls-version=only-1.2 address=($shieldAddress . "/32") disabled=no
/ip service set api disabled=yes

# ---- 3. flow export -----------------------------------------------------------------------
# sampling-interval=1 sampling-space=1023: export 1 packet, skip 1023 (1 in 1024). The rate is sent
# in IPFIX options records and Shield scales counts by it.
/ip traffic-flow set enabled=yes interfaces=[:toarray $upstreamInterfaces] cache-entries=256k active-flow-timeout=1m inactive-flow-timeout=15s packet-sampling=yes sampling-interval=1 sampling-space=1023
:if ([:len [/ip traffic-flow target find dst-address=$shieldAddress]] = 0) do={
  /ip traffic-flow target add dst-address=$shieldAddress port=$collectorPort version=ipfix src-address=$routerMgmtAddress
} else={
  /ip traffic-flow target set [find dst-address=$shieldAddress] port=$collectorPort version=ipfix src-address=$routerMgmtAddress disabled=no
}

:put ""
:put "Done. Compare this fingerprint with the one Shield shows (Routers > Get certificate) before pinning it:"
:put [/certificate get [find name="shield-api"] fingerprint]
}
