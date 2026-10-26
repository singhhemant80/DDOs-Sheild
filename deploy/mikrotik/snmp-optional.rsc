# Crapplet DDoS Shield - optional SNMP read access for the shield-snmp-poller.
#
# Shield already reads interface counters over the API every 10 s, so SNMP is only needed for
# devices Shield has no API access to, or as a second source. SNMPv2c communities travel in clear
# text: allow the Shield address only, keep write access off, and never reuse the community name.
# Run:   /import file-name=snmp-optional.rsc
{
:local shieldAddress "10.255.0.10"
:local community ""
:if ([:len $community] < 16) do={ :error "Set community (16+ random characters) before running" }
:if ([:len [/snmp community find name=$community]] = 0) do={
  /snmp community add name=$community addresses=($shieldAddress . "/32") read-access=yes write-access=no
}
/snmp set enabled=yes
}
