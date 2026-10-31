# Exactly what the setup guide tells you to paste, with Shield's address as the router sees it in
# this lab (10.99.0.1) instead of 162.4.12.101.
/routing/filter/rule
add chain=shield-rtbh-in rule="if (dst in 163.5.191.0/24 && dst-len >= 32 && bgp-communities includes 154950:666) { set blackhole yes; accept }" comment="Shield: 163.5.191.0/24"
add chain=shield-rtbh-in rule="if (dst in 77.107.95.0/24 && dst-len >= 32 && bgp-communities includes 154950:666) { set blackhole yes; accept }" comment="Shield: 77.107.95.0/24"
add chain=shield-rtbh-in rule="reject" comment="Shield: everything else"
add chain=shield-rtbh-out rule="reject" comment="Shield: send nothing to Shield"
# RouterOS 7.20 and later: a BGP connection belongs to a BGP instance. Use the router's
# existing instance for AS154950 (the one its upstream sessions use).
{
:local inst [/routing/bgp/instance find where as=154950]
:if ([:len $inst] = 0) do={ :error "No BGP instance with AS 154950 on this router" }
/routing/bgp/connection add name=shield-rtbh instance=[/routing/bgp/instance get ($inst->0) name] remote.address=10.99.0.1 remote.as=154950 local.role=ibgp multihop=yes input.filter=shield-rtbh-in output.filter-chain=shield-rtbh-out input.limit-process-routes-ipv4=100 comment="Crapplet Shield blackhole signalling"
}
