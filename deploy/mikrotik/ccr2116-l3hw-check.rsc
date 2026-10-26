# Crapplet DDoS Shield - CCR2116 / CCR2216: is traffic-flow seeing your upstream traffic?
#
# These models can route in the switch chip (L3 hardware offloading). Packets forwarded in hardware
# never reach the CPU, so traffic-flow does not export them and Shield cannot see attacks carried
# on those ports. This script only prints; it changes nothing.
#
# Run:   /import file-name=ccr2116-l3hw-check.rsc
/interface ethernet switch print where l3-hw-offloading=yes
/interface ethernet switch port print where l3-hw-offloading=yes

# If offloading is on for the upstream ports you have three options. Choose deliberately:
#
#  a) Keep offloading and accept that Shield sees only traffic the CPU handles. Not recommended for
#     the upstream ports: volumetric attacks can then go unnoticed.
#
#  b) Turn offloading off on the upstream-facing ports only. Forwarding for those ports moves to the
#     CPU, which on a CCR2116 handles far less than the switch chip (roughly single-digit to low tens
#     of Gbit/s depending on packet size, firewall and queues). Check that your normal peak, plus
#     headroom, fits before doing this, and do it in a maintenance window:
#        /interface ethernet switch port set sfp28-1 l3-hw-offloading=no
#
#  c) Keep offloading and give Shield another view of the traffic: sFlow or NetFlow from the
#     upstream provider or from a device in front of this router, pointed at the Shield collector.
#
# A router cannot filter or absorb more than its upstream links carry. For attacks near link
# capacity, mitigation has to happen upstream (provider RTBH or scrubbing), whatever is chosen here.
