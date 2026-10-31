#!/usr/bin/env bash
# Boot MikroTik CHR (RouterOS 7) in QEMU, configure it exactly as the setup guide says, peer it
# with an FRR standing in for Shield, and record what the router shows.
set -euo pipefail
OUT=${OUT:-$PWD/out}; mkdir -p "$OUT"
HERE=$(cd "$(dirname "$0")" && pwd)
V=$(curl -fsSL https://upgrade.mikrotik.com/routeros/NEWESTa7.stable | awk '{print $1}')
echo "RouterOS $V" | tee "$OUT/version.txt"
curl -fsSLO "https://download.mikrotik.com/routeros/$V/chr-$V.img.zip"
unzip -o -q "chr-$V.img.zip"
ACCEL=""; [ -w /dev/kvm ] && ACCEL="-enable-kvm -cpu host"
# A real point-to-point link between the router (ether2, 10.99.0.2) and "Shield" (this host, 10.99.0.1).
sudo ip tuntap add tap0 mode tap user "$(id -un)"; sudo ip addr add 10.99.0.1/24 dev tap0; sudo ip link set tap0 up
qemu-system-x86_64 $ACCEL -m 512 -smp 2 -display none -serial "file:$OUT/serial.log" -daemonize \
  -drive "file=chr-$V.img,format=raw,if=virtio" \
  -netdev "user,id=n0,hostfwd=tcp:127.0.0.1:8080-:80" -device virtio-net-pci,netdev=n0 \
  -netdev tap,id=n1,ifname=tap0,script=no,downscript=no -device virtio-net-pci,netdev=n1

for i in $(seq 1 120); do curl -fsS -u admin: http://127.0.0.1:8080/rest/system/resource >/dev/null 2>&1 && break; sleep 2; done
curl -fsS -u admin: http://127.0.0.1:8080/rest/system/resource | tee "$OUT/resource.json"; echo

ros() {  # run a RouterOS script, print its output
  jq -Rs '{script: ., "as-string": true}' | curl -sS -u admin: -H 'content-type: application/json' \
    -X POST http://127.0.0.1:8080/rest/execute -d @- | jq -r '.ret // .message // .'
}
show() {  # name, command
  { echo "[admin@MikroTik] > $2"; echo "$2" | ros; } | tee "$OUT/t-$1.txt"; echo
}

echo "/system/identity set name=Crapplet-Core-Router" | ros
echo "/ip/address add address=10.99.0.2/24 interface=ether2 comment=\"link to Shield (lab)\"" | ros
# An existing input rule, as on a real router, so place-before=0 has something to go before.
echo '/ip/firewall/filter add chain=input action=accept connection-state=established,related comment="existing rule"' | ros

echo "== BGP instance probe"
show instances-before "/routing/bgp/instance/print detail"
# Stands in for the instance a real edge router already has for its upstream sessions.
echo "/routing/bgp/instance add name=core as=154950 router-id=10.99.0.2" | ros | tee "$OUT/apply-instance.txt"
show instances "/routing/bgp/instance/print detail"
for v in "as=154950 instance=core" "instance=core"; do
  echo "probe: $v"; echo "/routing/bgp/connection add name=probe $v remote.address=192.0.2.9 remote.as=154950 local.role=ibgp disabled=yes" | ros
  echo "/routing/bgp/connection remove [find name=probe]" | ros
done 2>&1 | tee "$OUT/probe-connection.txt"
echo "== router config (guide step B3)"; ros < "$HERE/router-config.rsc" | tee "$OUT/apply-config.txt"
echo "== firewall (guide step B3)"
echo '/ip/firewall/filter add chain=input protocol=tcp dst-port=179 src-address=10.99.0.1 action=accept place-before=0 comment="Crapplet Shield BGP"' | ros | tee "$OUT/apply-fw.txt"

echo "== filter account (guide step C1)"
cat > /tmp/fu.rsc <<'RSC'
/user group add name=shield-filter policy=read,write,api,!local,!telnet,!ssh,!ftp,!reboot,!policy,!test,!winbox,!password,!web,!sniff,!sensitive,!romon,!rest-api comment="Crapplet Shield: local filtering"
/user add name=shield-fw group=shield-filter address=10.99.0.1/32 password="lab-only-long-password-123" comment="Crapplet Shield filter account"
RSC
ros < /tmp/fu.rsc | tee "$OUT/apply-user.txt"
echo "== what Shield adds when you filter an NTP attack (Part C)"
cat > /tmp/raw.rsc <<'RSC'
/ip/firewall/raw add chain=prerouting action=jump jump-target=shield-filter comment="shield:jump"
/ip/firewall/raw add chain=shield-filter action=drop dst-address=163.5.191.40/32 protocol=udp src-port=123 comment="shield:3817c8ca:0"
RSC
ros < /tmp/raw.rsc | tee "$OUT/apply-raw.txt"

echo "== FRR as Shield"
sudo sed -i 's/^bgpd=no/bgpd=yes/' /etc/frr/daemons
sudo cp "$HERE/frr.conf" /etc/frr/frr.conf
sudo systemctl restart frr
for i in $(seq 1 60); do
  st=$(echo '/routing/bgp/session/print count-only where established' | ros || true)
  [ "${st//[^0-9]/}" = "1" ] && break; sleep 3
done
sleep 10
sudo vtysh -c "show bgp summary" | tee "$OUT/f-summary.txt"
sudo vtysh -c "show bgp ipv4 unicast neighbors 10.99.0.2 advertised-routes" | tee "$OUT/f-advertised.txt"

show bgp-connection "/routing/bgp/connection/print detail"
show bgp-session "/routing/bgp/session/print"
show filter-rules "/routing/filter/rule/print"
show routes-bgp "/ip/route/print where bgp"
show route-detail "/ip/route/print detail where dst-address=163.5.191.250/32"
show routes-blackhole "/ip/route/print where blackhole"
show routing-route "/routing/route/print where belongs-to~\"bgp\""
show fw-filter "/ip/firewall/filter/print"
show raw "/ip/firewall/raw/print"
show users "/user/print"
show groups "/user/group/print where name=shield-filter"
show version "/system/resource/print"
show log-bgp "/log/print where topics~\"bgp\""

pip install -q playwright >/dev/null 2>&1 && python3 -m playwright install --with-deps chromium >/dev/null 2>&1
python3 "$HERE/shots.py" "$OUT" || true

echo "== filter syntax probe"
show route-250 "/routing/route/print detail where dst-address=163.5.191.250/32"
probe() {  # label, rule text
  printf '%s\n' "/routing/filter/rule remove [find where chain=probe-in]" \
    "/routing/filter/rule add chain=probe-in rule=\"$2\"" \
    "/routing/filter/rule add chain=probe-in rule=\"reject\"" \
    "/routing/bgp/connection set shield-rtbh input.filter=probe-in" | ros
  sleep 2; echo "/routing/bgp/session refresh [find]" | ros; sleep 6
  { echo "### $1: $2"; echo '/routing/route/print where belongs-to~"bgp"' | ros; echo '/ip/route/print where blackhole' | ros; } | tee -a "$OUT/probe-filter.txt"
}
probe A 'if (dst in 163.5.191.0/24) { accept }'
probe B 'if (dst in 163.5.191.0/24 && dst-len == 32) { accept }'
probe C 'if (dst in 163.5.191.0/24 && dst-len >= 32) { accept }'
probe D 'if (bgp-communities includes 154950:666) { accept }'
probe E 'if (dst in 163.5.191.0/24 && dst-len >= 32 && bgp-communities includes 154950:666) { accept }'
probe F 'if (dst in 163.5.191.0/24 && dst-len >= 32 && bgp-communities includes 154950:666) { set blackhole yes; accept }'
probe G 'if (dst in 163.5.191.0/24 && dst-len == 32 && bgp-communities includes 154950:666) { set blackhole yes; accept; }'
probe H 'if (dst in 163.5.191.0/24 && dst-len>=32 && bgp-communities includes 154950:666) { set blackhole yes; accept; }'
show route-250-after "/ip/route/print detail where dst-address=163.5.191.250/32"
echo "/routing/bgp/connection set shield-rtbh input.filter=shield-rtbh-in" | ros
echo "== removal (guide G4)"
cat > /tmp/rm.rsc <<'RSC'
/routing/bgp/connection remove [find name="shield-rtbh"]
/routing/filter/rule remove [find where chain~"^shield-"]
/ip/firewall/raw remove [find where comment~"^shield:"]
/ipv6/firewall/raw remove [find where comment~"^shield:"]
/user remove [find name="shield-fw"]
/user group remove [find name="shield-filter"]
RSC
ros < /tmp/rm.rsc | tee "$OUT/apply-remove.txt"
show after-remove "/routing/filter/rule/print count-only; /ip/firewall/raw/print count-only; /routing/bgp/connection/print count-only; /ip/route/print count-only where blackhole"
