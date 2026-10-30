#!/bin/bash
# Remote EVPN leaves for tests/vxlan/test_vxlan_evpn_l2.py. Runs ON the test server, as root.
#
#   vxlan_evpn_l2_leaves.sh <env-file> up | down | image
#   vxlan_evpn_l2_leaves.sh <env-file> status                (by hand, when debugging: each leaf's BGP, VNIs, FDB)
#   vxlan_evpn_l2_leaves.sh <env-file> fdb add|del <leaf> <mac> <vid> [<dev> [static]]
#       (dev: default hb, the leaf's host; static: a static sticky entry, which zebra advertises with the MAC mobility
#       sticky bit; zebra takes a local MAC as sticky from the kernel's sticky flag, not from static)
#   vxlan_evpn_l2_leaves.sh <env-file> vni down|up <leaf> <vni>
#   vxlan_evpn_l2_leaves.sh <env-file> vniadd <leaf> <vid> <vni>   (one more VNI, tagged on hb, route targets RT_ASN:vni)
#   vxlan_evpn_l2_leaves.sh <env-file> vnidel <leaf> <vid> <vni>   (undoes vniadd)
#   vxlan_evpn_l2_leaves.sh <env-file> send <leaf> <dst-mac> <src-mac> <count> <tag>   (untagged, from the host)
#   vxlan_evpn_l2_leaves.sh <env-file> fdbshow <leaf>        (bridge -j fdb show of the leaf)
#   vxlan_evpn_l2_leaves.sh <env-file> show <leaf> <words...>   (vtysh -c 'show <words...>' on the leaf)
#   vxlan_evpn_l2_leaves.sh <env-file> svi add <leaf> <vid> <vrf|default> [<addr/len> ...] | svi del <leaf> <vid>
#       (SVI vl<vid> on br0, in <vrf> unless default; IPv6 on, without a link-local address)
#   vxlan_evpn_l2_leaves.sh <env-file> neigh add|del <leaf> <vid> <mac> <ip> [<ip> ...]
#       (permanent neighbours on vl<vid>: with <mac> local on the leaf, FRR advertises a Type-2 MAC/IP for each)
#   vxlan_evpn_l2_leaves.sh <env-file> l3vni add|del <leaf> <vrf> <vid> <vni>
#       (VRF <vrf> (table <vid>) with L3 VNI <vni> on vx<vni> in VLAN <vid>, its SVI vl<vid>, and a BGP instance in
#       the VRF that exports Type-5 routes; route targets RT_ASN:vni)
#   vxlan_evpn_l2_leaves.sh <env-file> prefix add|del <leaf> <vrf> <prefix>   (a Type-5 route from the VRF, blackholed)
#   vxlan_evpn_l2_leaves.sh <env-file> vrfcheck   (VRF_OK, or VRF_MISSING <error>: whether this kernel makes VRF devices)
#   vxlan_evpn_l2_leaves.sh <env-file> ulmac <leaf>   (the MAC of the leaf's uplink ul0: the DUT's next hop toward it)
#
# Each leaf is an FRR container (the stock frrouting/frr image) with its own network namespace:
#
#   PTF netns     <PTF_IF> (the PTF port cabled to the DUT's routed port) <=tc mirred=> evw_<leaf>
#   leaf netns    ul0 (peer of evw_<leaf>) <ip>/<plen>, lo <vtep>/32, eBGP ipv4 + l2vpn evpn to the DUT
#                 br0 (vlan_filtering) = { vx<vni> per VNI (pvid <vid>), hb }, hh <-veth-> hb is the leaf's host
#
# The PTF port is never moved out of the PTF: tc matchall actions join it to the leaf's veth both ways, so the PTF
# still captures everything the DUT sends toward the leaf (packet taps run before tc ingress) and can inject frames
# toward the DUT as if it were the leaf. Leaves may share one PTF port (the same L_PTF_IF): they are then BGP
# neighbours of the DUT on one segment (one subnet, L_PLEN), each with its own address and uplink MAC; the port's
# ingress is mirrored to every leaf on it but the last, and redirected to the last, and each leaf's uplink keeps only
# the frames addressed to its MAC (and broadcasts). Leaves on one segment reach each other through the DUT (routes
# learned from the DUT take the DUT as next hop). `down` removes exactly what `up` built and leaves the PTF port as it
# was. `up` first runs `down`, so a run that died half way does not leave a second set behind.
#
# The env file (written by the test) sets PTF, IMAGES (candidate leaf images, first usable wins), WORK, PREFIX,
# DUT_ASN, DUT_VTEP, RT_ASN, LEAVES, and for each
# leaf L in LEAVES: L_PTF_IF L_ASN L_VTEP L_IP L_PLEN (prefix length of L_IP's subnet with the DUT) L_DUT_IP
# L_VNIS ("vid:vni vid:vni ...", the first one untagged on hb).
set -uo pipefail
ENV=${1:?env file}; CMD=${2:?command}; shift 2
# shellcheck disable=SC1090
. "$ENV"
die(){ echo "FATAL: $*" >&2; exit 1; }
log(){ echo "$(date +%H:%M:%S) $*"; }
[ "$(id -u)" = 0 ] || die "run as root"

v(){ eval "echo \"\${${1}_${2}}\""; }       # v <leaf> <field>
cname(){ echo "${PREFIX}_$1"; }
ptf_pid(){ docker inspect -f '{{.State.Pid}}' "$PTF" 2>/dev/null; }
pns(){ nsenter -t "$PTF_PID" -n "$@"; }
cx(){ docker exec "$(cname "$1")" sh -c "$2"; }

write_frr(){ # write_frr <leaf>
  local l=$1 d="$WORK/$1" peer asn vtep host p vni
  peer=$(v "$l" DUT_IP); asn=$(v "$l" ASN); vtep=$(v "$l" VTEP); host=$(cname "$l")
  mkdir -p "$d"
  cat > "$d/daemons" <<'EOF'
bgpd=yes
vtysh_enable=yes
zebra_options="  -A 127.0.0.1 -s 90000000"
bgpd_options="   -A 127.0.0.1"
mgmtd_options="  -A 127.0.0.1"
staticd_options="-A 127.0.0.1"
EOF
  echo "service integrated-vtysh-config" > "$d/vtysh.conf"
  {
    cat <<EOF
frr defaults datacenter
hostname $host
log stdout informational
!
ip prefix-list FROM-DUT seq 10 permit 10.0.0.0/8 ge 32
route-map FROM-DUT permit 10
 match ip address prefix-list FROM-DUT
 set ip next-hop peer-address
exit
route-map ALL permit 10
exit
!
router bgp $asn
 bgp router-id $vtep
 no bgp ebgp-requires-policy
 no bgp default ipv4-unicast
 neighbor $peer remote-as $DUT_ASN
 address-family ipv4 unicast
  network $vtep/32
  neighbor $peer activate
  neighbor $peer route-map FROM-DUT in
  neighbor $peer route-map ALL out
 exit-address-family
 address-family l2vpn evpn
  neighbor $peer activate
  advertise-all-vni
EOF
    for p in $(v "$l" VNIS); do
      vni=${p#*:}
      cat <<EOF
  vni $vni
   route-target import $RT_ASN:$vni
   route-target export $RT_ASN:$vni
  exit-vni
EOF
    done
    cat <<EOF
 exit-address-family
exit
EOF
  } > "$d/frr.conf"
  chmod 755 "$d"; chmod 644 "$d"/*
}

pick_image(){ # sets IMAGE to the first of IMAGES (from the env file) present on this server, else the first pullable
  local i     # (a name without a registry is a local build: never pulled)
  IMAGE=""
  # shellcheck disable=SC2153
  for i in $IMAGES; do docker image inspect "$i" >/dev/null 2>&1 && { IMAGE=$i; return 0; }; done
  for i in $IMAGES; do
    case $i in */*) ;; *) continue ;; esac
    timeout 300 docker pull -q "$i" >/dev/null 2>&1 && { IMAGE=$i; return 0; }
  done
  return 1
}

leaf_up(){ # leaf_up <leaf>
  local l=$1 c pid ptf_if first=1 p vid vni a b mtu
  c=$(cname "$l"); ptf_if=$(v "$l" PTF_IF)
  # the uplink MTU follows the PTF port (never above the DUT port's 9100), so BGP segments always fit the path
  # (ip, not /sys: nsenter -n keeps the host's sysfs mount)
  mtu=$(pns ip -o link show dev "$ptf_if" | sed -n 's/.* mtu \([0-9]*\) .*/\1/p')
  [ -n "$mtu" ] || mtu=1500
  [ "$mtu" -gt 9100 ] && mtu=9100
  write_frr "$l"
  # FRR starts only once the netdevs exist (.netready), so zebra's first scan already sees br0 and the VNIs
  docker run -d --name "$c" --hostname "$c" --privileged --network none --restart no \
    -v "$WORK/$l:/etc/frr" --entrypoint /bin/sh "$IMAGE" \
    -c 'while [ ! -f /etc/frr/.netready ]; do sleep 1; done; exec /sbin/tini -- /usr/lib/frr/docker-start' \
    >/dev/null || die "docker run $c"
  pid=$(docker inspect -f '{{.State.Pid}}' "$c") || die "no pid for $c"
  [ "$pid" -gt 0 ] || die "$c is not running"
  a="evA$$$l"; b="evB$$$l"
  ip link add "$a" type veth peer name "$b" || die "veth for $l"
  ip link set "$a" netns "$PTF_PID"; pns ip link set "$a" name "evw_$l"
  ip link set "$b" netns "$pid"; nsenter -t "$pid" -n ip link set "$b" name ul0
  cx "$l" "
set -e
sysctl -w net.ipv4.ip_forward=1 net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 >/dev/null
sysctl -w net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1 >/dev/null
ip link set lo up
ip addr add $(v "$l" VTEP)/32 dev lo
ip link set ul0 mtu $mtu up
ip addr add $(v "$l" IP)/$(v "$l" PLEN) dev ul0
ip link add br0 type bridge vlan_filtering 1 vlan_default_pvid 0 mcast_snooping 0 ageing_time 720000
ip link set br0 up
ip link add hh type veth peer name hb
ip link set hh mtu $((mtu - 100)) up
ip link set hb mtu $((mtu - 100)) master br0 up
" || die "netdevs in $c"
  for p in $(v "$l" VNIS); do
    vid=${p%%:*}; vni=${p#*:}
    cx "$l" "
set -e
ip link add vx$vni type vxlan id $vni local $(v "$l" VTEP) dstport 4789 nolearning
ip link set vx$vni mtu $((mtu - 100)) master br0 up
bridge vlan add vid $vid dev vx$vni pvid untagged
bridge link set dev vx$vni learning off neigh_suppress off
if [ $first = 1 ]; then bridge vlan add vid $vid dev hb pvid untagged; else bridge vlan add vid $vid dev hb; fi
" || die "VNI $vni in $c"
    first=0
  done
  # the leaf's uplink to the PTF port (the other direction is wire_port's, once every leaf of the port is up);
  # remember the port's promisc flag so down can put it back (wire_port sets it, after every leaf of the port)
  pns ip -o link show "$ptf_if" | grep -q PROMISC && echo 1 > "$WORK/promisc_$l" || echo 0 > "$WORK/promisc_$l"
  pns sysctl -w "net.ipv6.conf.evw_$l.disable_ipv6=1" >/dev/null
  pns ip link set "evw_$l" mtu "$mtu" up
  pns tc qdisc add dev "evw_$l" ingress || die "tc qdisc on evw_$l"
  pns tc filter add dev "evw_$l" parent ffff: protocol all prio 1 matchall \
    action mirred egress redirect dev "$ptf_if" || die "tc mirred evw_$l -> $ptf_if"
  log "$c up: ul0 $(v "$l" IP)/$(v "$l" PLEN) -> $ptf_if, VTEP $(v "$l" VTEP), VNIs $(v "$l" VNIS)"
}

ptf_ifs(){ local l; for l in $LEAVES; do v "$l" PTF_IF; done | awk '!seen[$0]++'; }   # in LEAVES order, once each
port_leaves(){ local l; for l in $LEAVES; do [ "$(v "$l" PTF_IF)" = "$1" ] && echo "$l"; done; }

wire_port(){ # wire_port <ptf_if>: what the DUT sends on the port reaches every leaf on it
  local p=$1 ls l last acts=()
  ls=$(port_leaves "$p"); last=$(echo "$ls" | tail -1)
  pns ip link set "$p" promisc on up
  for l in $ls; do
    if [ "$l" = "$last" ]; then acts+=(action mirred egress redirect dev "evw_$l")
    else acts+=(action mirred egress mirror dev "evw_$l" pipe); fi
  done
  pns tc qdisc add dev "$p" ingress || die "tc qdisc on $p"
  pns tc filter add dev "$p" parent ffff: protocol all prio 1 matchall "${acts[@]}" \
    || die "tc mirred $p -> $(echo $ls)"
  log "$p -> $(for l in $ls; do printf 'evw_%s ' "$l"; done)"
}

leaf_down(){ # leaf_down <leaf>: quiet, every step tolerates a missing piece
  local l=$1 c ptf_if
  c=$(cname "$l"); ptf_if=$(v "$l" PTF_IF)
  if [ -n "${PTF_PID:-}" ] && [ "$PTF_PID" -gt 0 ] 2>/dev/null; then
    # the qdisc goes only if it is ours: our veth still exists, or its filter still names it
    if pns ip link show "evw_$l" >/dev/null 2>&1 || \
       pns tc filter show dev "$ptf_if" ingress 2>/dev/null | grep -q "evw_$l"; then
      pns tc qdisc del dev "$ptf_if" ingress 2>/dev/null
      pns ip link del "evw_$l" 2>/dev/null
      [ "$(cat "$WORK/promisc_$l" 2>/dev/null)" = 1 ] || pns ip link set "$ptf_if" promisc off 2>/dev/null
      log "unwired $ptf_if"
    fi
  fi
  docker rm -f "$c" >/dev/null 2>&1 && log "removed $c"
  rm -rf "${WORK:?}/$l" "$WORK/promisc_$l"
}

PTF_PID=$(ptf_pid || echo 0)
case $CMD in
up)
  [ "$PTF_PID" -gt 0 ] 2>/dev/null || die "PTF container $PTF is not running"
  for l in $LEAVES; do pns ip link show "$(v "$l" PTF_IF)" >/dev/null 2>&1 || die "$PTF has no $(v "$l" PTF_IF)"; done
  pick_image || die "no leaf image: none of [$IMAGES] is present and none could be pulled"
  echo "LEAF_IMAGE $IMAGE"
  for m in vxlan veth bridge sch_ingress cls_matchall act_mirred; do modprobe "$m" 2>/dev/null; done
  mkdir -p "$WORK"
  for l in $LEAVES; do leaf_down "$l" >/dev/null; done
  # a run that died while mapped to other PTF ports left their redirects behind (the PTF netns is this testbed's):
  # ingress redirects to an evw_ device, or to a deleted device (tc prints "device *"), are ours and dead
  for d in $(pns ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1); do
    pns tc filter show dev "$d" ingress 2>/dev/null | grep -qE "device (evw_|\*)" &&
      pns tc qdisc del dev "$d" ingress 2>/dev/null \
      && log "removed a stale leaf redirect on $d"
  done
  # an ingress qdisc left on a leaf's PTF port now is not ours; refuse before anything exists that `down` would undo
  for l in $LEAVES; do
    pns tc qdisc show dev "$(v "$l" PTF_IF)" ingress 2>/dev/null | grep -q ingress &&
      die "$(v "$l" PTF_IF) already has an ingress qdisc"
  done
  for l in $LEAVES; do leaf_up "$l"; done
  for p in $(ptf_ifs); do wire_port "$p"; done
  for l in $LEAVES; do touch "$WORK/$l/.netready"; done
  echo "LEAVES_UP"
  ;;
image)
  pick_image || die "no leaf image: none of [$IMAGES] is present and none could be pulled within 300 s each"
  echo "LEAF_IMAGE $IMAGE"
  ;;
down)
  for l in $LEAVES; do leaf_down "$l"; done
  rmdir "$WORK" 2>/dev/null
  echo "LEAVES_DOWN"
  ;;
status)
  for l in $LEAVES; do
    echo "== $(cname "$l")"
    cx "$l" "vtysh -c 'show bgp summary' -c 'show evpn vni' -c 'show evpn mac vni all'; bridge fdb show | grep -v permanent" 2>&1
  done
  ;;
fdb)
  op=${1:?add|del}; l=${2:?leaf}; mac=${3:?mac}; vid=${4:?vid}; dev=${5:-hb}; kind=${6:-dynamic}
  case $kind in dynamic|static) ;; *) die "fdb kind dynamic|static" ;; esac
  case $op in
    add) cx "$l" "bridge fdb replace $mac dev $dev master ${kind/static/static sticky} vlan $vid" ;;
    del) cx "$l" "bridge fdb del $mac dev $dev master vlan $vid" ;;
    *) die "fdb add|del" ;;
  esac
  ;;
vni)
  op=${1:?down|up}; l=${2:?leaf}; vni=${3:?vni}
  cx "$l" "ip link set vx$vni $op"
  ;;
vniadd)
  l=${1:?leaf}; vid=${2:?vid}; vni=${3:?vni}
  mtu=$(cx "$l" "ip -o link show dev hb" | sed -n 's/.* mtu \([0-9]*\) .*/\1/p')
  cx "$l" "
set -e
ip link add vx$vni type vxlan id $vni local $(v "$l" VTEP) dstport 4789 nolearning
ip link set vx$vni mtu ${mtu:-1400} master br0 up
bridge vlan add vid $vid dev vx$vni pvid untagged
bridge link set dev vx$vni learning off neigh_suppress off
bridge vlan add vid $vid dev hb
" || die "VNI $vni in $(cname "$l")"
  cx "$l" "vtysh -c 'configure terminal' -c 'router bgp $(v "$l" ASN)' -c 'address-family l2vpn evpn' \
    -c 'vni $vni' -c 'route-target import $RT_ASN:$vni' -c 'route-target export $RT_ASN:$vni'" \
    || die "FRR vni $vni in $(cname "$l")"
  ;;
vnidel)
  l=${1:?leaf}; vid=${2:?vid}; vni=${3:?vni}; rc=0
  cx "$l" "vtysh -c 'configure terminal' -c 'router bgp $(v "$l" ASN)' -c 'address-family l2vpn evpn' \
    -c 'no vni $vni'" || rc=1
  cx "$l" "ip link del vx$vni" || rc=1
  cx "$l" "bridge vlan del vid $vid dev hb" || rc=1
  exit $rc
  ;;
send)
  l=${1:?leaf}; dst=${2:?dst}; src=${3:?src}; count=${4:?count}; tag=${5:?tag}
  # the same frame shape as vxlan_l2_helpers.probe_frame: ethertype 0x0805, tag + '.' padding to 100 bytes
  docker exec "$(cname "$l")" python3 -c '
import socket, sys
dst, src, count, tag = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4]
mac = lambda m: bytes(int(x, 16) for x in m.split(":"))
payload = tag.encode() + b"." * max(0, 100 - len(tag))
hdr = mac(dst) + mac(src) + b"\x08\x05"
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind(("hh", 0))
for _ in range(count):
    s.send(hdr + payload)
print("SENT", count)
' "$dst" "$src" "$count" "$tag"
  ;;
fdbshow)
  l=${1:?leaf}; cx "$l" "bridge -j fdb show"
  ;;
show)
  l=${1:?leaf}; shift; cx "$l" "vtysh -c 'show $*'"
  ;;
svi)
  # add: on any failure, what was built is removed before the error
  op=${1:?add|del}; l=${2:?leaf}; vid=${3:?vid}
  undo="ip link del vl$vid 2>/dev/null; bridge vlan del vid $vid dev br0 self 2>/dev/null; true"
  case $op in
    add)
      vrf=${4:?vrf or default}; shift 4; modprobe 8021q 2>/dev/null
      for a in "$@"; do case $a in *[!0-9a-fA-F:./]*) die "svi: not an address/len: $a" ;; esac; done
      cx "$l" "
set -e
bridge vlan add vid $vid dev br0 self
ip link add link br0 name vl$vid type vlan id $vid
sysctl -w net.ipv6.conf.vl$vid.addr_gen_mode=1 net.ipv6.conf.vl$vid.disable_ipv6=0 >/dev/null
$([ "$vrf" = default ] || echo "ip link set vl$vid master $vrf")
ip link set vl$vid up
$(for a in "$@"; do case $a in *:*) echo "ip -6 addr add $a dev vl$vid nodad" ;; *) echo "ip addr add $a dev vl$vid" ;; esac; done)
" || { cx "$l" "$undo"; die "SVI vl$vid in $(cname "$l")"; }
      ;;
    del) cx "$l" "$undo" ;;
    *) die "svi add|del" ;;
  esac
  ;;
neigh)
  # add: all addresses or none (a failure removes the ones added before it)
  op=${1:?add|del}; l=${2:?leaf}; vid=${3:?vid}; mac=${4:?mac}; shift 4
  [ $# -gt 0 ] || die "neigh: no address"
  case $op in add|del) ;; *) die "neigh add|del" ;; esac
  done_ips=""
  for a in "$@"; do
    if [ "$op" = del ]; then cx "$l" "ip neigh del $a dev vl$vid 2>/dev/null; true"; continue; fi
    if ! cx "$l" "ip neigh replace $a lladdr $mac dev vl$vid nud permanent"; then
      for b in $done_ips; do cx "$l" "ip neigh del $b dev vl$vid 2>/dev/null; true"; done
      die "neigh $a in $(cname "$l")"
    fi
    done_ips="$done_ips $a"
  done
  ;;
l3vni)
  # add: on any failure, the FRR config and the netdevs are removed before the error
  op=${1:?add|del}; l=${2:?leaf}; vrf=${3:?vrf}; vid=${4:?vid}; vni=${5:?vni}; asn=$(v "$l" ASN)
  # FRR keeps a VRF's BGP instance while the VRF has its L3 VNI: the VNI goes first, in its own vtysh call
  frr_undo="rc=0; vtysh -c 'configure terminal' -c 'vrf $vrf' -c 'no vni $vni' || rc=1; \
vtysh -c 'configure terminal' -c 'no router bgp $asn vrf $vrf' || rc=1; exit \$rc"
  dev_undo="ip link del vl$vid 2>/dev/null; ip link del vx$vni 2>/dev/null; \
bridge vlan del vid $vid dev br0 self 2>/dev/null; ip link del $vrf 2>/dev/null; true"
  case $op in
    add)
      modprobe vrf 2>/dev/null; modprobe 8021q 2>/dev/null
      cx "$l" "
set -e
ip link add $vrf type vrf table $vid
ip link set $vrf up
ip link add vx$vni type vxlan id $vni local $(v "$l" VTEP) dstport 4789 nolearning
ip link set vx$vni master br0 up
bridge vlan add vid $vid dev vx$vni pvid untagged
bridge link set dev vx$vni learning off
bridge vlan add vid $vid dev br0 self
ip link add link br0 name vl$vid type vlan id $vid
ip link set vl$vid master $vrf up
" || { cx "$l" "$dev_undo"; die "L3 VNI $vni in $(cname "$l")"; }
      cx "$l" "vtysh -c 'configure terminal' -c 'vrf $vrf' -c 'vni $vni' -c 'exit-vrf' -c 'router bgp $asn vrf $vrf' \
        -c 'bgp router-id $(v "$l" VTEP)' -c 'no bgp network import-check' -c 'address-family l2vpn evpn' \
        -c 'advertise ipv4 unicast' -c 'advertise ipv6 unicast' -c 'route-target import $RT_ASN:$vni' \
        -c 'route-target export $RT_ASN:$vni'" \
        || { cx "$l" "$frr_undo"; cx "$l" "$dev_undo"; die "FRR L3 VNI $vni in $(cname "$l")"; }
      ;;
    del)
      rc=0
      cx "$l" "$frr_undo" || rc=1
      cx "$l" "$dev_undo" || rc=1
      exit $rc
      ;;
    *) die "l3vni add|del" ;;
  esac
  ;;
prefix)
  op=${1:?add|del}; l=${2:?leaf}; vrf=${3:?vrf}; p=${4:?prefix}; af=ipv4; no=""
  case $p in *:*) af=ipv6 ;; esac
  case $op in
    add) cx "$l" "ip route replace blackhole $p vrf $vrf" || die "blackhole $p in $vrf of $(cname "$l")" ;;
    del) no="no "; cx "$l" "ip route del blackhole $p vrf $vrf 2>/dev/null; true" ;;
    *) die "prefix add|del" ;;
  esac
  cx "$l" "vtysh -c 'configure terminal' -c 'router bgp $(v "$l" ASN) vrf $vrf' -c 'address-family $af unicast' \
    -c '${no}network $p'" || {
    [ "$op" = add ] && cx "$l" "ip route del blackhole $p vrf $vrf 2>/dev/null; true"
    die "prefix $op $p in $(cname "$l")"
  }
  ;;
ulmac)
  l=${1:?leaf}; cx "$l" "ip -o link show dev ul0" | sed -n 's/.* link\/ether \([0-9a-fA-F:]*\) .*/\1/p'
  ;;
vrfcheck)
  # the leaves share this kernel: a VRF device in a scratch namespace tells whether l3vni add can work
  modprobe vrf 2>/dev/null
  n="${PREFIX}_vrfcheck"
  ip netns del "$n" 2>/dev/null
  ip netns add "$n" || die "netns $n"
  if err=$(ip -n "$n" link add vrfcheck type vrf table 10 2>&1); then echo VRF_OK; else echo "VRF_MISSING $err"; fi
  ip netns del "$n"
  ;;
*) die "unknown command $CMD" ;;
esac
