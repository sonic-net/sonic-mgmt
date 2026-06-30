import json
import logging

from tests.common.devices.eos import EosHost
from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)


def _get_t2_peer_ips(duthost):
    """Return DUT-side BGP peer IPs whose remote description identifies them as T2."""
    out = duthost.shell('vtysh -c "show ip bgp summary json"')["stdout"]
    summary = json.loads(out)
    peers = summary.get("ipv4Unicast", {}).get("peers", {})
    return [
        ip for ip, p in peers.items()
        if "T2" in (p.get("hostname") or "") or "T2" in (p.get("desc") or "")
    ]


def check_vip_advertised_to_t2(duthosts, vip):
    """Verify the DUT advertises the VIP /32 prefix to every T2 BGP peer."""
    vip_prefix = "{}/32".format(vip)
    # DutHosts proxies any attribute name to its node list, so hasattr() lies.
    # A real single host has a string `hostname`; DutHosts.hostname is a method.
    if isinstance(getattr(duthosts, "hostname", None), str):
        duts = [duthosts]
    else:
        duts = list(duthosts)

    missing = []
    found_any = False
    for duthost in duts:
        t2_peer_ips = _get_t2_peer_ips(duthost)
        if not t2_peer_ips:
            logger.info("%s: no T2 BGP peers found", duthost.hostname)
            continue
        for peer_ip in t2_peer_ips:
            cmd = 'vtysh -c "show ip bgp neighbors {} advertised-routes json"'.format(peer_ip)
            res = duthost.shell(cmd, module_ignore_errors=True)
            adv = {}
            if not res.get("failed"):
                try:
                    adv = json.loads(res["stdout"]).get("advertisedRoutes", {})
                except ValueError:
                    adv = {}
            if vip_prefix in adv:
                found_any = True
                logger.info("%s -> %s: VIP %s advertised", duthost.hostname, peer_ip, vip_prefix)
            else:
                missing.append("{}->{}".format(duthost.hostname, peer_ip))

    pytest_assert(found_any and not missing,
                  "VIP {} not advertised to T2 peers: {}".format(vip_prefix, missing))
    logger.info("VIP %s advertised to all T2 peers on %s",
                vip_prefix, [d.hostname for d in duts])


def get_dut_t2_local_addrs(duthost):
    """Return the DUT's local IPv4 BGP addresses used to peer with its T2 neighbors.

    These are the IPs the T2 VMs see as the remote peer for their BGP session
    with this DUT, i.e. what `peerId` / `peerAddr` would show on the T2 side.
    """
    cfg = duthost.get_running_config_facts()
    addrs = []
    for peer_cfg in cfg.get("BGP_NEIGHBOR", {}).values():
        if not peer_cfg.get("name", "").endswith("T2"):
            continue
        local = peer_cfg.get("local_addr") or ""
        if local and ":" not in local:
            addrs.append(local)
    return addrs


def _vip_path_peer_ids_on_vm(host, vip_prefix):
    """Return the set of BGP peer IPs from which a neighbor VM has received `vip_prefix`.

    Dispatches on host type (Arista cEOS vs vsonic/FRR). Empty set means the
    prefix isn't in the VM's BGP RIB at all, or the query failed.
    """
    peer_ids = set()
    try:
        if isinstance(host, EosHost):
            cmd = "show ip bgp {} | json".format(vip_prefix)
            out = host.eos_command(commands=[cmd], module_ignore_errors=True)
            stdouts = out.get("stdout", [])
            if not stdouts:
                return peer_ids
            data = stdouts[0]
            if isinstance(data, str):
                data = json.loads(data)
            for vrf in data.get("vrfs", {}).values():
                for entry in vrf.get("bgpRouteEntries", {}).values():
                    for path in entry.get("bgpRoutePaths", []):
                        peer = path.get("peerEntry", {}).get("peerAddr")
                        if peer:
                            peer_ids.add(peer)
        else:
            cmd = 'vtysh -c "show ip bgp {} json"'.format(vip_prefix)
            res = host.shell(cmd, module_ignore_errors=True)
            if res.get("failed"):
                return peer_ids
            try:
                data = json.loads(res.get("stdout", ""))
            except ValueError:
                return peer_ids
            for path in data.get("paths", []):
                peer = path.get("peerId")
                if peer:
                    peer_ids.add(peer)
    except Exception as e:
        logger.info("BGP query on %s failed: %s",
                    getattr(host, "hostname", host), e)
    return peer_ids


def is_vip_withdrawn_from_t2_vm(nbrhosts, rebooted_dut_t2_local_ips, vip):
    """Return True iff no T2 neighbor VM still has `vip`/32 received from any
    of the rebooted DUT's local BGP IPs.

    Args:
        nbrhosts: pytest nbrhosts dict (vm_name -> {"host": ..., ...}).
        rebooted_dut_t2_local_ips: list of IPs that T2 VMs use as the peer
            address for their BGP session with the rebooted DUT (collected
            BEFORE reboot via get_dut_t2_local_addrs()).
        vip: VIP address (no prefix length).
    """
    vip_prefix = "{}/32".format(vip)
    rebooted_ips = set(rebooted_dut_t2_local_ips)
    if not rebooted_ips:
        logger.warning("No rebooted-DUT T2 local IPs provided; nothing to check")
        return True

    saw_via_rebooted = False
    for vm_name, info in nbrhosts.items():
        if "T2" not in vm_name:
            continue
        host = info.get("host") if isinstance(info, dict) else None
        if host is None:
            continue

        peer_ids = _vip_path_peer_ids_on_vm(host, vip_prefix)
        overlap = peer_ids & rebooted_ips
        if overlap:
            logger.info("VM %s still has VIP %s received from rebooted-DUT IP(s) %s",
                        vm_name, vip_prefix, sorted(overlap))
            saw_via_rebooted = True
        else:
            other = peer_ids - rebooted_ips
            logger.info("VM %s: VIP %s no longer received from rebooted-DUT IPs "
                        "(other sources=%s)", vm_name, vip_prefix, sorted(other))

    return not saw_via_rebooted


def _ha_bgp_oper(duthost, start=True):

    cmd = 'show ip bgp summary'
    parse_result = duthost.show_and_parse(cmd)
    logger.info(f"{duthost.hostname} BGP neighbor parsed as {parse_result}")
    # Column name is misspelled in the show command: neighbhor instead of neighbor
    neighbor_ips = {entry['neighbhor'] for entry in parse_result}
    # Shutdown each BGP neighbor
    logger.info(f"{duthost.hostname} BGP neighbor list {neighbor_ips}")
    for neighbor_ip in neighbor_ips:
        if start:
            bgp_command = f'config bgp start neighbor {neighbor_ip}'
        else:
            bgp_command = f'config bgp shutdown neighbor {neighbor_ip}'

        logger.info(f"BGP neighbor command: {bgp_command}")
        duthost.shell(bgp_command)


def ha_bgp_shutdown(duthost):

    return _ha_bgp_oper(duthost, False)


def ha_bgp_start(duthost):

    return _ha_bgp_oper(duthost, True)
