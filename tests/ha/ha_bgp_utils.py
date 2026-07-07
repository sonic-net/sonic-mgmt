import json
import logging

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
