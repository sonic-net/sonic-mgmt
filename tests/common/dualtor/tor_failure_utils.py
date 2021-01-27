"""
Tor Failure utilities to test switchover and MUX handling during:
Shutdown all BGP sessions on a ToR
Shutdown the LinkProber on a ToR
Blackhole all traffic on a ToR
Reboot a ToR
"""
from tests.common.reboot import *
import ipaddress
import pytest
import logging
import time

logger = logging.getLogger(__name__)


@pytest.fixture
def shutdown_tor_bgp():
    """
    Shutdown all BGP sessions 
    """
    torhost = []
    def shutdown_tor_bgp(duthost, shutdown_all=True):
        torhost.append(duthost)
        bgp_neighbors = duthost.get_bgp_neighbors()
        up_bgp_neighbors = [ k.lower() for k, v in bgp_neighbors.items() if v["state"] == "established" ]
        if shutdown_all and up_bgp_neighbors:
            logger.info("Shutdown BGP sessions on {}".format(duthost.hostname))
            duthost.shell("config bgp shutdown all")

    yield shutdown_tor_bgp

    time.sleep(1)
    for duthost in torhost:
        logger.info("Starting BGP sessions on {}".format(duthost.hostname))
        duthost.shell("config bgp startup all")


@pytest.fixture
def shutdown_tor_heartbeat():
    """
    Shutdown the LinkProber
    """
    torhost = []
    def shutdown_tor_heartbeat(duthost):
        # TODO - verify support after LinkProber submodule is ready
        torhost.append(duthost)
        duthost.shell("systemctl stop mux")
        duthost.shell("systemctl disable mux")

    yield shutdown_tor_heartbeat

    for duthost in torhost:
        duthost.shell("systemctl start mux")
        duthost.shell("systemctl enable mux")


@pytest.fixture
def tor_blackhole_traffic():
    """
    Configure tor to blackhole all traffic
    Install a blackhole route
    """
    torhost = []
    def tor_blackhole_traffic(duthost, kernel=False, asic=False):
        torhost.append(duthost)
        if asic:
            duthost.shell("ip route del 0.0.0.0/0")
        elif kernel:
            pass # TODO

    yield tor_blackhole_traffic

    for duthost in torhost:
        lo_ipv4 = None
        lo_ipv6 = None
        config_facts = duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']
        los = config_facts.get("LOOPBACK_INTERFACE", {})
        logger.info("Loopback IPs: {}".format(los))
        for k, v in los.items():
            if k == "Loopback0":
                for ipstr in v.keys():
                    ip = ipaddress.ip_interface(ipstr)
                    if ip.version == 4:
                        lo_ipv4 = ip
                    elif ip.version == 6:
                        lo_ipv6 = ip

        duthost.shell("ip -4 route add 0.0.0.0/0 nexthop via {}".format(lo_ipv4.ip))


@pytest.fixture
def reboot_tor(localhost):
    """
    Reboot TOR
    """
    torhost = []
    def reboot_tor(duthost, reboot_type=REBOOT_TYPE_COLD):
        torhost.append(duthost)
        logger.info("Issuing reboot of type {} on {}".format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type, wait_for_ssh=False)

    yield reboot_tor
    # TODO Add IO check capability

    for duthost in torhost:
        dut_ip = duthost.setup()['ansible_facts']['ansible_eth0']['ipv4']['address']
        logger.info("Waiting for ssh to startup on {}".format((duthost.hostname)))
        res = localhost.wait_for(host=dut_ip,
                                port=SONIC_SSH_PORT,
                                state='started',
                                search_regex=SONIC_SSH_REGEX,
                                delay=10,
                                timeout=300,
                                module_ignore_errors=True)
        if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
            raise Exception("DUT {} did not startup after reboot".format((duthost.hostname)))
        logger.info("SSH started on {}".format((duthost.hostname)))
