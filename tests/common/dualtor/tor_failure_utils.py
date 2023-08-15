"""
Tor Failure utilities to test switchover and MUX handling during:
Shutdown all BGP sessions on a ToR
Shutdown the LinkProber on a ToR
Blackhole all traffic on a ToR
Reboot a ToR
"""
from tests.common.reboot import reboot, SONIC_SSH_PORT, SONIC_SSH_REGEX, \
                                REBOOT_TYPE_COLD
import ipaddress
import pytest
import logging
import time
import contextlib
from tests.common.utilities import wait_until

logger = logging.getLogger(__name__)


@pytest.fixture
def kill_bgpd():
    """
    Kill bgpd process on a device
    """
    torhost = []

    def kill_bgpd(duthost, shutdown_all=True):
        torhost.append(duthost)
        bgp_neighbors = duthost.get_bgp_neighbors()
        up_bgp_neighbors = [k.lower() for k, v in list(bgp_neighbors.items()) if v["state"] == "established"]
        if shutdown_all and up_bgp_neighbors:
            logger.info("Kill bgpd process on {}".format(duthost.hostname))
            duthost.shell("pkill -9 bgpd")

    yield kill_bgpd

    time.sleep(1)
    for duthost in torhost:
        logger.info("Restarting BGP container on {}".format(duthost.hostname))
        duthost.shell("systemctl reset-failed bgp")
        duthost.shell("systemctl restart bgp")


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
            pass  # TODO

    yield tor_blackhole_traffic

    for duthost in torhost:
        lo_ipv4 = None
        config_facts = duthost.config_facts(
                            host=duthost.hostname, source="running"
                       )['ansible_facts']
        los = config_facts.get("LOOPBACK_INTERFACE", {})
        logger.info("Loopback IPs: {}".format(los))
        for k, v in list(los.items()):
            if k == "Loopback0":
                for ipstr in list(v.keys()):
                    ip = ipaddress.ip_interface(ipstr)
                    if ip.version == 4:
                        lo_ipv4 = ip

        duthost.shell("ip -4 route add 0.0.0.0/0 nexthop via {}"
                      .format(lo_ipv4.ip))


@pytest.fixture
def reboot_tor(localhost, wait_for_device_reachable, wait_for_mux_container):
    """
    Reboot TOR
    """
    torhost = []

    def reboot_tor(duthost, reboot_type=REBOOT_TYPE_COLD):
        torhost.append(duthost)
        logger.info("Issuing reboot of type {} on {}"
                    .format(reboot_type, duthost.hostname))
        reboot(duthost, localhost, reboot_type=reboot_type, wait_for_ssh=False)

    yield reboot_tor
    # TODO Add IO check capability

    for duthost in torhost:
        wait_for_device_reachable(duthost)
    for duthost in torhost:
        wait_for_mux_container(duthost)


@pytest.fixture
def wait_for_device_reachable(localhost):
    """
    Returns a function that waits for a device to become reachable over SSH
    """

    def wait_for_device_reachable(duthost, timeout=300):
        dut_ip = duthost.mgmt_ip
        logger.info("Waiting for ssh to startup on {}"
                    .format((duthost.hostname)))
        res = localhost.wait_for(host=dut_ip,
                                 port=SONIC_SSH_PORT,
                                 state='started',
                                 search_regex=SONIC_SSH_REGEX,
                                 delay=10,
                                 timeout=timeout,
                                 module_ignore_errors=True)
        if res.is_failed or ('msg' in res and 'Timeout' in res['msg']):
            raise Exception("DUT {} did not startup after reboot"
                            .format((duthost.hostname)))
        logger.info("SSH started on {}".format((duthost.hostname)))

    return wait_for_device_reachable


def check_mux_feature(duthost):
    """
    Check output of 'show feature status mux' to find if feature is enabled.
    For dualtor:
    $ show feature status mux
    Feature    State    AutoRestart
    ---------  -------  -------------
    mux        enabled  enabled

    For non-dualtor:
    $ show feature status mux
    Feature    State            AutoRestart
    ---------  ---------------  -------------
    mux        always_disabled  enabled
    """
    output = duthost.shell("show feature status mux")['stdout_lines']
    return "disabled" not in str(output)


def check_mux_container(duthost):
    output = duthost.shell("docker inspect -f '{{ '{{' }} .State.Status {{ '}}' }}' mux")['stdout_lines']
    return "running" in str(output)


@pytest.fixture
def wait_for_mux_container(duthost):
    """
    Returns a function that waits for mux container to be available on a device
    """

    def wait_for_mux_container(duthost, timeout=100, check_interval=1):
        if not wait_until(timeout, check_interval, 0, check_mux_feature, duthost):
            logger.info("mux feature is not enabled on {}".format((duthost.hostname)))
            return

        logger.info("Waiting for mux container to start on {}".format((duthost.hostname)))

        if not wait_until(timeout, check_interval, 0, check_mux_container, duthost):
            # Could not detect mux container so raise exception
            raise Exception("Mux container is not up after {} seconds".format(timeout))

    return wait_for_mux_container


@contextlib.contextmanager
def shutdown_bgp_sessions_on_duthost():
    """Shutdown all BGP sessions on a device"""
    duthosts = []

    def _shutdown_bgp_sessions_on_duthost(duthost):
        duthosts.append(duthost)
        logger.info("Shutdown all BGP sessions on {}".format(duthost.hostname))
        duthost.shell("config bgp shutdown all")

    try:
        yield _shutdown_bgp_sessions_on_duthost
    finally:
        time.sleep(1)
        for duthost in duthosts:
            logger.info("Startup all BGP sessions on {}".format(duthost.hostname))
            duthost.shell("config bgp startup all")


@pytest.fixture
def shutdown_bgp_sessions():
    """Shutdown all bgp sessions on a device."""
    with shutdown_bgp_sessions_on_duthost() as shutdown_util:
        yield shutdown_util
