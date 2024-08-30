import pytest
import os
import ipaddress
import logging
import random

logger = logging.getLogger(__name__)

TEMPLATES_DIR = "vxlan/templates/"
VNET_PING_DST_DIR = "/opt"
VNET_PING_RESPONDER_PY = "vnet_ping_responder.py"
VNET_PING_CONF = "vnet_ping_responder.conf"
SUPERVISOR_CONFIG_DIR = "/etc/supervisor/conf.d/"

# Any IP in this list on ptf container will not receive a reply
VIP_BLOCK_LIST = "/tmp/vnet_monitor_block_ips.txt"


@pytest.fixture(scope="module")
def setup_vnet_ping_responder(ptfhost):
    """
    Setup VNET ping responder on ptf container.

 ┌─────────────────┐         1 VNET ping request     ┌──────────────────┐
 │                 │◄────────────────────────────────┤                  │
 │      PTF        │                                 │       DUT        │
 │                 ├────────────────────────────────►│                  │
 └─────────────────┘         2 VNET ping reply       └──────────────────┘
    """

    logger.info("Setup vnet_ping_responder on ptf container")
    ptfhost.copy(
        src=os.path.join(TEMPLATES_DIR, VNET_PING_CONF),
        dest=os.path.join(SUPERVISOR_CONFIG_DIR, VNET_PING_CONF)
        )
    ptfhost.copy(
        src=os.path.join("vxlan", VNET_PING_RESPONDER_PY),
        dest=os.path.join(VNET_PING_DST_DIR, VNET_PING_RESPONDER_PY)
        )
    ptfhost.shell("touch {}".format(VIP_BLOCK_LIST))
    ptfhost.shell("supervisorctl update")
    ptfhost.shell("supervisorctl start vnet_ping_responder")

    yield

    logger.info("Remove vnet_ping_responder from ptf container")
    ptfhost.shell("supervisorctl stop vnet_ping_responder")
    ptfhost.file(
        path=os.path.join(SUPERVISOR_CONFIG_DIR, VNET_PING_CONF),
        state="absent"
        )
    ptfhost.file(
        path=os.path.join(VNET_PING_DST_DIR, VNET_PING_RESPONDER_PY),
        state="absent"
        )
    ptfhost.file(
        path=VIP_BLOCK_LIST,
        state="absent"
        )


def block_reply_for_vip(ptfhost, vip_to_block):
    """
    Block reply for a VIP on ptf container.
    """
    logger.info("Block reply for VIP {} on ptf container".format(vip_to_block))
    vip_to_block = ipaddress.ip_network(vip_to_block, strict=False).network_address
    ptfhost.shell("echo {} >> {}".format(vip_to_block, VIP_BLOCK_LIST))


def unblock_reply_for_vip(ptfhost, vip_to_unblock):
    """
    Unblock reply for a VIP on ptf container.
    """
    logger.info("Unblock reply for VIP {} on ptf container".format(vip_to_unblock))
    vip_to_unblock = ipaddress.ip_network(vip_to_unblock, strict=False).network_address
    ptfhost.shell("sed -i '/{}/d' {}".format(vip_to_unblock, VIP_BLOCK_LIST))


@pytest.fixture(scope="module")
def setup_info(rand_selected_dut, tbinfo):
    config = {}
    mg_facts = rand_selected_dut.get_extended_minigraph_facts(tbinfo)
    portchannels = list(mg_facts['minigraph_portchannels'].keys())
    # Randomly select a portchannel
    rand_portchannel = random.choice(portchannels)
    config['portchannel'] = rand_portchannel
    # Get the IP address of the neighbor
    output = rand_selected_dut.show_and_parse("show ip interface")
    for itfs in output:
        if itfs['interface'] == rand_portchannel:
            config['portchannel_ipv4_neigh'] = itfs['neighbor ip']
            break
    return config


def add_vnet_ping_task(duthost, t0_loopback, vip_to_ping,
                       packet_type="vxlan", interval=1000, multiplier=3, overlay_mac="00:AA:BB:CC:DD:EE"):
    """
    Add a VNET ping task.
    """
    logger.info("Add VNET ping task for VIP {}".format(vip_to_ping))
    cmd = "redis-cli -n 0 hmset VNET_MONITOR_TABLE:{}:{} \
        packet_type {} \
        interval {} \
        multiplier {} \
        overlay_mac {} \
        ".format(t0_loopback, vip_to_ping, packet_type, interval, multiplier, overlay_mac)
    duthost.shell(cmd)


def remove_vnet_ping_task(duthost, t0_loopback, vip_to_ping):
    """
    Remove a VNET ping task.
    """
    logger.info("Remove VNET ping task for VIP {}".format(vip_to_ping))
    cmd = "redis-cli -n 0 del VNET_MONITOR_TABLE:{}:{}".format(t0_loopback, vip_to_ping)
    duthost.shell(cmd)


def verity_vnet_monitor_state(duthost, t0_loopback, vip_to_ping, expected_state):
    """
    Verify the state of a VNET ping task in STATE_DB.
    """
    logger.info("Verify VNET ping task for VIP {}".format(vip_to_ping))
    cmd = "redis-cli -n 6 hget \'VNET_MONITOR_TABLE|{}|{}\' state".format(t0_loopback, vip_to_ping)
    res = duthost.shell(cmd)["stdout"]
    return (res.strip() == expected_state)
