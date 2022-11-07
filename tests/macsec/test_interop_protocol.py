from time import sleep
import pytest
import logging
import re
import scapy.all as scapy
import ptf.testutils as testutils
from collections import Counter

from tests.common.utilities import wait_until
from tests.common.devices.eos import EosHost
from tests.common import config_reload
from macsec_helper import *
from macsec_config_helper import *
from macsec_platform_helper import *

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.macsec_required,
    pytest.mark.topology("t0", "t2"),
]


class TestInteropProtocol():
    '''
    Macsec interop with other protocols
    '''

    @pytest.mark.disable_loganalyzer
    def test_port_channel(self, duthost, profile_name, ctrl_links, wait_mka_establish):
        '''Verify lacp
        '''
        ctrl_port, _ = ctrl_links.items()[0]
        pc = find_portchannel_from_member(ctrl_port, get_portchannel(duthost))
        assert pc["status"] == "Up"

        disable_macsec_port(duthost, ctrl_port)
        # Remove ethernet interface <ctrl_port> from PortChannel interface <pc>
        duthost.command("sudo config portchannel {} member del {} {}".format(getns_prefix(duthost, ctrl_port), pc["name"], ctrl_port))
        assert wait_until(90, 1, 0, lambda: get_portchannel(
            duthost)[pc["name"]]["status"] == "Dw")

        enable_macsec_port(duthost, ctrl_port, profile_name)
        # Add ethernet interface <ctrl_port> back to PortChannel interface <pc>
        duthost.command("sudo config portchannel {} member add {} {}".format(getns_prefix(duthost, ctrl_port), pc["name"], ctrl_port))
        assert wait_until(90, 1, 0, lambda: find_portchannel_from_member(
            ctrl_port, get_portchannel(duthost))["status"] == "Up")

    @pytest.mark.disable_loganalyzer
    def test_lldp(self, duthost, ctrl_links, profile_name, wait_mka_establish):
        '''Verify lldp
        '''
        LLDP_ADVERTISEMENT_INTERVAL = 30  # default interval in seconds
        LLDP_HOLD_MULTIPLIER = 4  # default multiplier number
        LLDP_TIMEOUT = LLDP_ADVERTISEMENT_INTERVAL * LLDP_HOLD_MULTIPLIER

        # select one macsec link
        for ctrl_port, nbr in ctrl_links.items():
            assert wait_until(LLDP_TIMEOUT, LLDP_ADVERTISEMENT_INTERVAL, 0,
                            lambda: nbr["name"] in get_lldp_list(duthost))

            disable_macsec_port(duthost, ctrl_port)
            disable_macsec_port(nbr["host"], nbr["port"])
            wait_until(20, 3, 0,
                lambda: not duthost.iface_macsec_ok(ctrl_port) and
                        not nbr["host"].iface_macsec_ok(nbr["port"]))
            assert wait_until(LLDP_TIMEOUT, LLDP_ADVERTISEMENT_INTERVAL, 0,
                            lambda: nbr["name"] in get_lldp_list(duthost))

            enable_macsec_port(duthost, ctrl_port, profile_name)
            enable_macsec_port(nbr["host"], nbr["port"], profile_name)
            wait_until(20, 3, 0,
                lambda: duthost.iface_macsec_ok(ctrl_port) and
                        nbr["host"].iface_macsec_ok(nbr["port"]))
            assert wait_until(LLDP_TIMEOUT, LLDP_ADVERTISEMENT_INTERVAL, 0,
                            lambda: nbr["name"] in get_lldp_list(duthost))

    @pytest.mark.disable_loganalyzer
    def test_bgp(self, duthost, ctrl_links, upstream_links, profile_name, wait_mka_establish):
        '''Verify BGP neighbourship
        '''
        bgp_config = duthost.get_running_config_facts()[
            "BGP_NEIGHBOR"].values()[0]
        BGP_KEEPALIVE = int(bgp_config["keepalive"])
        BGP_HOLDTIME = int(bgp_config["holdtime"])
        BGP_TIMEOUT = 90

        def check_bgp_established(ctrl_port, up_link):
            command = "sonic-db-cli {} STATE_DB HGETALL 'NEIGH_STATE_TABLE|{}'".format(getns_prefix(duthost, ctrl_port), up_link["local_ipv4_addr"])
            fact = sonic_db_cli(duthost, command)
            logger.info("bgp state {}".format(fact))
            return fact["state"] == "Established"

        # Ensure the BGP sessions have been established
        for ctrl_port in ctrl_links.keys():
            assert wait_until(BGP_TIMEOUT, 5, 0,
                              check_bgp_established, ctrl_port, upstream_links[ctrl_port])

        # Check the BGP sessions are present after port macsec disabled
        for ctrl_port, nbr in ctrl_links.items():
            disable_macsec_port(duthost, ctrl_port)
            disable_macsec_port(nbr["host"], nbr["port"])
            wait_until(BGP_TIMEOUT, 3, 0,
                lambda: not duthost.iface_macsec_ok(ctrl_port) and
                        not nbr["host"].iface_macsec_ok(nbr["port"]))
            # BGP session should keep established even after holdtime
            assert wait_until(BGP_TIMEOUT, BGP_KEEPALIVE, BGP_HOLDTIME,
                              check_bgp_established, ctrl_port, upstream_links[ctrl_port])

        # Check the BGP sessions are present after port macsec enabled
        for ctrl_port, nbr in ctrl_links.items():
            enable_macsec_port(duthost, ctrl_port, profile_name)
            enable_macsec_port(nbr["host"], nbr["port"], profile_name)
            wait_until(BGP_TIMEOUT, 3, 0,
                lambda: duthost.iface_macsec_ok(ctrl_port) and
                        nbr["host"].iface_macsec_ok(nbr["port"]))
            # Wait PortChannel up, which might flap if having one port member
            wait_until(BGP_TIMEOUT, 5, 5, lambda: find_portchannel_from_member(
                ctrl_port, get_portchannel(duthost))["status"] == "Up")
            # BGP session should keep established even after holdtime
            assert wait_until(BGP_TIMEOUT, BGP_KEEPALIVE, BGP_HOLDTIME,
                              check_bgp_established, ctrl_port, upstream_links[ctrl_port])

    def test_snmp(self, duthost, ctrl_links, upstream_links, creds, wait_mka_establish):
        '''
        Verify SNMP request/response works across interface with macsec configuration
        '''
        if duthost.is_multi_asic:
            pytest.skip("The test is for Single ASIC devices")

        for ctrl_port, nbr in ctrl_links.items():
            if isinstance(nbr["host"], EosHost):
                result = nbr["host"].eos_command(
                    commands=['show snmp community | include name'])
                community = re.search(r'Community name: (\S+)',
                                      result['stdout'][0]).groups()[0]
            else:  # vsonic neighbour
                community = creds['snmp_rocommunity']

            up_link = upstream_links[ctrl_port]
            sysDescr = ".1.3.6.1.2.1.1.1.0"
            command = "docker exec snmp snmpwalk -v 2c -c {} {} {}".format(
                community, up_link["local_ipv4_addr"], sysDescr)
            assert not duthost.command(command)["failed"]
