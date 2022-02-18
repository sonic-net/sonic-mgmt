import os
import ipaddress
import pytest

from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert
from mclag_helpers import CONFIG_DB_BACKUP, check_partner_lag_member
from mclag_helpers import check_lags_on_ptf
from mclag_helpers import remove_vlan_members
from mclag_helpers import add_mclag_and_orphan_ports
from mclag_helpers import config_peer_link_and_keep_alive
from mclag_helpers import apply_mclag
from mclag_helpers import generate_and_verify_traffic
from mclag_helpers import mclag_intf_to_shutdown
from mclag_helpers import DUT1_INDEX, DUT2_INDEX
from mclag_helpers import TEMPLATE_DIR, MCLAG_DOMAINE_ID
from mclag_helpers import MCLAG_LOCAL_IP, MCLAG_PEER_IP
from mclag_helpers import MCLAG_PEER_LINK_IP_ACTIVE, MCLAG_PEER_LINK_IP_STANDBY
from mclag_helpers import CONFIG_DB_TEMP, CONFIG_DB_BACKUP, PTF_SCRIPT_TEMP, RENDERED_SCRIPT_PATH

pytestmark = [
    pytest.mark.topology('t0-mclag')
]


@pytest.fixture(scope="module", autouse=True)
def setup_mclag(duthost1, duthost2, ptfhost, mg_facts, collect, get_routes, tear_down):
    """
    Configurate mclag configuration on both DUTs and PTF
    Args:
        duthost1: DUT host object
        duthost2: DUT host object
        ptfhost: PTF host object
        mg_facts: Dict with minigraph facts for each DUT
        collect: Fixture which collects main info about link connection
        get_routes: Dict with advertised routes for each DUT
        tear_down: Fixture that performs tear down
    """
    duthost1.shell("cp {} {}".format(CONFIG_DB_TEMP, CONFIG_DB_BACKUP))
    duthost2.shell("cp {} {}".format(CONFIG_DB_TEMP, CONFIG_DB_BACKUP))

    ptf_map = {0: collect[duthost1.hostname]['ptf_map'], 1: collect[duthost2.hostname]['ptf_map']}

    ptf_extra_vars = {
        'ptf_map': ptf_map,
        'dut1_index': DUT1_INDEX,
        'dut2_index': DUT2_INDEX
        }

    ptfhost.host.options['variable_manager'].extra_vars.update(ptf_extra_vars)
    ptfhost.template(src=os.path.join(TEMPLATE_DIR, PTF_SCRIPT_TEMP), dest=RENDERED_SCRIPT_PATH, mode="u+rwx")
    ptfhost.shell(RENDERED_SCRIPT_PATH)

    check_lags_on_ptf(ptfhost, collect[duthost1.hostname]['mclag_interfaces'])

    remove_vlan_members(duthost1, mg_facts)
    remove_vlan_members(duthost2, mg_facts)

    add_mclag_and_orphan_ports(duthost1, collect, mg_facts)
    add_mclag_and_orphan_ports(duthost2, collect, mg_facts, ip_base=len(collect[duthost1.hostname]['all_links']))

    config_peer_link_and_keep_alive(duthost1, collect, mg_facts, MCLAG_LOCAL_IP, MCLAG_PEER_LINK_IP_ACTIVE)
    config_peer_link_and_keep_alive(duthost2, collect, mg_facts, MCLAG_PEER_IP, MCLAG_PEER_LINK_IP_STANDBY)

    cmd = "sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}"
    duthost2.shell(cmd.format(str(get_routes[duthost1.hostname][2]), MCLAG_PEER_LINK_IP_ACTIVE.ip))
    duthost1.shell(cmd.format(str(get_routes[duthost2.hostname][2]), MCLAG_PEER_LINK_IP_STANDBY.ip))

    apply_mclag(duthost1, collect, MCLAG_DOMAINE_ID, MCLAG_LOCAL_IP.ip, MCLAG_PEER_IP.ip)
    apply_mclag(duthost2, collect, MCLAG_DOMAINE_ID, MCLAG_PEER_IP.ip, MCLAG_LOCAL_IP.ip)

    #Save config to be persistent
    duthost1.shell('config save -y')
    duthost2.shell('config save -y')


class TestVerifyMclagStatus(object):
    def test_check_keepalive_link(self, duthosts):
        """
        Verify that mclag status on both MCLAG PEERs is OK
        """
        for dut in duthosts:
            status = dut.shell("mclagdctl dump state|grep keepalive")['stdout'].split(":")[-1].strip()
            pytest_assert(status == "OK", "MCLAG keepalive status should be OK on {}, actual state {}".format(dut.hostname, status))

    def test_check_teamd_system_id(self, duthost1, duthost2, collect):
        """
        Verify that mclag inetrfaces MAC on standby device is changed to active device MAC
        """
        for lag in collect[duthost1.hostname]['mclag_interfaces']:
            dut1_sys_id = duthost1.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            pytest_assert(dut1_sys_id == dut2_sys_id, "Mclag standby device {} system ID shoule be same as active device, but is {}".format(lag, dut2_sys_id))


class TestMclagMemberPortStatusChange(object):
    @pytest.fixture(scope="function")
    def pre_setup(self, duthost1, duthost2, ptfhost, collect, mg_facts, mclag_intf_num):
        mclag_info = mclag_intf_to_shutdown(duthost1, duthost2, mg_facts, collect, num_intf=mclag_intf_num)
        dut1_to_shut = [mclag_info[i]['member_to_shut'] for i in mclag_info if mclag_info[i]['link_down_on_dut'] == duthost1.hostname]
        dut2_to_shut = [mclag_info[i]['member_to_shut'] for i in mclag_info if mclag_info[i]['link_down_on_dut'] == duthost2.hostname]
        duthost1.shutdown_multiple(dut1_to_shut)
        duthost2.shutdown_multiple(dut2_to_shut)
        wait_until(120, 5, 0, check_partner_lag_member, ptfhost, mclag_info, "DOWN")

        yield mclag_info

        duthost1.no_shutdown_multiple(dut1_to_shut)
        duthost2.no_shutdown_multiple(dut2_to_shut)
        wait_until(90, 5, 0, check_partner_lag_member, ptfhost, mclag_info)


    def test_mclag_intf_status_down(self, duthost1, duthost2, ptfhost, ptfadapter, get_routes, collect, pre_setup,
                                    update_and_clean_ptf_agent):
        """
        Change mclag inetrfaces status on both peers, by shutting down PortChannel members, send packets to destinaion ip so that traffic would go trough PeerLink
        Verify that packets will be received
        """
        dut1_route = get_routes[duthost1.hostname][2]
        dut2_route = get_routes[duthost2.hostname][2]
        for indx, mclag_intf in enumerate(pre_setup):
            down_link_on_dut = pre_setup[mclag_intf]['link_down_on_dut']
            dst_route = ipaddress.IPv4Interface(dut1_route) if down_link_on_dut == duthost1.hostname else ipaddress.IPv4Interface(dut2_route)
            dst_ip = unicode(str(dst_route.ip + (indx + 1)))
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf, dst_ip, get_routes, collect, down_link_on_dut=down_link_on_dut)


    def test_mclag_intf_status_up(self, duthost1, duthost2, ptfhost, ptfadapter, get_routes, collect, mclag_intf_num,
                                  update_and_clean_ptf_agent):
        """
        Set all mclag inetrfaces members UP, send traffic to different destiontion ip
        Verify that packets will be received
        """
        dut1_route = get_routes[duthost1.hostname][2]
        dut2_route = get_routes[duthost2.hostname][2]
        for indx, mclag_intf in enumerate(collect[duthost1.hostname]['mclag_interfaces'][:mclag_intf_num]):
            dst_route = ipaddress.IPv4Interface(dut1_route) if indx % 2 == 0 else ipaddress.IPv4Interface(dut2_route)
            dst_ip = unicode(str(dst_route.ip + (indx + 1)))
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf, dst_ip, get_routes, collect)
