import os
import ipaddress
import pytest
import time

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
from mclag_helpers import check_keepalive_link
from mclag_helpers import gen_list_pcs_to_check
from mclag_helpers import DUT1_INDEX, DUT2_INDEX
from mclag_helpers import TEMPLATE_DIR, MCLAG_DOMAINE_ID
from mclag_helpers import MCLAG_LOCAL_IP, MCLAG_PEER_IP
from mclag_helpers import MCLAG_PEER_LINK_IP_ACTIVE, MCLAG_PEER_LINK_IP_STANDBY
from mclag_helpers import CONFIG_DB_TEMP, CONFIG_DB_BACKUP, PTF_SCRIPT_TEMP, RENDERED_SCRIPT_PATH
from mclag_helpers import DEFAULT_SESSION_TIMEOUT, NEW_SESSION_TIMEOUT

pytestmark = [
    pytest.mark.topology('t0-mclag')
]


@pytest.fixture(scope="module", autouse=True)
def setup_mclag(duthost1, duthost2, ptfhost, mg_facts, collect, get_routes, keep_and_peer_link_member,
                tear_down):
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
    feature_status1, _ = duthost1.get_feature_status()
    feature_status2, _ = duthost2.get_feature_status()
    if 'iccpd' not in feature_status1 or 'iccpd' not in feature_status2:
        pytest.skip("iccpd feature is not present in Sonic image")

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

    config_peer_link_and_keep_alive(duthost1, keep_and_peer_link_member, MCLAG_LOCAL_IP, MCLAG_PEER_LINK_IP_ACTIVE)
    config_peer_link_and_keep_alive(duthost2, keep_and_peer_link_member, MCLAG_PEER_IP, MCLAG_PEER_LINK_IP_STANDBY)

    cmd = "sonic-db-cli CONFIG_DB hmset 'STATIC_ROUTE|{}' nexthop {}"
    duthost2.shell(cmd.format(str(get_routes[duthost1.hostname][2]), MCLAG_PEER_LINK_IP_ACTIVE.ip))
    duthost1.shell(cmd.format(str(get_routes[duthost2.hostname][2]), MCLAG_PEER_LINK_IP_STANDBY.ip))

    apply_mclag(duthost1, collect, MCLAG_DOMAINE_ID, MCLAG_LOCAL_IP.ip, MCLAG_PEER_IP.ip)
    apply_mclag(duthost2, collect, MCLAG_DOMAINE_ID, MCLAG_PEER_IP.ip, MCLAG_LOCAL_IP.ip)

    #Save config to be persistent
    duthost1.shell('config save -y')
    duthost2.shell('config save -y')

    duthost1.critical_services.append('iccpd')
    duthost2.critical_services.append('iccpd')


class TestVerifyMclagStatus(object):
    def test_check_keepalive_link(self, duthost1, duthost2):
        """
        Verify that mclag status on both MCLAG PEERs is OK
        """
        check_keepalive_link(duthost1, duthost2, 'OK')

    def test_check_teamd_system_id(self, duthost1, duthost2, collect):
        """
        Verify that mclag inetrfaces MAC on standby device is changed to active device MAC
        """
        for lag in collect[duthost1.hostname]['mclag_interfaces']:
            dut1_sys_id = duthost1.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            pytest_assert(dut1_sys_id == dut2_sys_id, "Mclag standby device {} system ID shoule be same as active device, but is {}".format(lag, dut2_sys_id))


class TestMclagMemberPortStatusChange(object):
    @pytest.fixture()
    def pre_setup(self, duthost1, duthost2, ptfhost, collect, mg_facts, mclag_intf_num):
        mclag_info = mclag_intf_to_shutdown(duthost1, duthost2, mg_facts, collect, num_intf=mclag_intf_num)
        dut1_to_shut = [mclag_info[i]['member_to_shut'] for i in mclag_info if mclag_info[i]['link_down_on_dut'] == duthost1.hostname]
        dut2_to_shut = [mclag_info[i]['member_to_shut'] for i in mclag_info if mclag_info[i]['link_down_on_dut'] == duthost2.hostname]
        duthost1.shutdown_multiple(dut1_to_shut)
        duthost2.shutdown_multiple(dut2_to_shut)
        pytest_assert(wait_until(140, 5, 0, check_partner_lag_member, ptfhost, mclag_info, "DOWN"),
                      "Expected Lag partner members isn't down")

        yield mclag_info

        duthost1.no_shutdown_multiple(dut1_to_shut)
        duthost2.no_shutdown_multiple(dut2_to_shut)
        pytest_assert(wait_until(120, 5, 0, check_partner_lag_member, ptfhost, mclag_info, "UP"),
                      "Expected Lag partner members isn't up")


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
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf, dst_ip,
                                        duthost1.facts["router_mac"], get_routes, collect, down_link_on_dut=down_link_on_dut)


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
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf, dst_ip,
                                        duthost1.facts["router_mac"], get_routes, collect)


class TestKeepAliveStatusChange(object):
    @pytest.fixture()
    def shutdown_keepalive_and_restore(self, duthost1, keep_and_peer_link_member):
        """
        Shutdown keepalive link and restore it on teardown
        """
        duthost1.shutdown(keep_and_peer_link_member[duthost1.hostname]['keepalive'])
        # default session-timeout is 15 sec
        time.sleep(DEFAULT_SESSION_TIMEOUT)

        yield

        time.sleep(DEFAULT_SESSION_TIMEOUT)
        duthost1.no_shutdown(keep_and_peer_link_member[duthost1.hostname]['keepalive'])


    def test_keepalive_link_down(self, duthost1, duthost2, collect, ptfhost, ptfadapter, get_routes,
                                 mclag_intf_num, shutdown_keepalive_and_restore, update_and_clean_ptf_agent):
        """
        Verify data forwarding is correct when keepalive link is in down state
        """
        dut1_route = get_routes[duthost1.hostname][2]
        dut2_route = get_routes[duthost2.hostname][2]

        # Verify that standby device changed its MAC to default MAC on MCLAG inetrfaces
        for lag in collect[duthost1.hostname]['mclag_interfaces']:
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            pytest_assert(duthost2.facts["router_mac"] == dut2_sys_id,
                          "MCLAG interface MAC on standby device shoudl be it's default MAC {}; lag = {}, mac = {}".format(duthost2.facts["router_mac"], lag, dut2_sys_id))

        # Verify that keepalive link status will be ERROR after keepalive link is set down
        check_keepalive_link(duthost1, duthost2, 'ERROR')

        # Verify that traffic will be able to reach both uplink, due to traffic will go trough active device
        # and reach standby by PeerLink
        for indx, mclag_intf in enumerate(collect[duthost1.hostname]['mclag_interfaces'][:mclag_intf_num]):
            dst_route = ipaddress.IPv4Interface(dut1_route) if indx % 2 == 0 else ipaddress.IPv4Interface(dut2_route)
            dst_ip = unicode(str(dst_route.ip + (indx + 1)))
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf, dst_ip,
                                        duthost1.facts["router_mac"], get_routes, collect)


    def test_session_timeout(self, duthost1, duthost2, collect, change_session_timeout):
        """
        Verify that MCLAG session_timeout can be changed
        """
        duthost2_router_mac = duthost2.facts["router_mac"]
        # Wait default session timeout and verify that MCLAG status still will be OK
        time.sleep(DEFAULT_SESSION_TIMEOUT)
        check_keepalive_link(duthost1, duthost2, 'OK')

        # Wait new session timeout and verify that MCLAG status will be ERROR
        # and that MAC on standby will be changed
        time.sleep((NEW_SESSION_TIMEOUT - DEFAULT_SESSION_TIMEOUT) + 1)
        check_keepalive_link(duthost1, duthost2, 'ERROR')

        for lag in collect[duthost1.hostname]['mclag_interfaces']:
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            pytest_assert(duthost2_router_mac == dut2_sys_id,
                          "MCLAG interface MAC on standby device shoudl be it's default MAC {}; lag = {}, mac = {}".format(duthost2_router_mac, lag, dut2_sys_id))


class TestActiveDeviceStatusChange():
    @pytest.fixture()
    def pre_active_setup(self, duthost1, collect, mg_facts, ptfhost, keep_and_peer_link_member):
        """
        Shutdown mclag interfaces and reboot active device, to simulate loss of active device
        """
        check_portchannels = gen_list_pcs_to_check(duthost1, mg_facts, collect)
        ports_to_shut = check_portchannels.keys() + [keep_and_peer_link_member[duthost1.hostname]['keepalive']] + \
                        [keep_and_peer_link_member[duthost1.hostname]['peerlink']]
        duthost1.shutdown_multiple(ports_to_shut)
        duthost1.shell("config save -y")
        duthost1.shell("sudo /sbin/reboot", module_ignore_errors=True)
        pytest_assert(wait_until(140, 5, 0, check_partner_lag_member, ptfhost, check_portchannels, "DOWN"),
                      "Expected partner Lag members isnt down")

        yield

        duthost1.no_shutdown_multiple(ports_to_shut)
        duthost1.shell("config save -y")
        pytest_assert(wait_until(120, 5, 0, check_partner_lag_member, ptfhost, check_portchannels, "UP"),
                                 "Expected partner Lag members isnt up")
        pytest_assert(wait_until(300, 20, 0, duthost1.critical_services_fully_started),
                      "All critical services should fully started!{}".format(duthost1.critical_services))


    def test_active_down(self, duthost1, duthost2, ptfadapter, ptfhost, collect, get_routes, mclag_intf_num,
                         update_and_clean_ptf_agent, pre_active_setup):
        """
        Verify behavior when active device is lost, traffic should reach only direct uplink of standby
        """
        dst_route1 = ipaddress.IPv4Interface(get_routes[duthost1.hostname][2])
        dst_route2 = ipaddress.IPv4Interface(get_routes[duthost2.hostname][2])

        status = duthost2.shell("mclagdctl dump state|grep keepalive")['stdout'].split(":")[-1].strip()
        pytest_assert(status == 'ERROR', "Keepalive status should be ERROR, not {}".format(status))

        for lag in collect[duthost2.hostname]['mclag_interfaces']:
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            pytest_assert(duthost2.facts["router_mac"] == dut2_sys_id,
                          "MCLAG interface MAC on standby device shoudl be it's default MAC {}; lag = {}, mac = {}".format(duthost2.facts["router_mac"], lag, dut2_sys_id))

        for indx, mclag_intf in enumerate(collect[duthost1.hostname]['mclag_interfaces'][:mclag_intf_num]):
            dst_ip1 = unicode(str(dst_route1.ip + (indx + 1)))
            dst_ip2 = unicode(str(dst_route2.ip + (indx + 1)))
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf,
                                        dst_ip2, duthost2.facts["router_mac"], get_routes, collect)
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf,
                                        dst_ip1, duthost2.facts["router_mac"], get_routes, collect, pkt_action='DROP')


class TestStandByDeviceStatusChange():
    @pytest.fixture()
    def pre_standby_setup(self, duthost2, collect, mg_facts, ptfhost, keep_and_peer_link_member):
        """
        Shutdown mclag interfaces and reboot standby device, to simulate loss of standby device
        """
        check_portchannels = gen_list_pcs_to_check(duthost2, mg_facts, collect)
        ports_to_shut = check_portchannels.keys() + [keep_and_peer_link_member[duthost2.hostname]['keepalive']] + [keep_and_peer_link_member[duthost2.hostname]['peerlink']]
        duthost2.shutdown_multiple(ports_to_shut)
        duthost2.shell("config save -y")
        duthost2.shell("sudo /sbin/reboot", module_ignore_errors=True)
        pytest_assert(wait_until(140, 5, 0, check_partner_lag_member, ptfhost, check_portchannels, "DOWN"),
                      "Expected partner Lag members isnt down")

        yield

        duthost2.no_shutdown_multiple(ports_to_shut)
        duthost2.shell("config save -y")
        pytest_assert(wait_until(120, 5, 0, check_partner_lag_member, ptfhost, check_portchannels, "UP"),
                      "Expected partner Lag members isnt up")
        pytest_assert(wait_until(300, 20, 0, duthost2.critical_services_fully_started),
                      "All critical services should fully started!{}".format(duthost2.critical_services))


    def test_standby_down(self, duthost1, duthost2, ptfadapter, ptfhost, collect, get_routes, mclag_intf_num,
                         update_and_clean_ptf_agent, pre_standby_setup):
        """
        Verify behavior when standby device is lost, traffic should reach only direct uplink of active
        """
        dst_route1 = ipaddress.IPv4Interface(get_routes[duthost1.hostname][2])
        dst_route2 = ipaddress.IPv4Interface(get_routes[duthost2.hostname][2])

        status = duthost2.shell("mclagdctl dump state|grep keepalive")['stdout'].split(":")[-1].strip()
        pytest_assert(status == 'ERROR', "Keepalive status should be ERROR, not {}".format(status))

        for indx, mclag_intf in enumerate(collect[duthost1.hostname]['mclag_interfaces'][:mclag_intf_num]):
            dst_ip1 = unicode(str(dst_route1.ip + (indx + 1)))
            dst_ip2 = unicode(str(dst_route2.ip + (indx + 1)))
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf,
                                        dst_ip1, duthost1.facts["router_mac"], get_routes, collect)
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf, dst_ip2,
                                        duthost1.facts["router_mac"], get_routes, collect, pkt_action='DROP')


class TestPeerLinkStatusChange():
    @pytest.fixture()
    def pre_setup_peerlink(self, duthost2, keep_and_peer_link_member):
        """
        Shutdown peerlink and restore it on teardown
        """
        peerlink = keep_and_peer_link_member[duthost2.hostname]['peerlink']
        duthost2.shutdown(peerlink)
        out = duthost2.show_interface(command="status")['ansible_facts']['int_status']
        pytest_assert(out[peerlink]['admin_state'] == 'down',
                      "PeerLink is expected to be in down state != {}".format(out[peerlink]['admin_state']))

        yield

        duthost2.no_shutdown(keep_and_peer_link_member[duthost2.hostname]['peerlink'])
        out = duthost2.show_interface(command="status")['ansible_facts']['int_status']
        pytest_assert(out[peerlink]['admin_state'] == 'up',
                      "PeerLink is expected to be in up state != {}".format(out[peerlink]['admin_state']))


    def test_peer_link_status_change(self, duthost1, duthost2, ptfadapter, ptfhost, collect,
                                     get_routes, mclag_intf_num, pre_setup_peerlink):
        """
        Verify data forwarding is correct when peerlink status change
        """
        dst_route1 = ipaddress.IPv4Interface(get_routes[duthost1.hostname][2])
        dst_route2 = ipaddress.IPv4Interface(get_routes[duthost2.hostname][2])
        active_mclag_interfaces = sorted(collect[duthost1.hostname]['ptf_map'].values())[:mclag_intf_num]
        standby_mclag_interfaces = sorted(collect[duthost2.hostname]['ptf_map'].values())[:mclag_intf_num]
        indx = 0

        # Check MCLAG status is OK
        check_keepalive_link(duthost1, duthost2, 'OK')
        # Check mclag interfaces on standby have same MAC as active device
        for lag in collect[duthost1.hostname]['mclag_interfaces']:
            dut1_sys_id = duthost1.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            dut2_sys_id = duthost2.shell("teamdctl {} state item get team_device.ifinfo.dev_addr".format(lag))['stdout']
            pytest_assert(dut1_sys_id == dut2_sys_id, "Mclag standby device {} system ID shoule be same as active device, but is {}".format(lag, dut2_sys_id))

        # To be able to predict trough which DUT traffic will traverse,
        # use PortChannel member as source port, not PortChannel
        for mclag_intf1, mclag_intf2 in zip(active_mclag_interfaces, standby_mclag_interfaces):
            indx += 1
            dst_ip1 = unicode(str(dst_route1.ip + indx))
            dst_ip2 = unicode(str(dst_route2.ip + indx))
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf1,
                                        dst_ip1, duthost1.facts["router_mac"], get_routes, collect)
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf1,
                                        dst_ip2, duthost1.facts["router_mac"], get_routes, collect, pkt_action='DROP')
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf2,
                                        dst_ip2, duthost1.facts["router_mac"], get_routes, collect)
            generate_and_verify_traffic(duthost1, duthost2, ptfadapter, ptfhost, mclag_intf2,
                                        dst_ip1, duthost1.facts["router_mac"], get_routes, collect, pkt_action='DROP')
