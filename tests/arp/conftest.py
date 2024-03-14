import logging
import ptf.testutils as testutils
import ptf.mask as mask
import ptf.packet as packet
import pytest
import time

from .args.wr_arp_args import add_wr_arp_args
from .arp_utils import collect_info, get_po
from tests.common import constants
from tests.common.config_reload import config_reload
from ipaddress import ip_network, IPv6Network, IPv4Network
from tests.arp.arp_utils import increment_ipv6_addr, increment_ipv4_addr
from tests.common.helpers.assertions import pytest_require as pt_require
from tests.common.utilities import wait
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6ND_NA, \
                      ICMPv6NDOptSrcLLAddr, in6_getnsmac, \
                      in6_getnsma, inet_pton, inet_ntop, socket


CRM_POLLING_INTERVAL = 1
CRM_DEFAULT_POLL_INTERVAL = 300

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def set_polling_interval(duthost):
    wait_time = 2
    duthost.command("crm config polling interval {}".format(CRM_POLLING_INTERVAL))
    wait(wait_time, "Waiting {} sec for CRM counters to become updated".format(wait_time))

    yield

    duthost.command("crm config polling interval {}".format(CRM_DEFAULT_POLL_INTERVAL))
    wait(wait_time, "Waiting {} sec for CRM counters to become updated".format(wait_time))


# WR-ARP pytest arguments
def pytest_addoption(parser):
    '''
        Adds option to FDB pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_wr_arp_args(parser)


@pytest.fixture(scope='module')
def get_function_conpleteness_level(pytestconfig):
    return pytestconfig.getoption("--completeness_level")


@pytest.fixture(scope="module")
def config_facts(duthosts, enum_rand_one_per_hwsku_frontend_hostname):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    return duthost.config_facts(host=duthost.hostname, source="running")['ansible_facts']


@pytest.fixture(scope="module")
def intfs_for_test(duthosts, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index, tbinfo, config_facts):
    duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
    asic = duthost.asic_instance(enum_frontend_asic_index)
    mg_facts = asic.get_extended_minigraph_facts(tbinfo)
    external_ports = [p for p in list(mg_facts['minigraph_ports'].keys()) if 'BP' not in p]
    ports = list(sorted(external_ports, key=lambda item: int(item.replace('Ethernet', ''))))
    po1 = None
    po2 = None

    is_storage_backend = 'backend' in tbinfo['topo']['name']

    if tbinfo['topo']['type'] == 't0':
        if is_storage_backend:
            vlan_sub_intfs = mg_facts['minigraph_vlan_sub_interfaces']
            intfs_to_t1 = [_['attachto'].split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0] for _ in vlan_sub_intfs]
            ports_for_test = [_ for _ in ports if _ not in intfs_to_t1]

            intf1 = ports_for_test[0]
            intf2 = ports_for_test[1]
        else:
            if 'PORTCHANNEL_MEMBER' in config_facts:
                portchannel_members = []
                for _, v in list(config_facts['PORTCHANNEL_MEMBER'].items()):
                    portchannel_members += list(v.keys())
                ports_for_test = [x for x in ports if x not in portchannel_members]
            else:
                ports_for_test = ports

            # Select two interfaces for testing which are not in portchannel
            intf1 = ports_for_test[0]
            intf2 = ports_for_test[1]
    else:
        if tbinfo['topo']['type'] == 't1' and is_storage_backend:
            # Select two vlan sub interfaces for t1-backend topology
            vlan_sub_intfs = mg_facts['minigraph_vlan_sub_interfaces']
            ports_for_test = [_['attachto'] for _ in vlan_sub_intfs]

            intf1 = ports_for_test[0]
            intf2 = ports_for_test[1]
        else:
            # Select first 2 ports that are admin 'up'
            intf_status = asic.show_interface(command='status')['ansible_facts']['int_status']

            intf1 = None
            intf2 = None
            for a_port in ports:
                if intf_status[a_port]['admin_state'] == 'up':
                    if intf1 is None:
                        intf1 = a_port
                    elif intf2 is None:
                        intf2 = a_port
                    else:
                        break

            if intf1 is None or intf2 is None:
                pytest.skip("Not enough interfaces on this host/asic (%s/%s) to support test." % (duthost.hostname,
                                                                                                  asic.asic_index))
            po1 = get_po(mg_facts, intf1)
            po2 = get_po(mg_facts, intf2)

            if po1:
                asic.config_portchannel_member(po1, intf1, "del")
                collect_info(duthost)
                asic.startup_interface(intf1)
                collect_info(duthost)

            if po2:
                asic.config_portchannel_member(po2, intf2, "del")
                collect_info(duthost)
                asic.startup_interface(intf2)
                collect_info(duthost)

            if po1 or po2:
                time.sleep(40)

    logger.info("Selected ints are {0} and {1}".format(intf1, intf2))

    if tbinfo['topo']['type'] == 't1' and is_storage_backend:
        intf1_indice = mg_facts['minigraph_ptf_indices'][intf1.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0]]
        intf2_indice = mg_facts['minigraph_ptf_indices'][intf2.split(constants.VLAN_SUB_INTERFACE_SEPARATOR)[0]]
    else:
        intf1_indice = mg_facts['minigraph_ptf_indices'][intf1]
        intf2_indice = mg_facts['minigraph_ptf_indices'][intf2]

    asic.config_ip_intf(intf1, "10.10.1.2/28", "add")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "add")

    yield intf1, intf2, intf1_indice, intf2_indice

    asic.config_ip_intf(intf1, "10.10.1.2/28", "remove")
    asic.config_ip_intf(intf2, "10.10.1.20/28", "remove")

    if tbinfo['topo']['type'] != 't0':
        if po1:
            asic.config_portchannel_member(po1, intf1, "add")
        if po2:
            asic.config_portchannel_member(po2, intf2, "add")


@pytest.fixture(scope="module")
def common_setup_teardown(duthosts, ptfhost, enum_rand_one_per_hwsku_frontend_hostname, enum_frontend_asic_index):
    try:
        duthost = duthosts[enum_rand_one_per_hwsku_frontend_hostname]
        router_mac = duthost.asic_instance(enum_frontend_asic_index).get_router_mac()

        # Copy test files
        ptfhost.copy(src="ptftests", dest="/root")
        logging.info("router_mac {}".format(router_mac))
        yield duthost, ptfhost, router_mac
    finally:
        # Recover DUT interface IP address
        config_reload(duthost, config_source='config_db', safe_reload=True, check_intf_up_ports=True)


@pytest.fixture
def garp_enabled(rand_selected_dut, config_facts):
    """
    Tries to enable gratuitious ARP for each VLAN on the ToR in CONFIG_DB

    Also checks the kernel `arp_accept` value to see if the
    attempt was successful.

    During teardown, restores the original `grat_arp` value in
    CONFIG_DB

    Yields:
        (bool) True if `arp_accept` was successfully set for all VLANs,
               False otherwise

    """
    duthost = rand_selected_dut

    vlan_intfs = list(config_facts['VLAN_INTERFACE'].keys())
    garp_check_cmd = 'sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|{}" grat_arp'
    garp_enable_cmd = 'sonic-db-cli CONFIG_DB HSET "VLAN_INTERFACE|{}" grat_arp enabled'
    cat_arp_accept_cmd = 'cat /proc/sys/net/ipv4/conf/{}/arp_accept'
    arp_accept_vals = []
    old_grat_arp_vals = {}

    for vlan in vlan_intfs:
        old_grat_arp_res = duthost.shell(garp_check_cmd.format(vlan))
        old_grat_arp_vals[vlan] = old_grat_arp_res['stdout']
        res = duthost.shell(garp_enable_cmd.format(vlan))

        if res['rc'] != 0:
            pytest.fail("Unable to enable GARP for {}".format(vlan))
        else:
            logger.info("Enabled GARP for {}".format(vlan))

            # Get the `arp_accept` values for each VLAN interface
            arp_accept_res = duthost.shell(cat_arp_accept_cmd.format(vlan))
            arp_accept_vals.append(arp_accept_res['stdout'])

    yield all(int(val) == 1 for val in arp_accept_vals)

    garp_disable_cmd = 'sonic-db-cli CONFIG_DB HDEL "VLAN_INTERFACE|{}" grat_arp'
    for vlan in vlan_intfs:
        old_grat_arp_val = old_grat_arp_vals[vlan]

        if 'enabled' not in old_grat_arp_val:
            res = duthost.shell(garp_disable_cmd.format(vlan))

            if res['rc'] != 0:
                pytest.fail("Unable to disable GARP for {}".format(vlan))
            else:
                logger.info("GARP disabled for {}".format(vlan))


@pytest.fixture(scope='module')
def ip_and_intf_info(config_facts, intfs_for_test, ptfhost, ptfadapter):
    """
    Calculate IP addresses and interface to use for test
    """
    ptf_ports_available_in_topo = ptfhost.host.options['variable_manager'].extra_vars.get("ifaces_map")

    _, _, intf1_index, _, = intfs_for_test
    ptf_intf_name = ptf_ports_available_in_topo[intf1_index]

    # Calculate the IPv6 address to assign to the PTF port
    vlan_addrs = list(list(config_facts['VLAN_INTERFACE'].items())[0][1].keys())
    intf_ipv6_addr = None
    intf_ipv4_addr = None

    for addr in vlan_addrs:
        try:
            if type(ip_network(addr, strict=False)) is IPv6Network:
                intf_ipv6_addr = ip_network(addr, strict=False)
            elif type(ip_network(addr, strict=False)) is IPv4Network:
                intf_ipv4_addr = ip_network(addr, strict=False)
        except ValueError:
            continue

    # Increment address by 3 to offset it from the intf on which the address may be learned
    if intf_ipv4_addr is not None:
        ptf_intf_ipv4_addr = increment_ipv4_addr(intf_ipv4_addr.network_address, incr=3)
        ptf_intf_ipv4_hosts = intf_ipv4_addr.hosts()
    else:
        ptf_intf_ipv4_addr = None
        ptf_intf_ipv4_hosts = None

    if intf_ipv6_addr is not None:
        ptf_intf_ipv6_addr = increment_ipv6_addr(intf_ipv6_addr.network_address, incr=3)
    else:
        ptf_intf_ipv6_addr = None

    logger.info("Using {}, {}, and PTF interface {}".format(ptf_intf_ipv4_addr, ptf_intf_ipv6_addr, ptf_intf_name))

    return ptf_intf_ipv4_addr, ptf_intf_ipv4_hosts, ptf_intf_ipv6_addr, ptf_intf_name, intf1_index


@pytest.fixture
def proxy_arp_enabled(rand_selected_dut, config_facts):
    """
    Tries to enable proxy ARP for each VLAN on the ToR

    Also checks CONFIG_DB to see if the attempt was successful

    During teardown, restores the original proxy ARP setting

    Yields:
        (bool) True if proxy ARP was enabled for all VLANs,
               False otherwise
    """
    duthost = rand_selected_dut
    pt_require(duthost.has_config_subcommand('config vlan proxy_arp'), "Proxy ARP command does not exist on device")

    proxy_arp_check_cmd = 'sonic-db-cli CONFIG_DB HGET "VLAN_INTERFACE|Vlan{}" proxy_arp'
    proxy_arp_config_cmd = 'config vlan proxy_arp {} {}'
    vlans = config_facts['VLAN']
    vlan_ids = [vlans[vlan]['vlanid'] for vlan in list(vlans.keys())]
    old_proxy_arp_vals = {}
    new_proxy_arp_vals = []

    # Enable proxy ARP/NDP for the VLANs on the DUT
    for vid in vlan_ids:
        old_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        old_proxy_arp_vals[vid] = old_proxy_arp_res['stdout']

        duthost.shell(proxy_arp_config_cmd.format(vid, 'enabled'))

        logger.info("Enabled proxy ARP for Vlan{}".format(vid))
        new_proxy_arp_res = duthost.shell(proxy_arp_check_cmd.format(vid))
        new_proxy_arp_vals.append(new_proxy_arp_res['stdout'])

    yield all('enabled' in val for val in new_proxy_arp_vals)

    proxy_arp_del_cmd = 'sonic-db-cli CONFIG_DB HDEL "VLAN_INTERFACE|Vlan{}" proxy_arp'
    for vid, proxy_arp_val in list(old_proxy_arp_vals.items()):
        if 'enabled' not in proxy_arp_val:
            # Disable proxy_arp explicitly
            duthost.shell(proxy_arp_config_cmd.format(vid, 'disabled'))
            time.sleep(2)
            # Delete the DB entry instead of using the config command to satisfy check_dut_health_status
            duthost.shell(proxy_arp_del_cmd.format(vid))


def generate_link_local_addr(mac):
    parts = mac.split(":")
    parts.insert(3, "ff")
    parts.insert(4, "fe")
    parts[0] = "{:x}".format(int(parts[0], 16) ^ 2)

    ipv6Parts = []
    for i in range(0, len(parts), 2):
        ipv6Parts.append("".join(parts[i:i+2]))
    ipv6 = "fe80::{}".format(":".join(ipv6Parts))
    return ipv6


@pytest.fixture(params=['v4', 'v6'])
def packets_for_test(request, ptfadapter, duthost, config_facts, tbinfo, ip_and_intf_info):
    ip_version = request.param
    src_addr_v4, _, src_addr_v6, _, ptf_intf_index = ip_and_intf_info
    ptf_intf_mac = ptfadapter.dataplane.get_mac(0, ptf_intf_index)
    vlans = config_facts['VLAN']
    topology = tbinfo['topo']['name']
    dut_mac = ''
    for vlan_details in list(vlans.values()):
        if 'dualtor' in topology:
            dut_mac = vlan_details['mac'].lower()
        else:
            dut_mac = duthost.shell('sonic-cfggen -d -v \'DEVICE_METADATA.localhost.mac\'')["stdout_lines"][0]
        break

    if ip_version == 'v4':
        tgt_addr = increment_ipv4_addr(src_addr_v4)
        out_pkt = testutils.simple_arp_packet(
                                eth_dst='ff:ff:ff:ff:ff:ff',
                                eth_src=ptf_intf_mac,
                                ip_snd=src_addr_v4,
                                ip_tgt=tgt_addr,
                                arp_op=1,
                                hw_snd=ptf_intf_mac
                            )
        exp_pkt = testutils.simple_arp_packet(
                                eth_dst=ptf_intf_mac,
                                eth_src=dut_mac,
                                ip_snd=tgt_addr,
                                ip_tgt=src_addr_v4,
                                arp_op=2,
                                hw_snd=dut_mac,
                                hw_tgt=ptf_intf_mac
        )
    elif ip_version == 'v6':
        tgt_addr = increment_ipv6_addr(src_addr_v6)
        ll_src_addr = generate_link_local_addr(ptf_intf_mac.decode())
        multicast_tgt_addr = in6_getnsma(inet_pton(socket.AF_INET6, tgt_addr))
        multicast_tgt_mac = in6_getnsmac(multicast_tgt_addr)
        out_pkt = Ether(src=ptf_intf_mac, dst=multicast_tgt_mac)
        out_pkt /= IPv6(dst=inet_ntop(socket.AF_INET6, multicast_tgt_addr), src=ll_src_addr)
        out_pkt /= ICMPv6ND_NS(tgt=tgt_addr)
        out_pkt /= ICMPv6NDOptSrcLLAddr(lladdr=ptf_intf_mac)

        exp_pkt = Ether(src=dut_mac, dst=ptf_intf_mac)
        exp_pkt /= IPv6(dst=ll_src_addr, src=generate_link_local_addr(dut_mac))
        exp_pkt /= ICMPv6ND_NA(tgt=tgt_addr, S=1, R=1, O=0)
        exp_pkt /= ICMPv6NDOptSrcLLAddr(type=2, lladdr=dut_mac)
        exp_pkt = mask.Mask(exp_pkt)
        exp_pkt.set_do_not_care_scapy(packet.IPv6, 'fl')
    return ip_version, out_pkt, exp_pkt
