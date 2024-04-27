import ipaddress

import ptf.testutils as testutils
import re
import logging
import time
import pytest
from paramiko.ssh_exception import AuthenticationException
from ptf import mask, packet
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import paramiko_ssh

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.disable_loganalyzer,  # disable automatic loganalyzer globally
    pytest.mark.topology('any'),
    pytest.mark.device_type('physical')
]


def parse_interfaces(output_lines, pc_ports_map):
    """
    Parse the interfaces from 'show ip route' into an array
    """
    route_targets = []
    ifaces = []
    output_lines = output_lines[3:]

    for item in output_lines:
        match = re.search("(Ethernet\\d+|PortChannel\\d+)", item)
        if match:
            route_targets.append(match.group(0))

    for route_target in route_targets:
        if route_target.startswith("Ethernet"):
            ifaces.append(route_target)
        elif route_target.startswith("PortChannel") and route_target in pc_ports_map:
            ifaces.extend(pc_ports_map[route_target])

    return route_targets, ifaces


def parse_rif_counters(lines):
    """
    Parse the output of duthost.show_and_parse("show interfaces counters rif")
    """

    result = {}

    for line in lines:
        result[line["iface"]] = line

    return result


def construct_packet_and_get_params(duthost, ptfadapter, tbinfo):
    """
    Construct data packet and get related params
    """
    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)
    is_backend_topo = 'backend' in tbinfo['topo']['name']

    # generate peer_ip and port channel pair, be like:[("10.0.0.57", "PortChannel0001")]
    peer_ip_pc_pair = [(pc["peer_addr"], pc["attachto"]) for pc in mg_facts["minigraph_portchannel_interfaces"]
                       if
                       ipaddress.ip_address(pc['peer_addr']).version == 4]

    pc_ports_map = {pair[1]: mg_facts["minigraph_portchannels"][pair[1]]["members"] for pair in
                    peer_ip_pc_pair}

    if is_backend_topo:
        # generate peer_ip and subinterfaces pair ex. [("10.0.0.57", ["Ethernet48.10"])]
        peer_ip_ifaces_pair = [(subintf_info["peer_addr"], [subintf_info["attachto"]]) for subintf_info in
                               mg_facts["minigraph_vlan_sub_interfaces"]
                               if ipaddress.ip_address(subintf_info['peer_addr']).version == 4]

    elif len(mg_facts["minigraph_interfaces"]) >= 2:
        # generate peer_ip and interfaces pair,
        # be like:[("10.0.0.57", ["Ethernet48"])]
        peer_ip_ifaces_pair = [(intf["peer_addr"], [intf["attachto"]]) for intf in mg_facts["minigraph_interfaces"]
                               if
                               ipaddress.ip_address(intf['peer_addr']).version == 4]

    else:
        # generate peer_ip and interfaces(port channel members) pair,
        # be like:[("10.0.0.57", ["Ethernet48", "Ethernet52"])]
        peer_ip_ifaces_pair = [(pair[0], mg_facts["minigraph_portchannels"][pair[1]]["members"]) for pair in
                               peer_ip_pc_pair]

    # use first port of first peer_ip_ifaces pair as input port
    # all ports in second peer_ip_ifaces pair will be output/forward port
    ptf_port_idx = mg_facts["minigraph_ptf_indices"][peer_ip_ifaces_pair[0][1][0].split(".")[0]]

    # get router mac per asic for multi-asic dut
    if duthost.is_multi_asic:
        namespace = mg_facts['minigraph_neighbors'][peer_ip_ifaces_pair[0][1][0]]['namespace']
        asic_idx = duthost.get_asic_id_from_namespace(namespace)
        router_mac = duthost.asic_instance(asic_idx).get_router_mac()
    else:
        router_mac = duthost.facts["router_mac"]

    # Some platforms do not support rif counter
    try:
        rif_counter_out = parse_rif_counters(duthost.show_and_parse("show interfaces counters rif"))
        rif_iface = list(rif_counter_out.keys())[0]
        rif_support = False if rif_counter_out[rif_iface]['rx_err'] == 'N/A' else True
    except Exception as e:
        logger.info("Show rif counters failed with exception: {}".format(repr(e)))
        rif_support = False

    pkt = testutils.simple_ip_packet(
        eth_dst=router_mac,
        eth_src=ptfadapter.dataplane.get_mac(0, ptf_port_idx),
        ip_src=peer_ip_ifaces_pair[0][0],
        ip_dst=peer_ip_ifaces_pair[1][0])

    exp_pkt = pkt.copy()
    exp_pkt.payload.ttl = pkt.payload.ttl - 1
    exp_pkt = mask.Mask(exp_pkt)

    exp_pkt.set_do_not_care_scapy(packet.Ether, 'dst')
    exp_pkt.set_do_not_care_scapy(packet.Ether, 'src')

    out_rif_ifaces, out_ifaces = parse_interfaces(
        duthost.command("show ip route %s" % peer_ip_ifaces_pair[1][0])["stdout_lines"],
        pc_ports_map)

    # map() in Python2 returns list object but in Python3 returns map object,
    # add explicit convert to compatible with different versions
    out_ptf_indices = list([mg_facts["minigraph_ptf_indices"][iface] for iface in out_ifaces])

    return pkt, ptf_port_idx, exp_pkt, out_ptf_indices, rif_support


def test_disk_exhaustion(duthost, ptfadapter, tbinfo, creds):
    """Test SONiC basic performance(like ssh-connect, packet forward...) when disk is exhausted
    Args:
        duthost: DUT host object
        ptfadapter: PTF adapter object
        tbinfo: Testbed information
    """

    PKT_NUM = 1000
    PKT_NUM_MIN = PKT_NUM * 0.9

    # Construct packet and get params
    pkt, ptf_port_idx, exp_pkt, out_ptf_indices, rif_support = construct_packet_and_get_params(duthost=duthost,
                                                                                               ptfadapter=ptfadapter,
                                                                                               tbinfo=tbinfo)

    # Clear stats
    duthost.command("portstat -c")

    if rif_support:
        duthost.command("sonic-clear rifcounters")
    ptfadapter.dataplane.flush()

    # Get default username and passwords for the duthost
    sonic_username = creds['sonicadmin_user']

    sonic_admin_alt_password = duthost.host.options['variable_manager']._hostvars[duthost.hostname].get(
        "ansible_altpassword")
    sonic_admin_alt_passwords = creds["ansible_altpasswords"]

    passwords = [creds['sonicadmin_password'], sonic_admin_alt_password] + sonic_admin_alt_passwords

    # Simulate disk exhaustion and release space after 60 seconds
    # Use command 'fallocate' to create large file, it's efficient.
    # Create a shell script to do the operations like fallocate and remove file,
    # because when space is full, duthost.command() is not work

    # i. First, get how much space total has in /tmp mounted partition, the output of "df /tmp" was like below:
    #   Filesystem     1K-blocks    Used Available Use% Mounted on
    #   root-overlay    14874056 6429908   8427764  44% /
    df_rst = duthost.shell("df /tmp")["stdout_lines"][1].split()
    total_space = df_rst[1]
    used_before_test = int(df_rst[4].rstrip('%'))

    # ii. Second create sh and execute
    duthost.shell_cmds(cmds=[
        "echo 'fallocate -l {}K /tmp/huge_dummy_file' > /tmp/test.sh".format(total_space),
        "echo 'sleep 60' >> /tmp/test.sh",
        "echo 'sudo rm /tmp/huge_dummy_file' >> /tmp/test.sh",
        "chmod u+x /tmp/test.sh",
        "nohup /tmp/test.sh >/dev/null 2>&1 &"
    ], continue_on_fail=False, module_ignore_errors=True)

    try:
        # Test ssh connection
        paramiko_ssh(ip_address=duthost.mgmt_ip, username=sonic_username, passwords=passwords)

        # Test IP packet forward
        testutils.send(ptfadapter, ptf_port_idx, pkt, PKT_NUM)
        time.sleep(5)
        match_cnt = testutils.count_matched_packets_all_ports(ptfadapter, exp_pkt, ports=out_ptf_indices)

        pytest_assert(match_cnt >= PKT_NUM_MIN, "DUT Forwarded {} packets, not in expected range".format(match_cnt))
        logger.info("DUT Forwarded {} packets, in expected range".format(match_cnt))
    except AuthenticationException:
        logger.info("Cannot access DUT {} via ssh, error: Password incorrect.")
        raise
    except Exception:
        raise
    finally:
        # Wait for disk space release
        # This should be involved in the final block
        # Otherwise, if the try block fails,
        # it will execute other post steps outside the module, but disk space has not released
        time.sleep(60)

        # Delete test.sh
        duthost.shell("sudo rm /tmp/test.sh")
        # Confirm disk space was released
        df_rst = duthost.shell("df /tmp")["stdout_lines"][1].split()
        used_after_test = int(df_rst[4].rstrip('%'))
        logger.info("Use% before test is {}%, Use% after test is {}%".format(used_before_test, used_after_test))
        pytest_assert(used_after_test < 100 and used_after_test <= used_before_test / 0.8,
                      "Disk space was not released expectedly, please check.")
