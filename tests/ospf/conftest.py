'''
Conftest file for OSPF tests
'''

import pytest
import re
from tests.common.config_reload import config_reload
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
import time


@pytest.fixture(scope="module")
def trap_copp_ospf(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    copp_trap_ospf_rule_json = "/tmp/copp_trap_ospf.json"

    cmd_copp_trap_group = '''
cat << EOF >  %s
{
    "COPP_TRAP": {
        "ospf": {
            "trap_ids": "ospf,ospfv6",
            "trap_group": "queue4_group1",
            "always_enabled": "true"
        }
    }
}
EOF
''' % (copp_trap_ospf_rule_json)

    duthost.shell(cmd_copp_trap_group)

    copp_config_file = copp_trap_ospf_rule_json if not duthost.is_multi_asic else \
        ",".join([copp_trap_ospf_rule_json for _ in range(duthost.num_asics() + 1)])

    duthost.command("sudo config load {} -y".format(copp_config_file))

    yield

    duthost.command(f"sudo rm {copp_trap_ospf_rule_json}")

    return duthost


@pytest.fixture(scope="module")
def ospf_Bfd_setup(duthosts, rand_one_dut_hostname, nbrhosts, trap_copp_ospf, request):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")

    duthost = duthosts[rand_one_dut_hostname]
    setup_info = {}

    for asic in duthost.asics:
        bgp_neighbors = asic.bgp_facts()['ansible_facts']['bgp_neighbors']

        neighbor_ips = [
            neigh_ip for neigh_ip in bgp_neighbors
            if bgp_neighbors[neigh_ip]["ip_version"] == 4
            and bgp_neighbors[neigh_ip]["description"] in nbrhosts
        ]

        for neigh_ip in neighbor_ips:
            setup_info[neigh_ip] = {
                "asic": asic
            }

    for nbr_name, nbr_info in nbrhosts.items():
        ipv4, ipv6 = list(nbr_info['conf']['bgp']['peers'].values())[0]
        nbr_ip = ipv4
        if nbr_ip:
            configure_ospf_and_bfd_vsonic(
                nbr_info["host"],
                nbr_ip,
                nbr_info['conf']['interfaces']['Loopback0']['ipv4'])

    yield setup_info

    config_reload(duthost, config_source='config_db', safe_reload=True)
    time.sleep(10)

    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for nbr_name in list(nbrhosts.keys()):
            executor.submit(config_reload, nbrhosts[nbr_name]["host"], is_dut=False)


def configure_ospf_and_bfd_vsonic(host, nbr_ip, loopback):
    cmd_list = [
        # Start required FRR daemons inside the bgp container without TTY
        "docker exec bgp bash -lc 'cd /usr/lib/frr; ./ospfd & ./bfdd &'",
        # Configure OSPF and BFD via non-interactive vtysh
        (
            "docker exec bgp vtysh "
            "-c 'configure terminal' "
            "-c 'router ospf' "
            f"-c 'network {nbr_ip}/31 area 0' "
            f"-c 'network {loopback} area 0' "
            "-c 'exit' "
            "-c 'bfd' "
            f"-c 'peer {nbr_ip}' "
            "-c 'do write' "
            "-c 'end'"
        ),
    ]
    host.shell_cmds(cmds=cmd_list)


def get_ospf_neighbor_interface(host):
    cmd = 'cd /usr/lib/frr && ./ospfd && exit && vtysh -c "show ip ospf neighbor"'
    ospf_neighbor_output = host.shell(cmd)['stdout']
    nbr_int_info = {'interface': '', 'ip': ''}
    # Parse the output to find the interface name corresponding to the
    # neighbor IP
    for line in ospf_neighbor_output.split('\n'):
        columns = line.split()
        # Check if the interface column contains 'PortChannel'
        if len(columns) >= 7 and 'PortChannel' in columns[6]:
            int_col = columns[6]
            parts = int_col.split(':', 1)
            if len(parts) == 2:
                nbr_int_info['interface'] = parts[0]
                nbr_int_info['ip'] = parts[1]
    # Return None if interface name is not found or not PortChannels.
    return nbr_int_info


@pytest.fixture(scope='module')
def ospf_setup(duthosts, rand_one_dut_hostname, nbrhosts, tbinfo, request):

    # verify neighbors are type sonic
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")

    duthost = duthosts[rand_one_dut_hostname]

    setup_info = {'nbr_addr': {}, 'bgp_routes': []}

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    for bgp_nbr in mg_facts['minigraph_bgp']:
        setup_info['nbr_addr'][bgp_nbr['name']] = bgp_nbr['addr']

    # gather original BGP routes
    cmd = "show ip route bgp"
    bgp_routes = duthost.shell(cmd)['stdout']
    bgp_routes_pattern = re.compile(r'B>\*(\d+\.\d+\.\d+\.\d+/\d+)')
    original_prefixes = bgp_routes_pattern.findall(bgp_routes).sort()
    setup_info['bgp_routes'] = original_prefixes

    for neigh_name in list(nbrhosts.keys()):
        ip_addr = None
        asn = None
        neigh_mg_facts = nbrhosts[neigh_name]["host"].minigraph_facts(host=nbrhosts[neigh_name]["host"].hostname)
        for neigh_bgp_nbr in neigh_mg_facts['minigraph_bgp']:
            if neigh_bgp_nbr['name'] == duthost.hostname:
                ip_addr = neigh_bgp_nbr['addr']
                asn = neigh_bgp_nbr['asn']
                break
        cmd_list = [
            'docker exec -it bgp bash',
            'cd /usr/lib/frr',
            './ospfd &',
            'exit',
            'vtysh',
            'config t',
            'router bgp',
            'no neighbor {} remote-as {}'.format(str(ip_addr), str(asn)),
            'exit',
            'router ospf',
            'network {}/31 area 0'.format(str(ip_addr)),
            'redistribute bgp',
            'do write',
            'end',
            'exit'
        ]
        nbrhosts[neigh_name]["host"].shell_cmds(cmd_list)

    yield setup_info

    # restore config to original state on both DUT and neighbor
    config_reload(duthost, safe_reload=True)
    time.sleep(10)
    for neigh_name in list(nbrhosts.keys()):
        config_reload(nbrhosts[neigh_name]["host"], is_dut=False)
