import pytest
import re
from tests.common.config_reload import config_reload
import time


@pytest.fixture(scope="module")
def ospf_Bfd_setup(duthosts, rand_one_dut_hostname, nbrhosts, request):
    if request.config.getoption("neighbor_type") != "sonic":
        pytest.skip("Neighbor type must be sonic")

    duthost = duthosts[rand_one_dut_hostname]
    setup_info = {"nbr_addr": {}, "int_info": {}}

    cmd = "show ip route bgp"
    bgp_neighbors = duthost.shell(cmd)["stdout"]
    for line in bgp_neighbors.splitlines():
        match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
        if match:
            nbr_ip = match.group(1)
            setup_info["nbr_addr"][nbr_ip] = None

    for nbr_name, nbr_info in nbrhosts.items():
        nbr_ip = setup_info["nbr_addr"].get(nbr_info["ip"])
        if nbr_ip:
            configure_ospf_and_bfd(
                nbr_info["host"],
                nbrhosts[nbr_name].hostname)
            setup_info["nbr_addr"][nbr_ip] = {"hostname": nbr_info["hostname"]}

    setup_info["int_info"] = get_ospf_neighbor_interface()
    yield setup_info

    config_reload(duthost, safe_reload=True)
    time.sleep(10)
    for nbr_name in list(nbrhosts.keys()):
        config_reload(nbrhosts[nbr_name]["host"], is_dut=False)


def configure_ospf_and_bfd(host, nbr_ip):
    cmd_list = [
        "docker exec -it bgp bash",
        "cd /usr/lib/frr",
        "./ospfd &",
        "./bfdd &",
        "exit",
        "vtysh",
        "config t",
        "router ospf",
        f"network {nbr_ip}/31 area 0",
        "exit"
        "bfd",
        f"peer {nbr_ip}",
        "do write",
        "end",
        "exit",
    ]
    host.shell_cmds(cmd_list)


def get_ospf_neighbor_interface(host):
    cmd = 'cd /usr/lib/frr && ./ospfd && exit && vtysh -c "show ip ospf neighbor"'
    ospf_neighbor_output = host.shell(cmd)['stdout']
    nbr_int_info = {'interface': '', 'ip': ''}
    # Parse the output to find the interface name corresponding to the
    # neighbor IP
    for line in ospf_neighbor_output.split('\n'):
        columns = line.split()
        # Check if the interface column contains 'PortChannel'
        if 'PortChannel' in columns[6]:
            nbr_int_info['interface'] = columns[6].split(':')[0]
            nbr_int_info['ip'] = columns[6].split(
                ':')[1]  # Return the interface name
    # Return None if interface name is not found or not PortChannels.
    return nbr_int_info
