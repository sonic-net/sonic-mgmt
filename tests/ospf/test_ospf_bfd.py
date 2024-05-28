import pytest
import logging
import time

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0', 't1')
]


def test_ospf_with_bfd(ospf_Bfd_setup, duthosts, rand_one_dut_hostname):
    setup_info_nbr_addr = ospf_Bfd_setup['nbr_addr']
    neighbor_ip_addrs = list(setup_info_nbr_addr.values())
    duthost = duthosts[rand_one_dut_hostname]

    # Enable BFD on the DUT
    for ip_addr in neighbor_ip_addrs:
        cmd_list = [
            'docker exec -it bgp bash',
            'cd /usr/lib/frr',
            './ospfd &',
            './bfdd &',
            'exit',
            'vtysh',
            'config t',
            'bfd',
            f'peer {ip_addr}',
            'exit'
        ]
        duthost.shell_cmds(cmd_list)

        # Get interface name for the neighbor
        interface_name = get_ospf_dut_interfaces(duthost)
        if interface_name:  # Check if interface name is retrieved
            cmd_list = [
                'cd /usr/lib/frr',
                './ospfd &',
                'exit',
                'vtysh',
                'config t',
                f'interface {interface_name}',
                'ip ospf bfd',
                'exit'
            ]
            duthost.shell_cmds(cmd_list)

    # Configure OSPF on the DUT
    cmd_list = [
        'docker exec -it bgp bash',
        'cd /usr/lib/frr',
        './ospfd &',
        'exit',
        'vtysh',
        'config t',
        'no router bgp',
        'router ospf'
    ]

    for ip_addr in neighbor_ip_addrs:
        cmd_list.append('network {}/31 area 0'.format(str(ip_addr)))

    cmd_list.extend([
        'do write',
        'end',
        'exit'
    ])

    duthost.shell_cmds(cmd_list)
    time.sleep(5)

    # Verify OSPF routes on the DUT
    cmd = 'show ip route ospf'
    ospf_routes = duthost.shell(cmd)['stdout']
    assert "O>" in ospf_routes  # Basic check for OSPF routes

    if interface_name:
        result = simulate_link_failure(duthost, interface_name)
        assert result.rc == 0, f"Ping failed after link failure: {result.stderr}"


def simulate_link_failure(duthost, interface_name):
    # Shutdown the specified interface
    shutdown_cmd = f'sudo config interface {interface_name} shutdown'
    duthost.command(shutdown_cmd)

    # Sleep for 5 seconds
    time.sleep(5)

    # Get the neighbor IP corresponding to the interface
    neighbor_ip = get_ospf_neighbor_ip(duthost, interface_name)

    # Ping the neighbor IP
    ping_cmd = f'ping -n 50 {neighbor_ip}'
    result = duthost.command(ping_cmd)

    # Check if the output contains any failure indicators
    failure_indicators = ['network unreachable', 'host unreachable', 'request timeout']
    for indicator in failure_indicators:
        if indicator in result.stdout.lower():
            raise Exception(f"Error: {indicator} found in the output.")

    # If no failure indicators found, return success
    return "Success"


def get_ospf_neighbor_ip(duthost, interface_name):
    cmd = 'vtysh -c "show ip ospf neighbor"'
    ospf_neighbor_output = duthost.command(cmd).stdout
    for line in ospf_neighbor_output.split('\n'):
        columns = line.split()
        if len(columns) >= 7 and columns[6] == interface_name:
            return columns[0]  # Neighbor IP
    return None


def get_ospf_dut_interfaces(host):
    cmd = 'cd /usr/lib/frr && ./ospfd && exit && vtysh -c "show ip ospf neighbor"'
    ospf_neighbor_output = host.shell(cmd)['stdout']
    dut_int_info = {}

    # Parse the output to find the interface name corresponding to the neighbor IP
    for line in ospf_neighbor_output.split('\n'):
        columns = line.split()
        # Check if the line has at least 7 columns and if the interface column contains 'PortChannel'
        if len(columns) >= 7 and 'PortChannel' in columns[6]:
            interface_info = columns[6].split(':')
            dut_int_info[columns[0]] = {'interface': interface_info[0], 'ip': interface_info[1]}

    # Return None if no OSPF interfaces found or if they don't match the criteria
    return dut_int_info if dut_int_info else None
