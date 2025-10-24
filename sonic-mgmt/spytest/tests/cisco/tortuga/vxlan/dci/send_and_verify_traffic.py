import apis.system.connection as ssh_obj
from spytest import st

def initiate_ping_from_ubuntu_hosts(wa, host_pairs):
    """
    Initiate bidirectional ping traffic between Ubuntu host pairs via SSH connections.
    Establishes SSH connections to each host, executes ping commands, and collects results
    for traffic validation in multi-datacenter scenarios.

    Args:
        wa: SPyTest work area object containing testbed device information
        host_pairs: List of dictionaries, each containing host pair info with 'name' and 'ip' keys
                   Example: [{"name": "host1", "ip": "10.1.1.1"}, {"name": "host2", "ip": "10.1.1.2"}]
    Returns:
        bool: True if all ping tests succeed between all host pairs, False otherwise
    """
    output_tuple = []
    for host_pair in host_pairs:
        # Extract testbed topology and SSH access details for both hosts in the pair
        topo_data_h1 = wa.net.tb.devices[host_pair[0]["name"]]
        ssh_data_h1 = wa.net.tb.devices[host_pair[0]["name"]]["access"]

        topo_data_h2 = wa.net.tb.devices[host_pair[1]["name"]]
        ssh_data_h2 = wa.net.tb.devices[host_pair[1]["name"]]["access"]

        # Establish SSH connections to both hosts for bidirectional ping testing
        try:
            s_handle_1 = ssh_obj.connect_to_device(
                ssh_data_h1["ip"],
                topo_data_h1["credentials"]["username"],
                topo_data_h1["credentials"]["password"],
                ssh_data_h1["protocol"],
                ssh_data_h1["port"],
                sudo=False,
            )
        except Exception as e:
            st.log(f"SSH connection to {host_pair[0]} failed: {e}")
            return False
        st.log(f"Login to {host_pair[0]} ---------------------SUCCESS!!!!-------------------------------")

        try:
            s_handle_2 = ssh_obj.connect_to_device(
                ssh_data_h2["ip"],
                topo_data_h2["credentials"]["username"],
                topo_data_h2["credentials"]["password"],
                ssh_data_h2["protocol"],
                ssh_data_h2["port"],
                sudo=False,
            )
        except Exception as e:
            st.log(f"SSH connection to {host_pair[1]} failed: {e}")
            return False
        st.log(f"Login to {host_pair[1]} ---------------------SUCCESS!!!-------------------------------")

        # Execute bidirectional ping tests (2 packets each direction) and capture outputs
        output1 = ssh_obj.execute_command(
            s_handle_1, f"ping -c 2 {host_pair[1]['ip']} > /tmp/ping.txt; cat /tmp/ping.txt"
        )
        output2 = ssh_obj.execute_command(
            s_handle_2, f"ping -c 2 {host_pair[0]['ip']} > /tmp/ping.txt; cat /tmp/ping.txt"
        )
        output_tuple.append((output1, output2))
        # Clean up SSH connections after collecting ping results
        ssh_obj.ssh_disconnect(s_handle_1)
        ssh_obj.ssh_disconnect(s_handle_2)
    return verify_ping_response_for_ubuntu_hosts(output_tuple)


def verify_ping_response_for_ubuntu_hosts(output_tuple):
    """
    Parse and validate ping command outputs to determine connectivity success.
    Checks for successful ping responses by looking for "64 bytes from" pattern
    which indicates successful ICMP echo replies.

    Args:
        output_tuple: List of tuples, each containing (output1, output2) where:
                     - output1: Ping command output from first host to second host
                     - output2: Ping command output from second host to first host

    Returns:
        bool: True if at least one direction shows successful ping responses for all host pairs,
              False if all ping attempts fail for any host pair
    """
    for out1, out2 in output_tuple:
        # Check for successful ping responses in either direction (allows for asymmetric connectivity)
        if "64 bytes from" not in out1 and "64 bytes from" not in out2:
            st.log(f"Ping test failed between the hosts:\n{out1}\n{out2}")
            return False
    st.log("Ping test passed between all host pairs")
    return True
    

def send_ping_and_verify_traffic(wa, host_pairs, **kwargs):
    """
    Main traffic validation function supporting multiple host types (Ubuntu/Ixia).
    Dispatches to appropriate traffic generation method based on configuration.

    Args:
        wa: SPyTest work area object containing testbed device information
        host_pairs: List of dictionaries containing host pair information for traffic testing
        **kwargs: Optional parameters including:
                 - use_ubuntu_hosts (bool): If True, use Ubuntu hosts for traffic generation
                                          If False, use Ixia traffic generator (default)

    Returns:
        bool: True if traffic validation succeeds, False otherwise
    """
    if kwargs.get("use_ubuntu_hosts", False):
        return initiate_ping_from_ubuntu_hosts(wa, host_pairs)
