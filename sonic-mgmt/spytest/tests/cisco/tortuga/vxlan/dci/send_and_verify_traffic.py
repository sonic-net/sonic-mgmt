import apis.system.connection as ssh_obj
import time
import threading
from spytest import st
from retry import retry
from concurrent.futures import ThreadPoolExecutor


def create_ssh_connection(wa, host_name):
    """
    Create SSH connection to a host using testbed device information.

    Args:
        wa: SPyTest work area object containing testbed device information
        host_name: Name of the host device to connect to

    Returns:
        ssh_handle: SSH connection handle if successful, None if failed
    """
    try:
        topo_data = wa.net.tb.devices[host_name]
        ssh_data = wa.net.tb.devices[host_name]["access"]

        ssh_handle = ssh_obj.connect_to_device(
            ssh_data["ip"],
            topo_data["credentials"]["username"],
            topo_data["credentials"]["password"],
            ssh_data["protocol"],
            ssh_data["port"],
            sudo=False,
        )
        st.log(f"Login to {host_name} ---------------------SUCCESS!!!!-------------------------------")
        return ssh_handle
    except Exception as e:
        st.log(f"SSH connection to {host_name} failed: {e}")
        return None


@retry(tries=3, delay=2)
def execute_ping_command(ssh_handle, target_ip, host_name, target_name, packet_count=2):
    """
    Execute ping command through SSH connection with retry mechanism.
    Retries up to 3 times with 2 second delay between attempts if ping fails.

    Args:
        ssh_handle: SSH connection handle
        target_ip: IP address to ping
        host_name: Name of the source host
        target_name: Name of the target host
        packet_count: Number of ping packets to send (default: 2)

    Returns:
        str: Ping command output

    Raises:
        Exception: If ping fails after all retry attempts
    """
    # Use unique filename per ping to avoid conflicts in parallel execution
    thread_id = threading.current_thread().ident
    timestamp = int(time.time() * 1000000)  # microseconds for uniqueness
    ping_file = f"/tmp/ping_{thread_id}_{timestamp}.txt"

    output = ssh_obj.execute_command(
        ssh_handle, f"ping -c {packet_count} {target_ip} > {ping_file}; cat {ping_file}; rm -f {ping_file}"
    )

    # Check if ping was successful - if not, raise exception to trigger retry
    if output is None or "64 bytes from" not in str(output):
        st.log(f"Ping attempt failed from {host_name} to {target_name} ({target_ip}), will retry...")
        raise Exception(f"Ping failed from {host_name} to {target_name} ({target_ip})")

    st.log(f"Executed ping from {host_name} to {target_name} ({target_ip}) with {packet_count} packets")
    return output


def initiate_ping_from_ubuntu_hosts(wa, host_pairs, **kwargs):
    """
    Initiate ping traffic between Ubuntu host pairs via SSH connections.
    Establishes SSH connections to each host, executes ping commands, and collects results
    for traffic validation in multi-datacenter scenarios.

    Args:
        wa: SPyTest work area object containing testbed device information
        host_pairs: List of dictionaries, each containing host pair info with 'name' and 'ip' keys
                   Example: [{"name": "host1", "ip": "10.1.1.1"}, {"name": "host2", "ip": "10.1.1.2"}]
        **kwargs: Optional parameters including:
                 - single_direction (bool): If True, ping only from first host to second host
                                          If False, ping in both directions (default)
                 - ignore_validation (bool): If True, skip validation and return True
                                           If False, validate ping results (default)
                 - packet_count (int): Number of ping packets to send (default: 2)
                 - allow_packet_loss (bool): If True, allows some packet loss based on max_loss_percent
                 - max_loss_percent (float): Maximum allowed packet loss percentage (default: 0.0)
    Returns:
        bool: True if all ping tests succeed between all host pairs, False otherwise
    """
    single_direction = kwargs.get("single_direction", False)
    ignore_validation = kwargs.get("ignore_validation", False)
    packet_count = kwargs.get("packet_count", 10)
    allow_packet_loss = kwargs.get("allow_packet_loss", False)
    max_loss_percent = kwargs.get("max_loss_percent", 0.0)

    # Group pings by source host to reuse SSH connections
    from collections import defaultdict

    pings_by_host = defaultdict(list)

    for idx, pair in enumerate(host_pairs):
        host1_name = pair[0]["name"]
        host2_name = pair[1]["name"]
        host1_ip = pair[0]["ip"]
        host2_ip = pair[1]["ip"]

        # Store ping task: (target_host_name, target_ip, pair_index, direction)
        pings_by_host[host1_name].append((host2_name, host2_ip, idx, "forward"))

        if not single_direction:
            pings_by_host[host2_name].append((host1_name, host1_ip, idx, "reverse"))

    # Results dictionary indexed by (pair_index, direction)
    results = {}

    def execute_pings_for_host(host_name):
        """Execute all pings from a single host using one SSH connection."""
        ping_tasks = pings_by_host[host_name]

        # Create one SSH connection for this host
        ssh_handle = create_ssh_connection(wa, host_name)
        if not ssh_handle:
            st.log(f"Failed to create SSH connection to {host_name}")
            # Mark all tasks from this host as failed
            for target_name, target_ip, pair_idx, direction in ping_tasks:
                results[(pair_idx, direction)] = None
            return

        try:
            # Execute all pings from this host sequentially
            for target_name, target_ip, pair_idx, direction in ping_tasks:
                try:
                    output = execute_ping_command(ssh_handle, target_ip, host_name, target_name, packet_count)
                    results[(pair_idx, direction)] = output
                except Exception as e:
                    st.log(f"Ping failed from {host_name} to {target_name}: {e}")
                    results[(pair_idx, direction)] = None
        finally:
            ssh_obj.ssh_disconnect(ssh_handle)
            st.log(f"Disconnected SSH session from {host_name}")

    # Execute pings grouped by host in parallel (max 4 hosts at a time)
    unique_hosts = list(pings_by_host.keys())
    st.log(f"Executing pings in parallel from {len(unique_hosts)} hosts with max 4 workers")

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(execute_pings_for_host, host) for host in unique_hosts]
        # Wait for all to complete
        for future in futures:
            future.result()

    # Reconstruct output_tuple in original host_pairs order with host information
    output_tuple = []
    for idx in range(len(host_pairs)):
        forward_output = results.get((idx, "forward"), None)
        reverse_output = results.get((idx, "reverse"), None) if not single_direction else None
        host1_name = host_pairs[idx][0]["name"]
        host2_name = host_pairs[idx][1]["name"]
        host1_ip = host_pairs[idx][0]["ip"]
        host2_ip = host_pairs[idx][1]["ip"]
        output_tuple.append((forward_output, reverse_output, host1_name, host2_name, host1_ip, host2_ip))

    # Return result based on validation setting
    if ignore_validation:
        st.log("Validation ignored - returning success")
        return True
    else:
        return verify_ping_response_for_ubuntu_hosts(
            output_tuple,
            single_direction=single_direction,
            allow_packet_loss=allow_packet_loss,
            max_loss_percent=max_loss_percent,
        )


def parse_ping_statistics(ping_output):
    """
    Parse ping output to extract packet loss information.

    Args:
        ping_output: String output from ping command

    Returns:
        dict: Dictionary containing packet statistics or None if parsing fails
              Format: {"transmitted": int, "received": int, "loss_percent": float}
    """
    if not ping_output:
        return None

    try:
        # Look for the statistics line: "2 packets transmitted, 2 received, 0% packet loss, time 1002ms"
        lines = ping_output.split("\n")
        for line in lines:
            if "packets transmitted" in line and "received" in line and "packet loss" in line:
                # Parse the statistics line
                parts = line.split(",")
                transmitted = int(parts[0].split()[0])
                received = int(parts[1].split()[0])
                loss_str = parts[2].strip().split()[0]  # "0%" -> "0"
                loss_percent = float(loss_str.rstrip("%"))

                return {"transmitted": transmitted, "received": received, "loss_percent": loss_percent}
    except (ValueError, IndexError) as e:
        st.log(f"Failed to parse ping statistics: {e}")
        return None

    return None


def verify_ping_response_for_ubuntu_hosts(
    output_tuple, single_direction=False, allow_packet_loss=False, max_loss_percent=0.0
):
    """
    Parse and validate ping command outputs to determine connectivity success.
    Checks for successful ping responses and optionally validates packet loss.

    Args:
        output_tuple: List of tuples, each containing (output1, output2, host1_name, host2_name, host1_ip, host2_ip) where:
                     - output1: Ping command output from first host to second host
                     - output2: Ping command output from second host to first host (None if single_direction=True)
                     - host1_name: Name of the first host
                     - host2_name: Name of the second host
                     - host1_ip: IP address of the first host
                     - host2_ip: IP address of the second host
        single_direction: If True, only validate output1; if False, validate both directions
        allow_packet_loss: If True, allows some packet loss based on max_loss_percent
        max_loss_percent: Maximum allowed packet loss percentage (default: 0.0)

    Returns:
        bool: True if ping responses show successful connectivity based on direction setting,
              False if ping attempts fail or exceed packet loss threshold
    """
    for i, (out1, out2, host1_name, host2_name, host1_ip, host2_ip) in enumerate(output_tuple):
        if single_direction:
            # Single direction: only check output1
            if out1 is None:
                st.log(f"Single direction ping test failed from {host1_name} ({host1_ip}) to {host2_name} ({host2_ip}): No output received")
                return False

            # Check for basic connectivity
            if "64 bytes from" not in out1:
                st.log(f"Single direction ping test failed from {host1_name} ({host1_ip}) to {host2_name} ({host2_ip}) - no responses:\n{out1}")
                return False

            # Check packet loss if configured
            if not allow_packet_loss or max_loss_percent < 100.0:
                stats = parse_ping_statistics(out1)
                if stats:
                    if stats["loss_percent"] > max_loss_percent:
                        st.log(
                            f"Single direction ping failed from {host1_name} ({host1_ip}) to {host2_name} ({host2_ip}) - packet loss {stats['loss_percent']}% exceeds threshold {max_loss_percent}%"
                        )
                        st.log(f"Stats: {stats['transmitted']} transmitted, {stats['received']} received")
                        return False
                    else:
                        st.log(
                            f"✓ Ping from {host1_name} ({host1_ip}) to {host2_name} ({host2_ip}): {stats['transmitted']} transmitted, {stats['received']} received, {stats['loss_percent']}% loss"
                        )
                else:
                    st.log(f"Warning: Could not parse ping statistics from {host1_name} to {host2_name} for packet loss validation")
        else:
            # Bidirectional: check both directions
            success1 = out1 is not None and "64 bytes from" in str(out1)
            success2 = out2 is not None and "64 bytes from" in str(out2)

            if not success1 and not success2:
                st.log(f"Ping test failed between {host1_name} ({host1_ip}) and {host2_name} ({host2_ip}) - no responses in either direction:\n{out1}\n{out2}")
                return False

            # Check packet loss for direction 1
            if success1 and (not allow_packet_loss or max_loss_percent < 100.0):
                stats1 = parse_ping_statistics(out1)
                if stats1:
                    if stats1["loss_percent"] > max_loss_percent:
                        st.log(
                            f"Ping failed from {host1_name} ({host1_ip}) to {host2_name} ({host2_ip}) - packet loss {stats1['loss_percent']}% exceeds threshold {max_loss_percent}%"
                        )
                        return False
                    else:
                        st.log(
                            f"✓ Ping from {host1_name} ({host1_ip}) to {host2_name} ({host2_ip}): {stats1['transmitted']} transmitted, {stats1['received']} received, {stats1['loss_percent']}% loss"
                        )

            # Check packet loss for direction 2
            if success2 and (not allow_packet_loss or max_loss_percent < 100.0):
                stats2 = parse_ping_statistics(out2)
                if stats2:
                    if stats2["loss_percent"] > max_loss_percent:
                        st.log(
                            f"Ping failed from {host2_name} ({host2_ip}) to {host1_name} ({host1_ip}) - packet loss {stats2['loss_percent']}% exceeds threshold {max_loss_percent}%"
                        )
                        return False
                    else:
                        st.log(
                            f"✓ Ping from {host2_name} ({host2_ip}) to {host1_name} ({host1_ip}): {stats2['transmitted']} transmitted, {stats2['received']} received, {stats2['loss_percent']}% loss"
                        )

    st.log("✓ Ping test passed between all host pairs")
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
                 - single_direction (bool): If True, ping only from first host to second host
                                          If False, ping in both directions (default)
                 - ignore_validation (bool): If True, skip validation and return True
                                           If False, validate ping results (default)
                 - packet_count (int): Number of ping packets to send (default: 2)
                 - allow_packet_loss (bool): If True, allows some packet loss based on max_loss_percent
                 - max_loss_percent (float): Maximum allowed packet loss percentage (default: 0.0)

    Returns:
        bool: True if traffic validation succeeds, False otherwise
    """
    if kwargs.get("use_ubuntu_hosts", False):
        return initiate_ping_from_ubuntu_hosts(wa, host_pairs, **kwargs)
