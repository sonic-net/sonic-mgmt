import apis.system.connection as ssh_obj
from spytest import st

def send_ping_and_verify_traffic(wa, host_pairs):
    """
    Function to send and verify ping traffic using IXIA.
    """

    output_tuple = []
    for host_pair in host_pairs:
        # Fetch access details for the current device
        topo_data_h1 = wa.net.tb.devices[host_pair[0]["name"]]
        ssh_data_h1 = wa.net.tb.devices[host_pair[0]["name"]]["access"]

        topo_data_h2 = wa.net.tb.devices[host_pair[1]["name"]]
        ssh_data_h2 = wa.net.tb.devices[host_pair[1]["name"]]["access"]


        # Establish an SSH connection to the devices
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
        st.log(
            f"Login to {host_pair[0]} ---------------------SUCCESS!!!!-------------------------------"
        )

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
        st.log(
            f"Login to {host_pair[1]} ---------------------SUCCESS!!!-------------------------------"
        )

        output1 = ssh_obj.execute_command(s_handle_1, f"ping -c 2 {host_pair[1]['ip']} > /tmp/ping.txt; cat /tmp/ping.txt")
        output2 = ssh_obj.execute_command(s_handle_2, f"ping -c 3 {host_pair[0]['ip']} > /tmp/ping.txt; cat /tmp/ping.txt")
        output_tuple.append((output1, output2))
        ssh_obj.ssh_disconnect(s_handle_1)
        ssh_obj.ssh_disconnect(s_handle_2)
    return verify_ping_traffic(output_tuple)


def verify_ping_traffic(output_tuple):
    """
    Function to verify ping traffic results.

    Args:
        output_tuple: Tuple containing ping outputs from both devices

    Returns:
        bool: True if ping is successful, False otherwise
    """
    for out1, out2 in output_tuple:
        if "64 bytes from" not in out1 and "64 bytes from" not in out2:
            st.log(f"Ping test failed between the hosts:\n{out1}\n{out2}")
            return False
    st.log("Ping test passed between all host pairs")
    return True