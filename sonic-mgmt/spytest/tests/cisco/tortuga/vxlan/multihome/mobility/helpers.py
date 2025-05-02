import vxlan_utils
from multihome import db
from multihome import const, traffic_generator
from multihome import vtysh
from multihome.status_report import report_fail

# Constants traffic error messages
ERR_PING_AND_UNICAST_TRAFFIC_FAILED = (
    "ping and unicast traffic from {} to {} {} failed."
)
ERR_PING_AND_UNICAST_TRAFFIC_FAILED_AFTER_MAC_MOVE = (
    "ping and traffic from {} to {} failed after mac move."
)
ERR_PING_AND_UNICAST_TRAFFIC_UNEXPECTED = (
    "ping and unicast traffic from {} to moved {} passed unexpectedly."
)
ERR_TRAFFIC_FLOOD = "traffic from {}->{} getting flooded on {} failed."


# constant mac error messages
ERR_MAC_NOT_FOUND_AFTER_MOVE = "mac {} not found after move to {}."
ERR_MAC_SHOULD_BE_PRESENT = (
    "mac {} should be remotely present on {} after move to {}-{}."
)
ERR_APP_DB_MAC_INCORRECT = "mac {} is incorrectly programmed in app db."

# constant kernel error messages
ERR_KERNEL_PROGRAMMING = "kernel is incorrectly programmed for ip/mac, dut:{} kernel_ip_flag:{} kernel_mac_flag:{}."

# constant zebra error messages
ERR_ZEBRA_SEQ_ID_AFTER_MAC_MOVE = (
    "seq id is incorrect in zebra after mac move, dut:{} frr:{}."
)

# constant log formats
LOG_DB_ASIC_MAC_NOT_FOUND = "mac {} not found after move back to {} in asic db but found in kernel without extern_learn flag."

# Success message formats
PING_AND_UNICAST_TRAFFIC_SUCCESS = (
    "ping and unicast traffic from {} to {} passed after mac move."
)


def create_h5_h1_traffic_stream_handle():
    """
    Create a traffic stream handle for H5 to H1.
    Returns:
        traffic_handle (dict): Handle for the created traffic stream.
    """
    return traffic_generator.create_a_raw_traffic_stream(
        {
            "dst_endpoint": {
                "port": "T1D2P1",
                "host_ip": const.spytest_data.t1d2p1_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d2p1_mac_addr,
            },
            "src_endpoint": {
                "port": "T1D3P2",
                "host_ip": const.spytest_data.t1d3p2_ip_addr,
                "gateway": const.spytest_data.d2t1_ip_addr,
                "mac": const.spytest_data.t1d3p2_mac_addr,
            },
        }
    )


def verify_sonic_app_db_for_pfx(nodes, ip, match1, match2, match3):
    """
    Verify the SONIC application database for a given prefix.
    Args:
        nodes (list): List of nodes.
        ip : ip address used in db key.
        match1 (str): First match string.
        match2 (str): Second match string.
        match3 (str): Third match string.
    Returns:
        None
    """
    # IP verification
    db.verify_sonic_app_db_for_pfx(
        nodes,
        ip,
        "leaf0",
        match1 + ":" + ip,
    )
    db.verify_sonic_app_db_for_pfx(
        nodes,
        ip,
        "leaf1",
        match2 + ":" + ip,
    )
    db.verify_sonic_app_db_for_pfx(
        nodes,
        ip,
        "leaf2",
        match3 + ":" + ip,
    )
