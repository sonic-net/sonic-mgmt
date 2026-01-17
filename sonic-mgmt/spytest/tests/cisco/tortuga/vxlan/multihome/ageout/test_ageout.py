import evpn_mh_utils as evpn_mh_obj
import re
from multihome import db
from multihome import const
from multihome.dut import wait
from multihome.host import (
    is_mac_exists,
    get_mac_static_dynamic,
)
from multihome.status_report import log, report_fail, report_pass
from multihome.traffic_generator import verify_l3_traffic
AGE_OUT_TIME = 200  # seconds
CYCLE_TIMES = 10


def test_mh_mac_ageout(traffic_setup):
    """
    Test mac ageout
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # reduce fdb ageout for mac ageout testcase
    evpn_mh_obj.change_fdb_ageout("5")

    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="stop_all_protocols",
    )
    wait(10)

    evpn_mh_obj.change_fdb_ageout("{}".format(AGE_OUT_TIME))

    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="start_all_protocols",
    )
    wait(15)

    db.is_nhg_installed(nodes)

    # Verify MH mac is static on 1 leaf and dynamic on another
    static0, dynamic0 = get_mac_static_dynamic(
        nodes, "leaf0", const.spytest_data.lag_mac
    )
    static1, dynamic1 = get_mac_static_dynamic(
        nodes, "leaf1", const.spytest_data.lag_mac
    )

    if not (static0 or static1):
        report_fail(
            nodes["leaf0"],
            "Multihomed host mac is not installed correctly as static on one of the leaf",
        )
    if not (dynamic0 or dynamic1):
        report_fail(
            nodes["leaf0"],
            "Multihomed host mac is not installed correctly as dynamic on one of the leaf",
        )

    # Stop L3 protocol
    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="stop_protocol",
        handle=[
            re.search(r"(.*?)/item", lag_handle[const.lag_name]["int_handle"]).group(1)
        ],
    )

    # Wait for ageout
    mac_present = is_mac_exists(nodes, "leaf0", const.spytest_data.lag_mac, True)
    if not mac_present:
        mac_present = is_mac_exists(nodes, "leaf1", const.spytest_data.lag_mac, True)
    time_elapsed = 0
    while mac_present and time_elapsed <= AGE_OUT_TIME:
        wait(AGE_OUT_TIME // CYCLE_TIMES)
        time_elapsed += AGE_OUT_TIME // CYCLE_TIMES
        mac_present = is_mac_exists(nodes, "leaf0", const.spytest_data.lag_mac, True)
        if not mac_present:
            mac_present = is_mac_exists(nodes, "leaf1", const.spytest_data.lag_mac, True)

    # Start L3 prtocol back
    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="start_protocol",
        handle=[
            re.search(r"(.*?)/item", lag_handle[const.lag_name]["int_handle"]).group(1)
        ],
    )

    if mac_present:
        report_fail(nodes["leaf0"], "Multihomed mac never aged out on leaf0/leaf1")

    # revert fdb ageout to original value
    evpn_mh_obj.change_fdb_ageout("600")

    report_pass(nodes["leaf0"], "Multihomed Mac aged out correctly")


def test_sh_mac_ageout(traffic_setup):
    """
    Test mac ageout
    """
    nodes = traffic_setup["duts"]
    lag_handle = traffic_setup["lag_handle"]

    # reduce fdb ageout for mac ageout testcase
    evpn_mh_obj.change_fdb_ageout("5")

    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="stop_all_protocols",
    )
    wait(10)

    evpn_mh_obj.change_fdb_ageout("{}".format(AGE_OUT_TIME))

    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="start_all_protocols",
    )
    wait(15)

    # Verify SH mac is dynamic on the leaf
    static0, dynamic0 = get_mac_static_dynamic(
        nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr
    )

    if static0 or not dynamic0:
        report_fail(
            nodes["leaf0"],
            "SingleHomed host mac is not installed correctly as dynamic on leaf0",
        )

    # Stop L3 protocol
    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="stop_protocol",
        handle=[
            re.search(r"(.*?)/item", lag_handle[const.lag_name]["int_handle"]).group(1)
        ],
    )

    # Wait for ageout
    mac_present = is_mac_exists(nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr, True)
    time_elapsed = 0
    while mac_present and time_elapsed <= AGE_OUT_TIME:
        wait(AGE_OUT_TIME // CYCLE_TIMES)
        time_elapsed += AGE_OUT_TIME // CYCLE_TIMES
        mac_present = is_mac_exists(nodes, "leaf0", const.spytest_data.t1d2p1_mac_addr, True)

    # Start L3 prtocol back
    lag_handle[const.lag_name]["tg_handle"].tg_test_control(
        action="start_protocol",
        handle=[
            re.search(r"(.*?)/item", lag_handle[const.lag_name]["int_handle"]).group(1)
        ],
    )

    if mac_present:
        report_fail(nodes["leaf0"], "SingleHomed mac never aged out on leaf0/leaf1")

    # revert fdb ageout to original value
    evpn_mh_obj.change_fdb_ageout("600")

    report_pass(nodes["leaf0"], "SingleHomed Mac aged out correctly")
