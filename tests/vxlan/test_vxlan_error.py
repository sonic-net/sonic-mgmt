import pytest
import logging

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.vxlan_ecmp_utils import Ecmp_Utils
from tests.common.plugins.loganalyzer.loganalyzer import LogAnalyzer, LogAnalyzerError

pytestmark = [
    # This script is only meant to be run on T1 switches.
    pytest.mark.topology("t1", "t1-64-lag", "t1-56-lag", "t1-lag"),
    # loganalyzer is disabled to avoid catching unrelated errors and the same error twice.
    pytest.mark.disable_loganalyzer
]

logger = logging.getLogger(__name__)
ecmp_utils = Ecmp_Utils()


@pytest.fixture(scope="module", autouse=True)
def check_platform(duthost):
    """
        Skip all tests in this module if the platform is not supported.
    """
    asic_type = duthost.facts["asic_type"]
    if asic_type not in ["cisco-8000", "mellanox"]:
        pytest.skip("This test will only run on Cisco-8000 and Mellanox ASICs.")
    platform = duthost.facts["platform"]
    if platform in ['x86_64-mlnx_msn2700-r0', 'x86_64-mlnx_msn2700a1-r0']:
        pytest.skip("Mellanox msn2700 switches do not support IPv6 underlay.")


@pytest.fixture(scope="module", autouse=True)
def setup_ecmp_utils(duthost):
    # Need to set these constants before calling any ecmp_utils function.
    ecmp_utils.Constants["KEEP_TEMP_FILES"] = False
    ecmp_utils.Constants["DEBUG"] = True
    ecmp_utils.Constants["DUT_HOSTID"] = 1


@pytest.fixture
def configure_vxlan_global_params(duthost):
    """
        Fixture to configure global VxLAN parameters before a test and restore previous values after the test.
    """
    logger.info("Configuring global VxLAN parameters...")
    prev_vxlan_port = duthost.shell("sonic-db-cli APPL_DB HGET 'SWITCH_TABLE:switch' 'vxlan_port'")["stdout"].strip()
    prev_vxlan_router_mac = \
        duthost.shell("sonic-db-cli APPL_DB HGET 'SWITCH_TABLE:switch' 'vxlan_router_mac'")["stdout"].strip()
    router_mac = duthost.facts["router_mac"]
    ecmp_utils.configure_vxlan_switch(duthost, dutmac=router_mac)
    yield
    if prev_vxlan_port:
        ecmp_utils.configure_vxlan_switch(duthost, vxlan_port=int(prev_vxlan_port), dutmac=prev_vxlan_router_mac)
    else:
        ecmp_utils.configure_vxlan_switch(duthost, dutmac=prev_vxlan_router_mac)
        duthost.shell("sonic-db-cli APPL_DB HDEL 'SWITCH_TABLE|switch' 'vxlan_port'")


def are_keys_in_app_db(duthost, table, keys, check_exist="all"):
    """
        Function to check if all or none of keys in "keys" exist in APP DB under the specified table.
        :param check_exist: "all" to check if all keys exist, "none" to check if none of the keys exist.
    """
    for key in keys:
        result = duthost.shell(f"sonic-db-cli APPL_DB KEYS '{table}:{key}'")["stdout_lines"]
        if check_exist == "all" and not result:
            return False
        if check_exist == "none" and result:
            return False
    return True


def are_vnet_routes_in_asic_db(duthost, dests, check_exist="all"):
    """
        Function to check if all of or none of VNET routes to destinations in dests are present in ASIC DB.
        :param check_exist: "all" to check if VNET routes to all destinations exist,
        "none" to check if no VNET route to destinations exist.
    """
    for dest in dests:
        result = duthost.shell(f"sonic-db-cli ASIC_DB KEYS \
                               'ASIC_STATE:SAI_OBJECT_TYPE_ROUTE_ENTRY*{dest}*'")["stdout_lines"]
        if check_exist == "all" and not result:
            return False
        if check_exist == "none" and result:
            return False
    return True


@pytest.fixture
def setup(duthost, tbinfo, configure_vxlan_global_params):
    tunnel_v4 = ""
    tunnel_v6 = ""
    vnet4 = ""
    vnet6 = ""
    vnet4_dest_to_endpoint_map = {}
    vnet6_dest_to_endpoint_map = {}
    try:
        minigraph_facts = duthost.get_extended_minigraph_facts(tbinfo)

        loganalyzer = LogAnalyzer(ansible_host=duthost, marker_prefix="TestVxlanError")
        loganalyzer.match_regex = \
            [r".*SAI_NEXT_HOP_ATTR_TUNNEL_ID:SAI_ATTR_VALUE_TYPE_OBJECT_ID object on list \[0\] is NULL, but not allowed.*"]  # noqa E501
        with loganalyzer:
            logger.info("Creating IPv4 and IPv6 VxLAN tunnels...")
            tunnel_v4 = ecmp_utils.create_vxlan_tunnel(duthost, minigraph_facts, af="v4")
            tunnel_v6 = ecmp_utils.create_vxlan_tunnel(duthost, minigraph_facts, af="v6")
            pytest_assert(wait_until(10, 2, 0, are_keys_in_app_db, duthost, "VXLAN_TUNNEL_TABLE",
                          [tunnel_v4, tunnel_v6]), "VxLAN tunnels are not configured in APP DB.")

            logger.info("Creating IPv4 and IPv6 VNETs...")
            vnet4_dict = ecmp_utils.create_vnets(duthost, tunnel_v4, scope="default",
                                                 vnet_name_prefix="Vnet_v4", advertise_prefix="true")
            vnet4 = next(iter(vnet4_dict))  # The first (and only) key is the VNET name
            vnet6_dict = ecmp_utils.create_vnets(duthost, tunnel_v6, scope="default",
                                                 vnet_name_prefix="Vnet_v6", advertise_prefix="true")
            vnet6 = next(iter(vnet6_dict))  # The first (and only) key is the VNET name
            pytest_assert(wait_until(10, 2, 0, are_keys_in_app_db, duthost, "VNET_TABLE", [vnet4, vnet6]),
                          "VNETs are not configured in APP DB.")

            logger.info("Creating IPv4 and IPv6 VNET routes...")
            vnet4_dest_to_endpoint_map = ecmp_utils.create_vnet_routes(duthost, [vnet4], dest_af="v4", nh_af="v4",
                                                                       number_of_available_nexthops=1,
                                                                       number_of_ecmp_nhs=1)
            vnet6_dest_to_endpoint_map = ecmp_utils.create_vnet_routes(duthost, [vnet6], dest_af="v6", nh_af="v6",
                                                                       number_of_available_nexthops=1,
                                                                       number_of_ecmp_nhs=1)
            dests = []
            dests.extend(vnet4_dest_to_endpoint_map[vnet4].keys())
            dests.extend(vnet6_dest_to_endpoint_map[vnet6].keys())
            pytest_assert(wait_until(10, 2, 0, are_vnet_routes_in_asic_db, duthost, dests),
                          "VNET routes are not in ASIC DB.")
        yield
    except LogAnalyzerError as err:
        pytest.fail(str(err))
    finally:
        logger.info("Deleting VNET routes...")
        dests = []
        if vnet4_dest_to_endpoint_map:
            ecmp_utils.set_routes_in_dut(duthost, vnet4_dest_to_endpoint_map, "v4", "DEL")
            dests.extend(vnet4_dest_to_endpoint_map[vnet4].keys())
        if vnet6_dest_to_endpoint_map:
            ecmp_utils.set_routes_in_dut(duthost, vnet6_dest_to_endpoint_map, "v6", "DEL")
            dests.extend(vnet6_dest_to_endpoint_map[vnet6].keys())
        pytest_assert(wait_until(10, 2, 0, are_vnet_routes_in_asic_db, duthost, dests, "none"),
                      "Could not remove VNET routes from ASIC DB.")

        logger.info("Deleting VNETs...")
        vnets = []
        if vnet4:
            duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'VNET|{vnet4}'")
            vnets.append(vnet4)
        if vnet6:
            duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'VNET|{vnet6}'")
            vnets.append(vnet6)
        pytest_assert(wait_until(10, 2, 0, are_keys_in_app_db, duthost, "VNET_TABLE", vnets, "none"),
                      "Could not remove VNETS from APP DB.")

        logger.info("Deleting VxLAN tunnels...")
        tunnels = []
        if tunnel_v4:
            duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'VXLAN_TUNNEL|{tunnel_v4}'")
            tunnels.append(tunnel_v4)
        if tunnel_v6:
            duthost.shell(f"sonic-db-cli CONFIG_DB DEL 'VXLAN_TUNNEL|{tunnel_v6}'")
            tunnels.append(tunnel_v6)
        pytest_assert(wait_until(10, 2, 0, are_keys_in_app_db, duthost, "VXLAN_TUNNEL_TABLE", tunnels, "none"),
                      "Could not remove VxLAN tunnels from APP DB.")


def test_vxlan_error_null_tunnel_id(setup):
    """
    This test ensures that the following error does not happen
    when configuring IPv4 and IPv6 VxLAN, VNET, and VNET routes:
        ERR swss#orchagent: :- meta_generic_validation_objlist: SAI_NEXT_HOP_ATTR_TUNNEL_ID:SAI_ATTR_VALUE_TYPE_OBJECT_ID object on list [0] is NULL, but not allowed  # noqa E501
    """
    pass
