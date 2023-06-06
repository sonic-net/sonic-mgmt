import pytest
import time
import logging
import json

from tests.common.helpers.assertions import pytest_assert
from tests.common import config_reload
from tests.common.reboot import reboot
from helper import apply_cert_config
from restapi_operations import Restapi


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t0'),
    pytest.mark.disable_loganalyzer
]

CLIENT_CERT = 'restapiclient.crt'
CLIENT_KEY = 'restapiclient.key'

restapi = Restapi(CLIENT_CERT, CLIENT_KEY)

'''
This test checks for reset status and sets it
'''


def test_check_reset_status(construct_url, duthosts, rand_one_dut_hostname, localhost):
    duthost = duthosts[rand_one_dut_hostname]
    # Set reset status
    logger.info("Checking for RESTAPI reset status")
    r = restapi.get_reset_status(construct_url)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    response = r.json()
    pytest_assert(response['reset_status'] == "true")
    logger.info("Setting RESTAPI reset status")
    params = '{"reset_status":"false"}'
    r = restapi.post_reset_status(construct_url, params)
    pytest_assert(r.status_code == 200)
    r = restapi.get_reset_status(construct_url)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    response = r.json()
    pytest_assert(response['reset_status'] == "false")

    # Check reset status post config reload
    logger.info("Checking for RESTAPI reset status after config reload")
    config_reload(duthost)
    apply_cert_config(duthost)
    r = restapi.get_reset_status(construct_url)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    response = r.json()
    pytest_assert(response['reset_status'] == "true")

    # Check reset status post fast reboot
    check_reset_status_after_reboot(
        'fast', "false", "true", duthost, localhost, construct_url)
    # Check reset status post cold reboot
    check_reset_status_after_reboot(
        'cold', "false", "true", duthost, localhost, construct_url)
    # Check reset status post warm reboot
    check_reset_status_after_reboot(
        'warm', "false", "false", duthost, localhost, construct_url)


def check_reset_status_after_reboot(reboot_type, pre_reboot_status, post_reboot_status,
                                    duthost, localhost, construct_url):
    logger.info("Checking for RESTAPI reset status after " +
                reboot_type+" reboot")
    params = '{"reset_status":"false"}'
    r = restapi.post_reset_status(construct_url, params)
    pytest_assert(r.status_code == 200)
    r = restapi.get_reset_status(construct_url)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    response = r.json()
    pytest_assert(response['reset_status'] == pre_reboot_status)
    # Add extra wait for warm-reboot to ensure warmboot-finalizer is done
    # Otherwise, the warmboot-finalizer will write the testing vnet and vlan config
    # into config_db.json and cause unrecoverable errors
    wait_warmboot_finalizer = False
    if reboot_type == 'warm':
        wait_warmboot_finalizer = True
    reboot(duthost, localhost, reboot_type,
           wait_warmboot_finalizer=wait_warmboot_finalizer)
    apply_cert_config(duthost)
    r = restapi.get_reset_status(construct_url)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    response = r.json()
    pytest_assert(response['reset_status'] == post_reboot_status)


@pytest.fixture
def cleanup_after_testing(rand_selected_dut):
    """
    Cleanup DUT by config reload after test running.
    """
    yield
    config_reload(rand_selected_dut)


'''
This test creates a default VxLAN Tunnel and two VNETs.
It adds VLAN, VLAN member, VLAN neighbor and routes to each VNET
'''


def test_data_path(construct_url, vlan_members, cleanup_after_testing):
    # Create Default VxLan Tunnel
    if restapi.get_config_tunnel_decap_tunnel_type(construct_url, 'vxlan').status_code == 404:
        params = '{"ip_addr": "10.1.0.32"}'
        logger.info("Creating Default VxLan Tunnel with ip_addr: 10.1.0.32")
        r = restapi.post_config_tunnel_decap_tunnel_type(
            construct_url, 'vxlan', params)
        pytest_assert(r.status_code == 204)

    # Check RESTAPI server heartbeat
    logger.info("Checking for RESTAPI server heartbeat")
    restapi.heartbeat(construct_url)

    #
    # Create first VNET and add VLAN, VLAN member, VLAN neighbor and routes to it
    #

    # Create VNET
    params = '{"vnid": 7036001}'
    logger.info("Creating VNET vnet-guid-2 with vnid: 7036001")
    r = restapi.post_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-2')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 7036001}, "vnet_id": "vnet-guid-2"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VNET with vnet_id: vnet-guid-2 has been successfully created with vnid: 7036001")

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-2", "ip_prefix": "100.0.10.1/24"}'
    logger.info(
        "Creating VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2")
    r = restapi.post_config_vlan(construct_url, '2000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '2000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "100.0.10.1/24", "vnet_id": "vnet-guid-2"}, "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2 has been successfully created")

    if len(vlan_members) < 1:
        pytest.skip("No VLAN interface available")
    vlan_intf = vlan_members[0]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 2000")
    r = restapi.post_config_vlan_member(
        construct_url, '2000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '2000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf + \
        '", "vlan_id": 2000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 2000")

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 100.0.10.4 to VLAN 2000")
    r = restapi.post_config_vlan_neighbor(
        construct_url, '2000', '100.0.10.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '2000', '100.0.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "100.0.10.4", "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 100.0.10.4 has been successfully added to VLAN 2000")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "101.0.20.5/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": "1c:34:da:72:b0:8a"}, \
               {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "100.0.30.0/24", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}]'
    logger.info("Adding routes with vnid: 7036001 to VNET vnet-guid-2")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    # Add some delay before query
    time.sleep(5)
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 7036001},
                {"nexthop": "100.3.152.52", "ip_prefix": "101.0.20.5/32",
                    "mac_address": "1c:34:da:72:b0:8a", "vnid": 7036001},
                {"nexthop": "100.3.152.52",
                    "ip_prefix": "100.0.20.4/32", "vnid": 7036001},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.30.0/24", "vnid": 7036001}]
    for route in expected:
        pytest_assert(route in r.json())
    logger.info(
        "Routes with vnid: 7036001 to VNET vnet-guid-2 have been added successfully")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.50.4/24", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "100.0.70.0/16", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}]'
    logger.info(
        "Adding routes with incorrect CIDR addresses with vnid: 7036001 to VNET vnet-guid-2")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 207)

    # Verify routes have not been added
    # Add some delay before query
    time.sleep(5)
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "100.0.50.4/24", "vnid": 7036001},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.70.0/16", "vnid": 7036001}]
    for route in expected:
        pytest_assert(route not in r.json())
    logger.info(
        "Routes with incorrect CIDR addresses with vnid: 7036001 to VNET vnet-guid-2 have not been added successfully")

    #
    # Create second VNET and add VLAN, VLAN member, VLAN neighbor and routes to it
    #

    # Create VNET
    params = '{"vnid": 7036002}'
    logger.info("Creating VNET vnet-guid-3 with vnid: 7036002")
    r = restapi.post_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-3')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 7036002}, "vnet_id": "vnet-guid-3"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VNET with vnet_id: vnet-guid-3 has been successfully created with vnid: 7036002")

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-3", "ip_prefix": "192.168.10.1/24"}'
    logger.info(
        "Creating VLAN 3000 with ip_prefix: 192.168.10.1/24 under vnet_id: vnet-guid-3")
    r = restapi.post_config_vlan(construct_url, '3000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '3000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "192.168.10.1/24", "vnet_id": "vnet-guid-3"}, "vlan_id": 3000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VLAN 3000 with ip_prefix: 192.168.10.1/24 under vnet_id: vnet-guid-3 has been successfully created")

    vlan_intf = vlan_members[1]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 3000")
    r = restapi.post_config_vlan_member(
        construct_url, '3000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '3000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf + \
        '", "vlan_id": 3000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 3000")

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 192.168.10.4 to VLAN 2000")
    r = restapi.post_config_vlan_neighbor(
        construct_url, '3000', '192.168.10.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '3000', '192.168.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "192.168.10.4", "vlan_id": 3000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 192.168.10.4 has been successfully added to VLAN 3000")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036002, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "101.0.20.5/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036002, "mac_address": "1c:34:da:72:b0:8a"}, \
               {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036002, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "100.0.30.0/24", "nexthop": "100.3.152.52",\
                    "vnid": 7036002, "mac_address": null}]'
    logger.info("Adding routes with vnid: 7036002 to VNET vnet-guid-3")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 7036002},
                {"nexthop": "100.3.152.52", "ip_prefix": "101.0.20.5/32",
                    "mac_address": "1c:34:da:72:b0:8a", "vnid": 7036002},
                {"nexthop": "100.3.152.52",
                    "ip_prefix": "100.0.20.4/32", "vnid": 7036002},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.30.0/24", "vnid": 7036002}]
    for route in expected:
        pytest_assert(route in r.json())
    logger.info(
        "Routes with vnid: 3000 to VNET vnet-guid-3 have been added successfully")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.50.4/24", "nexthop": "100.3.152.52",\
                    "vnid": 7036002, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "100.0.70.0/16", "nexthop": "100.3.152.52",\
                    "vnid": 7036002, "mac_address": null}]'
    logger.info(
        "Adding routes with incorrect CIDR addresses with vnid: 7036002 to VNET vnet-guid-3")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 207)

    # Verify routes have not been added
    # Add some delay before query
    time.sleep(5)
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "100.0.50.4/24", "vnid": 7036002},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.70.0/16", "vnid": 7036002}]
    for route in expected:
        pytest_assert(route not in r.json())
    logger.info(
        "Routes with incorrect CIDR addresses with vnid: 7036002 to VNET vnet-guid-3 have not been added successfully")


def test_data_path_sad(construct_url, vlan_members, cleanup_after_testing):
    # Create Default VxLan Tunnel
    if restapi.get_config_tunnel_decap_tunnel_type(construct_url, 'vxlan').status_code == 404:
        params = '{"ip_addr": "10.1.0.32"}'
        logger.info("Creating Default VxLan Tunnel with ip_addr: 10.1.0.32")
        r = restapi.post_config_tunnel_decap_tunnel_type(
            construct_url, 'vxlan', params)
        pytest_assert(r.status_code == 204)

    # Check RESTAPI server heartbeat
    logger.info("Checking for RESTAPI server heartbeat")
    restapi.heartbeat(construct_url)

    #
    # Create first VNET and add VLAN, VLAN member, VLAN neighbor and routes to it
    #

    # Create VNET
    params = '{"vnid": 7036001}'
    logger.info("Creating VNET vnet-guid-2 with vnid: 7036001")
    r = restapi.post_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-2')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 7036001}, "vnet_id": "vnet-guid-2"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VNET with vnet_id: vnet-guid-2 has been successfully created with vnid: 7036001")

    # Repeat create VNET
    params = '{"vnid": 7036001}'
    logger.info("Repeating creation of VNET vnet-guid-2 with vnid: 7036001")
    for i in range(5):
        r = restapi.post_config_vrouter_vrf_id(
            construct_url, 'vnet-guid-2', params)
        pytest_assert(r.status_code == 409)

    # Create new VNET with existing VNID
    params = '{"vnid": 7036001}'
    logger.info("Creation of VNET vnet-guid-3 with vnid: 7036001")
    for i in range(5):
        r = restapi.post_config_vrouter_vrf_id(
            construct_url, 'vnet-guid-3', params)
        pytest_assert(r.status_code == 409)

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-2", "ip_prefix": "100.0.10.1/24"}'
    logger.info(
        "Creating VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2")
    r = restapi.post_config_vlan(construct_url, '2000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '2000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "100.0.10.1/24", "vnet_id": "vnet-guid-2"}, "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2 has been successfully created")

    # Repeat create VLAN
    params = '{"vnet_id": "vnet-guid-2", "ip_prefix": "100.0.10.1/24"}'
    logger.info(
        "Repeating creation of VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2")
    for i in range(5):
        r = restapi.post_config_vlan(construct_url, '2000', params)
        pytest_assert(r.status_code == 409)

    if len(vlan_members) < 1:
        pytest.skip("No VLAN interface available")
    vlan_intf = vlan_members[0]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 2000")
    r = restapi.post_config_vlan_member(
        construct_url, '2000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '2000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf + \
        '", "vlan_id": 2000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 2000")

    # Repeat add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Repeating Adding "+vlan_intf +
                " with tagging_mode: tagged to VLAN 2000")
    for i in range(5):
        r = restapi.post_config_vlan_member(
            construct_url, '2000', vlan_intf, params)
        pytest_assert(r.status_code == 409)

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 100.0.10.4 to VLAN 2000")
    r = restapi.post_config_vlan_neighbor(
        construct_url, '2000', '100.0.10.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '2000', '100.0.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "100.0.10.4", "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 100.0.10.4 has been successfully added to VLAN 2000")

    # Repeat add neighbor
    params = '{}'
    logger.info("Repeat adding neighbor 100.0.10.4 to VLAN 2000")
    for i in range(5):
        r = restapi.post_config_vlan_neighbor(
            construct_url, '2000', '100.0.10.4', params)
        pytest_assert(r.status_code == 409)

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "101.0.20.5/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": "1c:34:da:72:b0:8a"}, \
               {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "100.0.30.0/24", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}]'
    logger.info("Adding routes with vnid: 7036001 to VNET vnet-guid-2")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    # Add some delay before query
    time.sleep(5)
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 7036001},
                {"nexthop": "100.3.152.52", "ip_prefix": "101.0.20.5/32",
                    "mac_address": "1c:34:da:72:b0:8a", "vnid": 7036001},
                {"nexthop": "100.3.152.52",
                    "ip_prefix": "100.0.20.4/32", "vnid": 7036001},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.30.0/24", "vnid": 7036001}]
    for route in expected:
        pytest_assert(route in r.json())
    logger.info(
        "Routes with vnid: 7036001 to VNET vnet-guid-2 have been added successfully")

    # Repeat add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "101.0.20.5/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": "1c:34:da:72:b0:8a"}, \
               {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}, \
               {"cmd": "add", "ip_prefix": "100.0.30.0/24", "nexthop": "100.3.152.52",\
                    "vnid": 7036001, "mac_address": null}]'
    logger.info("Adding routes with vnid: 7036001 to VNET vnet-guid-2")
    for i in range(5):
        r = restapi.patch_config_vrouter_vrf_id_routes(
            construct_url, 'vnet-guid-2', params)
        pytest_assert(r.status_code == 204)


'''
This test creates a VNET. It adds routes to the VNET and deletes them
'''


def test_create_vrf(construct_url, cleanup_after_testing):
    # Create Default VxLan Tunnel
    if restapi.get_config_tunnel_decap_tunnel_type(construct_url, 'vxlan').status_code == 404:
        params = '{"ip_addr": "10.1.0.32"}'
        logger.info("Creating Default VxLan Tunnel with ip_addr: 10.1.0.32")
        r = restapi.post_config_tunnel_decap_tunnel_type(
            construct_url, 'vxlan', params)
        pytest_assert(r.status_code == 204)

    # Create VNET
    params = '{"vnid": 7039114}'
    logger.info("Creating VNET vnet-guid-10 with vnid: 7039114")
    r = restapi.post_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-10', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-10')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 7039114}, "vnet_id": "vnet-guid-10"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VNET with vnet_id: vnet-guid-10 has been successfully created with vnid: 7039114")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "10.1.0.1/32", "nexthop": "100.78.60.37",\
                    "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "add", "ip_prefix": "10.1.0.2/32", "nexthop": "100.78.60.37",\
                    "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "add", "ip_prefix": "10.1.0.3/32", "nexthop": "100.78.60.37",\
                    "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "add", "ip_prefix": "10.1.0.4/32", "nexthop": "100.78.60.37",\
                    "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "add", "ip_prefix": "10.1.0.5/32", "nexthop": "100.78.60.37",\
                    "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}]'
    logger.info("Adding routes with vnid: 7039114 to VNET vnet-guid-10")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-10', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-10', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.78.60.37", "ip_prefix": "10.1.0.1/32",
                 "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"},
                {"nexthop": "100.78.60.37", "ip_prefix": "10.1.0.2/32",
                 "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"},
                {"nexthop": "100.78.60.37", "ip_prefix": "10.1.0.3/32",
                 "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"},
                {"nexthop": "100.78.60.37", "ip_prefix": "10.1.0.4/32",
                 "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"},
                {"nexthop": "100.78.60.37", "ip_prefix": "10.1.0.5/32",
                 "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}]
    for route in expected:
        pytest_assert(route in r.json())
    logger.info(
        "Routes with vnid: 7039114 to VNET vnet-guid-10 have been added successfully")

    # Delete routes
    params = '[{"cmd": "delete", "ip_prefix": "10.1.0.1/32", "nexthop": "100.78.60.37",\
                   "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "delete", "ip_prefix": "10.1.0.2/32", "nexthop": "100.78.60.37",\
                   "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "delete", "ip_prefix": "10.1.0.3/32", "nexthop": "100.78.60.37",\
                   "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "delete", "ip_prefix": "10.1.0.4/32", "nexthop": "100.78.60.37",\
                   "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}, \
               {"cmd": "delete", "ip_prefix": "10.1.0.5/32", "nexthop": "100.78.60.37",\
                   "vnid": 7039114, "mac_address": "00:0d:3a:f9:1a:20"}]'
    logger.info("Deleting routes with vnid: 7039114 from VNET vnet-guid-10")
    r = restapi.patch_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-10', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(
        construct_url, 'vnet-guid-10', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    pytest_assert(len(r.json()) == 0)
    logger.info(
        "Routes with vnid: 7039114 from VNET vnet-guid-10 have been deleted successfully")


'''
This test creates a default VxLAN Tunnel and two VNETs. It adds VLAN, VLAN member, VLAN neighbor and routes to each VNET
'''


def test_create_interface(construct_url, vlan_members, cleanup_after_testing):
    # Create Default VxLan Tunnel
    if restapi.get_config_tunnel_decap_tunnel_type(construct_url, 'vxlan').status_code == 404:
        params = '{"ip_addr": "10.1.0.32"}'
        logger.info("Creating Default VxLan Tunnel with ip_addr: 10.1.0.32")
        r = restapi.post_config_tunnel_decap_tunnel_type(
            construct_url, 'vxlan', params)
        pytest_assert(r.status_code == 204)

    # Create VNET
    params = '{"vnid": 7039115}'
    logger.info("Creating VNET vnet-guid-3 with vnid: 7039115")
    r = restapi.post_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-4', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 7039115}, "vnet_id": "vnet-guid-4"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VNET with vnet_id: vnet-guid-4 has been successfully created with vnid: 7039115")

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-4", "ip_prefix": "40.0.0.1/24"}'
    logger.info(
        "Creating VLAN 4000 with ip_prefix: 40.0.0.1/24 under vnet_id: vnet-guid-4")
    r = restapi.post_config_vlan(construct_url, '4000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '4000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "40.0.0.1/24", "vnet_id": "vnet-guid-4"}, "vlan_id": 4000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VLAN 4000 with ip_prefix: 40.0.0.1/24 under vnet_id: vnet-guid-4 has been successfully created")

    vlan_intf = vlan_members[0]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 4000")
    r = restapi.post_config_vlan_member(
        construct_url, '4000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '4000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf + \
        '", "vlan_id": 4000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 4000")

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 40.0.0.4 to VLAN 4000")
    r = restapi.post_config_vlan_neighbor(
        construct_url, '4000', '40.0.0.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '4000', '40.0.0.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "40.0.0.4", "vlan_id": 4000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 40.0.0.4 has been successfully added to VLAN 4000")

    # Delete Neighbor
    params = '{}'
    logger.info("Deleting neighbor 40.0.0.4 from VLAN 4000")
    r = restapi.delete_config_vlan_neighbor(
        construct_url, '4000', '40.0.0.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been deleted
    r = restapi.get_config_vlan_neighbor(construct_url, '4000', '40.0.0.4')
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info("Neighbor 40.0.0.4 has been successfully deleted to VLAN 4000")

    # Delete VLAN member
    params = '{}'
    logger.info("Deleting "+vlan_intf +
                " with tagging_mode: tagged to VLAN 4000")
    r = restapi.delete_config_vlan_member(
        construct_url, '4000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been deleted
    r = restapi.get_config_vlan_member(construct_url, '4000', vlan_intf)
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully deleted to VLAN 4000")

    # Delete VLAN
    params = '{}'
    logger.info("Deleting VLAN 4000")
    r = restapi.delete_config_vlan(construct_url, '4000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been deleted
    r = restapi.get_config_vlan(construct_url, '4000')
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info("VLAN 4000 has been successfully deleted")

    # Delete VNET
    params = '{}'
    logger.info("Deleting VNET vnet-guid-3")
    r = restapi.delete_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-4', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been deleted
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-4')
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info("VNET with vnet_id: vnet-guid-4 has been successfully deleted")


def test_create_interface_sad(construct_url, vlan_members):
    # Create Default VxLan Tunnel
    if restapi.get_config_tunnel_decap_tunnel_type(construct_url, 'vxlan').status_code == 404:
        params = '{"ip_addr": "10.1.0.32"}'
        logger.info("Creating Default VxLan Tunnel with ip_addr: 10.1.0.32")
        r = restapi.post_config_tunnel_decap_tunnel_type(
            construct_url, 'vxlan', params)
        pytest_assert(r.status_code == 204)

    # Create VNET
    params = '{"vnid": 7039115}'
    logger.info("Creating VNET vnet-guid-3 with vnid: 7039115")
    r = restapi.post_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-4', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 7039115}, "vnet_id": "vnet-guid-4"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VNET with vnet_id: vnet-guid-4 has been successfully created with vnid: 7039115")

    # Repeat create VNET
    params = '{"vnid": 7039115}'
    logger.info("Repeat creating VNET vnet-guid-3 with vnid: 7039115")
    for i in range(5):
        r = restapi.post_config_vrouter_vrf_id(
            construct_url, 'vnet-guid-4', params)
        pytest_assert(r.status_code == 409)

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-4", "ip_prefix": "40.0.0.1/24"}'
    logger.info(
        "Creating VLAN 4000 with ip_prefix: 40.0.0.1/24 under vnet_id: vnet-guid-4")
    r = restapi.post_config_vlan(construct_url, '4000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '4000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "40.0.0.1/24", "vnet_id": "vnet-guid-4"}, "vlan_id": 4000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        "VLAN 4000 with ip_prefix: 40.0.0.1/24 under vnet_id: vnet-guid-4 has been successfully created")

    # Repeat create VLAN
    params = '{"vnet_id": "vnet-guid-4", "ip_prefix": "40.0.0.1/24"}'
    logger.info(
        "Repeat creating VLAN 4000 with ip_prefix: 40.0.0.1/24 under vnet_id: vnet-guid-4")
    for i in range(5):
        r = restapi.post_config_vlan(construct_url, '4000', params)
        pytest_assert(r.status_code == 409)

    vlan_intf = vlan_members[0]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 4000")
    r = restapi.post_config_vlan_member(
        construct_url, '4000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '4000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf + \
        '", "vlan_id": 4000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 4000")

    # Repeat add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Repeat adding "+vlan_intf +
                " with tagging_mode: tagged to VLAN 4000")
    for i in range(5):
        r = restapi.post_config_vlan_member(
            construct_url, '4000', vlan_intf, params)
        pytest_assert(r.status_code == 409)

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 40.0.0.4 to VLAN 4000")
    r = restapi.post_config_vlan_neighbor(
        construct_url, '4000', '40.0.0.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '4000', '40.0.0.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "40.0.0.4", "vlan_id": 4000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 40.0.0.4 has been successfully added to VLAN 4000")

    # Repeat add neighbor
    params = '{}'
    logger.info("Repeat adding neighbor 40.0.0.4 to VLAN 4000")
    for i in range(5):
        r = restapi.post_config_vlan_neighbor(
            construct_url, '4000', '40.0.0.4', params)
        pytest_assert(r.status_code == 409)

    # Delete VLAN before VLAN deleting neigbor and member
    params = '{}'
    logger.info("Deleting VLAN 4000 before deleting VLAN neigbor and member")
    r = restapi.delete_config_vlan(construct_url, '4000', params)
    pytest_assert(r.status_code == 409)

    # Delete Neighbor
    params = '{}'
    logger.info("Deleting neighbor 40.0.0.4 from VLAN 4000")
    r = restapi.delete_config_vlan_neighbor(
        construct_url, '4000', '40.0.0.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been deleted
    r = restapi.get_config_vlan_neighbor(construct_url, '4000', '40.0.0.4')
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info("Neighbor 40.0.0.4 has been successfully deleted to VLAN 4000")

    # Repeat delete Neighbor
    params = '{}'
    logger.info("Repeat deleting neighbor 40.0.0.4 from VLAN 4000")
    for i in range(5):
        r = restapi.delete_config_vlan_neighbor(
            construct_url, '4000', '40.0.0.4', params)
        pytest_assert(r.status_code == 404)

    # Delete VLAN before deleting member
    params = '{}'
    logger.info("Deleting VLAN 4000 before deleting VLAN member")
    r = restapi.delete_config_vlan(construct_url, '4000', params)
    pytest_assert(r.status_code == 409)

    # Delete VLAN member
    params = '{}'
    logger.info("Deleting "+vlan_intf +
                " with tagging_mode: tagged to VLAN 4000")
    r = restapi.delete_config_vlan_member(
        construct_url, '4000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been deleted
    r = restapi.get_config_vlan_member(construct_url, '4000', vlan_intf)
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info(
        vlan_intf+" with tagging_mode: tagged has been successfully deleted to VLAN 4000")

    # Repeat delete VLAN member
    params = '{}'
    logger.info("Repeat deleting "+vlan_intf +
                " with tagging_mode: tagged to VLAN 4000")
    for i in range(5):
        r = restapi.delete_config_vlan_member(
            construct_url, '4000', vlan_intf, params)
        pytest_assert(r.status_code == 404)

    # Delete VLAN
    params = '{}'
    logger.info("Deleting VLAN 4000")
    r = restapi.delete_config_vlan(construct_url, '4000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been deleted
    r = restapi.get_config_vlan(construct_url, '4000')
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info("VLAN 4000 has been successfully deleted")

    # Repeat delete VLAN
    params = '{}'
    logger.info("Repeat deleting VLAN 4000")
    for i in range(5):
        r = restapi.delete_config_vlan(construct_url, '4000', params)
        pytest_assert(r.status_code == 404)

    # Delete VNET
    params = '{}'
    logger.info("Deleting VNET vnet-guid-3")
    r = restapi.delete_config_vrouter_vrf_id(
        construct_url, 'vnet-guid-4', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been deleted
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-4')
    pytest_assert(r.status_code == 404)
    logger.info(r.json())
    logger.info("VNET with vnet_id: vnet-guid-4 has been successfully deleted")

    # Repeat delete VNET
    params = '{}'
    logger.info("Repeat deleting VNET vnet-guid-3")
    for i in range(5):
        r = restapi.delete_config_vrouter_vrf_id(
            construct_url, 'vnet-guid-4', params)
        pytest_assert(r.status_code == 404)
