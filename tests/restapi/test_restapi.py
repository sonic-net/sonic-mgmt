import pytest
import time
import logging
import requests
import json

from tests.common.helpers.assertions import pytest_assert
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
This test creates a default VxLAN Tunnel and two VNETs. It adds VLAN, VLAN member, VLAN neighbor and routes to each VNET
'''
def test_data_path(construct_url, vlan_members):
    # Create Default VxLan Tunnel
    params = '{"ip_addr": "10.3.152.32"}'
    logger.info("Creating Default VxLan Tunnel with ip_addr: 10.3.152.32")
    r = restapi.post_config_tunnel_decap_tunnel_type(construct_url, 'vxlan', params)
    pytest_assert(r.status_code == 204)

    # Check RESTAPI server heartbeat
    logger.info("Checking for RESTAPI server heartbeat")
    restapi.heartbeat(construct_url)

    #
    # Create first VNET and add VLAN, VLAN member, VLAN neighbor and routes to it
    #

    # Create VNET
    params = '{"vnid": 2000}'
    logger.info("Creating VNET vnet-guid-2 with vnid: 2000")
    r = restapi.post_config_vrouter_vrf_id(construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-2')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 2000}, "vnet_id": "vnet-guid-2"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("VNET with vnet_id: vnet-guid-2 has been successfully created with vnid: 2000")

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-2", "ip_prefix": "100.0.10.1/24"}'
    logger.info("Creating VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2")
    r = restapi.post_config_vlan(construct_url, '2000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '2000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "100.0.10.1/24", "vnet_id": "vnet-guid-2"}, "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("VLAN 2000 with ip_prefix: 100.0.10.1/24 under vnet_id: vnet-guid-2 has been successfully created")

    vlan_intf = vlan_members[0]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 2000")
    r = restapi.post_config_vlan_member(construct_url, '2000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '2000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf+'", "vlan_id": 2000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 2000")

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 100.0.10.4 to VLAN 2000")
    r = restapi.post_config_vlan_neighbor(construct_url, '2000', '100.0.10.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '2000', '100.0.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "100.0.10.4", "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 100.0.10.4 has been successfully added to VLAN 2000")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52", "vnid": 2000, "mac_address": null}, \
                {"cmd": "add", "ip_prefix": "101.0.20.5/32", "nexthop": "100.3.152.52", "vnid": 2000, "mac_address": "1c:34:da:72:b0:8a"}, \
                {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52", "vnid": 2000, "mac_address": null}]'
    logger.info("Adding routes with vnid: 2000 to VNET vnet-guid-2")
    r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-2', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 2000},
                {"nexthop": "100.3.152.52", "ip_prefix": "101.0.20.5/32", "mac_address": "1c:34:da:72:b0:8a", "vnid": 2000},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.20.4/32", "vnid": 2000}]
    for route in expected:
        pytest_assert(route in r.json())
    logger.info("Routes with vnid: 2000 to VNET vnet-guid-2 have been added successfully")


    #
    # Create second VNET and add VLAN, VLAN member, VLAN neighbor and routes to it
    #

    # Create VNET
    params = '{"vnid": 3000}'
    logger.info("Creating VNET vnet-guid-3 with vnid: 3000")
    r = restapi.post_config_vrouter_vrf_id(construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-3')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 3000}, "vnet_id": "vnet-guid-3"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("VNET with vnet_id: vnet-guid-3 has been successfully created with vnid: 3000")

    # Create VLAN
    params = '{"vnet_id": "vnet-guid-3", "ip_prefix": "192.168.10.1/24"}'
    logger.info("Creating VLAN 3000 with ip_prefix: 192.168.10.1/24 under vnet_id: vnet-guid-3")
    r = restapi.post_config_vlan(construct_url, '3000', params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN has been created
    r = restapi.get_config_vlan(construct_url, '3000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "192.168.10.1/24", "vnet_id": "vnet-guid-3"}, "vlan_id": 3000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("VLAN 3000 with ip_prefix: 192.168.10.1/24 under vnet_id: vnet-guid-3 has been successfully created")

    vlan_intf = vlan_members[1]
    logger.info("VLAN Interface: "+vlan_intf)

    # Add and configure VLAN member
    params = '{"tagging_mode": "tagged"}'
    logger.info("Adding "+vlan_intf+" with tagging_mode: tagged to VLAN 3000")
    r = restapi.post_config_vlan_member(construct_url, '3000', vlan_intf, params)
    pytest_assert(r.status_code == 204)

    # Verify VLAN member has been added
    r = restapi.get_config_vlan_member(construct_url, '3000', vlan_intf)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "'+vlan_intf+'", "vlan_id": 3000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info(vlan_intf+" with tagging_mode: tagged has been successfully added to VLAN 3000")

    # Add neighbor
    params = '{}'
    logger.info("Adding neighbor 192.168.10.4 to VLAN 2000")
    r = restapi.post_config_vlan_neighbor(construct_url, '3000', '192.168.10.4', params)
    pytest_assert(r.status_code == 204)

    # Verify neighbor has been added
    r = restapi.get_config_vlan_neighbor(construct_url, '3000', '192.168.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "192.168.10.4", "vlan_id": 3000}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("Neighbor 192.168.10.4 has been successfully added to VLAN 3000")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52", "vnid": 3000, "mac_address": null}, \
                {"cmd": "add", "ip_prefix": "101.0.20.5/32", "nexthop": "100.3.152.52", "vnid": 3000, "mac_address": "1c:34:da:72:b0:8a"}, \
                {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52", "vnid": 3000, "mac_address": null}]'
    logger.info("Adding routes with vnid: 3000 to VNET vnet-guid-3")
    r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 3000},
                {"nexthop": "100.3.152.52", "ip_prefix": "101.0.20.5/32", "mac_address": "1c:34:da:72:b0:8a", "vnid": 3000},
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.20.4/32", "vnid": 3000}]
    for route in expected:
        pytest_assert(route in r.json())
    logger.info("Routes with vnid: 3000 to VNET vnet-guid-3 have been added successfully")
