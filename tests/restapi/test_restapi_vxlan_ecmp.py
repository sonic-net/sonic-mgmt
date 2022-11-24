import pytest
import logging
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


def test_vxlan_ecmp_multirequest(construct_url, vlan_members):
    #test to emulate common scenario in pilot.
    # Create Generic tunnel
    params = '{"ip_addr": "100.78.1.1"}'
    logger.info("Creating default vxlan tunnel")
    r = restapi.post_config_tunnel_decap(construct_url, params)
    pytest_assert(r.status_code == 204)
    
    # Create VNET
    params = '{"vnid": 703}'
    logger.info("Creating VNET vnet-guid-3 with vnid: 703")
    r = restapi.post_config_vrouter_vrf_id(construct_url, 'vnet-default', params)
    pytest_assert(r.status_code == 204)

    # Verify VNET has been created
    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-default')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 703}, "vnet_id": "vnet-default"}'
    pytest_assert(r.json() == json.loads(expected))
    logger.info("VNET with vnet_id: vnet-guid-4 has been successfully created with vnid: 7039115")

    # Add routes
    params = '[{"cmd": "add", "ip_prefix": "10.1.0.1/32", "nexthop": "100.78.60.37,100.78.61.37"}, \
                {"cmd": "add", "ip_prefix": "10.1.0.5/32", "nexthop": "100.78.60.41,100.78.61.41"}]'
    logger.info("Adding routes with vnid: 703 to VNET vnet-default")
    r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
    pytest_assert(r.status_code == 204)

    for i in range(1,10):

        params = '{}'
        r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
        pytest_assert(r.status_code == 200)
        logger.info(r.json())
        expected = [{"nexthop": "100.78.60.37,100.78.61.37", "ip_prefix": "10.1.0.1/32"}, 
                    {"nexthop": "100.78.60.41,100.78.61.41", "ip_prefix": "10.1.0.5/32"}]
        for route in expected:
            pytest_assert(route in r.json())
        logger.info("Routes with vnid: 703 to VNET vnet-default have been added successfully")

        # Add routes
        params = '[{"cmd": "add", "ip_prefix": "10.1.0.2/32", "nexthop": "100.78.60.38,100.78.61.38"}, \
                    {"cmd": "add", "ip_prefix": "10.1.0.3/32", "nexthop": "100.78.60.39,100.78.61.39"}, \
                    {"cmd": "add", "ip_prefix": "10.1.0.4/32", "nexthop": "100.78.60.40,100.78.61.40"}]'
        logger.info("Adding routes with vnid: 703 to VNET vnet-default")
        r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
        pytest_assert(r.status_code == 204)

        params = '{}'
        for j in range(1,10):
            r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
            pytest_assert(r.status_code == 200)
            logger.info(r.json())
            expected = [{"nexthop": "100.78.60.37,100.78.61.37", "ip_prefix": "10.1.0.1/32"}, 
                    {"nexthop": "100.78.60.38,100.78.61.38", "ip_prefix": "10.1.0.2/32"},
                    {"nexthop": "100.78.60.39,100.78.61.39", "ip_prefix": "10.1.0.3/32"},
                    {"nexthop": "100.78.60.40,100.78.61.40", "ip_prefix": "10.1.0.4/32"},
                    {"nexthop": "100.78.60.41,100.78.61.41", "ip_prefix": "10.1.0.5/32"}]
            for route in expected:
                pytest_assert(route in r.json())
        logger.info("Routes with vnid: 703 to VNET vnet-default have been added successfully")

        # Delete routes
        params = '[{"cmd": "delete", "ip_prefix": "10.1.0.2/32", "nexthop": "100.78.60.38,100.78.61.38"}, \
                    {"cmd": "delete", "ip_prefix": "10.1.0.3/32", "nexthop": "100.78.60.39,100.78.61.39"}, \
                    {"cmd": "delete", "ip_prefix": "10.1.0.4/32", "nexthop": "100.78.60.40,100.78.61.40"}]'
        logger.info("Deleting routes with vnid: 703 from VNET vnet-default")
        r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
        pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.78.60.37,100.78.61.37", "ip_prefix": "10.1.0.1/32"}, 
                {"nexthop": "100.78.60.41,100.78.61.41", "ip_prefix": "10.1.0.5/32"}]

    for route in expected:
        pytest_assert(route in r.json())
    logger.info("Routes with vnid: 703 to VNET vnet-default have been added successfully")

    # Delete routes
    params = '[{"cmd": "delete", "ip_prefix": "10.1.0.1/32", "nexthop": "100.78.60.37,100.78.61.37"}, \
                {"cmd": "delete", "ip_prefix": "10.1.0.5/32", "nexthop": "100.78.60.41,100.78.61.41"}]'
    logger.info("Deleting routes with vnid: 703 from VNET vnet-default")
    r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
    pytest_assert(r.status_code == 204)

    # Verify routes
    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-default', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    pytest_assert(len(r.json()) == 0)
    logger.info("Routes with vnid: 703 from VNET vnet-default have been deleted successfully")
    
