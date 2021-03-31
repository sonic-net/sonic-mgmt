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

# Tests
def test_data_path(construct_url):
    params = '{"ip_addr": "10.3.152.32"}'
    r = restapi.post_config_tunnel_decap_tunnel_type(construct_url, 'vxlan', params)
    pytest_assert(r.status_code == 204)

    restapi.heartbeat(construct_url)

    params = '{"vnid": 2000}'
    r = restapi.post_config_vrouter_vrf_id(construct_url, 'vnet-guid-1', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-1')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 2000}, "vnet_id": "vnet-guid-1"}'
    pytest_assert(r.json() == json.loads(expected))

    params = '{"vnet_id": "vnet-guid-1", "ip_prefix": "100.0.10.1/24"}'
    r = restapi.post_config_vlan(construct_url, '2000', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vlan(construct_url, '2000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "100.0.10.1/24", "vnet_id": "vnet-guid-1"}, "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))

    params = '{"tagging_mode": "tagged"}'
    r = restapi.post_config_vlan_member(construct_url, '2000', 'Ethernet216', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vlan_member(construct_url, '2000', 'Ethernet216')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "Ethernet216", "vlan_id": 2000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))

    params = '{}'
    r = restapi.post_config_vlan_neighbor(construct_url, '2000', '100.0.10.4', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vlan_neighbor(construct_url, '2000', '100.0.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "100.0.10.4", "vlan_id": 2000}'
    pytest_assert(r.json() == json.loads(expected))  

    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52", "vnid": 2000, "mac_address": null}, \
                {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52", "vnid": 2000, "mac_address": null}]'
    r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-1', params)
    pytest_assert(r.status_code == 204)

    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-1', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 2000}, 
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.20.4/32", "vnid": 2000}]
    for route in expected:
        pytest_assert(route in r.json())


    params = '{"vnid": 3000}'
    r = restapi.post_config_vrouter_vrf_id(construct_url, 'vnet-guid-3', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vrouter_vrf_id(construct_url, 'vnet-guid-3')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"vnid": 3000}, "vnet_id": "vnet-guid-3"}'
    pytest_assert(r.json() == json.loads(expected))

    params = '{"vnet_id": "vnet-guid-3", "ip_prefix": "192.168.10.1/24"}'
    r = restapi.post_config_vlan(construct_url, '3000', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vlan(construct_url, '3000')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"attr": {"ip_prefix": "192.168.10.1/24", "vnet_id": "vnet-guid-3"}, "vlan_id": 3000}'
    pytest_assert(r.json() == json.loads(expected))

    params = '{"tagging_mode": "tagged"}'
    r = restapi.post_config_vlan_member(construct_url, '3000', 'Ethernet220', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vlan_member(construct_url, '3000', 'Ethernet220')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"if_name": "Ethernet220", "vlan_id": 3000, "attr": {"tagging_mode": "tagged"}}'
    pytest_assert(r.json() == json.loads(expected))

    params = '{}'
    r = restapi.post_config_vlan_neighbor(construct_url, '3000', '192.168.10.4', params)
    pytest_assert(r.status_code == 204)

    r = restapi.get_config_vlan_neighbor(construct_url, '3000', '192.168.10.4')
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = '{"ip_addr": "192.168.10.4", "vlan_id": 3000}'
    pytest_assert(r.json() == json.loads(expected))  

    params = '[{"cmd": "add", "ip_prefix": "100.0.20.4/32", "nexthop": "100.3.152.52", "vnid": 3000, "mac_address": null}, \
                {"cmd": "add", "ip_prefix": "192.168.20.4/32", "nexthop": "100.3.152.52", "vnid": 3000, "mac_address": null}]'
    r = restapi.patch_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-1', params)
    pytest_assert(r.status_code == 204)

    params = '{}'
    r = restapi.get_config_vrouter_vrf_id_routes(construct_url, 'vnet-guid-1', params)
    pytest_assert(r.status_code == 200)
    logger.info(r.json())
    expected = [{"nexthop": "100.3.152.52", "ip_prefix": "192.168.20.4/32", "vnid": 3000}, 
                {"nexthop": "100.3.152.52", "ip_prefix": "100.0.20.4/32", "vnid": 3000}]
    for route in expected:
        pytest_assert(route in r.json())
