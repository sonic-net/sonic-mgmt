import logging
import requests

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

API_VERSION = 'v1'
GET = 'GET'
POST = 'POST'
DELETE = 'DELETE'
PATCH = 'PATCH'

class Restapi:
    def __init__(self, client_cert, client_key):
        self.CLIENT_CERT = client_cert
        self.CLIENT_KEY = client_key

    # Generic request
    def request(self, method, url, params=None):
        session = requests.Session()
        session.headers.update({'Content-type': 'application/json'})
        if method == GET:
            req = requests.Request(GET, url)
        elif method == POST:
            req = requests.Request(POST, url, data=params)
        elif method == DELETE:
            req = requests.Request(DELETE, url, data=params)
        elif method == PATCH:
            req = requests.Request(PATCH, url, data=params)
        req_p = req.prepare()
        clientcert=(self.CLIENT_CERT, self.CLIENT_KEY)
        response = session.send(req_p,
                        verify=False,
                        cert=clientcert
                    )
        response.close()
        return response
    #
    # Fundamental operations
    #
    # Decap
    def post_config_tunnel_decap_tunnel_type(self, construct_url, tunnel_type, params):
        path = API_VERSION+'/config/tunnel/decap/{tunnel_type}'.format(tunnel_type=tunnel_type)
        url = construct_url(path)
        if url:
            return self.request(POST, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    # VRF/VNET
    def post_config_vrouter_vrf_id(self, construct_url, vrf_id, params):
        path = API_VERSION+'/config/vrouter/{vrf_id}'.format(vrf_id=vrf_id)
        url = construct_url(path)
        if url:
            return self.request(POST, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def get_config_vrouter_vrf_id(self, construct_url, vrf_id):
        path = API_VERSION+'/config/vrouter/{vrf_id}'.format(vrf_id=vrf_id)
        url = construct_url(path)
        if url:
            return self.request(GET, url)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def delete_config_vrouter_vrf_id(self, construct_url, vrf_id, params):
        path = API_VERSION+'/config/vrouter/{vrf_id}'.format(vrf_id=vrf_id)
        url = construct_url(path)
        if url:
            return self.request(DELETE, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")
    
    # Vlan
    def post_config_vlan(self, construct_url, vlan_id, params):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}'.format(vlan_id=vlan_id)
        url = construct_url(path)
        if url:
            return self.request(POST, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def get_config_vlan(self, construct_url, vlan_id):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}'.format(vlan_id=vlan_id)
        url = construct_url(path)
        if url:
            return self.request(GET, url)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def delete_config_vlan(self, construct_url, vlan_id, params):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}'.format(vlan_id=vlan_id)
        url = construct_url(path)
        if url:
            return self.request(DELETE, url, params)      
        else:
            logger.error("Malformed URL for "+path+"!")

    # Vlan Member
    def post_config_vlan_member(self, construct_url, vlan_id, if_name, params):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}/member/{if_name}'.format(vlan_id=vlan_id, if_name=if_name)
        url = construct_url(path)
        if url:
            return self.request(POST, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def get_config_vlan_member(self, construct_url, vlan_id, if_name):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}/member/{if_name}'.format(vlan_id=vlan_id, if_name=if_name)
        url = construct_url(path)
        if url:
            return self.request(GET, url)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def delete_config_vlan_member(self, construct_url, vlan_id, if_name, params):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}/member/{if_name}'.format(vlan_id=vlan_id, if_name=if_name)
        url = construct_url(path)
        if url:
            return self.request(DELETE, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    # Vlan Neighbor
    def post_config_vlan_neighbor(self, construct_url, vlan_id, ip_addr, params):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}/neighbor/{ip_addr}'.format(vlan_id=vlan_id, ip_addr=ip_addr)
        url = construct_url(path)
        if url:
            return self.request(POST, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def get_config_vlan_neighbor(self, construct_url, vlan_id, ip_addr):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}/neighbor/{ip_addr}'.format(vlan_id=vlan_id, ip_addr=ip_addr)
        url = construct_url(path)
        if url:
            return self.request(GET, url)           
        else:
            logger.error("Malformed URL for "+path+"!")

    def delete_config_vlan_neighbor(self, construct_url, vlan_id, ip_addr, params):
        path = API_VERSION+'/config/interface/vlan/{vlan_id}/neighbor/{ip_addr}'.format(vlan_id=vlan_id, ip_addr=ip_addr)
        url = construct_url(path)
        if url:
            return self.request(DELETE, url, params)           
        else:
            logger.error("Malformed URL for "+path+"!")

    # Routes
    def patch_config_vrouter_vrf_id_routes(self, construct_url, vrf_id, params):
        path = API_VERSION+'/config/vrouter/{vrf_id}/routes'.format(vrf_id=vrf_id)
        url = construct_url(path)
        if url:
            return self.request(PATCH, url, params)
        else:
            logger.error("Malformed URL for "+path+"!")

    def get_config_vrouter_vrf_id_routes(self, construct_url, vrf_id, params):
        path = API_VERSION+'/config/vrouter/{vrf_id}/routes'.format(vrf_id=vrf_id)
        url = construct_url(path)
        if url:
            return self.request(GET, url)
        else:
            logger.error("Malformed URL for "+path+"!")

    # Basic operations        
    def heartbeat(self, construct_url):
        path = API_VERSION+"/state/heartbeat"
        url = construct_url(path)
        if url:
            r = self.request(GET, url)
            pytest_assert(r.status_code == 200)
        else:
            logger.error("Malformed URL for "+path+"!")
