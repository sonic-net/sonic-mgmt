import pytest
import pprint
# from common.devices import SonicHost, Localhost, PTFHost, EosHost, FanoutHost
from common.devices import FanoutHost
""" 
In an IXIA testbed, there is no PTF docker. 
Hence, we use ptf_ip field to store IXIA API server. 
This fixture returns the IP address of the IXIA API server.
"""
@pytest.fixture(scope = "module")
def ixia_api_serv_ip(testbed):
    return testbed['ptf_ip']

"""
Return the username of IXIA API server
"""
@pytest.fixture(scope = "module")
def ixia_api_serv_user(duthost):
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['user']

"""
Return the password of IXIA API server
"""
@pytest.fixture(scope = "module")
def ixia_api_serv_passwd(duthost):
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['password']

"""
Return REST port. 
"""
@pytest.fixture(scope = "module")
def ixia_api_serv_port(duthost):
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['rest_port']

"""
IXIA PTF can spawn multiple session on the same REST port. Optional for LINUX, Rewuired for windows 
Return the session ID. 
"""
@pytest.fixture(scope = "module")
def ixia_api_serv_session_id(duthost):
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['session_id']
  
"""
IXIA chassis are leaf fanout switches in the testbed.
This fixture returns the hostnames and IP addresses of the IXIA chassis in the dictionary format.
"""  
@pytest.fixture(scope = "module")
def ixia_dev(duthost, ansible_adhoc, conn_graph_facts, creds):
    dev_conn     = conn_graph_facts['device_conn'] if 'device_conn' in conn_graph_facts else {}
    fanout_hosts = {}
    result       = dict()
    # WA for virtual testbed which has no fanout
    try:
        for dut_port in dev_conn.keys():
            fanout_rec  = dev_conn[dut_port]
            fanout_host = fanout_rec['peerdevice']
            fanout_port = fanout_rec['peerport']
            if fanout_host in fanout_hosts.keys():
                fanout  = fanout_hosts[fanout_host]
            else:
                user = pswd = None
                host_vars = ansible_adhoc().options['inventory_manager'].get_host(fanout_host).vars
                os_type = 'eos' if 'os' not in host_vars else host_vars['os']
                if os_type == "ixia":
                    fanout  = FanoutHost(ansible_adhoc, os_type, fanout_host, 'FanoutLeaf', user, pswd)
                    fanout_hosts[fanout_host] = fanout
                    fanout.add_port_map(dut_port, fanout_port)
    except:
        pass

    ixia_dev_hostnames = fanout_hosts.keys()
    for hostname in ixia_dev_hostnames:
        result[hostname] = duthost.host.options['inventory_manager'].get_host(hostname).get_vars()['ansible_host']
    
    return result
