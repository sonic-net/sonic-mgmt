import pytest
import pprint
from common.devices import FanoutHost
from ixnetwork_restpy import SessionAssistant, Files

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
IXIA session manager with PTF server
"""
@pytest.fixture(scope = "function")
def ixia_api_server_session(ixia_api_serv_ip,
    ixia_api_serv_user, ixia_api_serv_passwd, ixia_api_serv_port,
    ixia_api_serv_session_id) :

    if (ixia_api_serv_session_id != "None") :
        session = SessionAssistant(IpAddress = ixia_api_serv_ip,
                               UserName = ixia_api_serv_user,
                               Password = ixia_api_serv_passwd,
                               RestPort = ixia_api_serv_port,
                               SessionId = ixia_api_serv_session_id)
    else :
        session = SessionAssistant(IpAddress = ixia_api_serv_ip,
                               UserName = ixia_api_serv_user,
                               Password = ixia_api_serv_passwd,
                               RestPort = ixia_api_serv_port)
    sessionData = session.Session
    ixNetwork   = session.Ixnetwork
    ixNetwork.NewConfig()
    return session

