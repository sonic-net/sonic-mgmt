"""
This module contains the necessary fixtures for running test cases with
Ixia devices and IxNetwork. If more fixtures are required, they should be
included in this file.
"""

import pytest
from ixnetwork_restpy import SessionAssistant
try:
    from ixnetwork_open_traffic_generator.ixnetworkapi import IxNetworkApi
except ImportError as e:
    raise pytest.skip.Exception("Test case is skipped: " + repr(e), allow_module_level=True)

@pytest.fixture(scope = "module")
def ixia_api_serv_ip(tbinfo):
    """
    In an Ixia testbed, there is no PTF docker.
    Hence, we use ptf_ip field to store Ixia API server.
    This fixture returns the IP address of the Ixia API server.

    Args:
       tbinfo (pytest fixture): fixture provides information about testbed

    Returns:
        Ixia API server IP
    """
    return tbinfo['ptf_ip']


@pytest.fixture(scope = "module")
def ixia_api_serv_user(duthosts, rand_one_dut_hostname):
    """
    Return the username of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server username.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['user']


@pytest.fixture(scope = "module")
def ixia_api_serv_passwd(duthosts, rand_one_dut_hostname):
    """
    Return the password of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server password.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['password']


@pytest.fixture(scope = "module")
def ixia_api_serv_port(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the TCP port for REST API of the ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server REST port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['rest_port']


@pytest.fixture(scope = "module")
def ixia_api_serv_session_id(duthosts, rand_one_dut_hostname):
    """
    Ixia API server can spawn multiple session on the same REST port.
    Optional for LINUX, required for windows return the session ID.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server session id.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['session_id']


@pytest.fixture(scope = "module")
def ixia_dev(duthosts, rand_one_dut_hostname, fanouthosts):
    """
    Returns the Ixia chassis IP. This fixture can return multiple IPs if
    multiple Ixia chassis are present in the test topology.

    Args:
        duthost (pytest fixture): The duthost fixture.
        fanouthosts (pytest fixture): The fanouthosts fixture.

    Returns:
        Dictionary of Ixia Chassis IP/IPs.
    """
    duthost = duthosts[rand_one_dut_hostname]
    result = dict()
    ixia_dev_hostnames = fanouthosts.keys()
    for hostname in ixia_dev_hostnames:
        result[hostname] = duthost.host.options['inventory_manager'].get_host(hostname).get_vars()['ansible_host']
    return result


@pytest.fixture(scope = "function")
def ixia_api_server_session(
        ixia_api_serv_ip,
        ixia_api_serv_user,
        ixia_api_serv_passwd,
        ixia_api_serv_port,
        ixia_api_serv_session_id) :
    """
    Ixia session manager fixture.

    Args:
        ixia_api_serv_ip (pytest fixture): ixia_api_serv_ip fixture
        ixia_api_serv_user (pytest fixture): ixia_api_serv_user fixture.
        ixia_api_serv_passwd (pytest fixture): ixia_api_serv_passwd fixture.
        ixia_api_serv_port (pytest fixture): ixia_api_serv_port fixture.
        ixia_api_serv_session_id (pytest fixture): ixia_api_serv_session_id
            fixture.

    Returns:
        IxNetwork Session
    """

    if (ixia_api_serv_session_id.lower() != 'none') :
        session = SessionAssistant(IpAddress=ixia_api_serv_ip,
                                   UserName=ixia_api_serv_user,
                                   Password=ixia_api_serv_passwd,
                                   RestPort=ixia_api_serv_port,
                                   SessionId=ixia_api_serv_session_id)
    else :
        session = SessionAssistant(IpAddress=ixia_api_serv_ip,
                                   UserName=ixia_api_serv_user,
                                   Password=ixia_api_serv_passwd,
                                   RestPort=ixia_api_serv_port)
    ixNetwork = session.Ixnetwork
    ixNetwork.NewConfig()

    yield session

    ixNetwork.NewConfig()
    session.Session.remove()

@pytest.fixture(scope = "function")
def ixia_api(ixia_api_serv_ip,
             ixia_api_serv_port,
             ixia_api_serv_user,
             ixia_api_serv_passwd):

    api_session = IxNetworkApi(address=ixia_api_serv_ip,
                               port=ixia_api_serv_port,
                               username=ixia_api_serv_user,
                               password=ixia_api_serv_passwd)

    yield api_session
    api_session.assistant.Session.remove()
