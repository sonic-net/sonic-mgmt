"""
This module contains the necessary fixtures for running test cases with
Ixia devices and IxNetwork. If more fixtures are required, they should be
included in this file.
"""

import pytest
from ixnetwork_restpy import SessionAssistant

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
def ixia_api_serv_user(duthost):
    """
    Return the username of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server username.
    """
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['user']


@pytest.fixture(scope = "module")
def ixia_api_serv_passwd(duthost):
    """
    Return the password of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server password.
    """
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['password']


@pytest.fixture(scope = "module")
def ixia_api_serv_port(duthost):
    """
    This fixture returns the TCP port for REST API of the ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server REST port.
    """
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['rest_port']


@pytest.fixture(scope = "module")
def ixia_api_serv_session_id(duthost):
    """
    Ixia API server can spawn multiple session on the same REST port.
    Optional for LINUX, required for windows return the session ID.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server session id.
    """
    return duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']['ixia_api_server']['session_id']


@pytest.fixture(scope = "module")
def ixia_dev(duthost, fanouthosts):
    """
    Returns the Ixia chassis IP. This fixture can return multiple IPs if
    multiple Ixia chassis are present in the test topology.

    Args:
        duthost (pytest fixture): The duthost fixture.
        fanouthosts (pytest fixture): The fanouthosts fixture.

    Returns:
        Dictionary of Ixia Chassis IP/IPs.
    """
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
