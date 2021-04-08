"""
This module contains the snappi fixture
"""
import pytest
import snappi


@pytest.fixture(scope="module")
def snappi_api_serv_ip(tbinfo):
    """
    In an tgen testbed, there is no PTF docker.
    Hence, we use ptf_ip field to store snappi API server.
    This fixture returns the IP address of the snappi API server.

    Args:
       tbinfo (pytest fixture): fixture provides information about testbed

    Returns:
        snappi API server IP
    """
    return tbinfo['ptf_ip']


@pytest.fixture(scope="module")
def snappi_api_serv_port(duthosts, rand_one_dut_hostname):
    """
    This fixture returns the REST API port of the Snappi API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        snappi API server REST port.
    """
    duthost = duthosts[rand_one_dut_hostname]
    return (duthost.host.options['variable_manager'].
            _hostvars[duthost.hostname]['secret_group_vars']
            ['ixia_api_server']['rest_port'])


@pytest.fixture(scope='module')
def snappi_api(snappi_api_serv_ip,
               snappi_api_serv_port):
    """
    Snappi session fixture for snappi Tgen API
    Args:
        snappi_api_serv_ip (pytest fixture): snappi_api_serv_ip fixture
        snappi_api_serv_port (pytest fixture): snappi_api_serv_port fixture.
    """
    host = "https://" + snappi_api_serv_ip + ":" + str(snappi_api_serv_port)
    # TODO: Currently extension is defaulted to ixnetwork.
    # Going forward, we should be able to specify extension
    # from command line while running pytest.
    api = snappi.api(host=host, ext="ixnetwork")

    yield api

    if getattr(api, 'assistant', None) is not None:
        api.assistant.Session.remove()

