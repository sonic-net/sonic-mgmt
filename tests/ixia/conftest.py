import pytest
import random
import pandas as pd
import re
import yaml
import site
import os
from os.path import dirname, abspath
from tests.common.ixia.common_helpers import enable_packet_aging, start_pfcwd
from tests.conftest import generate_priority_lists
from ixnetwork_restpy import SessionAssistant

from tests.common.reboot import logger
# from tests.common.ixia.ixia_helpers import *

site.addsitedir(dirname(abspath(__file__)) + '/lib')


@pytest.fixture(autouse=True, scope="module")
def rand_lossless_prio(request):
    """
    Fixture that randomly selects a lossless priority

    Args:
        request (object): pytest request object

    Yields:
        lossless priority (str): string containing 'hostname|lossless priority'

    """
    lossless_prios = generate_priority_lists(request, "lossless")
    if lossless_prios:
        yield random.sample(lossless_prios, 1)[0]
    else:
        yield 'unknown|unknown'


@pytest.fixture(autouse=True, scope="module")
def rand_lossy_prio(request):
    """
    Fixture that randomly selects a lossy priority

    Args:
        request (object): pytest request object

    Yields:
        lossy priority (str): string containing 'hostname|lossy priority'

    """
    lossy_prios = generate_priority_lists(request, "lossy")
    if lossy_prios:
        yield random.sample(lossy_prios, 1)[0]
    else:
        yield 'unknown|unknown'


@pytest.fixture(autouse=True, scope="module")
def start_pfcwd_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that PFC watchdog is enabled with default setting after tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    start_pfcwd(duthost)


@pytest.fixture(autouse=True, scope="module")
def enable_packet_aging_after_test(duthosts, rand_one_dut_hostname):
    """
    Ensure that packet aging is enabled after tests

    Args:
        duthosts (pytest fixture) : list of DUTs
        rand_one_dut_hostname (pytest fixture): DUT hostname

    Yields:
        N/A
    """
    yield

    duthost = duthosts[rand_one_dut_hostname]
    enable_packet_aging(duthost)


@pytest.fixture(scope="module")
def ixia_api_serv_ip(testbed):
    """
    In an Ixia testbed, there is no PTF docker.
    Hence, we use ptf_ip field to store Ixia API server.
    This fixture returns the IP address of the Ixia API server.

    Args:
       testbed (pytest fixture): The testbed fixture.

    Returns:
        Ixia API server IP
    """
    return testbed['ptf_ip']


@pytest.fixture(scope="module")
def ixia_api_serv_user(duthost):
    """
    Return the username of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server username.
    """
    yaml_file_path = os.path.join(os.getcwd(), '../ansible/group_vars/lab/lab.yml')

    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
        user = data.get('secret_group_vars', {}).get('snappi_api_server', {}).get('user', None)

    return user


@pytest.fixture(scope="module")
def ixia_api_serv_passwd(duthost):
    """
    Return the password of Ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server password.
    """
    yaml_file_path = os.path.join(os.getcwd(), '../ansible/group_vars/lab/lab.yml')

    with open(yaml_file_path, 'r') as file:
        data = yaml.safe_load(file)
        password = data.get('secret_group_vars', {}).get('snappi_api_server', {}).get('password', None)

    return password


@pytest.fixture(scope="module")
def ixia_api_serv_port(duthost):
    """
    This fixture returns the TCP port for REST API of the ixia API server.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server REST port.
    """
    # secret_group_vars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']
    # return secret_group_vars['ixia_api_server']['rest_port']
    return '443'


@pytest.fixture(scope="module")
def ixia_api_serv_session_id(duthost):
    """
    Ixia API server can spawn multiple session on the same REST port.
    Optional for LINUX, required for windows return the session ID.

    Args:
        duthost (pytest fixture): The duthost fixture.

    Returns:
        Ixia API server session id.
    """
    # secret_group_vars = duthost.host.options['variable_manager']._hostvars[duthost.hostname]['secret_group_vars']
    # return secret_group_vars['ixia_api_server']['session_id']
    return 'None'


@pytest.fixture(scope="module")
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


@pytest.fixture(scope="module")
def ixia_chassis(testbed, duthost):
    table = pd.read_csv(r'../ansible/files/snappi_sonic_devices.csv')
    table = table.loc[table['Hostname'] == 'snappi-sonic']
    return table['ManagementIp'][0].split('/')[0]


@pytest.fixture(scope="function")
def ixia_api_server_session(
        ixia_api_serv_ip,
        ixia_api_serv_user,
        ixia_api_serv_passwd,
        ixia_api_serv_port,
        ixia_api_serv_session_id):
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

    if (ixia_api_serv_session_id.lower() != 'none'):
        session = SessionAssistant(IpAddress=ixia_api_serv_ip,
                                   UserName=ixia_api_serv_user,
                                   Password=ixia_api_serv_passwd,
                                   RestPort=ixia_api_serv_port,
                                   SessionId=ixia_api_serv_session_id,
                                   ClearConfig=True)

    else:
        session = SessionAssistant(IpAddress=ixia_api_serv_ip,
                                   UserName=ixia_api_serv_user,
                                   Password=ixia_api_serv_passwd,
                                   RestPort=ixia_api_serv_port,
                                   LogLevel='all', LogFilename='restpy.log')
    ixNetwork = session.Ixnetwork
    ixNetwork.NewConfig()

    yield session


@pytest.fixture(scope="function")
def get_ixia_port_list(ixia_chassis, testbed):
    # get port list from csv file
    ixia = ixia_chassis
    ixChassisIpList = [ixia]
    table = pd.read_csv(r'../ansible/files/snappi_sonic_link.csv')
    portlist = []
    portinfolist = table['EndPort'].values.tolist()
    for portinfo in portinfolist:
        pattern = r'Card(\d+)/Port(\d+)'
        if isinstance(portinfo, str):
            m = re.match(pattern, portinfo)
            card = m.group(1)
            port = m.group(2)
            portlist.append([ixChassisIpList[0], card, port])
    return portlist


@pytest.fixture(scope="function")
def ixiahost(ixia_api_server_session, get_ixia_port_list):
    session = ixia_api_server_session
    portlist = get_ixia_port_list
    yield session, portlist
    session.Ixnetwork.NewConfig()
    session.Session.remove()


@pytest.fixture(scope="module", autouse=True)
def common_function(testbed, duthost):
    logger.info('common setup operations')
    dut_name = testbed['duts'][0]
    dut_ip = duthost.host.options['inventory_manager'].get_host(dut_name).get_vars()['ansible_host']
    logger.info(dut_name)
    logger.info(dut_ip)
    yield
    logger.info('common cleanup operations')


@pytest.hookimpl(optionalhook=True)
def pytest_assert(condition, message=None):
    __tracebackhide__ = True
    if not condition:
        pytest.fail(message)
