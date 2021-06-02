import pytest
import logging
import re
from multiprocessing.pool import ThreadPool

from tests.common  import config_reload

logger = logging.getLogger(__name__)


def pytest_configure(config):
    config.addinivalue_line("markers", "macsec_required: mark test as MACsec required to run")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--neighbor_type") == "sonic":
        return
    skip_macsec = pytest.mark.skip(reason="Neighbor devices don't support MACsec")
    for item in items:
        if "macsec_required" in item.keywords:
            item.add_marker(skip_macsec)


def global_cmd(duthost, nbrhosts, cmd):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(duthost.command, args=(cmd,))
    for nbr in nbrhosts.values():
        pool.apply_async(nbr["host"].command, args=(cmd, ))
    pool.close()
    pool.join()


def recover_configuration(duthost, nbrhosts):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(config_reload, args=(duthost, "minigraph"))
    for nbr in nbrhosts.values():
        pool.apply_async(config_reload, args=(nbr["host"], "config_db"))
    pool.close()
    pool.join()


@pytest.fixture(scope="module")
def macsec_environment(duthost, nbrhosts):
    recover_configuration(duthost, nbrhosts)
    logger.info("Prepare MACsec environment")
    yield
    recover_configuration(duthost, nbrhosts)
    logger.info("Cleanup MACsec configuration")


@pytest.fixture(scope="module")
def enable_macsec_feature(duthost, nbrhosts, macsec_environment):
    global_cmd(duthost, nbrhosts, "sudo config feature state macsec enabled")
    logger.info("Enable MACsec feature")


def get_portchannel_list(host):
    '''
        Here is an output example of `show interfaces portchannel`
        admin@sonic:~$ show interfaces portchannel
        Flags: A - active, I - inactive, Up - up, Dw - Down, N/A - not available,
            S - selected, D - deselected, * - not synced
        No.  Team Dev         Protocol     Ports
        -----  ---------------  -----------  ---------------------------
        0001  PortChannel0001  LACP(A)(Up)  Ethernet112(S) Ethernet108(D)
        0002  PortChannel0002  LACP(A)(Up)  Ethernet116(S)
        0003  PortChannel0003  LACP(A)(Up)  Ethernet120(S)
        0004  PortChannel0004  LACP(A)(Up)  N/A
    '''
    lines = host.command("show interfaces portchannel")["stdout_lines"]
    lines = lines[4:] # Remove the output header
    portchannel_list = {}
    for line in lines:
        items = line.split()
        portchannel = items[1]
        portchannel_list[portchannel] = []
        if items[-1] == "N/A":
            continue
        for item in items[3:]:
            port = re.search(r"(Ethernet.*)\(", item).group(1)
            portchannel_list[portchannel].append(port)
    return portchannel_list


# TODO: Temporary solution, because MACsec cannot be enabled on a portchannel member in the current version
def delete_all_portchannel(host):
    portchannel_list = get_portchannel_list(host)
    for name, members in portchannel_list.items():
        if len(members) > 0:
            for member in members:
                host.command("sudo config portchannel member del {} {}".format(name, member))



# TODO: Re-added member port to port channel
@pytest.fixture(scope="module")
def cleanup_portchannel(duthost, nbrhosts, macsec_environment):
    pool = ThreadPool(1 + len(nbrhosts))
    pool.apply_async(delete_all_portchannel, args=(duthost, ))
    for nbr in nbrhosts.values():
        pool.apply_async(delete_all_portchannel, args=(nbr["host"], ))
    pool.close()
    pool.join()
    logging.info("Cleanup all port channels")


@pytest.fixture(scope="module")
def profile_name():
    return "test"


@pytest.fixture(scope="module")
def default_priority():
    return 64


# TODO: params=["GCM-AES-128", "GCM-AES-256"]
@pytest.fixture(scope="module", params=["GCM-AES-128"])
def cipher_suite(request):
    return request.param


@pytest.fixture(scope="module")
def primary_ckn():
    cak = "6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435"
    return cak


@pytest.fixture(scope="module")
def primary_cak(cipher_suite):
    ckn = "0123456789ABCDEF0123456789ABCDEF"
    if cipher_suite == "GCM-AES-128":
        ckn = ckn * 1
    elif cipher_suite == "GCM-AES-256":
        ckn = ckn * 2
    else:
        raise ValueError("Unknown cipher suite {}".format(cipher_suite))
    return ckn


@pytest.fixture(scope="module", params=["integrity_only", "security"])
def policy(request):
    return request.param


@pytest.fixture(scope="module")
def ctrl_links(nbrhosts):
    return [
        {
            "host": nbrhosts["ARISTA01T1"]["host"],
            "dut_ctrl_port": "Ethernet112",
            "host_ctrl_port": "Ethernet0",
        },
        {
            "host": nbrhosts["ARISTA02T1"]["host"],
            "dut_ctrl_port": "Ethernet116",
            "host_ctrl_port": "Ethernet0",
        }
    ]
