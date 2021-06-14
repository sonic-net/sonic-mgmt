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
    time.sleep(30)


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
