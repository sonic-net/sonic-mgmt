import pytest
import logging
import collections

import natsort

from tests.common.utilities import wait_until
from macsec_platform_helper import *

logger = logging.getLogger(__name__)


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "macsec_required: mark test as MACsec required to run")


@pytest.fixture(scope="module")
def profile_name():
    return "test"


@pytest.fixture(scope="module")
def default_priority():
    return 64

@pytest.fixture(scope="module", params=["GCM-AES-128", "GCM-AES-256", "GCM-AES-XPN-128", "GCM-AES-XPN-256"])
def cipher_suite(request):
    if request.config.getoption("--neighbor_type") == "eos" and "XPN" in request.param:
        pytest.skip("{} is not supported on neighbor EOS".format(request.param))
    return request.param


@pytest.fixture(scope="module")
def primary_ckn():
    cak = "6162636465666768696A6B6C6D6E6F707172737475767778797A303132333435"
    return cak


@pytest.fixture(scope="module")
def primary_cak(cipher_suite):
    ckn = "0123456789ABCDEF0123456789ABCDEF"
    if "128" in cipher_suite:
        ckn = ckn * 1
    elif "256" in cipher_suite:
        ckn = ckn * 2
    else:
        raise ValueError("Unknown cipher suite {}".format(cipher_suite))
    return ckn


# Some platform cannot support "integrity_only" mode, skip this option
# @pytest.fixture(scope="module", params=["integrity_only", "security"])
@pytest.fixture(scope="module", params=["security"])
def policy(request):
    return request.param


@pytest.fixture(scope="module", params=["true", "false"])
def send_sci(request):
    if request.param == "false" and request.config.getoption("--neighbor_type") == "eos":
        pytest.skip("EOS with send_sci false does not work due to portchannel mac not matching ether port mac!")
    return request.param

