from args.ecn_args import add_ecn_args
from tests.common.devices.ptf import PTFHost
from tests.common.system_utils import docker

import pytest

def pytest_addoption(parser):
    '''
    Add option to ECN pytest
    Args:
        parser: pytest parser object
    Returns:
        None
    '''
    add_ecn_args(parser)

@pytest.fixture(scope="module", autouse=True)
def ptfhost(ansible_adhoc, request):
    ptf_name = request.config.getoption("--ixia_ptf_name")
    if ptf_name:

        return PTFHost(ansible_adhoc, ptf_name)
    else:
        print("No ixia_ptf_name argument is given, No ptf access will work.")
        return

@pytest.fixture(scope="module", autouse=True)
def prepare_ptf(ptfhost):
    if not ptfhost:
        yield
    else:
        ptfhost.copy(src="ptftests", dest="/root/ixia_ptftests")
        ptfhost.copy(src="saitests", dest="/root/ixia_saitests")

        yield
        ptfhost.file(path='/root/ixia_ptftests', state="absent")
        ptfhost.file(path='/root/ixia_saitests', state="absent")

# Pulled from qos_sai_base.py
@pytest.fixture(scope='module', autouse=True)
def swapSyncd(request, ptfhost, duthosts, rand_one_dut_hostname, creds):
    """ 
        Swap syncd on DUT host

        Args:
            request (Fixture): pytest request object
            duthost (AnsibleHost): Device Under Test (DUT)
        Returns:
            None
    """
    duthost = duthosts[rand_one_dut_hostname]
    if not ptfhost:
        yield
    else:
        swapSyncd = request.config.getoption("--qos_swap_syncd")
        try:
            if swapSyncd:
                docker.swap_syncd(duthost, creds)
            yield
        finally:
            if swapSyncd:
                docker.restore_default_syncd(duthost, creds)
