import pytest

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.fixtures.pfc_asym import *
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory   # lgtm[py/unused-import]

from tests.pfc_asym.args.pfc_asym_args import add_pfc_asym_args


@pytest.fixture(autouse=True)
def flush_neighbors(duthosts, rand_one_dut_hostname):
    """ Clear ARP table to make sure that neighbors learning will be triggered """
    duthost = duthosts[rand_one_dut_hostname]
    duthost.command("sonic-clear arp")


def pytest_addoption(parser):
    '''
        Adds option to QoS pytest

        Args:
            parser: pytest parser object

        Returns:
            None
    '''
    add_pfc_asym_args(parser)
