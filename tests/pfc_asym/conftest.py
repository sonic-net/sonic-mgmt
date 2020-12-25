import pytest

from tests.common.fixtures.conn_graph_facts import fanout_graph_facts
from tests.common.fixtures.pfc_asym import *
from tests.common.fixtures.ptfhost_utils import copy_ptftests_directory   # lgtm[py/unused-import]
from tests.common.fixtures.ptfhost_utils import copy_saitests_directory   # lgtm[py/unused-import]


@pytest.fixture(autouse=True)
def flush_neighbors(pre_selected_dut):
    """ Clear ARP table to make sure that neighbors learning will be triggered """
    pre_selected_dut.command("sonic-clear arp")
