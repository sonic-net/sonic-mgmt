import pytest
from tests.common.dualtor.dual_tor_utils import force_active_tor

@pytest.fixture(scope="module", autouse=True)
def set_selected_tor_active(duthosts, rand_one_dut_hostname):
    force_active_tor(duthosts[rand_one_dut_hostname], 'all')

