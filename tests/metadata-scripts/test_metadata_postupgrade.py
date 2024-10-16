import logging
import pytest
from postupgrade_helper import run_postupgrade_actions

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.skip_check_dut_health
]
logger = logging.getLogger(__name__)


def test_postupgrade_actions(duthosts, localhost, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]
    run_postupgrade_actions(duthost, localhost, tbinfo, True, False)