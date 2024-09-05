"""
Test the database scripts
"""
import logging
import pytest

from tests.common.utilities import skip_release
from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.device_type('vs')
]


def test_flush_unused_database(duthosts, rand_one_dut_hostname):
    """
    @summary: Test 'flush_unused_database' scripts can run correctly inside database container.
     ./run_tests.sh -n vms-kvm-t0 -d vlab-01 -c database/test_db_scripts.py -f vtestbed.csv -i veos_vtb
    """
    duthost = duthosts[rand_one_dut_hostname]

    # the flush_unused_database exist after 202012 branch
    skip_release(duthost, ["201811", "201911"])

    result = duthost.shell("docker exec -t database flush_unused_database")
    pytest_assert(result["rc"] == 0, "flush_unused_database script failed with {}".format(result["stdout"]))
