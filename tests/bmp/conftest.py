import pytest
import shutil

from tests.common.helpers.assertions import pytest_require as pyrequire
from tests.common.helpers.dut_utils import check_container_state
from tests.bmp.helper import bmp_container
from tests.generic_config_updater.gu_utils import create_checkpoint, rollback

SETUP_ENV_CP = "test_setup_checkpoint"


@pytest.fixture(scope="function", autouse=True)
def skip_non_x86_platform(duthosts, rand_one_dut_hostname):
    """
    Skip the current test if DUT is not x86_64 platform.
    """
    duthost = duthosts[rand_one_dut_hostname]
    platform = duthost.facts["platform"]
    if 'x86_64' not in platform:
        pytest.skip("Test not supported for current platform. Skipping the test")