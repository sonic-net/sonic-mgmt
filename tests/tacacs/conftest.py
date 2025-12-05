import logging
import pytest
from tests.common.fixtures.tacacs import tacacs_creds     # noqa: F401
from tests.common.helpers.tacacs.tacacs_helper import tacacs_v6_context

logger = logging.getLogger(__name__)


@pytest.fixture
def skip_in_container_test(request):
    container_test = request.config.getoption("--container_test", default="")
    if container_test:
        pytest.skip("Testcase skip in container test")


@pytest.fixture(scope="module")
def check_tacacs_v6(ptfhost, duthosts, enum_rand_one_per_hwsku_hostname, tacacs_creds):  # noqa: F811
    with tacacs_v6_context(ptfhost, duthosts[enum_rand_one_per_hwsku_hostname], tacacs_creds) as result:
        yield result
