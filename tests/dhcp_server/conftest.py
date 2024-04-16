import pytest
from tests.common.utilities import wait_until

DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATRUE_NAME = "dhcp_server"


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_setup_teardown(duthost):
    features_state, _ = duthost.get_feature_status()
    if DHCP_SERVER_FEATRUE_NAME not in features_state:
        pytest.fail('There is no dhcp server feature in the DUT')
    restore_state_flag = True
    if "enabled" not in features_state.get(DHCP_SERVER_FEATRUE_NAME, ""):
        duthost.shell("config feature state dhcp_server enabled")
    else:
        restore_state_flag = False
    if not wait_until(10, 1, 1, duthost.is_container_running, DHCP_SERVER_CONTAINER_NAME):
        pytest.fail('feature dhcp_server is enabled but container is not running')

    yield

    if restore_state_flag:
        duthost.shell("config feature state dhcp_server disabled", module_ignore_errors=True)
        duthost.shell("docker rm dhcp_server", module_ignore_errors=True)
