import logging
import sys

import pytest
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.assertions import pytest_require as py_require
from tests.common import dhcp_relay_utils
from dhcp_server_test_common import clean_dhcp_server_config

DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATRUE_NAME = "dhcp_server"

logger = logging.getLogger(__name__)


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_setup_teardown(duthost):
    features_state, succeeded = duthost.get_feature_status()
    py_require(succeeded, "Skip when dhcp server feature status cannot be retrieved")
    py_require(DHCP_SERVER_FEATRUE_NAME in features_state, "Skip on vs testbed without dhcp server feature")
    dhcp_server_state = features_state[DHCP_SERVER_FEATRUE_NAME]
    py_require(dhcp_server_state in ('enabled', 'always_enabled', 'disabled'),
               "Skip on testbed with unsupported dhcp server feature state: {}".format(dhcp_server_state))

    restore_state_flag = dhcp_server_state == 'disabled'

    def restore_dhcp_server_state():
        if restore_state_flag:
            duthost.shell("config feature state dhcp_server disabled")
        dhcp_relay_utils.restart_dhcp_service(duthost, [dhcp_relay_utils.get_dhcp_relay_type(duthost)])
        if restore_state_flag:
            result = duthost.shell("docker rm dhcp_server", module_ignore_errors=True)
            if result['rc'] != 0 and "No such container" not in result.get('stderr', ''):
                raise RuntimeError("Failed to remove dhcp_server container: {}".format(result.get('stderr', '')))

    try:
        if restore_state_flag:
            duthost.shell("config feature state dhcp_server enabled")

        dhcp_relay_utils.restart_dhcp_service(duthost, [dhcp_relay_utils.get_dhcp_relay_type(duthost)])

        def is_supervisor_subprocess_running(duthost, container_name, app_name):
            return "RUNNING" in duthost.shell(f"docker exec {container_name} supervisorctl status {app_name}")["stdout"]

        py_assert(
            wait_until(120, 1, 1,
                       is_supervisor_subprocess_running,
                       duthost,
                       DHCP_SERVER_CONTAINER_NAME,
                       "dhcp-server-ipv4:kea-dhcp4"),
            'feature dhcp_server is enabled but container is not running'
        )
        yield
    finally:
        setup_or_test_error = sys.exc_info()[1]
        try:
            restore_dhcp_server_state()
        except Exception:
            if setup_or_test_error is not None:
                logger.exception("Failed to restore DHCP server state after fixture failure")
            else:
                raise


@pytest.fixture(scope="function", autouse=True)
def clean_dhcp_server_config_after_test(duthost):
    clean_dhcp_server_config(duthost)

    yield

    clean_dhcp_server_config(duthost)
