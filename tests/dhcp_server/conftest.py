import logging
import sys

import pytest
from _pytest.outcomes import OutcomeException
from tests.common.utilities import wait_until
from tests.common.helpers.assertions import pytest_assert as py_assert
from tests.common.helpers.assertions import pytest_require as py_require
from tests.common import dhcp_relay_utils
from dhcp_server_test_common import clean_dhcp_server_config

DHCP_SERVER_CONTAINER_NAME = "dhcp_server"
DHCP_SERVER_FEATURE_NAME = "dhcp_server"

logger = logging.getLogger(__name__)


def require_internal_relay_modes():
    """Skip standalone runs until the prerequisite shared modes are available."""
    try:
        dhcp_relay_utils._validate_relay_types('dhcp_server_setup_teardown', ['isc-internal-idle'])
    except (AttributeError, ValueError):
        pytest.skip("#26526 requires the internal relay modes from #26525")


def get_lifecycle_relay_type(duthost, internal):
    """Select the lifecycle mode from the existing SONiC DHCPv4 relay flag."""
    config_facts = duthost.config_facts(host=duthost.hostname, source='running')['ansible_facts']
    device_metadata = config_facts['DEVICE_METADATA']['localhost']
    sonic_relay = device_metadata.get('has_sonic_dhcpv4_relay', 'False') == 'True'
    if sonic_relay:
        return 'sonic'
    if not internal:
        return 'isc'
    dhcp_server_ipv4 = config_facts.get('DHCP_SERVER_IPV4', {})
    if any(config.get('state') == 'enabled' for config in dhcp_server_ipv4.values()):
        return 'isc-internal'
    return 'isc-internal-idle'


@pytest.fixture(scope="module", autouse=True)
def dhcp_server_setup_teardown(duthost):
    require_internal_relay_modes()
    features_state, succeeded = duthost.get_feature_status()
    py_require(succeeded, "Skip when dhcp server feature status cannot be retrieved")
    py_require(DHCP_SERVER_FEATURE_NAME in features_state, "Skip on vs testbed without dhcp server feature")
    dhcp_server_state = features_state[DHCP_SERVER_FEATURE_NAME]
    py_require(dhcp_server_state in ('enabled', 'always_enabled', 'disabled'),
               "Skip on testbed with unsupported dhcp server feature state: {}".format(dhcp_server_state))
    restore_state_flag = dhcp_server_state == 'disabled'

    def restore_dhcp_server_state():
        first_cleanup_error = None

        def cleanup_step(step_name, callback):
            nonlocal first_cleanup_error
            try:
                callback()
            except (Exception, OutcomeException) as cleanup_error:
                logger.exception("DHCP server cleanup step '%s' failed", step_name)
                if first_cleanup_error is None:
                    first_cleanup_error = cleanup_error

        if restore_state_flag:
            cleanup_step('disable feature', lambda: duthost.shell("config feature state dhcp_server disabled"))
        cleanup_step('restore relay layout',
                     lambda: dhcp_relay_utils.restart_dhcp_service(
                         duthost, [get_lifecycle_relay_type(duthost, not restore_state_flag)]))
        if restore_state_flag:
            def remove_dhcp_server_container():
                result = duthost.shell("docker rm -f {}".format(DHCP_SERVER_CONTAINER_NAME), module_ignore_errors=True)
                inspection = duthost.shell("docker inspect {}".format(DHCP_SERVER_CONTAINER_NAME),
                                           module_ignore_errors=True)
                if inspection['rc'] != 0 and "No such object" in inspection.get('stderr', ''):
                    return
                raise RuntimeError(
                    "Failed to remove dhcp_server container: stdout={} stderr={} inspect_stdout={} inspect_stderr={}"
                    .format(result.get('stdout', ''), result.get('stderr', ''),
                            inspection.get('stdout', ''), inspection.get('stderr', '')))

            cleanup_step('remove dhcp_server container', remove_dhcp_server_container)

        return first_cleanup_error

    try:
        if restore_state_flag:
            duthost.shell("config feature state dhcp_server enabled")

        dhcp_relay_utils.restart_dhcp_service(duthost, [get_lifecycle_relay_type(duthost, True)])

        def is_supervisor_subprocess_running(duthost, container_name, app_name):
            result = duthost.shell(f"docker exec {container_name} supervisorctl status {app_name}",
                                   module_ignore_errors=True)
            return result['rc'] == 0 and "RUNNING" in result.get('stdout', '')

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
        cleanup_error = restore_dhcp_server_state()
        if cleanup_error is not None and setup_or_test_error is None:
            raise cleanup_error


@pytest.fixture(scope="function", autouse=True)
def clean_dhcp_server_config_after_test(duthost, request, relay_agent):
    clean_dhcp_server_config(duthost, relay_agent)

    try:
        yield
    finally:
        test_has_outcome = any(
            getattr(request.node, report_name, None) is not None
            and (
                getattr(request.node, report_name).failed
                or getattr(request.node, report_name).skipped
            )
            for report_name in ('rep_setup', 'rep_call')
        )
        try:
            clean_dhcp_server_config(duthost, relay_agent)
        except (Exception, OutcomeException):
            if not test_has_outcome:
                raise
            logger.exception("DHCP server config cleanup failed after test outcome")
