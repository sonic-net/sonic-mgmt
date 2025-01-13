from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until


def restart_dhcp_service(duthost):
    duthost.shell('systemctl reset-failed dhcp_relay')
    duthost.shell('systemctl restart dhcp_relay')
    duthost.shell('systemctl reset-failed dhcp_relay')

    def _is_dhcp_relay_ready():
        output = duthost.shell('docker exec dhcp_relay supervisorctl status | grep dhcp | awk \'{print $2}\'',
                               module_ignore_errors=True)
        return (not output['rc'] and output['stderr'] == '' and len(output['stdout_lines']) != 0 and
                all(element == 'RUNNING' for element in output['stdout_lines']))

    pytest_assert(wait_until(120, 1, 10, _is_dhcp_relay_ready), "dhcp_relay is not ready after restarting")
