import pytest
import logging
from tests.common.helpers.assertions import pytest_assert
from tests.platform_tests.fwutil.fwutil_common import complete_install

pytestmark = [
    pytest.mark.topology("any")
]

"""
The following test cases are added to test the following clis on cisco platforms
fwutil show updates
fwutil update chassis component eCPLD fw
"""


def test_fwutil_show(duthost):
    """Checks current fw version is up-to-date with available fw version
       for all the components in fwutil show updates CLI"""

    if "8102_64h" not in duthost.facts['platform']:
        pytest.skip("Test is not supported for this platform")

    output_fwutil_updates = duthost.show_and_parse('fwutil show updates')
    errors = []

    for index in range(len(output_fwutil_updates)):
        parse_output = output_fwutil_updates[index]
        current, available = map(str.strip, parse_output['version (current/available)'].split('/'))
        logging.info("Verifying output of '{}'...'{}'".format(current, available))

        if current != available:
            errors.append(
                "Current FW version for Component '{}' is not up-to-date "
                "(Current = {}, Available = {})".format(
                    parse_output['component'], current, available
                )
            )

    pytest_assert(not errors, "Firmware version mismatches found:\n" + "\n".join(errors))


def test_fwutil_update(request, duthost, localhost, pdu_controller):
    """Tests upgrade for eCPLD fw using fwutil update cli"""

    if "8102_64h" not in duthost.facts['platform']:
        pytest.skip("Test is not supported for this platform")

    logging.info("Checking eCPLD fw is up-to-date")
    fwutil_status = duthost.shell('fwutil show updates | grep eCPLD')
    if "up-to-date" in fwutil_status['stdout']:
        pytest.skip("eCPLD FW is already up-to-date")

    logging.info("Upgrading eCPLD fw")
    task, res = duthost.command("fwutil update chassis component eCPLD fw -y",
                                module_ignore_errors=True, module_async=True)

    logging.info("Cold rebooting")
    current = duthost.shell('sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
    complete_install(duthost, localhost, "cold", res, pdu_controller, False, current)

    logging.info("Checking the status after upgrade")
    output_fwutil_status = duthost.shell('fwutil show updates | grep eCPLD')
    pytest_assert("up-to-date" in output_fwutil_status['stdout'],
                  "fwutil update has been failed for eCPLD")

