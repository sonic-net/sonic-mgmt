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

    supported_platforms = ["8102_64h", "8101"]
    platform = duthost.facts['platform']

    if not any(p in platform for p in supported_platforms):
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


@pytest.mark.parametrize("component,platform_check", [
    ("eCPLD", "8102_64h"),
    ("IOFPGA", "8101"),
])
def test_fwutil_component_update(request, duthost, localhost, pdu_controller,
                                 component, platform_check):
    """Tests firmware upgrade for specified component using fwutil update CLI"""

    if platform_check not in duthost.facts['platform']:
        pytest.skip(f"Test is not supported for platform: {duthost.facts['platform']}")

    logging.info(f"Checking {component} firmware is up-to-date")
    fwutil_status = duthost.shell(f'fwutil show updates | grep {component}')
    if "up-to-date" in fwutil_status['stdout']:
        pytest.skip(f"{component} firmware is already up-to-date")

    logging.info(f"Upgrading {component} firmware")
    task, res = duthost.command(
        f"fwutil update chassis component {component} fw -y",
        module_ignore_errors=True,
        module_async=True
    )

    logging.info("Cold rebooting after firmware update")
    current = duthost.shell('sonic-installer list | grep Current | cut -f2 -d " "')['stdout']
    complete_install(duthost, localhost, "cold", res, pdu_controller, False, current)

    logging.info(f"Checking the status after {component} firmware upgrade")
    output_fwutil_status = duthost.shell(f'fwutil show updates | grep {component}')
    pytest_assert("up-to-date" in output_fwutil_status['stdout'],
                  f"fwutil update has failed for {component}")
