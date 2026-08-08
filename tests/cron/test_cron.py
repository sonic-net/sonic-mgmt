import logging
import pytest

from tests.common.helpers.assertions import pytest_assert

logger = logging.getLogger(__name__)

CRON_FILE = "/etc/cron.d/logrotate"
CRON_LOG = "/var/log/cron.log"
EXPECTED_MODE = "0644"

CRON_ERROR_KEYWORDS = [
    "INSECURE MODE",
]


@pytest.mark.topology("any")
def test_cron_job(duthost, loganalyzer):
    # Validate cron file permission
    stat = duthost.stat(path=CRON_FILE)["stat"]
    if stat["exists"]:
        mode = stat["mode"][-4:]
        pytest_assert(
            mode == EXPECTED_MODE,
            f"{CRON_FILE} exists but permission is incorrect: {mode} (expected {EXPECTED_MODE})",
        )
    else:
        logger.warning(f"{CRON_FILE} does not exist - skipping permission check.")

    # Find cron logs for error
    pattern = "|".join(CRON_ERROR_KEYWORDS)
    cmd = "sudo zgrep -iE '{}' /var/log/cron.log*".format(pattern)
    logger.info(f"Running cron log check: {cmd}")
    result = duthost.shell(cmd, module_ignore_errors=True)
    output = result["stdout"].strip()

    pytest_assert(
        output == "",
        f"Unexpected cron errors found in {CRON_LOG}*: \n{output}",
    )

    logger.info("Cron job log check completed successfully (no known error patterns found).")
