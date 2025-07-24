import pytest
import logging
from tests.common.constants import RESOLV_CONF_NAMESERVERS
from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import get_image_type
from tests.common.config_reload import config_reload, config_reload_minigraph_with_rendered_golden_config_override
from tests.common.utilities import backup_config, restore_config

pytestmark = [
    pytest.mark.topology("any"),
    pytest.mark.disable_loganalyzer
]

GOLDEN_CONFIG = "/etc/sonic/golden_config_db.json"
GOLDEN_CONFIG_BACKUP = "/etc/sonic/golden_config_db.json_before_override"
CONFIG_DB = "/etc/sonic/config_db.json"
CONFIG_DB_BACKUP = "/etc/sonic/config_db.json_before_override"

logger = logging.getLogger(__name__)


def file_exists_on_dut(duthost, filename):
    return duthost.stat(path=filename).get('stat', {}).get('exists', False)


@pytest.fixture(scope="module", autouse=True)
def setup_env(duthost):
    """
    Setup/teardown
    Args:
        duthost: DUT.
        golden_config_exists_on_dut: Check if golden config exists on DUT.
    """
    if duthost.is_multi_asic:
        pytest.skip("Skip test on multi-asic platforms as it is designed for single asic.")

    # Backup configDB
    backup_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    if file_exists_on_dut(duthost, GOLDEN_CONFIG):
        backup_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)

    # Restore default dns
    config_reload_minigraph_with_rendered_golden_config_override(
        duthost, safe_reload=True, check_intf_up_ports=True
    )

    yield

    # Restore configDB after test.
    restore_config(duthost, CONFIG_DB, CONFIG_DB_BACKUP)
    if file_exists_on_dut(duthost, GOLDEN_CONFIG_BACKUP):
        restore_config(duthost, GOLDEN_CONFIG, GOLDEN_CONFIG_BACKUP)
    else:
        duthost.file(path=GOLDEN_CONFIG, state='absent')

    # Restore config
    config_reload(duthost, safe_reload=True)


def test_dns_resolv_conf(duthost):
    """verify that /etc/resolv.conf contains the expected nameservers

    Args:
        duthost: AnsibleHost instance for DUT
    """
    # Check SONiC image type and get expected nameservers in /etc/resolv.conf
    expected_nameservers = set(RESOLV_CONF_NAMESERVERS[get_image_type(duthost=duthost)])

    logger.info("expected nameservers: [{}]".format(" ".join(expected_nameservers)))

    resolv_conf = duthost.shell("cat /etc/resolv.conf", module_ignore_errors=True)
    pytest_assert(resolv_conf["rc"] == 0, "Failed to read /etc/resolf.conf!")
    current_nameservers = []
    for resolver_line in resolv_conf["stdout_lines"]:
        if not resolver_line.startswith("nameserver"):
            continue
        current_nameservers.append(resolver_line.split()[1])

    current_nameservers = set(current_nameservers)

    logger.info("current nameservers: [{}]".format(" ".join(current_nameservers)))

    pytest_assert(not (current_nameservers ^ expected_nameservers),
                  "Mismatch between expected and current nameservers! Expected: [{}]. Current: [{}].".format(
                  " ".join(expected_nameservers), " ".join(current_nameservers)))

    containers = duthost.get_running_containers()
    for container in containers:
        resolv_conf = duthost.shell("docker exec %s cat /etc/resolv.conf" % container, module_ignore_errors=True)
        pytest_assert(resolv_conf["rc"] == 0, "Failed to read /etc/resolf.conf!")
        current_nameservers = []
        for resolver_line in resolv_conf["stdout_lines"]:
            if not resolver_line.startswith("nameserver"):
                continue
            current_nameservers.append(resolver_line.split()[1])

        current_nameservers = set(current_nameservers)

        logger.info("{} container, current nameservers: [{}]".format(container, " ".join(current_nameservers)))

        pytest_assert(not (current_nameservers ^ expected_nameservers),
                      "Mismatch between expected and current nameservers for {}! Expected: [{}]. Current: [{}].".format(
                      container, " ".join(expected_nameservers), " ".join(current_nameservers)))
