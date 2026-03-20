import logging
import pytest

from tests.common.helpers.assertions import pytest_assert


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.disable_loganalyzer
]

CONTAINER_UPGRADE_LABEL = "io.kubernetes.pod.namespace=sonic"


def find_excluded_containers(duthost, containers):
    """Return any container names that match container_upgrade containers identified by Docker label.

    Builds the excluded set from both the running container name and the
    io.kubernetes.container.name label value so that k8s-style names
    (e.g. k8s_acms_ds) and original names (e.g. acms) are both excluded.
    """
    running = duthost.get_running_containers()
    label_filter = "--filter label=%s" % CONTAINER_UPGRADE_LABEL
    # Get k8s-style container names (e.g. k8s_acms_ds)
    names = duthost.shell(
        r"docker ps %s --format \{\{.Names\}\}" % label_filter,
        module_ignore_errors=True
    )
    # Get original container names from label (e.g. acms)
    original = duthost.shell(
        r'docker ps %s --format \{\{.Label\ \"io.kubernetes.container.name\"\}\}' % label_filter,
        module_ignore_errors=True
    )
    excluded_names = set()
    for line in names.get("stdout_lines", []) + original.get("stdout_lines", []):
        name = line.strip()
        if name:
            excluded_names.add(name)
    # Only consider containers that are actually running
    excluded_names = excluded_names.intersection(set(running))
    return [c.strip() for c in containers if c.strip() in excluded_names]


def test_system_health_no_upgrade_containers(duthosts, enum_rand_one_per_hwsku_hostname,
                                             verify_acms_containers_running):
    """Verify container_upgrade containers do not appear in system health detail output."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    output = duthost.shell("sudo show system-health detail", module_ignore_errors=True)["stdout"]
    logger.info("system-health detail output:\n%s" % output)

    excluded = find_excluded_containers(duthost, output.split())
    pytest_assert(len(excluded) == 0,
                  "system-health detail should not contain container_upgrade containers, "
                  "found: %s" % excluded)


def test_service_checker_current_containers(duthosts, enum_rand_one_per_hwsku_hostname,
                                            verify_acms_containers_running):
    """Verify ServiceChecker.get_current_running_containers() does not include container_upgrade containers."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    cmd = ("python3 -c \"from health_checker.service_checker import ServiceChecker; "
           "print(ServiceChecker().get_current_running_containers())\"")
    result = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, "Failed to run ServiceChecker: %s" % result["stderr"])

    output = result["stdout"].strip()
    logger.info("get_current_running_containers output: %s" % output)

    found = find_excluded_containers(duthost, output.split(","))
    pytest_assert(len(found) == 0,
                  "get_current_running_containers should not contain container_upgrade containers, "
                  "found: %s" % found)


def test_service_checker_expected_containers(duthosts, enum_rand_one_per_hwsku_hostname,
                                             verify_acms_containers_running):
    """Verify ServiceChecker.get_expected_running_containers() does not include container_upgrade containers."""
    duthost = duthosts[enum_rand_one_per_hwsku_hostname]

    cmd = ("python3 -c \""
           "from health_checker.service_checker import ServiceChecker; "
           "from swsscommon import swsscommon; "
           "config_db = swsscommon.ConfigDBConnector(use_unix_socket_path=True); "
           "config_db.connect(); "
           "feature_table = config_db.get_table('FEATURE'); "
           "expected, container_feature_dict = ServiceChecker().get_expected_running_containers(feature_table); "
           "print(expected)\"")
    result = duthost.shell(cmd, module_ignore_errors=True)
    pytest_assert(result["rc"] == 0, "Failed to run ServiceChecker: %s" % result["stderr"])

    output = result["stdout"].strip()
    logger.info("get_expected_running_containers output: %s" % output)

    found = find_excluded_containers(duthost, output.split(","))
    pytest_assert(len(found) == 0,
                  "get_expected_running_containers should not contain container_upgrade containers, "
                  "found: %s" % found)
