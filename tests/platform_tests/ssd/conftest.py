import json
import logging
import os
import pytest

from tests.common.fixtures.duthost_utils import duthost_shutdown_ebgp, duthost_startup_ebgp

logger = logging.getLogger(__name__)

SSD_MOUNT_POINT = "/host"
SUPPORTED_DISK_TYPES = ["sata", "nvme"]
SSD_THRESHOLDS_FILE = "ssd_thresholds.json"

# Time limit of each apt-get command, so a DUT that cannot reach the package server skips instead of hanging
APT_GET_TIMEOUT = 300

SSD_HEALTH_TOOLS = {
    "sata": {"command": "smartctl", "package": "smartmontools"},
    "nvme": {"command": "nvme", "package": "nvme-cli"},
}
SSD_STRESS_TOOLS = [
    {"command": "fio", "package": "fio"},
    {"command": "iostat", "package": "sysstat"},
]

SSD_TEST_FILE_NAME = "ssd_stress_test_file"
SSD_TEST_FILE_MAX_SIZE_GB = 4
SSD_TEST_FILE_MIN_SIZE_GB = 1
# Free space that must stay on the filesystem while the test file exists, for the logs and core dumps of SONiC
SSD_MIN_FREE_AFTER_FILE_GB = 4


def pytest_addoption(parser):
    """
    @summary: Add the options used by the SSD stress tests.
    """
    parser.addoption(
        "--ssd_stress_runtime",
        action="store",
        type=int,
        default=600,
        help="Runtime in seconds of each fio job in the SSD stress tests",
    )


@pytest.fixture(scope="module")
def ssd_device(duthosts, rand_one_dut_hostname):
    """
    @summary: Disk-detection fixture. Find the SSD and detect if it is SATA or NVMe.
    @return: Dictionary with the disk information.
    """
    duthost = duthosts[rand_one_dut_hostname]
    partition = duthost.command("findmnt -n -o SOURCE {}".format(SSD_MOUNT_POINT))["stdout"].strip()
    disk = "/dev/{}".format(duthost.command("lsblk -n -o PKNAME {}".format(partition))["stdout"].strip())
    lsblk_output = duthost.command("lsblk -J -d -o TRAN,MODEL {}".format(disk))["stdout"]
    disk_info = json.loads(lsblk_output)["blockdevices"][0]
    device = {
        "mount_point": SSD_MOUNT_POINT,
        "partition": partition,
        "disk": disk,
        "type": (disk_info["tran"] or "").lower(),
        "model": (disk_info["model"] or "").strip(),
    }

    if device["type"] not in SUPPORTED_DISK_TYPES:
        pytest.skip("Disk type '{}' of {} is not in supported test disks: {}".format(
            device["type"], device["disk"], SUPPORTED_DISK_TYPES))

    logger.info("Detected SSD on {}: {}".format(duthost.hostname, device))
    return device


@pytest.fixture(scope="module")
def ssd_thresholds(ssd_device):
    """
    @summary: Read the thresholds of the SSD model from SSD_THRESHOLDS_FILE, and fail if the model is not in the file.
    """
    thresholds_path = os.path.join(os.path.dirname(os.path.realpath(__file__)), SSD_THRESHOLDS_FILE)
    with open(thresholds_path) as thresholds_file:
        disk_type_thresholds = json.load(thresholds_file)[ssd_device["type"]]
    model_thresholds = disk_type_thresholds["models"].get(ssd_device["model"])
    if model_thresholds is None:
        pytest.fail("SSD model '{}' ({}) is not supported, add it to {}".format(
            ssd_device["model"], ssd_device["type"], SSD_THRESHOLDS_FILE))
    thresholds = dict(disk_type_thresholds["defaults"], **model_thresholds)
    logger.info("SSD thresholds of {}: {}".format(ssd_device["model"], thresholds))
    return thresholds


def _install_missing_tools(duthost, tools, installed_packages):
    """
    @summary: Install the tools that are missing on the DUT.
    """
    missing_tools = []
    for tool in tools:
        if duthost.shell("which {}".format(tool["command"]), module_ignore_errors=True)["rc"] == 0:
            logger.info("{} is already installed on {}".format(tool["command"], duthost.hostname))
        else:
            missing_tools.append(tool)
    if not missing_tools:
        return

    bgp_neighbors = duthost.config_facts(host=duthost.hostname, source="running")["ansible_facts"].get(
        "BGP_NEIGHBOR", {})
    neighbors_without_admin_status = [ip for ip, fields in bgp_neighbors.items() if "admin_status" not in fields]
    disabled_neighbors = [ip for ip, fields in bgp_neighbors.items() if fields.get("admin_status") == "down"]
    sumv4, sumv6 = duthost.get_ip_route_summary()
    v4_routes_count = sumv4.get("ebgp", {"routes": 0})["routes"]
    v6_routes_count = sumv6.get("ebgp", {"routes": 0})["routes"]
    try:
        duthost_shutdown_ebgp(duthost)
        duthost.shell("sudo timeout {} apt-get update".format(APT_GET_TIMEOUT), module_ignore_errors=True)
        for tool in missing_tools:
            logger.info("Installing {} on {}".format(tool["package"], duthost.hostname))
            result = duthost.shell("sudo timeout {} apt-get install -y {}".format(APT_GET_TIMEOUT, tool["package"]),
                                   module_ignore_errors=True)
            if result["rc"] != 0:
                pytest.skip("Failed to install {} on {}: {}".format(tool["package"], duthost.hostname,
                                                                    result["stderr"]))
            installed_packages.append(tool["package"])
    finally:
        try:
            duthost_startup_ebgp(duthost, v4_routes_count, v6_routes_count)
        finally:
            for ip in neighbors_without_admin_status:
                duthost.command("sonic-db-cli CONFIG_DB hdel 'BGP_NEIGHBOR|{}' admin_status".format(ip))
            for ip in disabled_neighbors:
                duthost.command("sudo config bgp shutdown neighbor {}".format(ip))


@pytest.fixture(scope="module", autouse=True)
def ssd_install_tools(duthosts, rand_one_dut_hostname, ssd_device):
    """
    @summary: Install the missing health and stress tools on the DUT before the tests.
              The installed packages are removed at the end of the module.
    """
    duthost = duthosts[rand_one_dut_hostname]
    installed_packages = []
    try:
        _install_missing_tools(duthost, [SSD_HEALTH_TOOLS[ssd_device["type"]]] + SSD_STRESS_TOOLS,
                               installed_packages)
        yield
    finally:
        for package in installed_packages:
            logger.info("Removing {} from {}".format(package, duthost.hostname))
            duthost.shell("sudo apt-get purge -y {}".format(package), module_ignore_errors=True)


@pytest.fixture(scope="module")
def ssd_test_file(duthosts, rand_one_dut_hostname, ssd_device):
    """
    @summary: Choose the path and size of the file that the stress tests write to, on the filesystem of the SSD.
              The file is removed at the end of the module.
    """
    duthost = duthosts[rand_one_dut_hostname]
    mount_point = ssd_device["mount_point"]
    test_file_path = "{}/{}".format(mount_point, SSD_TEST_FILE_NAME)

    # A file left by an interrupted run would make the free space look smaller than it is
    duthost.shell("sudo rm -f {}".format(test_file_path), module_ignore_errors=True)

    free_bytes = int(duthost.command("df -B1 --output=avail {}".format(mount_point))["stdout_lines"][-1])
    free_gb = free_bytes / 1024 ** 3
    size_gb = min(SSD_TEST_FILE_MAX_SIZE_GB, free_gb - SSD_MIN_FREE_AFTER_FILE_GB)
    if size_gb < SSD_TEST_FILE_MIN_SIZE_GB:
        pytest.skip("Not enough free space on {} of {}: {:.2f} GB free, {} GB needed".format(
            mount_point, duthost.hostname, free_gb, SSD_TEST_FILE_MIN_SIZE_GB + SSD_MIN_FREE_AFTER_FILE_GB))

    test_file = {"path": test_file_path, "size_mb": int(size_gb * 1024)}
    logger.info("SSD stress test file on {}: {}".format(duthost.hostname, test_file))
    yield test_file
    duthost.shell("sudo rm -f {}".format(test_file_path), module_ignore_errors=True)
