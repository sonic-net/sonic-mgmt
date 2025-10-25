import pytest
import logging
import os
from tests.common.helpers.firmware_helper import show_firmware

logger = logging.getLogger(__name__)

DUT_HOME = "/home/admin"
DEVICES_PATH = "/usr/share/sonic/device"
FS_PATH_TEMPLATE = "/host/image-{}/fs.squashfs"
FS_RW_TEMPLATE = "/host/image-{}/rw"
FS_WORK_TEMPLATE = "/host/image-{}/work"
FS_MOUNTPOINT_TEMPLATE = "/tmp/image-{}-fs"
OVERLAY_MOUNTPOINT_TEMPLATE = "/tmp/image-{}-overlay"


def pytest_addoption(parser):
    """
    Adds pytest options that are used by fwutil tests
    """

    parser.addoption(
        "--shutdown_bgp", action="store_true", default=False, help="Shutdown bgp before getting fw image from url"
    )


@pytest.fixture(scope="session", autouse=True)
def shutdown_bgp(request, duthost):
    if request.config.getoption('shutdown_bgp'):
        duthost.command("sudo config bgp shutdown all")
        duthost.command("sudo config save -y")

    yield

    if request.config.getoption('shutdown_bgp'):
        duthost.command("sudo config bgp startup all")
        duthost.command("sudo config save -y")


def check_path_exists(duthost, path):
    return duthost.stat(path=path)["stat"]["exists"]


@pytest.fixture(scope='function', params=["CPLD", "ONIE", "BIOS", "FPGA"])
def component(request, duthost, fw_pkg):
    component_type = request.param
    chassis = list(show_firmware(duthost)["chassis"].keys())[0]
    available_components = list(fw_pkg["chassis"].get(chassis, {}).get("component", {}).keys())
    cpld_components = [com for com in available_components if "CPLD" in com]
    # if in the host section, the CPLD defined is different, then need to use the one defined for this host.
    # For example: if the CPLD2 is defined for the SN3700c, and CPLD1 defined for the r-anaconda-15, then when run
    # test for the r-anaconda-15, it will take the CPLD1 instead of CPLD2 as on of the component
    if "host" in fw_pkg and duthost.hostname in fw_pkg["host"]:
        host_components = list(fw_pkg["host"].get(duthost.hostname, {}).get("component", []).keys())
        cpld_host_components = [com for com in host_components if "CPLD" in com]
        if cpld_host_components:
            available_components = list(set(available_components) ^ set(cpld_components) | set(host_components))
        else:
            available_components = list(set(available_components) | set(host_components))

    if len(available_components) > 0:
        for component in available_components:
            if component_type in component:
                return component
    pytest.skip(f"No suitable components found in config file for "
                f"platform {duthost.facts['platform']}, firmware type {component_type}.")


@pytest.fixture(scope='function')
def host_firmware(localhost, duthost):
    logger.info("Starting local python server to test URL firmware update....")
    comm = "python3 -m http.server --directory {}".format(os.path.join(DEVICES_PATH, duthost.facts['platform']))
    duthost.command(comm, module_ignore_errors=True, module_async=True)
    yield "http://localhost:8000/"
    logger.info("Stopping local python server.")
    duthost.command('pkill -f "{}"'.format(comm), module_ignore_errors=True)


@pytest.fixture(scope='function')
def next_image(duthost, fw_pkg):

    # Install next version of sonic
    current = duthost.shell('sonic-installer list | grep Current | cut -f2 -d " "')['stdout']

    image = list(fw_pkg.get("images", {}).keys())
    target = None

    for i in image:
        if "SONiC-OS-{}".format(i) != current:
            target = i

    if target is None:
        pytest.skip("No suitable image definitions found in config")

    logger.info("Installing new image {}".format(target))

    if fw_pkg["images"][target].startswith("http"):
        duthost.get_url(url=fw_pkg["images"][target], dest=DUT_HOME)
    else:
        duthost.copy(src=os.path.join("firmware", fw_pkg["images"][target]), dest=DUT_HOME)

    remote_path = os.path.join(DUT_HOME, os.path.basename(fw_pkg["images"][target]))
    duthost.command("sonic-installer install -y {}".format(remote_path), module_ignore_errors=True)

    # Mount newly installed image
    fs_path = FS_PATH_TEMPLATE.format(target)
    fs_mountpoint = FS_MOUNTPOINT_TEMPLATE.format(target)
    fs_rw = FS_RW_TEMPLATE.format(target)
    fs_work = FS_WORK_TEMPLATE.format(target)
    overlay_mountpoint = OVERLAY_MOUNTPOINT_TEMPLATE.format(target)

    logger.info("Attempting to stage test firware onto newly-installed image.")
    # noinspection PyBroadException
    try:
        duthost.command("mkdir -p {}".format(fs_mountpoint))
        duthost.command("mkdir -p {}".format(fs_rw))
        duthost.command("mkdir -p {}".format(fs_work))

        cmd = "mount -t squashfs {} {}".format(fs_path, fs_mountpoint)
        duthost.command(cmd)

        duthost.command("mkdir -p {}".format(overlay_mountpoint))
        cmd = "mount -n -r -t overlay -o lowerdir={},upperdir={},workdir={},rw overlay {}".format(
            fs_mountpoint,
            fs_rw,
            fs_work,
            overlay_mountpoint
        )
        duthost.command(cmd)
    except Exception:
        duthost.command("sonic-installer remove {} -y".format("SONiC-OS-{}".format(target)))
        pytest.fail("Failed to setup next-image.")

    yield overlay_mountpoint

    logger.info("Ensuring correct image is set to default boot.")
    duthost.command("sonic-installer remove {} -y".format("SONiC-OS-{}".format(target)))
