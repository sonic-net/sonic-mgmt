import tarfile
import json
import pytest
import logging
import os
from fwutil_common import show_firmware
from pytest_ansible.errors import AnsibleConnectionFailure

logger = logging.getLogger(__name__)

DUT_HOME = "/home/admin"
DEVICES_PATH = "/usr/share/sonic/device"
FS_PATH_TEMPLATE = "/host/image-{}/fs.squashfs"
FS_RW_TEMPLATE = "/host/image-{}/rw"
FS_WORK_TEMPLATE = "/host/image-{}/work"
FS_MOUNTPOINT_TEMPLATE = "/tmp/image-{}-fs"
OVERLAY_MOUNTPOINT_TEMPLATE = "/tmp/image-{}-overlay"
PLATFORMS_HAVE_FPGA = ['x86_64-nvidia_sn4280-r0']


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


def pytest_generate_tests(metafunc):
    val = metafunc.config.getoption('--fw-pkg')
    if 'fw_pkg_name' in metafunc.fixturenames:
        metafunc.parametrize('fw_pkg_name', [val], scope="module")


@pytest.fixture(scope='module')
def fw_pkg(fw_pkg_name):
    if fw_pkg_name is None:
        pytest.skip("No fw package specified.")

    yield extract_fw_data(fw_pkg_name)


@pytest.fixture(scope='session', autouse=True)
def update_ssh_client_alive_interval(duthost, localhost):
    """
    Fixture to increase the ssh ClientAliveInterval of the dut. It may take very long time for the firmware burning
    and the default interval is not enough for the ansible command to complete.
    """
    sshd_config = "/etc/ssh/sshd_config"
    default_interval = duthost.shell(f"cat {sshd_config} | grep ^ClientAliveInterval |  awk '{{print $2}}'")['stdout']
    if not default_interval:
        return

    def _update_interval(interval):
        duthost.shell(f"sudo sed -i 's/^ClientAliveInterval.*/ClientAliveInterval {interval}/' {sshd_config}")
        duthost.shell("sudo systemctl restart sshd")
        # Kill the sshd of the duthost to make sure the new interval take effect in the next ansible command
        pid_list = duthost.shell('ps -aux | grep "[s]shd: admin@notty" | awk \'{print $2}\'')['stdout_lines']
        for pid in pid_list:
            try:
                duthost.shell(f"kill {pid}")
            except AnsibleConnectionFailure:
                pass

    _update_interval('3600')

    yield

    _update_interval(default_interval)


def extract_fw_data(fw_pkg_path):
    """
    Extract fw data from updated-fw.tar.gz file or firmware.json file
    :param fw_pkg_path: the path to tar.gz file or firmware.json file
    :return: fw_data in dictionary
    """
    if tarfile.is_tarfile(fw_pkg_path):
        path = "/tmp/firmware"
        isExist = os.path.exists(path)
        if not isExist:
            os.mkdir(path)
        with tarfile.open(fw_pkg_path, "r:gz") as f:
            f.extractall(path)
            json_file = os.path.join(path, "firmware.json")
            with open(json_file, 'r') as fw:
                fw_data = json.load(fw)
    else:
        with open(fw_pkg_path, 'r') as fw:
            fw_data = json.load(fw)

    return fw_data


@pytest.fixture(scope='function', params=["CPLD", "ONIE", "BIOS", "FPGA"])
def component(request, duthost, fw_pkg):
    component_type = request.param
    if component_type == 'FPGA' and duthost.facts['platform'] not in PLATFORMS_HAVE_FPGA:
        pytest.skip("Skip the FPGA test for the platform doesn't have FPGA components.")
    chassis = list(show_firmware(duthost)["chassis"].keys())[0]
    available_components = list(fw_pkg["chassis"].get(chassis, {}).get("component", {}).keys())
    if 'ONIE' in available_components:
        available_components.remove('ONIE')
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
