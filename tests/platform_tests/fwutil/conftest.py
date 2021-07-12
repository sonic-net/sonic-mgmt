import tarfile
import json
import pytest

from random import randrange

from fwutil_common import show_firmware

DUT_HOME="/home/admin"
DEVICES_PATH="/usr/share/sonic/device"
FS_PATH_TEMPLATE = "/host/image-{}/fs.squashfs"
FS_RW_TEMPLATE = "/host/image-{}/rw"
FS_WORK_TEMPLATE = "/host/image-{}/work"
FS_MOUNTPOINT_TEMPLATE = "/tmp/image-{}-fs"
OVERLAY_MOUNTPOINT_TEMPLATE = "/tmp/image-{}-overlay"

def pytest_generate_tests(metafunc):
    val = metafunc.config.getoption('--fw-pkg')
    if 'fw_pkg_name' in metafunc.fixturenames and val is not None:
        metafunc.parametrize('fw_pkg_name', [val], scope="module")

@pytest.fixture(scope='module')
def fw_pkg(fw_pkg_name):
    with tarfile.open(fw_pkg_name, "r:gz") as f:
        f.extractall()
        with open('firmware.json', 'r') as fw:
            fw_data = json.load(fw)
            yield fw_data
        for m in f.getmembers():
            subprocess.call("rm -rf {}".format(m.name), shell=True)

@pytest.fixture(scope='function')
def random_component(duthost, fw_pkg):
    chass = show_firmware(duthost)["chassis"].keys()[0]
    components = fw_pkg["chassis"].get(chass, {})["component"].keys()

    if len(components) == 0:
        pytest.skip("No suitable components found in config file for platform {}.".format(duthost.facts['platform']))

    return components[randrange(len(components))] 

@pytest.fixture(scope='function')
def host_firmware(localhost, duthost):
    comm = "python3 -m http.server --directory {}".format(os.path.join(DEVICES_PATH, 
        duthost.facts['platform']))
    task, res = duthost.command(comm, module_ignore_errors=True, module_async=True)
    yield "http://localhost:8000/"
    task.terminate()

@pytest.fixture(scope='function')
def next_image(duthost, fw_pkg):

    # Install next version of sonic
    current = duthost.shell('sonic_installer list | grep Current | cut -f2 -d " "')['stdout']

    image = fw_pkg.get("images", {}).keys()
    target = None

    for i in image:
        if "SONiC-OS-{}".format(i) != current:
            target = i

    if target is None:
        pytest.skip("No suitable image definitions found in config")

    duthost.copy(src=fw_pkg["images"][target], dest=DUT_HOME)
    remote_path = os.path.join(DUT_HOME, os.path.basename(fw_pkg["images"][target]))
    duthost.command("sonic_installer install -y {}".format(remote_path), module_ignore_errors=True)

    # Mount newly installed image
    fs_path = FS_PATH_TEMPLATE.format(target)
    fs_mountpoint = FS_MOUNTPOINT_TEMPLATE.format(target)
    fs_rw = FS_RW_TEMPLATE.format(target)
    fs_work = FS_WORK_TEMPLATE.format(target)
    overlay_mountpoint = OVERLAY_MOUNTPOINT_TEMPLATE.format(target)

    duthost.command("mkdir -p {}".format(fs_mountpoint))
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

    yield overlay_mountpoint

