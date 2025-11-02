import logging
import os
import pytest
import time

from postupgrade_helper import run_postupgrade_actions, run_bgp_neighbor

from tests.common.devices.eos import EosHost
from tests.common.helpers.assertions import pytest_assert
from tests.common.helpers.multi_thread_utils import SafeThreadPoolExecutor
from tests.common.platform.device_utils import get_current_sonic_version
from tests.common.platform.interface_utils import check_interface_status_of_up_ports
from tests.common.reboot import reboot

logger = logging.getLogger(__name__)


pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.disable_loganalyzer,
]


LOCAL_MG_BACKUP_DIR = "/tmp/conversion-minigraphs/"
SONIC_PROVISION_ARTIFACTS_DIR = "/host/test_eos2sonic/"
EOS_PROVISION_ARTIFACTS_DIR = "/mnt/flash/test_eos2sonic/"
TMP_PROVISION_ARTIFACTS_DIR = "/tmp/provision-artifacts/"
SONIC_IMAGE_NAME = "sonic-aboot-broadcom-dnx.swi"
SONIC_IMAGE_URL = f"http://10.201.148.43/pipelines/Networking-acs-buildimage-Official/broadcom/internal-202405-chassis/{SONIC_IMAGE_NAME}"      # noqa E501
CONVERSION_SCRIPT_NAME = "chassis_eos2sonic.py"
MINIGRAPH = "/etc/sonic/minigraph.xml"
NGS_BASE_URL = "https://ngstest.trafficmanager.net/netgraph/ReadDeviceMinigraph?hostname="

MINIGRAPH_LOCATION_DEVICE_EXISTING = 1
MINIGRAPH_NGS_DOWNLOAD = 2  # Don't use until proxy authentication updated

TSB_TIMER = 900  # TSB timer in seconds
CONVERSION_WAIT_SONIC = 600  # Wait time after SONiC conversion in seconds
CONVERSION_WAIT_EOS = 420  # Wait time after EOS conversion in seconds


def check_conversion_is_applicable(sup_duthost):
    logger.info("Checking if chassis has the relevant SKU and files for conversion testing")

    if "Arista-7808" not in sup_duthost.facts['hwsku']:
        pytest.skip("Test only supports Arista 7808 SKUs")

    if not sup_duthost.stat(path="/host/EOS.swi")['stat']['exists']:
        pytest.skip("No EOS.swi on device - skipping conversion test")

    if not sup_duthost.stat(path="/host/startup-config")['stat']['exists']:
        pytest.skip("No EOS startup-config on device - skipping conversion test")


def convert_dut_to_eos(ansible_adhoc, duthosts, enum_supervisor_dut_hostname, localhost, creds):
    sup_duthost = duthosts[enum_supervisor_dut_hostname]

    # Backup boot config, and overwrite to boot into EOS next boot
    logger.info("Backing up boot-config, and updating boot-config to EOS")
    sup_duthost.copy(src="/host/boot-config", dest="/host/boot-config.test_eos2sonic.bkp", remote_src=True)
    sup_duthost.shell('echo "SWI=flash:EOS.swi" > /host/boot-config')

    logger.info("Rebooting DUT to EOS")
    reboot(sup_duthost, localhost, wait_for_ssh=False)
    time.sleep(CONVERSION_WAIT_EOS)

    eos_host = EosHost(ansible_adhoc=ansible_adhoc,
                       hostname=enum_supervisor_dut_hostname,
                       eos_user=creds['sonicadmin_user'],
                       eos_passwd=creds['lab_admin_pass'],
                       shell_user=creds['sonicadmin_user'],
                       shell_passwd=creds['lab_admin_pass'])

    # Check reachability
    eos_ver = eos_host.get_version()
    logger.info(f"DUT {enum_supervisor_dut_hostname} converted to EOS (version: {eos_ver})")

    return eos_host


def download_minigraph_to_sup(sup_duthost, duthost, creds, mg_path):
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    logger.info(f"Downloading minigraph on {duthost.hostname} through NGS")
    try:
        result = sup_duthost.shell(
            f"sudo curl -k -x {https_proxy} -o {mg_path} {NGS_BASE_URL + duthost.hostname}"
        )
        if result['rc'] != 0:
            raise Exception(f"Failed to download minigraph. Error: {result['stderr']}")
    except Exception as e:
        logger.error(f"Error downloading minigraph: {e}")
        raise


def save_minigraphs_locally(duthosts):
    for duthost in duthosts:
        duthost.fetch(src="/etc/sonic/minigraph.xml", dest=LOCAL_MG_BACKUP_DIR)


def copy_minigraph_to_provision_dir(sup_duthost, duthost, minigraph_source, creds=None):
    slot = duthost.slot_number
    pytest_assert(slot, f"No slot number for {duthost}")
    mg_path = f"{SONIC_PROVISION_ARTIFACTS_DIR}/minigraph-{'lc' if sup_duthost != duthost else 'sup'}{slot:02}.xml"

    if minigraph_source == MINIGRAPH_LOCATION_DEVICE_EXISTING:
        sup_duthost.copy(src=f"{LOCAL_MG_BACKUP_DIR}/{duthost.hostname}/etc/sonic/minigraph.xml",
                         dest=mg_path)
    elif minigraph_source == MINIGRAPH_NGS_DOWNLOAD:
        download_minigraph_to_sup(sup_duthost, duthost, creds, mg_path)


def cleanup_old_sonic_image(eos_host, image_version):
    eos_host.eos_command(commands=[
        "bash",
        "rm -rf /mnt/flash/provision",
        "rm -rf /mnt/flash/provision-artifacts",
        f"sudo rm -rf /mnt/flash/image-{image_version}"
    ])


def download_artifacts(sonic_host_linecards, sonic_host_sup, minigraph_source, creds):

    # Setup provisioning folder
    sonic_host_sup.file(path=SONIC_PROVISION_ARTIFACTS_DIR, state="absent")
    sonic_host_sup.file(path=SONIC_PROVISION_ARTIFACTS_DIR, state="directory")

    # Backup minigraphs locally
    logger.info("Backing up minigraphs")
    save_minigraphs_locally([sonic_host_sup, *sonic_host_linecards])

    # Copy minigraphs to provisioning folder
    for duthost in sonic_host_linecards:
        copy_minigraph_to_provision_dir(sonic_host_sup, duthost, minigraph_source, creds=creds)

    copy_minigraph_to_provision_dir(sonic_host_sup, sonic_host_sup, minigraph_source, creds=creds)

    # Copy eos2sonic script to provisioning folder on supervisor host
    logger.info("Copying eos2sonic script to provisioning folder from local sonic-metadata repository")
    base_path = os.path.dirname(__file__)
    if "sonic-mgmt-int" in base_path:
        sonic_metadata_dir_prefix = "../../../sonic-metadata/"
    else:
        sonic_metadata_dir_prefix = "../../sonic-metadata/"

    metadata_scripts_path = os.path.join(base_path, sonic_metadata_dir_prefix+"scripts")
    eos2sonic_path = os.path.join(base_path, sonic_metadata_dir_prefix+"scripts/"+CONVERSION_SCRIPT_NAME)

    pytest_assert(os.path.exists(metadata_scripts_path), f"SONiC Metadata scripts not found in {metadata_scripts_path}")
    pytest_assert(os.path.exists(eos2sonic_path), f"SONiC Metadata eos2sonic script not found in {eos2sonic_path}")

    sonic_host_sup.copy(src=eos2sonic_path, dest=f"{SONIC_PROVISION_ARTIFACTS_DIR}/{CONVERSION_SCRIPT_NAME}")

    # Copy optics firmware - currently not in use by eos2sonic script
    # TODO: Pull optics firmware from source
    logger.info("Copying optics firmware to provisioning folder from current sonic-mgmt repository")
    optics_firmware = os.path.join(base_path, "./files/common/Arista_7808_fw.tar.gz")

    pytest_assert(os.path.exists(optics_firmware),
                  f"Optics firmware Arista_7808_fw.tar.gz not found in {optics_firmware}")

    sonic_host_sup.copy(src=optics_firmware,
                        dest=f"{SONIC_PROVISION_ARTIFACTS_DIR}/Arista_7808_fw.tar.gz")

    # Download SONiC image file to provisioning folder on supervisor host
    logger.info(f"Downloading SONiC image from {SONIC_IMAGE_URL} to provisioning folder")
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')
    result = sonic_host_sup.shell(f'curl -k -x {https_proxy} -o {SONIC_PROVISION_ARTIFACTS_DIR}/{SONIC_IMAGE_NAME} \
                                  "{SONIC_IMAGE_URL}"')
    pytest_assert(result['failed'] is False,
                  f"Failed to download SONiC image from {SONIC_IMAGE_URL} to {sonic_host_sup.hostname}")


def prepare_eos_for_conversion(eos_duthost, linecard_duthosts):
    # Depower linecards
    eos_duthost.eos_config(lines=[
        f"no power enable module linecard {d.slot_number}" for d in linecard_duthosts
    ])

    # move artifacts to correct location
    rc, _ = eos_duthost.run_bash_command(f"mv {EOS_PROVISION_ARTIFACTS_DIR} {TMP_PROVISION_ARTIFACTS_DIR}")
    pytest_assert(rc == 0, f"Failed to move {EOS_PROVISION_ARTIFACTS_DIR} to {TMP_PROVISION_ARTIFACTS_DIR}")


def perform_conversion(eos_duthost):
    script_path = f"{TMP_PROVISION_ARTIFACTS_DIR}/{CONVERSION_SCRIPT_NAME}"

    rc, _ = eos_duthost.run_bash_command(f"chmod +x {script_path}")
    pytest_assert(rc == 0, f"Failed to make {script_path} executable")

    rc, _ = eos_duthost.run_bash_command(f"sudo {script_path} install-local &> /mnt/flash/test_eos2sonic.log")
    pytest_assert(rc == 0, f"Conversion script exited with rc {rc}")

    eos_duthost.run_command_list(["bash", "sudo reboot"])

    logger.info(f"Waiting {CONVERSION_WAIT_SONIC}s for DUT to reboot into SONiC")
    time.sleep(CONVERSION_WAIT_SONIC)


def post_conversion_health_check(duthosts):
    # no wait_until because we have already waited a substantial amount of time
    for duthost in duthosts:
        # Check all interfaces are up
        pytest_assert(check_interface_status_of_up_ports(duthost),
                      "Not all ports that are admin up on are operationally up")
        # Check all BGP sessions are established
        pytest_assert(duthost.check_bgp_session_state_all_asics(duthost.get_bgp_neighbors_per_asic(state="all")),
                      "Not all bgp sessions are established after config reload")
        # Check for core files generated after conversion
        core_count = int(duthost.shell("ls /var/core | wc -l")["stdout_lines"][0])
        pytest_assert(core_count == 0)


def run_post_conversion_scripts(duthost, localhost):
    run_postupgrade_actions(duthost=duthost, localhost=localhost,
                            tbinfo=None, metadata_process=True, skip_postupgrade_actions=False)
    run_bgp_neighbor(duthost=duthost, localhost=localhost,
                     tbinfo=None, metadata_process=True)


@pytest.mark.parametrize("minigraph_source", [
    pytest.param(MINIGRAPH_LOCATION_DEVICE_EXISTING, id="existing_minigraph")
])
def test_eos2sonic(ansible_adhoc, duthosts, enum_supervisor_dut_hostname, localhost, creds, minigraph_source):
    sup_duthost = duthosts[enum_supervisor_dut_hostname]
    linecard_duthosts = [d for d in duthosts if d is not sup_duthost]

    check_conversion_is_applicable(sup_duthost)

    # Check & log pre-test versions
    for duthost in duthosts:
        current_ver = get_current_sonic_version(duthost)
        pytest_assert("SONiC" in current_ver, f"Expected SONiC in version string, got {current_ver}")
        logger.info(f"Pre-test {duthost.hostname} version is {current_ver}")

    download_artifacts(linecard_duthosts, sup_duthost, minigraph_source, creds)

    logger.info("Converting DUT to EOS")
    eos_duthost = convert_dut_to_eos(ansible_adhoc, duthosts, enum_supervisor_dut_hostname, localhost, creds)

    logger.info("Preparing DUT for EOS to SONiC Conversion")
    cleanup_old_sonic_image(eos_duthost, sup_duthost.os_version)
    prepare_eos_for_conversion(eos_duthost, linecard_duthosts)

    logger.info("Performing EOS to SONiC Conversion")
    perform_conversion(eos_duthost)

    # Check & log post-test versions
    for duthost in duthosts:
        current_ver = get_current_sonic_version(duthost)
        pytest_assert("SONiC" in current_ver, f"Expected SONiC in version string, got {current_ver}")
        logger.info(f"Post-test {duthost.hostname} version is {current_ver}")

    # Run post conversion scripts in parallel
    logger.info("Running post-conversion scripts")
    with SafeThreadPoolExecutor(max_workers=8) as executor:
        for duthost in duthosts:
            executor.submit(run_post_conversion_scripts, duthost, localhost)

    logger.info("Performing post-conversion health check")
    post_conversion_health_check(duthosts)
