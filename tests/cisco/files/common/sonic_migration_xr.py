"""sonic_migration_xr.py

    ====XR-to-SONiC Migration Script====

    This Python script is intended for use on Cisco 8800 Series modular routers to automate the actions
    necessary for migration from IOS XR to SONiC.  In addition, it can be used to rollback a
    migrated device to IOS XR and restore its original configuration.
    
    ====Usage Instructions====

    To support execution of individual actions either as part of full migration or to execute an isolated
    step of the migration, sonic_migration_xr.py support multiple arguments associated with the actions
    being taken, including:
      --xr_upgrade - Upgrade to IOS XR 7.5.41 interim release required for SONiC migration
      --ov_install - Install Ownership Vouchers from OV tarball
      --av_install - Install Authenticated Variable from AV file
      --sonic_migration_rp - Migrate RP from IOS XR 7.5.41 to SONiC
      --sonic_migration_lc - Migrate all LCs from IOS XR 7.5.41 to SONiC after completion of RP SONiC migration
      --sonic_migration_postcheck - Verify health of device following migration to SONiC
      --zeroization - Zeroize the device

    When performing a rollback to restore the target device back to IOS XR (initial version) with its original
    configuration, the --rollback argument can be used for the following scenarios:
      - Rollback from SONiC to IOS XR (initial version)
      - Rollback from IOS XR 7.5.41 to IOS XR (initial version)
      - Applying any needed FPD updates after rollback to IOS XR (initial version)
      - Verifying health of device following rollback to IOS XR (initial version) and completion of FPD updates

    Typical usage instructions for full migration from IOS XR to SONiC:
        1. run python /harddisk:/sonic_migration_xr.py --xr_upgrade
           <device reloads>
        2. run python /harddisk:/sonic_migration_xr.py --ov_install
           <device reloads>
        3. run python /harddisk:/sonic_migration_xr.py --av_install --sonic_migration_rp
           <device reloads>
        4. sudo python /host/sonic_migration_xr.py --sonic_migration_lc
            <device reloads>
        4. sudo python /host/sonic_migration_xr.py --sonic_migration_postcheck

    Typical usage instructions for rollback from SONiC to IOS XR (initial version)
        1. sudo python /host/sonic_migration_xr.py --rollback
           <device reloads>
        2. run python /mnt/mtd0/sonic_migration_xr.py --rollback
           <device reloads>
        3. run python /mnt/mtd0/sonic_migration_xr.py --rollback

    Typical usage instructions for rollback from IOS XR 7.5.41 to IOS XR (initial version)
        1. run python /mnt/mtd0/sonic_migration_xr.py --rollback
           <device reloads>
        2. run python /mnt/mtd0/sonic_migration_xr.py --rollback
           <device reloads>
        3. run python /mnt/mtd0/sonic_migration_xr.py --rollback
    
    Typical usage instructions for zeroization at IOS XR 7.5.41
        1. run python /harddisk:/sonic_migration_xr.py --zeroization
           <device reloads>
"""

import argparse
import sys
import re
import subprocess
import os
import logging
import logging.handlers
import time
import ast
from datetime import datetime

sys.path.append("/pkg/bin")
try:
    from ztp_helper import ZtpHelpers

    on_sonic = False
except ModuleNotFoundError:
    on_sonic = True
if on_sonic:
    import cisco.pacific.triggers
    from sonic_platform.platform import Platform
logger = logging.getLogger()
log_file_path_xr = "/mnt/mtd0/"
log_file_path_sonic = "/host/"
log_context = "GENERAL"
args = ""
if not on_sonic:
    xr_cli = ZtpHelpers()
wd_xr = "/harddisk:/"
wd_sonic = "/host/"
module_healthcheck_override = []
generic_mode_modules = []
customer_mode_modules = []
non_av_modules = []
xr_version = None
xr_filename = None
xr_md5 = None
sonic_filename = "sonic-cisco-8000.bin.openssl.ipxcontainer"
xr_upgrade_version_precheck = False

RELEASE_MAPPINGS = {
    "7.3.5": {
        "XR_FILENAME": "8000-goldenk9-x64-7.3.5-fabric_2.iso",
        "XR_MD5": "cdfa10995653f7b8a9c410fad26ab997",
    },
    "7.3.6": {
        "XR_FILENAME": "8000-goldenk9-x64-7.3.6-fabric_3.iso",
        "XR_MD5": "757c55cfd6558198c432684fe7e33358",
    },
}
XR_INTERMEDIATE_VERSION = "7.5.41.04I"
XR_INTERMEDIATE_FILENAME = "8000-golden-x86_64-7.5.41.04I-GB_FPD_MACSEC.iso"
XR_INTERMEDIATE_MD5 = "2ec58e3d048eb6af235739a45abd9c97"
ONIE_FILENAME = "onie-recovery-x86_64-cisco_8000-r0.efi64.pxe"
ONIE_MD5 = "8b1e5332add1237a2c6df4c60cfea670"
OV_FILENAME = "vouchers.tar.gz"
#OV_FILENAME_MD5 = "vouchers.tar.gz.md5"
AV_FILENAME = "dbcustomer_onie_sonic_rel.auth"
#AV_FILENAME_MD5 = "dbcustomer_onie_sonic_rel.auth.md5"
ZEROIZATION_FILENAME = "CertStoreZeroize.auth"
LOG_CONTEXT_CODES = {
    "GENERAL": "00",
    "EXECUTION_PRECHECK": "01",
    "XR_UPGRADE": "02",
    "XR_UPGRADE_POSTCHECK": "03",
    "ZEROIZE_PRECHECK": "04",
    "ZEROIZE_INSTALL": "05",
    "OV_PRECHECK": "06",
    "OV_INSTALL": "07",
    "OV_POSTCHECK": "08",
    "AV_PRECHECK": "09",
    "AV_INSTALL": "10",
    "AV_POSTCHECK": "11",
    "SONIC_MIGRATION_PRECHECK_RP": "12",
    "SONIC_MIGRATION_RP": "13",
    "SONIC_MIGRATION_POSTCHECK": "14",
    "ROLLBACK_PRECHECK_SONIC": "15",
    "ROLLBACK_SONIC": "16",
    "ROLLBACK_PRECHECK": "17",
    "XR_ROLLBACK": "18",
    "ROLLBACK_POSTCHECK": "19",
    "EXIT_ON_FAILURE": "20",
    "SONIC_MIGRATION_PRECHECK_LC": "21",
    "SONIC_MIGRATION_LC": "22",
    "SONIC_MIGRATION_CHECK_LC_ON_XR": "23",
    "SONIC_MIGRATION_LC_RECOVERY_ON_XR": "24"
}


def module_healthcheck_xr(interval=0, timeout=0, ignore_shut=False):
    """
    Performs a health check for IOS XR modules by checking "show platform" output.

    Args:
        interval (int, optional): The time interval (in seconds) between consecutive health checks. Defaults to 0.
        timeout (int, optional): The maximum time (in seconds) to wait for modules to enter a healthy state. Defaults to 0.
        ignore_shut (bool, optional): If True, ignore modules that are in the 'SHUT' configuration state. Defaults to False.

    Returns:
        bool: True if all nodes are operational. Otherwise the script will exit.

    """
    log_msg("Performing module healthcheck for IOS XR")
    if timeout > 0:
        log_msg(
            "Module healthcheck will run for up to {} seconds to wait for modules to enter healthy state".format(
                timeout
            )
        )
    start_time = time.time()
    while True:
        non_operational_slot_numbers = []
        platform_modules = parse_show_platform()
        fail_state = 0
        for module in platform_modules:
            if (
                (module["state"] != "IOS XR RUN" and module["state"] != "OPERATIONAL")
                and module["config_state"] == "NSHUT"
            ) or (module["config_state"] == "SHUT" and not ignore_shut):
                fail_state = 1
                non_operational_slot_numbers.append(module["node"])
        if fail_state == 1:
            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout:
                log_msg(
                    "Module number(s) {non_operational_slot_numbers} are not operational.".format(
                        non_operational_slot_numbers=non_operational_slot_numbers
                    ),
                    "ERROR",
                    "000",
                )
                exit_script(
                    return_code="000",
                    exit_reason="Failure. Modules are not operational",
                )
            time.sleep(interval)
        else:
            log_msg("All nodes are operational")
            return True


def module_healthcheck_sonic(interval=0, timeout=0, ignore_shut=False):
    """
    Performs a health check for SONIC line cards by checking "show chassis modules status" output.

    Args:
        interval (int, optional): The time interval (in seconds) between consecutive health checks. Defaults to 0.
        timeout (int, optional): The maximum time (in seconds) to wait for line cards to become operational. Defaults to 0.
        ignore_shut (bool, optional): If True, ignore line cards in a 'Shut' state. Defaults to False.

    Returns:
        bool: True if all nodes are operational. Otherwise the script will exit.

    Functionality:
        - If `default_config` is not set, it runs the `show chassis modules status` command to check module health.
        - If `default_config` is set, it instead runs `show platform inventory` to check module initialization status.
        - The function waits for modules to be in an operational state, with a timeout mechanism in place.
        - If modules remain in a failed state beyond the timeout period, the script exits with an appropriate error code.
    """
    log_msg("Performing module healthcheck for SONIC")
    if timeout > 0:
        log_msg(
            "Module healthcheck will run for up to {} seconds to wait for modules to enter healthy state".format(
                timeout
            )
        )
    start_time = time.time()
    if not args.default_config:
        while True:
            stdout, stderr = shell_cmd("show chassis modules status")
            command_output = str(stdout)
            text_by_lines = command_output.split("\\n")
            if "Key * not found in CHASSIS_MODULE_TABLE table" in text_by_lines[0]:
                exit_script(
                    return_code="046",
                    exit_reason="show chassis modules status command not supported with current configuration",
                )
            fail_state = 0
            for line in range(2, len(text_by_lines) - 1):
                sonic_module = text_by_lines[line].split()[0]
                if (
                    len(module_healthcheck_override) > 0
                    and sonic_module in module_healthcheck_override
                ):
                    continue
                if (
                    "Online" not in text_by_lines[line]
                    and "Empty" not in text_by_lines[line]
                ):
                    fail_state = 1
                    break
            if fail_state == 1:
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout:
                    exit_script(
                        return_code="001",
                        exit_reason="All modules are not migrated to sonic",
                    )
                time.sleep(interval)
            else:
                log_msg("All modules are migrated to sonic")
                return True
    else:
        while True:
            stdout, stderr = shell_cmd("show platform inventory")
            command_output = str(stdout)
            fail_state = 0
            if "not initialized" in command_output:
                fail_state = 1
            if fail_state == 1:
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout:
                    exit_script(
                        return_code="001",
                        exit_reason="All modules are not migrated to sonic",
                    )
                time.sleep(interval)
            else:
                log_msg("All modules are migrated to sonic")
                return True


def platform_server_healthcheck_sonic(interval=0, timeout=0):
    """
    Performs a health check for the platform server service on SONiC devices.

    Args:
        interval (int, optional): The time interval (in seconds) between consecutive health checks. Defaults to 0.
        timeout (int, optional): The maximum time (in seconds) to wait for the service to become healthy. Defaults to 0.

    Returns:
        bool: True if the service is healthy. Otherwise the script will exit.
    """
    def is_service_healthy():
        cmd = "systemctl status platform-migration-server.service"
        sp = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = sp.communicate()
        command_output = str(stdout)
        text_by_lines = command_output.split("\\n")
        for line in text_by_lines:
            if re.search(r"Main PID: \d+ \(code=exited, status=0/SUCCESS\)", line):
                return True
        return False

    def wait_for_health(interval, timeout):
        start_time = time.time()
        while True:
            if is_service_healthy():
                log_msg("RP successfully copied Onie and Sonic Image from Staging LC")
                return True
            if timeout and (time.time() - start_time) >= timeout:
                return False
            time.sleep(interval)

    log_msg("Performing Platform server service check for SONIC")
    if timeout > 0:
        log_msg("Platform server service check will run for up to {} seconds".format(timeout))

    # Initial wait
    if wait_for_health(interval, timeout):
        return True

    # On failure, restart and retry once
    log_msg("Platform migration server did not become healthy in time.")
    log_msg("Executing systemctl reset-failed platform-migration-server.service")
    shell_cmd("systemctl reset-failed platform-migration-server.service")
    log_msg("Executing systemctl start platform-migration-server.service")
    shell_cmd("systemctl start platform-migration-server.service")

    # Retry once with fixed interval and timeout
    retry_interval = 30
    retry_timeout = 600
    log_msg("Retrying health check with interval={} and timeout={}".format(retry_interval, retry_timeout))
    if wait_for_health(retry_interval, retry_timeout):
        return True

    exit_script(return_code="044", exit_reason="All services are not up after retry")

def execution_precheck():
    """
    Performs precheck before upgrade to 'XR_INTERMEDIATE_VERSION'. It checks the device version, verifies the operational status of modules, validates the use of supported PIDs for linecards/RPs, and ensures the presence and integrity of required files.

    Prechecks:
    1. Validate Device Version:
        - Checks the device version using the 'show version' command.
        - If the device version matches 'XR_INTERMEDIATE_VERSION', exits with a success message.
        - When `xr_upgrade_version_precheck` is set to True:
            - If the device version matches 'XR_VERSION', logs the device version.
            - If neither 'XR_INTERMEDIATE_VERSION' nor 'XR_VERSION' is found, exits with an error message.

    2. Validate Nodes are Operational:
        - Calls the function 'module_healthcheck_xr()' to validate that all modules are operational.

    3. Validate Supported PIDs:
        - Validates that only supported PIDs from the 'pid_list' are used for linecards/RPs on the device.

    4. Validate OV Tarball:
        - Retrieves the serial numbers of the device using the 'get_serial_numbers()' function.
        - Extracts the OV tarball ('OV_FILENAME') and verifies the presence of the required files.

    5. Verify MD5 checksums for Files:
        - Verifies the MD5 checksums of 'XR_INTERMEDIATE_FILENAME', 'ONIE_FILENAME', 'OV_FILENAME' and 'AV_FILENAME'.

    6. Save Backup of Running-Config:
        - Saves a backup of the running-config on the device for rollback support.

    7. Copy Configuration and Script Backups:
        - Copies the configuration backup ('backup.cfg') and the script backup ('sonic_migration_xr.py') to '/mnt/mtd0' on the device.

    Returns:
        None. If any of the prechecks fail, the script will exit with an appropriate error message and return code.

    """
    global log_context, xr_version
    log_context = "EXECUTION_PRECHECK"
    log_msg("Starting precheck for the device")

    # Validate device version
    log_msg("Validate version of device")
    command_result = xr_cli_cmd("show version")

    xr_cli_output = "\n".join(command_result)

    if bool(
        re.search(
            r"Version[ :]+{XR_INTERMEDIATE_VERSION}".format(
                XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
            ),
            xr_cli_output,
            flags=re.MULTILINE,
        )
    ):
        exit_script(
            return_code="0",
            exit_reason="XR Upgrade not required. Device is on {XR_INTERMEDIATE_VERSION}. Please proceed with OV installation. Script will now exit.".format(
                XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
            ),
        )
    elif xr_upgrade_version_precheck:
        calculated_version = find_matching_version(
            xr_cli_output, RELEASE_MAPPINGS.keys()
        )
        if calculated_version:
            xr_version = calculated_version
            log_msg("Device is on {xr_version}".format(xr_version=xr_version))
        else:
            expected_versions = " or ".join(RELEASE_MAPPINGS.keys())
            exit_script(
                return_code="002",
                exit_reason="Fail. Not on Correct Version of IOS XR. Expected: {expected_versions}".format(
                    expected_versions=expected_versions
                ),
            )

    # Validate nodes are operational or not
    log_msg("Validate that all modules are operational")
    module_healthcheck_xr()

    # Validate only supported PIDs are being used for linecards/RPs on the device
    log_msg(
        "Validate only supported PIDs are being used for linecards/RPs on the device"
    )
    pid_list = [
        "8800-RP",
        "8800-RP(Active)",
        "88-LC0-36FH-M",
        "88-LC0-36FH",
        "8800-LC-48H",
    ]
    platform_modules = parse_show_platform()
    for module in platform_modules:
        is_pattern_found = bool(
            re.search(r"^[0-9]+\/[A-Z]*[0-9]+\/[A-Z]+[0-9]+", module["node"])
        )
        if is_pattern_found and module["type"] not in pid_list:
            exit_script(
                return_code="003",
                exit_reason="{} is not supported PID".format(module["type"]),
            )
    log_msg("All supported PIDs are being used for linecards/RPs on the device")

    # Check to confirm that all required files are present on the device in preparation for migration
    file_list = [
        OV_FILENAME,
        #OV_FILENAME_MD5,
        AV_FILENAME,
        #AV_FILENAME_MD5,
        sonic_filename,
        ONIE_FILENAME,
        XR_INTERMEDIATE_FILENAME,
        "sonic-migutil.py",
    ]
    file_check(file_list)

    if not args.default_config:
        log_msg("Validate minigraph files are present in {wd_xr}".format(wd_xr=wd_xr))
        minigraph_files = minigraph_files_list()
        log_msg(
            "Minigraph files present in {wd_xr}: {minigraph_files}".format(
                wd_xr=wd_xr, minigraph_files=minigraph_files
            )
        )

    log_msg("Verifying MD5 checksum for {}".format(XR_INTERMEDIATE_FILENAME))
    shell_cmd(
        cmd="md5sum {}".format(XR_INTERMEDIATE_FILENAME),
        pass_pattern=XR_INTERMEDIATE_MD5,
        pass_message="MD5 checksum matches expected value",
        fail_message="MD5 checksum does not match",
        error_code="005",
    )
    log_msg("Verifying MD5 checksum for {}".format(ONIE_FILENAME))
    shell_cmd(
        cmd="md5sum {}".format(ONIE_FILENAME),
        pass_pattern=ONIE_MD5,
        pass_message="MD5 checksum matches expected value",
        fail_message="MD5 checksum does not match",
        error_code="005",
    )
    # log_msg("Verifying MD5 checksum for {}".format(OV_FILENAME))
    # shell_cmd(
    #     cmd="md5sum {}".format(OV_FILENAME),
    #     pass_pattern=get_md5_from_file(OV_FILENAME_MD5),
    #     pass_message="MD5 checksum matches expected value",
    #     fail_message="MD5 checksum does not match",
    #     error_code="005",
    # )
    # log_msg("Verifying MD5 checksum for {}".format(AV_FILENAME))
    # shell_cmd(
    #     cmd="md5sum {}".format(AV_FILENAME),
    #     pass_pattern=get_md5_from_file(AV_FILENAME_MD5),
    #     pass_message="MD5 checksum matches expected value",
    #     fail_message="MD5 checksum does not match",
    #     error_code="005",
    # )
    # Validate OV tarball
    log_msg("Validate OV tarball")
    serial_number_list = get_serial_numbers()
    log_msg(
        "Serial Numbers: {serial_number_list}".format(
            serial_number_list=serial_number_list
        )
    )

    tar_string = ""
    for serial_number in serial_number_list:
        tar_string += serial_number + ".vcj" + " "

    shell_cmd(
        cmd="tar -zxvf {OV_FILENAME} {tar_string}".format(
            OV_FILENAME=OV_FILENAME, tar_string=tar_string
        ),
        pass_message="All files are present in the OV tarball file",
        fail_message="Files are missing in the OV tarball file",
        error_code="006",
    )

    # Get output of show clock
    command_result = xr_cli_cmd("show clock")
    xr_cli_output = list(command_result)
    show_clock_date = extract_clock_output(xr_cli_output)

    # Check each .vcj file in the tarball
    files = os.listdir(".")
    for file_name in files:
        if file_name.endswith(".vcj") and file_name in tar_string:
            with open(file_name, "r") as file:
                content = file.read()
                expires_on_match = re.search(r'"expires-on":\s*"([^"]+)"', content)
                serial_number_match = re.search(
                    r'"serial-number":\s*"([^"]+)"', content
                )
                voucher_expiry_date = datetime.strptime(
                    expires_on_match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ"
                )

                if serial_number_match.group(1) not in serial_number_list:
                    exit_script(
                        return_code="038",
                        exit_reason="Serial number {serial_number} in OV file {OV_FILENAME} does not match any serial number on the device.".format(
                            serial_number=serial_number_match.group(1),
                            OV_FILENAME=OV_FILENAME,
                        ),
                    )
                if voucher_expiry_date < show_clock_date:
                    exit_script(
                        return_code="039",
                        exit_reason="OV file {file_name} has expired. Expiration date-time set to {voucher_expiry_date}. Current date-time is {show_clock_date}.".format(
                            file_name=file_name,
                            voucher_expiry_date=voucher_expiry_date,
                            show_clock_date=show_clock_date,
                        ),
                    )

    shell_cmd("rm {wd_xr}*.vcj".format(wd_xr=wd_xr))

    # Saving running config before migration
    log_msg("Save backup of running-config to support config restoration on rollback")

    cmd = {
        "exec_cmd": "copy running-config harddisk:backup.cfg",
        "prompt_response": "\ny\ny",
    }
    command_result = xr_cli.xrcmd(cmd)

    if command_result["status"] != "success":
        exit_script(
            return_code="007",
            exit_reason="copy running-config harddisk:backup.cfg failed",
        )

    command_result_value = list(command_result.values())
    command_subresult = command_result_value[1]

    if command_subresult[-1] == "[OK]":
        log_msg("Sucessfully backed up configuration")
    else:
        exit_script(return_code="008", exit_reason="Failed to backup configuration")

    log_msg("Copying configuration backup to /mnt/mtd0")
    shell_cmd("cp /harddisk:/backup.cfg /mnt/mtd0/")

    log_msg("Copying script backup to /mnt/mtd0")
    shell_cmd("cp {wd_xr}sonic_migration_xr.py /mnt/mtd0/".format(wd_xr=wd_xr))

    log_msg("Completed precheck for the device")


def xr_upgrade():
    """
    Performs IOS XR upgrade on the device. This function initiates the IOS XR upgrade process on the device by replacing the current image with the intermediate IOS XR image specified by 'XR_INTERMEDIATE_FILENAME'. The function will trigger a reload to apply the upgrade.

    Returns:
        None.

    """
    global log_context
    log_context = "XR_UPGRADE"

    log_msg(
        "Device will now reload for IOS XR upgrade to {XR_INTERMEDIATE_FILENAME} image".format(
            XR_INTERMEDIATE_FILENAME=XR_INTERMEDIATE_FILENAME
        )
    )
    exit_script(exit=False)
    xr_cli_cmd(
        "install replace {wd_xr}{XR_INTERMEDIATE_FILENAME} commit noprompt synchronous".format(
            wd_xr=wd_xr, XR_INTERMEDIATE_FILENAME=XR_INTERMEDIATE_FILENAME
        )
    )


def xr_upgrade_postcheck():
    """
    Performs post-check after IOS XR upgrade on the device. It verifies that the upgrade has been successful and validates the operational status of modules.

    Postchecks:
    1. Validate Device Version:
       - Checks the device version using the 'show version' command.
       - Verifies if the device version matches the intermediate IOS XR version ('XR_INTERMEDIATE_VERSION').
       - Logs the result as success if the device version matches the intermediate version.
       - Logs an error message if the device version does not match the intermediate version.

    2. Validate Nodes are Operational:
       - Calls the function 'module_healthcheck_xr()' with a time interval of 30 seconds and a maximum wait time of 600 seconds to validate that all modules are operational after the upgrade.

    Returns:
        None.

    """
    global log_context
    log_context = "XR_UPGRADE_POSTCHECK"

    log_msg("Starting postcheck for the device")
    # Validate device has been successfully upgraded to XR_INTERMEDIATE_VERSION
    log_msg(
        "Validate device is running {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        )
    )

    xr_cli_cmd(
        "show version",
        pass_pattern=r"Version[ :]+{XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        pass_message="Device is on {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        fail_message="Device is not on {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        return_code="009",
    )

    # Validate nodes are operational or not
    log_msg("Validate that modules are operational")
    module_healthcheck_xr(30, 600)

    log_msg("Completed postcheck for the device")


def zeroize_precheck():
    """
    Perform a zeroization precheck on a network device.

    It performs the following steps:

    1. Logs the start of the zeroization precheck process.
    2. Validates that the device has been successfully upgraded to the required intermediate version.
    3. Ensures that all nodes (modules) on the device are operational.
    4. Checks for the presence of the zeroization file on the device.
    5. Verifies that the device ownership is in Customer mode.
    6. Categorizes modules based on their mode: Customer Mode, Generic Mode, or modules with zeroization installed but needing a reload.
    7. Summarizes the states of the modules after the checks.

    Returns:
        None.

    """
    global log_context, customer_mode_modules
    log_context = "ZEROIZE_PRECHECK"

    log_msg("Starting Zeroization precheck for the device")
    # Validate device has been successfully upgraded to XR_INTERMEDIATE_VERSION
    log_msg(
        "Validate device is running {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        )
    )
    xr_cli_cmd(
        "show version",
        pass_pattern=r"Version[ :]+{XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        pass_message="Device is on {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        fail_message="Device is not on {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        return_code="009",
    )

    # Validate nodes are operational or not
    log_msg("Validate that modules are operational")
    module_healthcheck_xr(30, 600)

    # Check to confirm that ZEROIZATION_FILENAME is present on the device
    file_list = [ZEROIZATION_FILENAME]
    file_check(file_list)

    # Verify device ownership is in Customer mode
    log_msg("Verify device ownership is in Customer mode")
    command_result = xr_cli_cmd("show platform security boot mode location all")

    generic_mode_modules = []
    zeroize_installed_modules = []
    result_items = list(command_result)

    success = 0
    for i in range(0, len(result_items)):
        modes = re.findall("Aikido mode: ([A-Z,a-z]+\s[A-Z,a-z]+)", result_items[i])
        if len(modes) != 0 and "Customer Mode" in modes:
            module = re.findall(
                "Location : ([0-9]+\/[A-Z]*[0-9]+\/[A-Z]+[0-9]+)", result_items[i - 2]
            )
            command_result = xr_cli_cmd(
                'show logging | i "!!!! Zeroization Install Success for {module} !!!!"'.format(
                    module=module[0]
                )
            )
            if len(command_result) > 0:
                zeroize_installed_modules.append(module[0])
            else:
                customer_mode_modules.append(module[0])
            success = 1
        elif len(modes) != 0 and "Generic Mode" in modes:
            module = re.findall(
                "Location : ([0-9]+\/[A-Z]*[0-9]+\/[A-Z]+[0-9]+)", result_items[i - 2]
            )
            generic_mode_modules.append(module[0])
        elif len(modes) != 0 and "Setup Mode" in modes:
            success = 2
            break
    if success == 2:
        exit_script(
            return_code="010",
            exit_reason="Device ownership is in Setup mode. Please check. Device is not upgraded with supported image",
        )
    elif success == 1:
        log_msg("Success. Router is controlled by Customer Mode")
    else:
        exit_script(
            return_code="0",
            exit_reason="Zeroization is not required: all modules are already in Generic Mode. Script will now exit.",
        )

    # Summarize OV states
    log_msg(
        "Modules in Generic Mode: {generic_mode_modules}".format(
            generic_mode_modules=generic_mode_modules
        )
    )
    log_msg(
        "Modules in Customer Mode: {customer_mode_modules}".format(
            customer_mode_modules=customer_mode_modules
        )
    )
    log_msg(
        "Modules with Zeroize Installed and needs reload: {zeroize_installed_modules}".format(
            zeroize_installed_modules=zeroize_installed_modules
        )
    )

    log_msg("Completed Zeroization precheck for the device")


def zeroize_install():
    """
    Perform zeroization installation on a network device.

    It performs the following steps:

    1. Logs the start of the zeroization installation process.
    2. Iterates over each module in Customer Mode and attempts to apply zeroization.
    3. Logs success or failure messages for each module.
    4. If any module fails to apply zeroization, logs the failure and exits the script.
    5. If all modules succeed, logs the success message.
    6. Initiates a reload of the device.

    Returns:
        None.

    """
    global log_context, customer_mode_modules
    log_context = "ZEROIZE_INSTALL"

    log_msg("ZEROIZATION Installation")

    # Install Zeroization on all modules
    failed_zeroization = []
    for module in range(0, len(customer_mode_modules)):
        command_result = xr_cli_cmd(
            "platform security variable customer zeroize {wd_xr}{ZEROIZATION_FILENAME} GUID f79d17d1-88d4-40dd-aff8-9f9da3c30e9e location {module_location}".format(
                wd_xr=wd_xr,
                ZEROIZATION_FILENAME=ZEROIZATION_FILENAME,
                module_location=customer_mode_modules[module],
            )
        )

        xr_cli_output = list(command_result)

        zeroization_success = 0
        for i in range(0, len(xr_cli_output)):
            if "Successfully applied AV" in xr_cli_output[i]:
                log_msg(
                    "Successfully applied Zeroization on {module_location}".format(
                        module_location=customer_mode_modules[module]
                    )
                )
                xr_cli_cmd(
                    "log !!!! Zeroization Install Success for {module_location} !!!!".format(
                        module_location=customer_mode_modules[module]
                    )
                )
                zeroization_success = 1
                break

        if zeroization_success == 0:
            log_msg(
                "Failed to apply Zeroization for {module_location}".format(
                    module_location=customer_mode_modules[module]
                )
            )
            failed_zeroization.append(customer_mode_modules[module])

    if len(failed_zeroization) > 0:
        exit_script(
            return_code="011",
            exit_reason="Modules failed to apply Zeroization: {failed_zeroization}".format(
                failed_zeroization=failed_zeroization
            ),
        )
    else:
        log_msg("Success. Applied Zeroization")
    # Reload device
    log_msg("Reloading Device")
    cmd = {"exec_cmd": "reload location all", "prompt_response": "\ny\ny"}
    command_result = xr_cli.xrcmd(cmd)
    log_msg(command_result)
    exit_script()


def ov_precheck():
    """
    Performs precheck before initiating OV (Ownership Voucher) installation. It checks the BIOS, X86FPGA, and TAM versions, verifies the device ownership mode, and validates the presence of the OV tarball ('OV_FILENAME').

    Steps:
    1. Verify BIOS, X86FPGA, and TAM Versions:
       - Checks the BIOS, X86FPGA, and TAM versions using the 'show hw-module fpd' command.
       - Compares the versions with the corresponding required versions based on the linecard type.
       - Logs success if all versions meet the requirements.
       - Exits with an error message if any version does not meet the requirements.

    2. Verify Device Ownership Mode:
       - Checks the device ownership mode using the 'show platform security boot mode location all' command.
       - Verifies if the device ownership mode is in "Generic Mode" or "Setup Mode".
       - Exits with an error message if the device ownership mode is in "Setup Mode".
       - Exits with a message to proceed directly for AV installation if the device ownership mode is in "Customer Mode".
       - Logs success if the device ownership mode is in "Generic Mode".

    3. Verify Presence of OV Tarball:
       - Verifies the presence of the OV tarball ('OV_FILENAME') on the device using the 'file_check()' function.

    4. Verifies the MD5 checksums of 'OV_FILENAME'.

    5. Create Final OV Tar File:
       - Retrieves the serial numbers of the device using the 'get_serial_numbers()' function.
       - Extracts the OV tarball ('OV_FILENAME') for the select serial numbers and creates a temporary OV tar file for them on the harddisk.
       - Logs success after creating the temporary OV tar file.

    Returns:
        None.

    """

    global log_context, generic_mode_modules
    log_context = "OV_PRECHECK"

    log_msg("Starting OV precheck for the device")

    # Verify BIOS, X86FPGA, and TAM version meet requirements
    LC036FH = {
        "Bios": 1.07,
        "BiosGolden": 0.15,
        "x86Fpga": 1.40,
        "x86FpgaGolden": 1.06,
        "x86TamFw": 6.16,
        "x86TamFwGolden": 6.05,
    }
    LC48H = {
        "Bios": 1.25,
        "BiosGolden": 1.15,
        "x86Fpga": 1.53,
        "x86FpgaGolden": 1.01,
        "x86TamFw": 5.14,
        "x86TamFwGolden": 5.06,
    }
    LC036FHM = {
        "Bios": 1.07,
        "BiosGolden": 0.15,
        "x86Fpga": 1.40,
        "x86FpgaGolden": 1.06,
        "x86TamFw": 6.16,
        "x86TamFwGolden": 6.05,
    }
    RP8800 = {
        "Bios": 1.25,
        "BiosGolden": 1.15,
        "x86Fpga": 1.35,
        "x86FpgaGolden": 1.02,
        "x86TamFw": 5.14,
        "x86TamFwGolden": 5.06,
    }

    log_msg("Checking BIOS Version")
    command_result = xr_cli_cmd('show hw-module fpd | i "Bios"')

    result_items = list(command_result)

    bios_failure = 0
    for i in range(0, len(result_items)):
        split_result = result_items[i].split()
        if split_result[0] in module_healthcheck_override:
            continue
        if (
            split_result[1] == "88-LC0-36FH"
            and split_result[3] == "Bios"
            and float(split_result[-2]) < LC036FH["Bios"]
        ):
            expected_value = LC036FH["Bios"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH"
            and split_result[3] == "BiosGolden"
            and float(split_result[-2]) < LC036FH["BiosGolden"]
        ):
            expected_value = LC036FH["BiosGolden"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "8800-LC-48H"
            and split_result[3] == "Bios"
            and float(split_result[-2]) < LC48H["Bios"]
        ):
            expected_value = LC48H["Bios"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "8800-LC-48H"
            and split_result[3] == "BiosGolden"
            and float(split_result[-2]) < LC48H["BiosGolden"]
        ):
            expected_value = LC48H["BiosGolden"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH-M"
            and split_result[3] == "Bios"
            and float(split_result[-2]) < LC036FHM["Bios"]
        ):
            expected_value = LC036FHM["Bios"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH-M"
            and split_result[3] == "BiosGolden"
            and float(split_result[-2]) < LC036FHM["BiosGolden"]
        ):
            expected_value = LC036FHM["BiosGolden"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "8800-RP"
            and split_result[3] == "Bios"
            and float(split_result[-2]) < RP8800["Bios"]
        ):
            expected_value = RP8800["Bios"]
            bios_failure = 1
            break
        elif (
            split_result[1] == "8800-RP"
            and split_result[3] == "BiosGolden"
            and float(split_result[-2]) < RP8800["BiosGolden"]
        ):
            expected_value = RP8800["BiosGolden"]
            bios_failure = 1
            break

    if bios_failure == 0:
        log_msg("Sucessfully verified BIOS version ")
    else:
        exit_script(
            return_code="012",
            exit_reason="Failure in BIOS version. Minimum expected value of {module} for {fpd_device} is {expected_value}. Currently running {version}.".format(
                module=split_result[1],
                fpd_device=split_result[3],
                expected_value=expected_value,
                version=split_result[-2],
            ),
        )

    log_msg("Checking X86FPGA and TAM version")
    command_result = xr_cli_cmd('show hw-module fpd | i "x86"')

    result_items = list(command_result)

    x86_failure = 0
    for i in range(0, len(result_items)):
        split_result = result_items[i].split()
        if split_result[0] in module_healthcheck_override:
            continue
        if (
            split_result[1] == "88-LC0-36FH"
            and split_result[3] == "x86Fpga"
            and float(split_result[-2]) < LC036FH["x86Fpga"]
        ):
            expected_value = LC036FH["x86Fpga"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH"
            and split_result[3] == "x86FpgaGolden"
            and float(split_result[-2]) < LC036FH["x86FpgaGolden"]
        ):
            expected_value = LC036FH["x86FpgaGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "88-LC0-36FH"
            and split_result[3] == "x86TamFw"
            and float(split_result[-2]) < LC036FH["x86TamFw"]
        ):
            expected_value = LC036FH["x86TamFw"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH"
            and split_result[3] == "x86TamFwGolden"
            and float(split_result[-2]) < LC036FH["x86TamFwGolden"]
        ):
            expected_value = LC036FH["x86TamFwGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "8800-LC-48H"
            and split_result[3] == "x86Fpga"
            and float(split_result[-2]) < LC48H["x86Fpga"]
        ):
            expected_value = LC48H["x86Fpga"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "8800-LC-48H"
            and split_result[3] == "x86FpgaGolden"
            and float(split_result[-2]) < LC48H["x86FpgaGolden"]
        ):
            expected_value = LC48H["x86FpgaGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "8800-LC-48H"
            and split_result[3] == "x86TamFw"
            and float(split_result[-2]) < LC48H["x86TamFw"]
        ):
            expected_value = LC48H["x86TamFw"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "8800-LC-48H"
            and split_result[3] == "x86TamFwGolden"
            and float(split_result[-2]) < LC48H["x86TamFwGolden"]
        ):
            expected_value = LC48H["x86TamFwGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "88-LC0-36FH-M"
            and split_result[3] == "x86Fpga"
            and float(split_result[-2]) < LC036FHM["x86Fpga"]
        ):
            expected_value = LC036FHM["x86Fpga"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH-M"
            and split_result[3] == "x86FpgaGolden"
            and float(split_result[-2]) < LC036FHM["x86FpgaGolden"]
        ):
            expected_value = LC036FHM["x86FpgaGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "88-LC0-36FH-M"
            and split_result[3] == "x86TamFw"
            and float(split_result[-2]) < LC036FHM["x86TamFw"]
        ):
            expected_value = LC036FHM["x86TamFw"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "88-LC0-36FH-M"
            and split_result[3] == "x86TamFwGolden"
            and float(split_result[-2]) < LC036FHM["x86TamFwGolden"]
        ):
            expected_value = LC036FHM["x86TamFwGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "8800-RP"
            and split_result[3] == "x86Fpga"
            and float(split_result[-2]) < RP8800["x86Fpga"]
        ):
            expected_value = RP8800["x86Fpga"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "8800-RP"
            and split_result[3] == "x86FpgaGolden"
            and float(split_result[-2]) < RP8800["x86FpgaGolden"]
        ):
            expected_value = RP8800["x86FpgaGolden"]
            x86_failure = 1
            break
        if (
            split_result[1] == "8800-RP"
            and split_result[3] == "x86TamFw"
            and float(split_result[-2]) < RP8800["x86TamFw"]
        ):
            expected_value = RP8800["x86TamFw"]
            x86_failure = 1
            break
        elif (
            split_result[1] == "8800-RP"
            and split_result[3] == "x86TamFwGolden"
            and float(split_result[-2]) < RP8800["x86TamFwGolden"]
        ):
            expected_value = RP8800["x86TamFwGolden"]
            x86_failure = 1
            break

    if x86_failure == 0:
        log_msg("Sucessfully verified X86FPGA and TAM version")
    else:
        exit_script(
            return_code="013",
            exit_reason="Failure in X86FPGA and TAM version. Minimum expected value of {module} for {fpd_device} is {expected_value}. Currently running {version}.".format(
                module=split_result[1],
                fpd_device=split_result[3],
                expected_value=expected_value,
                version=split_result[-2],
            ),
        )

    # Verify device ownership is in Generic mode
    log_msg("Verify device ownership is in Generic mode")
    command_result = xr_cli_cmd("show platform security boot mode location all")

    customer_mode_modules = []
    ov_installed_modules = []
    result_items = list(command_result)

    success = 0
    for i in range(0, len(result_items)):
        modes = re.findall("Aikido mode: ([A-Z,a-z]+\s[A-Z,a-z]+)", result_items[i])
        if len(modes) != 0 and "Customer Mode" in modes:
            module = re.findall(
                "Location : ([0-9]+\/[A-Z]*[0-9]+\/[A-Z]+[0-9]+)", result_items[i - 2]
            )
            customer_mode_modules.append(module[0])
        elif len(modes) != 0 and "Generic Mode" in modes:
            module = re.findall(
                "Location : ([0-9]+\/[A-Z]*[0-9]+\/[A-Z]+[0-9]+)", result_items[i - 2]
            )
            command_result = xr_cli_cmd(
                'show logging | i "!!!! OV Install Success for {module} !!!!"'.format(
                    module=module[0]
                )
            )
            if len(command_result) > 0:
                ov_installed_modules.append(module[0])
            else:
                generic_mode_modules.append(module[0])
            success = 1
        elif len(modes) != 0 and "Setup Mode" in modes:
            success = 2
            break
    if success == 2:
        exit_script(
            return_code="010",
            exit_reason="Device ownership is in Setup mode. Please check. Device is not upgraded with supported image",
        )
    elif success == 1:
        log_msg("Success. Router is controlled by Cisco Mode")
    else:
        exit_script(
            return_code="0",
            exit_reason="OV installation not required: all modules are already in Customer Mode. Please proceed with AV installation. Script will now exit.",
        )

    # Check to confirm that OV_FILENAME is present on the device
    file_list = [OV_FILENAME]
    file_check(file_list)
    # log_msg("Verifying MD5 checksum for {}".format(OV_FILENAME))
    # shell_cmd(
    #     cmd="md5sum {}".format(OV_FILENAME),
    #     pass_pattern=get_md5_from_file(OV_FILENAME_MD5),
    #     pass_message="MD5 checksum matches expected value",
    #     fail_message="MD5 checksum does not match",
    #     error_code="005",
    # )

    # Create Final OV tar file
    log_msg("Creating final OV tar file on the harddisk")
    serial_number_list = get_serial_numbers()
    log_msg(
        "Serial Numbers: {serial_number_list}".format(
            serial_number_list=serial_number_list
        )
    )

    tar_string = ""
    for serial in serial_number_list:
        tar_string += serial + ".vcj" + " "

    shell_cmd(
        cmd="tar -zxvf {OV_FILENAME} {tar_string}".format(
            OV_FILENAME=OV_FILENAME, tar_string=tar_string
        ),
        pass_message="All files are present in the OV tarball file",
        fail_message="Files are missing in the OV tarball file",
        error_code="006",
    )

    # Get output of show clock
    command_result = xr_cli_cmd("show clock")
    xr_cli_output = list(command_result)
    show_clock_date = extract_clock_output(xr_cli_output)

    # Check each .vcj file in the tarball
    files = os.listdir(".")
    for file_name in files:
        if file_name.endswith(".vcj") and file_name in tar_string:
            with open(file_name, "r") as file:
                content = file.read()
                expires_on_match = re.search(r'"expires-on":\s*"([^"]+)"', content)
                serial_number_match = re.search(
                    r'"serial-number":\s*"([^"]+)"', content
                )
                voucher_expiry_date = datetime.strptime(
                    expires_on_match.group(1), "%Y-%m-%dT%H:%M:%S.%fZ"
                )

                if serial_number_match.group(1) not in serial_number_list:
                    exit_script(
                        return_code="038",
                        exit_reason="Serial number {serial_number} in OV file {OV_FILENAME} does not match any serial number on the device.".format(
                            serial_number=serial_number_match.group(1),
                            OV_FILENAME=OV_FILENAME,
                        ),
                    )
                if voucher_expiry_date < show_clock_date:
                    exit_script(
                        return_code="039",
                        exit_reason="OV file {file_name} has expired. Expiration date-time set to {voucher_expiry_date}. Current date-time is {show_clock_date}.".format(
                            file_name=file_name,
                            voucher_expiry_date=voucher_expiry_date,
                            show_clock_date=show_clock_date,
                        ),
                    )

    shell_cmd(
        cmd="tar -czvf {wd_xr}select_ov.tar.gz ./*.vcj".format(wd_xr=wd_xr),
        pass_message="Temporary OV TAR file created for select serial numbers",
        fail_message="Unable to create OV TAR file for select serial numbers",
        error_code="014",
    )
    shell_cmd("rm {wd_xr}*.vcj".format(wd_xr=wd_xr))

    # Summarize OV states
    log_msg(
        "Modules in Generic Mode: {generic_mode_modules}".format(
            generic_mode_modules=generic_mode_modules
        )
    )
    log_msg(
        "Modules in Customer Mode: {customer_mode_modules}".format(
            customer_mode_modules=customer_mode_modules
        )
    )
    log_msg(
        "Modules with OV Installed and needs reload: {ov_installed_modules}".format(
            ov_installed_modules=ov_installed_modules
        )
    )

    log_msg("Completed OV precheck for the device")


def ov_install():
    """
    Performs OV (Ownership Voucher) installation on the device. It enables extended ownership by applying the ownership voucher ('select_ov.tar.gz') to the device. After successfully applying the ownership voucher, it reloads the device to complete the OV installation.

    Returns:
        None.

    """
    global log_context, generic_mode_modules
    log_context = "OV_INSTALL"

    log_msg("OV Installation")
    # Apply ownership voucher on device to enable extended ownership

    log_msg("Enabling extended ownership")
    failed_ov = []
    for module in range(0, len(generic_mode_modules)):
        command_result = xr_cli_cmd(
            "platform security device-ownership {wd_xr}select_ov.tar.gz location {module_location}".format(
                wd_xr=wd_xr, module_location=generic_mode_modules[module]
            )
        )

        xr_cli_output = list(command_result)

        ov_success = 0
        for i in range(0, len(xr_cli_output)):
            if "Successfully applied ownership voucher" in xr_cli_output[i]:
                log_msg(
                    "Successfully applied OV on {module_location}".format(
                        module_location=generic_mode_modules[module]
                    )
                )
                xr_cli_cmd(
                    "log !!!! OV Install Success for {module_location} !!!!".format(
                        module_location=generic_mode_modules[module]
                    )
                )
                ov_success = 1
                break

        if ov_success == 0:
            log_msg(
                "Failed to apply OV for {module_location}".format(
                    module_location=generic_mode_modules[module]
                )
            )
            failed_ov.append(generic_mode_modules[module])

    if len(failed_ov) > 0:
        exit_script(
            return_code="015",
            exit_reason="Modules failed to apply OV: {failed_ov}".format(
                failed_ov=failed_ov
            ),
        )
    else:
        log_msg("Success. Applied OV")
    # Reload device
    log_msg("Reloading Device")
    cmd = {"exec_cmd": "reload location all", "prompt_response": "\ny\ny"}
    command_result = xr_cli.xrcmd(cmd)
    log_msg(command_result)
    exit_script()


def ov_postcheck():
    """
    Performs post-check after OV (Ownership Voucher) installation on the device. It validates the operational status of modules, verifies the device ownership mode, and checks the activation and registration status of the platform key certificate.

    Postchecks:
    1. Validate Nodes are Operational:
       - Calls the function 'module_healthcheck_xr()' with a time interval of 30 seconds and a maximum wait time of 600 seconds to validate that all modules are operational after the OV installation.

    2. Verify Device Ownership Mode:
       - Checks the device ownership mode using the 'show platform security boot mode location all' command.
       - Verifies if the device ownership mode is in "Customer Mode".
       - Exits with an error message if the device ownership mode is not in "Customer Mode".
       - Logs success if the device ownership mode is in "Customer Mode".

    3. Verify Platform Key Certificate Status:
       - Checks the platform key certificate status using the 'show platform security variable customer PKCustomer location all' command.
       - Verifies if the platform key certificate is active and registered successfully.
       - Exits with an error message if the platform key certificate is not active and registered successfully.
       - Logs success if the platform key certificate is active and registered successfully.

    Returns:
        None.

    """
    global log_context
    log_context = "OV_POSTCHECK"

    log_msg("Starting OV postcheck for the device")

    # Validate nodes are operational or not
    log_msg("Validate that modules are operational")
    module_healthcheck_xr(30, 600)

    # Verify device ownership is in Customer mode
    log_msg("Verify device ownership is in Customer mode")
    command_result = xr_cli_cmd("show platform security boot mode location all")

    result_items = list(command_result)

    customer_mode_failure = 0
    for i in range(0, len(result_items)):
        modes = re.findall("Aikido mode: ([A-Z,a-z]+\s[A-Z,a-z]+)", result_items[i])
        if len(modes) != 0 and "Customer Mode" not in modes:
            customer_mode_failure = 1
            break

    if customer_mode_failure == 0:
        log_msg("Device ownership is in Customer mode")
    else:
        exit_script(
            return_code="016",
            exit_reason="Fail. Device ownership is not in Customer mode",
        )

    # Verify platform key certificate is active and registered successfully
    log_msg("Verify platform key certificate is active and registered successfully")
    command_result = xr_cli_cmd(
        "show platform security variable customer PKCustomer location all"
    )

    result_items = list(command_result)

    certificate_failure = 0
    for i in range(0, len(result_items)):
        if "Variable PKCustomer has no entries" in result_items[i]:
            certificate_failure = 1
            break
    if certificate_failure == 1:
        exit_script(
            return_code="017",
            exit_reason="Fail. Platform key certificate is not active and registered successfully",
        )
    else:
        log_msg(
            "Success. Platform key certificate is active and registered successfully"
        )

    log_msg("Completed OV postcheck for the device")


def av_precheck():
    """
    Performs precheck before initiating AV (Authentication variable) installation on the device. It verifies the activation status of the 'dbCustomer' key certificate, checks the presence of the AV tarball ('AV_FILENAME'), and determines whether AV installation or SONIC migration is required based on the precheck results.

    Prechecks:
    1. Verify Activation of dbCustomer Key Certificate:
       - Checks the activation status of the 'dbCustomer' key certificate using the 'show platform security variable customer dbCustomer location all' command.
       - Logs success if the 'dbCustomer' key certificate is not active.
       - If the certificate is active and the 'args.sonic_migration' flag is True, proceeds with SONIC migration precheck and migration process by calling the 'sonic_migration_precheck()' and 'sonic_migration()' functions, respectively.
       - If the certificate is active and 'args.sonic_migration' is False, exits with a success message indicating that AV installation is not required.

    2. Verify Presence of AV Tarball:
       - Verifies the presence of the AV tarball ('AV_FILENAME') on the device using the 'file_check()' function.

    3. Verifies the MD5 checksums of 'AV_FILENAME'.

    Returns:
        None.

    """
    global log_context, args, non_av_modules
    log_context = "AV_PRECHECK"

    log_msg("Starting AV precheck for the device")

    module_locations = []
    av_modules = []

    platform_modules = parse_show_platform()
    for module in platform_modules:
        if module["state"] == "IOS XR RUN":
            module_locations.append(module["node"])

    # Verify if dbCustomer is active or not
    for i in range(0, len(module_locations)):
        command_result = xr_cli_cmd(
            "show platform security variable customer dbCustomer location {}".format(
                module_locations[i]
            )
        )
        xr_cli_output = list(command_result)
        if "Variable dbCustomer has no entries" in xr_cli_output[5]:
            non_av_modules.append(module_locations[i])
        else:
            av_modules.append(module_locations[i])

    if len(non_av_modules) > 0:
        log_msg(
            "Success. dbCustomer key certificate is not active for {non_av_modules}".format(
                non_av_modules=non_av_modules
            )
        )
        log_msg(
            "dbCustomer key certificate is active for {av_modules}".format(
                av_modules=av_modules
            )
        )
    elif args.sonic_migration_rp and len(non_av_modules) == 0:
        log_msg(
            "AV installation not required: dbCustomer key certificate is active. Proceeding with SONIC migration."
        )
        sonic_migration_precheck()
        sonic_migration()
    else:
        exit_script(
            return_code="0",
            exit_reason="AV installation not required: dbCustomer key certificate is active. Please proceed with SONIC migration. Script will now exit",
        )

    # Check to confirm that AV_FILENAME is present on the device
    file_list = [AV_FILENAME]
    file_check(file_list)
    # log_msg("Verifying MD5 checksum for {}".format(AV_FILENAME))
    # shell_cmd(
    #     cmd="md5sum {}".format(AV_FILENAME),
    #     pass_pattern=get_md5_from_file(AV_FILENAME_MD5),
    #     pass_message="MD5 checksum matches expected value",
    #     fail_message="MD5 checksum does not match",
    #     error_code="005",
    # )

    log_msg("Completed AV precheck for the device")


def av_install():
    """
    Performs AV (Authentication variable) installation on the device. It applies the 'dbCustomer' key certificate to the device using the AV tarball ('AV_FILENAME').

    Returns:
        None.

    """
    global log_context, non_av_modules
    log_context = "AV_INSTALL"

    log_msg("Installing AV")
    failed_av = []
    # Apply AV on device
    for module in range(0, len(non_av_modules)):
        command_result = xr_cli_cmd(
            "platform security variable customer append dbCustomer {wd_xr}{AV_FILENAME} location {module_location}".format(
                wd_xr=wd_xr,
                AV_FILENAME=AV_FILENAME,
                module_location=non_av_modules[module],
            )
        )

        xr_cli_output = list(command_result)

        av_success = 0
        for i in range(0, len(xr_cli_output)):
            if "Successfully applied AV" in xr_cli_output[i]:
                av_success = 1
                log_msg(
                    "Successfully applied AV on {module_location}".format(
                        module_location=non_av_modules[module]
                    )
                )
                break

        if av_success == 0:
            log_msg(
                "Failed to apply AV for {module_location}".format(
                    module_location=non_av_modules[module]
                )
            )
            failed_av.append(non_av_modules[module])

    if len(failed_av) > 0:
        exit_script(
            return_code="020",
            exit_reason="Modules failed to apply AV: {failed_av}".format(
                failed_av=failed_av
            ),
        )
    else:
        log_msg("Success. Applied AV")

    log_msg("AV installation completed successfully.")


def av_postcheck():
    """
    Performs post-check after AV (Authentication variable) installation on the device. It verifies the activation and registration status of the 'dbCustomer' key certificate.

    Postcheck:
    1. Verify Activation of dbCustomer Key Certificate:
       - Checks the activation status of the 'dbCustomer' key certificate using the 'show platform security variable customer dbCustomer location all' command.
       - Logs success if the 'dbCustomer' key certificate is active and registered successfully.
       - Exits with an error message if the 'dbCustomer' key certificate is not active and registered successfully.

    Returns:
        None.

    """
    global log_context
    log_context = "AV_POSTCHECK"

    log_msg("Starting AV postcheck for the device")

    # Verify if dbCustomer is active or not
    log_msg("Verify if dbCustomer is active or not")
    command_result = xr_cli_cmd(
        "show platform security variable customer dbCustomer location all"
    )

    result_items = list(command_result)

    dbCustomer_failure = 0
    for i in range(0, len(result_items)):
        if "Variable dbCustomer has no entries" in result_items[i]:
            dbCustomer_failure = 1
            break
    if dbCustomer_failure == 1:
        exit_script(
            return_code="021",
            exit_reason="Fail. dbCustomer certificate is not active and registered successfully",
        )
    else:
        log_msg("Success. dbCustomer certificate is active and registered successfully")

    log_msg("Completed AV postcheck for the device")


def configure_logger(log_file_path=""):
    """
    Configures the logging system for the script. This function sets up the logging system with appropriate log levels, handlers, and formatters for console output and log file ('sonic_migration.log').

    Args:
        log_file_path (str, optional): The path to the directory where the log file should be created. Defaults to an empty string.

    Returns:
        None.

    """
    logger.setLevel(logging.DEBUG)

    # create console handler and set level to debug
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # create formatter
    formatter = logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s")

    # add formatter to console_handler
    console_handler.setFormatter(formatter)

    # add console_handler to logger
    logger.addHandler(console_handler)

    file_handler = logging.handlers.RotatingFileHandler(
        filename="{}sonic_migration.log".format(log_file_path),
        mode="a",
        maxBytes=1024 * 1024,  # 1 MB
        backupCount=1,
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)


def get_lc_powered_off(interval=0, timeout=0):
    """
    Retrieves the list of Line Card (LC) slots that are Offline by parsing the output using platform library.

    Returns:
        list: A list of integers representing the LC slots that are powered off.
    """
    log_msg("Checking modules status using platform library")
    if timeout > 0:
        log_msg(
            "Check will run for up to {} seconds".format(
                timeout
            )
        )
    start_time = time.time()
    lc_powered_off = []
    platform = Platform()
    chassis = platform.get_chassis()
    while True:
        fail_state = 0
        lc_powered_off.clear()  # reset each iteration

        modules = chassis.get_all_modules()
        for module in modules:
            name = module.get_name()  # e.g. "LINE-CARD0"

            if "LINE-CARD" in name:
                slot = module.get_slot()
                oper_status = module.get_oper_status()

                # Only consider offline LCs
                if oper_status == "Offline":
                    lc_powered_off.append(slot)
                    fail_state = 1

        if fail_state == 1:
            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout:
                return lc_powered_off
            time.sleep(interval)
        else:
            log_msg("All modules are migrated to sonic")
            return lc_powered_off


def determine_rma_or_migration():
    """
    Determines whether the device should undergo an RMA or proceed with LC migration.

    This function first checks for powered-off line cards using `get_lc_powered_off()`.
    - If any LCs are powered off, it logs the information and returns "RMA".
    - Otherwise, it executes "show platform inventory" for up to 60 seconds to verify
      if all modules have migrated to SONiC.
    - If any module remains in the "not initialized" state for 60 seconds, it returns "MIGRATION".
    - If all modules are successfully migrated, it returns "FULLY_MIGRATED".

    Returns:
        str: "RMA" if line cards are powered off, "MIGRATION" if migration is required.
    """
    if not os.path.exists("/mnt/obfl/.xr2sonic"):
        log_msg("Migration context is not present")
        lc_powered_off = get_lc_powered_off()
        if lc_powered_off:
            return "RMA"
        else:
            return "FULLY_MIGRATED"
    else:
        log_msg(
            "Executing 'show platform inventory' for 60 seconds to check if all modules are migrated to sonic"
        )
        start_time = time.time()
        timeout = 60
        while True:
            stdout, stderr = shell_cmd("show platform inventory")
            command_output = str(stdout)
            fail_state = 0
            if "not initialized" in command_output:
                fail_state = 1
            if fail_state == 1:
                elapsed_time = time.time() - start_time
                if elapsed_time >= timeout:
                    return "MIGRATION"
                time.sleep(10)
            else:
                return "FULLY_MIGRATED"


def log_msg(message="", severity="INFO", return_code="037", temp_log_context=""):
    """
    Logs a message with the specified severity level and log context. The message splits into lines, and each line is logged with the appropriate severity level.

    Args:
        message (str, optional): The message to be logged. Defaults to an empty string.
        severity (str, optional): The severity level of the message. It can be 'ERROR', 'DEBUG', or 'INFO'. Defaults to 'INFO'.

    Returns:
        None.

    """
    if severity == "ERROR":
        if temp_log_context != "":
            return_code = LOG_CONTEXT_CODES.get(temp_log_context) + return_code
        else:
            return_code = LOG_CONTEXT_CODES.get(log_context) + return_code
        for line in str(message).splitlines():
            logging.error(
                "{log_context}: {line} (Error code: EC{return_code})".format(
                    log_context=log_context, line=line, return_code=return_code
                )
            )
    elif severity == "DEBUG":
        for line in str(message).splitlines():
            logging.debug(
                "{log_context}: {line}".format(log_context=log_context, line=line)
            )
    else:
        for line in str(message).splitlines():
            logging.info(
                "{log_context}: {line}".format(log_context=log_context, line=line)
            )


def sonic_migration_precheck():
    """
    Performs precheck for SONiC migration. It verifies the device is running the specified intermediate version of IOS XR and checks the presence and MD5 checksum of required files for SONiC migration. It also checks the health of all line cards using the module_healthcheck_xr function.

    Prechecks:
    1. Validate Device Version:
        - Use xr_cli_cmd to check if the device version matches the specified XR_INTERMEDIATE_VERSION. If it matches, log the message "Device is on {XR_INTERMEDIATE_VERSION}". If it does not match, an exception will be raised automatically.

    2. Check File Presence and MD5 Checksums:
        - Create a list of files [sonic_filename, ONIE_FILENAME, 'sonic-migutil.py'].
        - Use the file_check function to verify the presence of these files.
        - Verify the MD5 checksum for ONIE_FILENAME using shell_cmd. If the checksums match the expected values (ONIE_MD5), log the corresponding success messages. If they don't match, an exception will be raised automatically.

    3. Check Line Card Health:
        - Use the module_healthcheck_xr function to check the health of all line cards.

    Returns:
        None.

    """
    global log_context
    log_context = "SONIC_MIGRATION_PRECHECK_RP"

    log_msg("Start SONiC migration prechecks")

    log_msg(
        "Validate device is running {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        )
    )
    xr_cli_cmd(
        "show version",
        pass_pattern=r"Version[ :]+{XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
        pass_message="Device is on {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        ),
    )

    file_list = [sonic_filename, ONIE_FILENAME, "sonic-migutil.py"]
    file_check(file_list)

    if not args.default_config:
        log_msg("Validate minigraph files are present in {wd_xr}".format(wd_xr=wd_xr))
        minigraph_files = minigraph_files_list()
        log_msg(
            "Minigraph files present in {wd_xr}: {minigraph_files}".format(
                wd_xr=wd_xr, minigraph_files=minigraph_files
            )
        )

    log_msg("Verifying MD5 checksum for {}".format(ONIE_FILENAME))
    shell_cmd(
        cmd="md5sum {}".format(ONIE_FILENAME),
        pass_pattern=ONIE_MD5,
        pass_message="MD5 checksum matches expected value",
        fail_message="MD5 checksum does not match",
        error_code="005",
    )

    log_msg("Checking health of all line cards")
    module_healthcheck_xr()

    log_msg("Copying script backup to /mnt/mtd0")
    shell_cmd("cp {wd_xr}sonic_migration_xr.py /mnt/mtd0/".format(wd_xr=wd_xr))

    log_msg("SONiC migration prechecks complete")


def sonic_migration():
    """
    Executes SONiC migration.

    Steps:
    1. Extracts information about RP and LC from the "show platform" output using the function 'parse_show_platform()'. Based on this information, it determines the active RP location, the LC location where iPXE service will be enabled, and the LC locations that will be temporarily disabled for migration.
    2. The required files (sonic-migutil.py, ONIE_FILENAME, and sonic_filename) are copied to the LC location specified for iPXE service using the SCP command.
    3. The iPXE service is then initiated on the specified LC location using an SSH command.
    4. Config changes are applied to prepare the line cards for SONiC migration, and all LCs except the iPXE LC are disabled using the "hw-module reset auto disable" and "hw-module shutdown" XR CLI commands, respectively.
    5. The function checks to confirm that all LCs are disabled except for the iPXE LC. If any LC is not properly disabled, an exception is raised.
    6. The RP is then configured to use iPXE on the next boot using the "sonic-migutil.py --rpconfigipxe" command, and the RP is reloaded to perform the SONiC migration.
    7. After the migration is completed, the function exits the script.

    Returns:
        None.

    """
    global log_context
    log_context = "SONIC_MIGRATION_RP"

    log_msg("Execute SONiC migration for RP")

    log_msg("Creating .xr2sonic in the obfl directory ")
    shell_cmd("touch /mnt/mtd0/.xr2sonic")

    xr_cli.set_vrf("xrnns")

    if not args.default_config:
        log_msg("Copying minigraph files to RP and LCs")
        minigraph_files = minigraph_files_list()

        # Generate shell commands for scp
        for minigraph_file_name in minigraph_files:
            if "sup00" in minigraph_file_name:
                shell_cmd("rm -f /mnt/mtd0/minigraph*")
                shell_cmd("rm -f /mnt/mtd0/*log_[0-9]*.txt")
                shell_cmd(
                    "cp /harddisk:/{minigraph_file_name} /mnt/mtd0/".format(
                        minigraph_file_name=minigraph_file_name
                    )
                )
            else:
                # Extract lc_slot from the file name
                lc_slot_pattern = r"lc(\d{2})"
                match = re.search(lc_slot_pattern, minigraph_file_name)
                if match:
                    lc_slot = int(match.group(1))  # Extract the slot number
                    shell_cmd("ssh -o StrictHostKeyChecking=no root@172.0.{lc_slot}.1 'rm -f /mnt/mtd0/minigraph*'".format(lc_slot=lc_slot))
                    shell_cmd("ssh -o StrictHostKeyChecking=no root@172.0.{lc_slot}.1 'rm -f /mnt/mtd0/*log_[0-9]*.txt'".format(lc_slot=lc_slot))
                    shell_cmd(
                        "scp -o StrictHostKeyChecking=no {minigraph_file_name} root@172.0.{lc_slot}.1:/mnt/mtd0/".format(
                            minigraph_file_name=minigraph_file_name, lc_slot=lc_slot
                        )
                    )

    log_msg("Extract RP and LC info from 'show platform'")
    platform_modules = parse_show_platform()
    lc_locations_to_disable = []
    lc_location_pxe = ""
    for module in platform_modules:
        if "RP(Active)" in module["type"]:
            rp_location = module["node"]
        elif "LC" in module["type"] and lc_location_pxe == "":
            lc_location_pxe = module["node"]
        elif "LC" in module["type"]:
            lc_locations_to_disable += [module["node"]]
    slot_pattern = r"^\S+/(\S+)/\S+$"
    lc_slot_pxe_match = re.match(slot_pattern, lc_location_pxe)
    lc_slot_pxe = lc_slot_pxe_match.group(1)
    log_msg(
        "Active RP detected at location {rp_location}".format(rp_location=rp_location)
    )
    log_msg(
        "iPXE service will be enabled on LC in location {lc_location_pxe}".format(
            lc_location_pxe=lc_location_pxe
        )
    )
    log_msg(
        "The following linecards will be temporarily disabled for migration: {lc_locations_to_disable}".format(
            lc_locations_to_disable=" ".join(lc_locations_to_disable)
        )
    )

    log_msg(
        "Copying required files to LC {lc_location_pxe}...".format(
            lc_location_pxe=lc_location_pxe
        )
    )

    shell_cmd(
        "scp -o StrictHostKeyChecking=no sonic-migutil.py root@172.0.{lc_slot_pxe}.1:/tmp/".format(
            lc_slot_pxe=lc_slot_pxe
        )
    )
    shell_cmd(
        "scp -o StrictHostKeyChecking=no {ONIE_FILENAME} root@172.0.{lc_slot_pxe}.1:/www/pages/onie-recovery-x86_64-cisco_8000-r0.efi64.pxe".format(
            lc_slot_pxe=lc_slot_pxe, ONIE_FILENAME=ONIE_FILENAME
        )
    )
    shell_cmd(
        "scp -o StrictHostKeyChecking=no {sonic_filename} root@172.0.{lc_slot_pxe}.1:/www/pages/onie-installer.bin".format(
            lc_slot_pxe=lc_slot_pxe, sonic_filename=sonic_filename
        )
    )

    log_msg(
        "Initiate iPXE service on LC {lc_location_pxe}".format(
            lc_location_pxe=lc_location_pxe
        )
    )

    shell_cmd(
        "ssh -o StrictHostKeyChecking=no root@172.0.{lc_slot_pxe}.1 'ip netns exec default python3 /tmp/sonic-migutil.py --start'".format(
            lc_slot_pxe=lc_slot_pxe
        )
    )
    shell_cmd(
        cmd="ssh -o StrictHostKeyChecking=no root@172.0.{lc_slot_pxe}.1 'ip netns exec default python3 /tmp/sonic-migutil.py --verify'".format(
            lc_slot_pxe=lc_slot_pxe
        ),
        fail_pattern="ERROR",
    )

    log_msg(
        "Apply config changes to prepare line card {lc_location_pxe} for SONiC migration".format(
            lc_location_pxe=lc_location_pxe
        )
    )
    xr_cli_cfg(
        "hw-module reset auto disable location {lc_location_pxe}".format(
            lc_location_pxe=lc_location_pxe
        )
    )

    if len(lc_locations_to_disable) > 0:
        log_msg(
            "Disable all LCs except iPXE LC {lc_location_pxe}".format(
                lc_location_pxe=lc_location_pxe
            )
        )
        lc_disable_config = ""
        for location in lc_locations_to_disable:
            lc_disable_config += "\nhw-module shutdown location {location}".format(
                location=location
            )
        xr_cli_cfg(lc_disable_config)

    # Check to confirm that all LCs are disabled except iPXE LC
    platform_modules_changes = parse_show_platform()
    for module in platform_modules_changes:
        if module["node"] == lc_location_pxe:
            if module["config_state"] != "NSHUT,NMON":
                exit_script(
                    return_code="018",
                    exit_reason="PXE LC at location {location} was disabled unexpectedly; config state is {config_state}".format(
                        location=module["node"], config_state=module["config_state"]
                    ),
                )
        elif "LC" in module["type"]:
            if module["config_state"] != "SHUT":
                exit_script(
                    return_code="019",
                    exit_reason="LC at location {location} was not properly disabled; config state is {config_state}".format(
                        location=module["node"], config_state=module["config_state"]
                    ),
                )
    log_msg("LCs successfully disabled")

    log_msg("Configure RP to use iPXE on next boot")
    shell_cmd(cmd="python3 sonic-migutil.py --rpconfigipxe", fail_pattern="ERROR")

    log_msg("Reloading RP to perform SONiC migration")
    xr_cli_cmd("reload location {rp_location} noprompt".format(rp_location=rp_location))

    exit_script()


def sonic_migration_precheck_lc():
    """
    Performs pre-checks for SONiC migration on line cards.

    Prechecks: the `platform_server_healthcheck_sonic` function to verify the health of the platform server service. The health check runs with a 30 second interval and a timeout of 600 seconds.

    Returns:
        None
    """
    global log_context
    log_context = "SONIC_MIGRATION_PRECHECK_LC"

    platform_server_healthcheck_sonic(30, 600)

def sonic_check_lc_on_xr():
    """
    Determines whether an RMA/Partial Migration is required during SONiC migration and exits the script with an appropriate return code.

    The function sets a logging context, evaluates the system state using `determine_rma_or_migration()`, and logs the result before exiting. 
    Depending on the returned state, it maps the result to a specific exit code:

        - "RMA/Partial Migration " - RMA/Partial Migration is required, exit code 0
        - "FULLY_MIGRATED"  - RMA is not required, exit code 1
        - Any other state   - Error scenario, exit code 2
    """
    global log_context
    log_context = "SONIC_MIGRATION_CHECK_LC_ON_XR"
    log_msg("Check if RMA or Partial Migration is required or not")
    state = determine_rma_or_migration()
    if state == "RMA":
        log_msg("RMA or partial migration is required")
        log_msg("Return code: 0")
        exit_script()
    elif state == "FULLY_MIGRATED":
        log_msg("RMA is not required")
        log_msg("Return code: 1")
        exit_script()
    else:
        log_msg("Error Scenario")
        log_msg("Return code: 2")
        exit_script()

def lc_recovery_on_xr():
    """
    Executes the recovery workflow for line cards when running on XR, specifically handling RMA or partial migration scenarios.

    - Determine migration state via `determine_rma_or_migration()`
    - If RMA:
        - Verify the presence of required files in the working directory
        - Retrieve the list of powered-off line cards.
        - If `--default-config` is not used then for each powered-off line card, check for a corresponding minigraph XML file
        - If `--sonic-filename` is provided, rename the SONiC image to the standard filename `sonic-cisco-8000.bin.openssl.ipxcontainer`.
        - Build and execute the RMA command: `lc_migration -s {}`
        - Remove the migration context(`/mnt/obfl/.xr2sonic`) if present.
    """
    global log_context
    log_context = "SONIC_MIGRATION_LC_RECOVERY_ON_XR"
    log_msg("Check if RMA or Partial Migration is required or not")
    state = determine_rma_or_migration()
    if state == "RMA":
        log_msg("RMA/Partial Migration case. Executing RMA/LC Migration Workflow")

        file_list = [
            OV_FILENAME,
            AV_FILENAME,
            sonic_filename,
            ONIE_FILENAME,
            "lc_migration.efi",
        ]
        for file in file_list:
            log_msg(
                "Checking if {file} is present in {wd_sonic} directory".format(
                    file=file, wd_sonic=wd_sonic
                )
            )
            shell_cmd(
                cmd="ls -l {wd_sonic}{file}".format(wd_sonic=wd_sonic, file=file),
                fail_message="{file} is missing from {wd_sonic} directory".format(
                    file=file, wd_sonic=wd_sonic
                ),
                error_code="047",
            )

        lc_powered_off = get_lc_powered_off()
        if not args.default_config:
            minigraph_files = []
            missing_files = []
            for slot in lc_powered_off:
                slot_number = str(slot).zfill(2)
                suffix = "lc{}".format(slot_number)
                pattern = r"^minigraph-.*-{}.xml".format(suffix)
                file_found = 0
                for file_name in os.listdir(wd_sonic):
                    if re.match(pattern, file_name):
                        minigraph_files.append(file_name)
                        file_found = 1
                        break
                if file_found == 0:
                    missing_files.append(suffix)
            if len(missing_files) > 0:
                exit_script(
                    return_code="045",
                    exit_reason="Minigraph file missing for: {missing_files}".format(
                        missing_files=missing_files
                    ),
                )
            else:
                log_msg("Minigraph file is present")
        if args.sonic_filename:
            shell_cmd(cmd="sudo mv {wd_sonic}{sonic_filename} {wd_sonic}sonic-cisco-8000.bin.openssl.ipxcontainer".format(wd_sonic=wd_sonic, sonic_filename=sonic_filename))
        rma_command = "lc_migration -s {}".format(",".join(map(str, lc_powered_off)))

        log_msg("Executing RMA command: {rma_command}".format(rma_command=rma_command))
        shell_cmd(rma_command, force_console_output=True)
        if os.path.exists("/mnt/obfl/.xr2sonic"):
            shell_cmd("rm /mnt/obfl/.xr2sonic")
        exit_script()
    elif state == "FULLY_MIGRATED":
        exit_script(
            return_code="0",
            exit_reason="All modules are migrated to SONiC. No further action required. Script will now exit.",
        )
    else:
        exit_script(return_code="052", exit_reason="Migration context is present. Not in RMA or partial migration LC scenario")

def sonic_migration_lc():
    """
    Executes SONiC migration for line cards.

    - Determine migration state by calling `determine_rma_or_migration()`
    - If RMA:
        - Exit the script indicating the device is in RMA state or requires partial LC migration.
    - If SONiC migration is required:
        - Executes the `migration.sh start` command to initiate migration for all line cards.
    - If all modules are already migrated to SONiC, the function exits with a success message.

    Returns:
        None
    """
    global log_context
    log_context = "SONIC_MIGRATION_LC"

    log_msg("Checking for LC Migration")
    state = determine_rma_or_migration()
    if state == "RMA":
        exit_script(return_code="051", exit_reason="Device is in RMA state or needs partial LC migration")
    elif state == "MIGRATION":
        action = cisco.pacific.triggers.trigger()
        lc_present = []
        action.load_lc_present(lc_present)
        for lc in lc_present:
            shell_cmd("echo 0x0 > /sys/bus/platform/devices/xil-lc.{lc}/cfg7".format(lc=lc))

        log_msg("Execute SONiC migration for all LCs")
        shell_cmd("rm /mnt/obfl/.xr2sonic")
        shell_cmd("migration.sh start", error_code="049", force_console_output=True)
    elif state == "FULLY_MIGRATED":
        exit_script(
            return_code="0",
            exit_reason="All modules are migrated to SONiC. No further action required. Script will now exit.",
        )

def sonic_migration_postcheck():
    """
    Performs postcheck after SONiC migration.

    Postchecks:
    1. Validates that all modules are operational by calling the function 'module_healthcheck_sonic()' with a time interval of 30 seconds and a maximum wait time of 600 seconds.

    Returns:
        None.

    """
    global log_context
    log_context = "SONIC_MIGRATION_POSTCHECK"

    log_msg("Validate that all modules are operational")
    module_healthcheck_sonic(30, 600)

    log_msg("SONiC migration postchecks complete")


def rollback_precheck_sonic():
    """
    Performs pre-check before initiating a rollback from SONIC_VERSION to XR_VERSION. It checks module health, validates the FPD version, checks the presence and MD5 checksum of the IOS XR image in the specified directory, and stages the image for the rollback process.

    Returns:
        None.

    """
    global log_context, xr_version, xr_filename, xr_md5
    log_context = "ROLLBACK_PRECHECK_SONIC"
    log_msg("Rollback precheck SONiC started")

    match = re.search(r"\/([^\/]+)$", sys.argv[0])
    if match:
        MIGRATION_SCRIPT = match.group(1)
    else:
        exit_script(return_code="022", exit_reason="Regex match not found.")

    log_msg("Validate that all modules are operational")
    module_healthcheck_sonic()

    all_filenames = []
    for version_key, version_data in RELEASE_MAPPINGS.items():
        for file_key, file_name in version_data.items():
            if file_key.startswith("XR_FILENAME"):
                all_filenames.append(file_name)
    xr_version = sonic_rollback_file_check(all_filenames)
    xr_filename = RELEASE_MAPPINGS[xr_version]["XR_FILENAME"]
    xr_md5 = RELEASE_MAPPINGS[xr_version]["XR_MD5"]

    log_msg(
        "Checking if {MIGRATION_SCRIPT} is present in {wd_sonic} directory".format(
            MIGRATION_SCRIPT=MIGRATION_SCRIPT, wd_sonic=wd_sonic
        )
    )
    shell_cmd(
        cmd="ls -l {wd_sonic}{MIGRATION_SCRIPT}".format(
            wd_sonic=wd_sonic, MIGRATION_SCRIPT=MIGRATION_SCRIPT
        ),
        fail_message="Migration script is missing from {wd_sonic} directory".format(
            wd_sonic=wd_sonic
        ),
        error_code="024",
    )

    log_msg(
        "Verifying MD5 checksum for {wd_sonic}{xr_filename}".format(
            wd_sonic=wd_sonic, xr_filename=xr_filename
        )
    )
    stdout, stderr = shell_cmd(
        cmd="md5sum {wd_sonic}{xr_filename}".format(
            wd_sonic=wd_sonic, xr_filename=xr_filename
        )
    )
    command_output = str(stdout)
    if xr_md5 in command_output:
        log_msg("MD5 checksum matches expected value")
    else:
        exit_script(return_code="005", exit_reason="MD5 checksum does not match")

    log_msg(
        "Copy IOS XR image to /opt/cisco/var/tftp/onie-recovery-x86_64-cisco_8000-r0.efi64.pxe"
    )
    shell_cmd(
        "cp {wd_sonic}{xr_filename} /opt/cisco/var/tftp/onie-recovery-x86_64-cisco_8000-r0.efi64.pxe".format(
            wd_sonic=wd_sonic, xr_filename=xr_filename
        )
    )
    shell_cmd(
        cmd="ls -l /opt/cisco/var/tftp/onie-recovery-x86_64-cisco_8000-r0.efi64.pxe",
        fail_message="Error staging IOS XR image for rollback. onie-recovery-x86_64-cisco_8000-r0.efi64.pxe not found in /opt/cisco/var/tftp.",
        error_code="025",
    )

    log_msg("Copy Migration script to /mnt/obfl")
    shell_cmd(
        "cp {wd_sonic}{MIGRATION_SCRIPT} /mnt/obfl/{MIGRATION_SCRIPT}".format(
            wd_sonic=wd_sonic, MIGRATION_SCRIPT=MIGRATION_SCRIPT
        )
    )
    shell_cmd(
        cmd="ls -l /mnt/obfl/{MIGRATION_SCRIPT}".format(
            MIGRATION_SCRIPT=MIGRATION_SCRIPT
        ),
        fail_message="Error staging migration script for rollback. {MIGRATION_SCRIPT} not found in /mnt/obfl.".format(
            MIGRATION_SCRIPT=MIGRATION_SCRIPT
        ),
        error_code="026",
    )


def rollback_sonic():
    """
    Initiates a rollback from SONIC_VERSION to XR_VERSION.

    Returns:
        None.

    """
    global log_context
    log_context = "ROLLBACK_SONIC"
    log_msg("SONiC to IOS XR rollback in progress...")
    log_msg("Execute xrmigration.sh - device will reload")
    shell_cmd("xrmigration.sh", error_code="050", force_console_output=True)
    exit_script()


def rollback_precheck_xr():
    """
    Performs pre-check before initiating a rollback from XR_INTERMEDIATE_VERSION to XR_VERSION. It validates the device version, checks the configuration state of line cards (LCs), and verifies the operational status of modules before initiating the rollback.
    The function also checks for intermediate stages of the rollback process to determine the appropriate action for the current state of the device. Depending on the state, it returns different strings to indicate the appropriate rollback procedure.

    Returns:
        str:
        - 'xr_rollback': If the device is on XR_INTERMEDIATE_VERSION, it indicates a direct rollback to XR_VERSION
                         after validating the modules' operational status.
        - 'xr_xr_rollback': If the device is on XR_VERSION and the 'check_xr.txt' file exists, it suggests that the
                            device rolled back from XR_INTERMEDIATE_VERSION to XR_VERSION.
        - 'sonic_xr_rollback': If the device is on XR_VERSION and both the 'check_xr.txt' and 'check_fpd.txt' files
                               do not exist, it suggests that the device rolled back from SONIC_VERSION to XR_VERSION.
        - 'finalize_rollback': If the device is on XR_VERSION and the 'check_fpd.txt' file exists, it indicates that
                               the FPD upgrade was completed.

    Returns:
        None.

    """

    global log_context, xr_version, xr_filename, xr_md5
    log_context = "ROLLBACK_PRECHECK"
    log_msg("Rollback pre_check started")

    # Validate device version
    log_msg("Validate version of device")
    command_result = xr_cli_cmd("show version")

    xr_cli_output = "\n".join(command_result)

    # Setting version variable as per XR Version on device
    if bool(
        re.search(
            r"Version[ :]+{XR_INTERMEDIATE_VERSION}".format(
                XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
            ),
            xr_cli_output,
            flags=re.MULTILINE,
        )
    ):
        version = XR_INTERMEDIATE_VERSION
        log_msg(
            "Device is on {XR_INTERMEDIATE_VERSION}".format(
                XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
            )
        )
        all_filenames = []
        for version_key, version_data in RELEASE_MAPPINGS.items():
            for file_key, file_name in version_data.items():
                if file_key.startswith("XR_FILENAME"):
                    all_filenames.append(file_name)
        xr_version = xr_rollback_file_check(all_filenames)
        xr_filename = RELEASE_MAPPINGS[xr_version]["XR_FILENAME"]
        xr_md5 = RELEASE_MAPPINGS[xr_version]["XR_MD5"]
        log_msg("Verifying MD5 checksum for {}".format(xr_filename))
        shell_cmd(
            cmd="md5sum {}".format(xr_filename),
            pass_pattern=xr_md5,
            pass_message="MD5 checksum matches expected value",
            fail_message="MD5 checksum does not match",
            error_code="005",
        )
    else:
        calculated_version = find_matching_version(
            xr_cli_output, RELEASE_MAPPINGS.keys()
        )
        if calculated_version:
            xr_version = calculated_version
            xr_filename = RELEASE_MAPPINGS[xr_version]["XR_FILENAME"]
            xr_md5 = RELEASE_MAPPINGS[xr_version]["XR_MD5"]
            version = xr_version
            log_msg("Device is on {xr_version}".format(xr_version=xr_version))
        else:
            exit_script(return_code="027", exit_reason="Fail. Not on Correct Version")

    # Validate if LCs Config state is in SHUT or NSHUT,NMON state
    log_msg("Validating if LCs are enabled or not")
    platform_modules = parse_show_platform()
    for module in platform_modules:
        if module["config_state"] == "SHUT" or module["config_state"] == "NSHUT,NMON":
            log_msg("LCs is either in SHUT or NSHUT, NMON state")
            recover_xr_linecards()
            break

    # Validate if device in on XR_INTERMEDIATE_VERSION.
    if version == XR_INTERMEDIATE_VERSION:
        log_msg("Validate that modules are operational before proceeding")
        module_healthcheck_xr(30, 600)
        return "xr_rollback"

    # Validate if device in on XR_VERSION and check_xr.txt file exists, suggesting that the device rolled back from XR_INTERMEDIATE_VERSION to XR_VERSION.
    elif version == xr_version and os.path.exists("check_xr.txt"):
        shell_cmd("rm {wd_xr}check_xr.txt".format(wd_xr=wd_xr))
        return "xr_xr_rollback"

    # Validate if device in on XR_VERSION and check_xr.txt, check_fpd.txt files do not exist, suggesting that the device rolled back from SONIC_VERSION to XR_VERSION.
    elif (
        version == xr_version
        and not os.path.exists("check_xr.txt")
        and not os.path.exists("check_fpd.txt")
    ):
        return "sonic_xr_rollback"

    # Validate if device in on XR_VERSION and check_fpd.txt file exists, suggesting that fpd upgrade was completed.
    elif version == xr_version and os.path.exists("check_fpd.txt"):
        return "finalize_rollback"


def rollback_xr(rollback_action):
    """
    Performs the appropriate rollback operation based on the specified rollback action. Depending on the value of 'rollback_action', the function proceeds with the corresponding rollback procedure.

    Args:
        rollback_action (str): The action to be performed for the current rollback state.
                                It can be one of the following values:
                               - 'xr_rollback': Rollback from XR_INTERMEDIATE_VERSION to XR_VERSION.
                               - 'xr_xr_rollback': Perform fpd upgrade after rollback from XR_INTERMEDIATE_VERSION.
                               - 'sonic_xr_rollback': Perform fpd upgrade after rollback from SONIC_VERSION.
                               - 'finalize_rollback': Restore Configuration after the FPD upgrade.

    Returns:
        None.

    """
    global log_context
    log_context = "XR_ROLLBACK"
    log_msg("Rollback Operation")

    if rollback_action == "xr_rollback":
        # Rollback from XR_INTERMEDIATE_VERSION to XR_VERSION
        xr_rollback()
    elif rollback_action == "xr_xr_rollback":
        # Perform fpd upgrade after rollback from XR_INTERMEDIATE_VERSION
        xr_xr_rollback()
    elif rollback_action == "sonic_xr_rollback":
        # Perform fpd upgrade after rollback from SONIC_VERSION
        sonic_xr_rollback()
    elif rollback_action == "finalize_rollback":
        # Restore Configuration
        finalize_rollback()


def xr_rollback():
    """
    Performs the rollback from XR_INTERMEDIATE_VERSION to XR_VERSION. The function performs the rollback using the 'install replace' command. Additionally, it removes the 'check_fpd.txt' file if it exists and creates a 'check_xr.txt' file to indicate that the rollback to 'XR_VERSION' has been completed successfully.

    Returns:
        None.

    """
    log_msg("Executing rollback to IOS XR {xr_version}".format(xr_version=xr_version))
    if os.path.exists("check_fpd.txt"):
        shell_cmd("rm {wd_xr}check_fpd.txt".format(wd_xr=wd_xr))

    shell_cmd("touch {wd_xr}check_xr.txt".format(wd_xr=wd_xr))
    exit_script(exit=False)
    xr_cli_cmd(
        "install replace {wd_xr}{xr_filename} commit noprompt synchronous".format(
            wd_xr=wd_xr, xr_filename=xr_filename
        )
    )

def xr_xr_rollback():
    """
    Performs the FPD upgrade after rolling back from XR_INTERMEDIATE_VERSION. The function creates a 'check_fpd.txt' file to indicate that the FPD upgrade has been completed successfully.
    The function retrieves platform module information using the 'parse_show_platform()' function and identifies the line cards requiring the FPD upgrade. It then proceeds with the FPD upgrade process using the 'fpd_upgrade()' function.

    Returns:
        None.

    """
    log_msg(
        "Executing fpd upgrade after rollback from {XR_INTERMEDIATE_VERSION}".format(
            XR_INTERMEDIATE_VERSION=XR_INTERMEDIATE_VERSION
        )
    )

    shell_cmd("touch {wd_xr}check_fpd.txt".format(wd_xr=wd_xr))

    platform_modules = parse_show_platform()
    linecards = []
    for module in platform_modules:
        linecard = re.findall(r"^[0-9]+\/[0-9]+\/[A-Z]+[0-9]+", module["node"])
        linecard_exist = bool(
            re.search(r"^[0-9]+\/[0-9]+\/[A-Z]+[0-9]+", module["node"])
        )
        if linecard_exist:
            linecards.append(linecard[0])

    fpd_upgrade(linecards)


def sonic_xr_rollback():
    """
    Performs the FPD upgrade after rolling back from SONIC_VERSION to XR_VERSION. The function creates a 'check_fpd.txt' file to indicate that the FPD upgrade has been completed successfully.
    The function retrieves platform module information using the 'parse_show_platform()' function and identifies the line cards requiring the FPD upgrade. It then initiates "reload bootmedia network location" command for each identified line card using the 'xr_cli_cmd()' function.
    It then proceeds with the FPD upgrade process using the 'fpd_upgrade()' function.

    Returns:
        None.

    """
    log_msg("Reloading line cards to initiate migration of line cards to IOS XR")

    shell_cmd("touch {wd_xr}check_fpd.txt".format(wd_xr=wd_xr))

    platform_modules = parse_show_platform()
    linecards = []
    for module in platform_modules:
        linecard = re.findall(r"^[0-9]+\/[0-9]+\/[A-Z]+[0-9]+", module["node"])
        linecard_exist = bool(
            re.search(r"^[0-9]+\/[0-9]+\/[A-Z]+[0-9]+", module["node"])
        )
        if linecard_exist:
            linecards.append(linecard[0])

    for lc in linecards:
        xr_cli_cmd("reload bootmedia network location {lc} noprompt".format(lc=lc))

    fpd_upgrade(linecards)


def fpd_upgrade(linecards):
    """
    Performs the FPD upgrade for the specified line cards. It verifies that all line cards are operational before initiating the FPD upgrade.
    During the FPD upgrade, the function executes the command "upgrade hw-module location all fpd all force" using the 'xr_cli_cmd()' function to force the upgrade on all FPDs.
    After the FPD upgrade, the function checks the FPD status using the 'parse_show_hw_module_fpd()' function followed by a reload.

    Args:
        linecards (list): A list of line card locations to be upgraded.

    Returns:
        None.

    """
    log_msg("Executing FPD upgrades for all modules")

    # Validating all LCs are operational
    module_recover_check = 0
    for i in range(0, 20):
        platform_modules = parse_show_platform()
        recovered_modules = []
        for module in platform_modules:
            if module["node"] in linecards and (
                module["state"] == "IOS XR RUN" or module["state"] == "OPERATIONAL"
            ):
                recovered_modules.append(module["node"])
            if module["node"] in linecards and (
                module["state"] != "IOS XR RUN" and module["state"] != "OPERATIONAL"
            ):
                log_msg(module)
                time.sleep(30)
        if len(recovered_modules) == len(linecards):
            log_msg(
                "Recovered module: {recovered_modules}".format(
                    recovered_modules=recovered_modules
                )
            )
            module_recover_check = 1
            break

    if module_recover_check == 1:
        log_msg("Service restored to all modules")
    else:
        exit_script(
            return_code="028", exit_reason="Unable to restore service to all modules"
        )

    # Executing "upgrade hw-module location all fpd all force"
    xr_cli_cmd("upgrade hw-module location all fpd all force")

    reload = 0
    for i in range(1, 30):
        fpd_status = 0
        fpd_modules = parse_show_hw_module_fpd()
        for module in fpd_modules:
            if (
                module["status"] != "NEED UPGD"
                and module["status"] != "CURRENT"
                and module["status"] != "RLOAD REQ"
                and module["status"] != "NOT READY"
                and module["status"] != "UPGD FAIL"
            ):
                fpd_status = 1
                log_msg(module)
                time.sleep(30)
                break
        if fpd_status == 0:
            log_msg("Reload Required")
            reload = 1
            break
    if reload == 1:
        # Reload device
        log_msg("Reloading Device")
        cmd = {"exec_cmd": "reload location all", "prompt_response": "\ny\ny"}
        command_result = xr_cli.xrcmd(cmd)
        log_msg(command_result)
        exit_script()
    else:
        log_msg(
            "FPD status check failed: Some FPDs are not in the expected state.",
            "ERROR",
            "029",
        )


def finalize_rollback():
    """
    Finalizes the rollback process by restoring the backup configuration
    The function first validates that all modules are operational using the 'module_healthcheck_xr()' function, with a maximum waiting time of 600 seconds and a 30-second interval for checking.
    After confirming the operational status of modules, the function removes the 'check_fpd.txt' file, indicating that the FPD upgrade process has been completed successfully.
    Next, it copies the backup configuration file ('backup.cfg') from the specified path '/mnt/mtd0/' to the working directory 'wd_xr'.
    It then checks the existence of the 'backup.cfg' file in the working directory and validates that the harddisk contains the backup configuration.
    If the 'backup.cfg' file is present in the harddisk directory, the function proceeds to load and apply the backup configuration using the 'xr_cli_replace()' function.

    Returns:
        None.

    """
    log_msg("Restore Configuration")

    # Validate nodes are operational or not
    log_msg("Validate that modules are operational")
    module_healthcheck_xr(30, 600)

    log_msg("Validate fpd status")
    fpd_modules = parse_show_hw_module_fpd()
    for module in fpd_modules:
        if module["status"] != "CURRENT":
            exit_script(
                return_code="030", exit_reason="FPD Upgrade was not successful."
            )
    log_msg("FPD Upgrade was successful.")

    shell_cmd("rm {wd_xr}check_fpd.txt".format(wd_xr=wd_xr))

    log_msg("Copying configuration backup to harddisk")
    shell_cmd("cp /mnt/mtd0/backup.cfg /harddisk:/")

    log_msg("Checking harddisk directory for configs")
    command_result = xr_cli_cmd("dir /harddisk:/backup.cfg")

    xr_cli_output = list(command_result)

    check = 0
    for i in range(0, len(xr_cli_output)):
        if "Path does not exist" in xr_cli_output[i]:
            check = 1
            break
    if check == 0:
        log_msg("Harddisk has the backup config file")
    else:
        exit_script(return_code="031", exit_reason="Missing config file from harddisk")

    file_path = "/harddisk:/backup.cfg"
    log_msg("Loading backup.cfg")
    command_result = xr_cli_replace(file_path)


def rollback_postcheck_xr():
    """
    Performs post-check after completing the rollback to IOS XR.
    It verifies the operational status of modules using the 'module_healthcheck_xr()' function, with a maximum waiting time of 600 seconds and a 30-second interval for checking.
    The function then confirms that the device is on the desired 'XR_VERSION' by executing the 'show version' IOS XR CLI command.

    Returns:
        None.

    """
    global log_context, xr_version
    log_context = "ROLLBACK_POSTCHECK"
    log_msg("Rollback post_check started")

    # Validate nodes are operational or not
    log_msg("Validate that modules are operational")
    module_healthcheck_xr(30, 600)

    xr_cli_cmd(
        "show version",
        pass_pattern=r"Version[ :]+{xr_version}".format(xr_version=xr_version),
        pass_message="Device is on {xr_version}".format(xr_version=xr_version),
        fail_message="Device is not on {xr_version}".format(xr_version=xr_version),
        return_code="032",
    )

    log_msg("Rollback to IOS XR successfully completed.")
    exit_script()


def recover_xr_linecards():
    """
    Recovers the IOS XR line cards that are either in SHUT or NSHUT, NMON state. It brings up the line cards by removing the shutdown configurations from the 'hw-module reset' and 'hw-module shutdown' commands in the running configuration.

    Returns:
        None.

    """
    # Bringing up LCs that are either in SHUT or NSHUT, NMON state
    log_msg("Bringing up LCs that are either in SHUT or NSHUT, NMON state")
    command_result = xr_cli_cmd("show running-config | i hw-module reset")

    shut_modules = []
    lc_enable_config = ""
    if len(command_result) > 0:
        for command in command_result:
            module = command.split(" ")[-1]
            shut_modules.append(module)
            lc_enable_config += "\nno {command}".format(command=command)

    command_result = xr_cli_cmd("show running-config | i hw-module shutdown")

    if len(command_result) > 0:
        for command in command_result:
            module = command.split(" ")[-1]
            shut_modules.append(module)
            lc_enable_config += "\nno {command}".format(command=command)

    if len(shut_modules) > 0:
        xr_cli_cfg(lc_enable_config)

        # State: RESET, POWERED ON, BOOTING, DATA PATH POWERED ON, IOS XR RUN
        module_recover_check = 0
        for i in range(1, 15):
            platform_modules = parse_show_platform()
            recovered_modules = []
            for module in platform_modules:
                if module["node"] in shut_modules and (
                    module["state"] == "IOS XR RUN" or module["state"] == "OPERATIONAL"
                ):
                    recovered_modules.append(module["node"])
                if module["node"] in shut_modules and (
                    module["state"] != "IOS XR RUN" and module["state"] != "OPERATIONAL"
                ):
                    log_msg(module)
                    time.sleep(30)

            if len(recovered_modules) == len(shut_modules):
                log_msg(
                    "Recovered module: {recovered_modules}".format(
                        recovered_modules=recovered_modules
                    )
                )
                module_recover_check = 1
                break
        if module_recover_check == 1:
            log_msg("Service restored to all modules")
        else:
            exit_script(
                return_code="028",
                exit_reason="Unable to restore service to all modules",
            )

    else:
        log_msg("All LCs are enabled")


def parse_show_platform():
    """
    This function executes the "show platform" command using xr_cli_cmd and parses the output to extract relevant information for each platform module. It uses a regular expression pattern to match and extract the data from each line of output.

    Returns:
        List of dictionaries, each containing information about a platform module.

    The dictionary has the following keys:
    - 'node': The node identifier for the module.
    - 'type': The type of the module.
    - 'state': The state of the module.
    - 'config_state': The configuration state of the module.

    """
    xr_cli_result = xr_cli_cmd("show platform")
    pattern = r"^([0-9]\S+)\s+(\S+)\s+([\S ]+?)\s+(\S+)$"
    platform_modules = []
    # Use the regular expression pattern to extract the relevant data from each line of output
    for line in xr_cli_result:
        match = re.match(pattern, line)
        module = {}
        if match:
            module["node"] = match.group(1)
            module["type"] = match.group(2)
            module["state"] = match.group(3)
            module["config_state"] = match.group(4)
            if module["node"] not in module_healthcheck_override:
                platform_modules += [module]

    return platform_modules


def parse_show_hw_module_fpd():
    """
    This function executes the "show hw-module fpd" command using xr_cli_cmd and parses the output to extract relevant information for each FPD module. It uses a regular expression pattern to match and extract the data from each line of output.

    Returns:
        List of dictionaries, each containing information about an FPD module.

    The dictionary has the following keys:
    - 'node': The node identifier for the module.
    - 'type': The type of the module.
    - 'hw_ver': The hardware version of the module.
    - 'fpd_device': The FPD device identifier.
    - 'atr': The ATR value.
    - 'status': The status of the FPD module.

    """
    xr_cli_result = xr_cli_cmd("show hw-module fpd")
    pattern = r"^([0-9]\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\s+||[B]\s[P]||[B|S]+)\s+(\S+\s\S+||\S+)\s+"
    fpd_modules = []

    # Use the regular expression pattern to extract the relevant data from each line of output
    for line in xr_cli_result:
        match = re.match(pattern, line)
        module = {}
        if match:
            module["node"] = match.group(1)
            module["type"] = match.group(2)
            module["hw_ver"] = match.group(3)
            module["fpd_device"] = match.group(4)
            module["atr"] = match.group(5)
            module["status"] = match.group(6)
            if module["node"] not in module_healthcheck_override:
                fpd_modules += [module]

    return fpd_modules


def xr_cli_cmd(
    cmd,
    pass_pattern=None,
    fail_pattern=None,
    pass_message=None,
    fail_message=None,
    return_code="035",
):
    """
    This function executes an XR CLI command using xr_cli.xrcmd and handles the result. It checks for success or failure of the command execution based on the output and provided patterns. If the command fails or does not meet the expected patterns, an Exception is raised, and the script is exited with a return code of 1.

    Args:
        cmd (str): The XR CLI command to be executed.
        pass_pattern (str, optional): A regular expression pattern to match against the command output, indicating successful execution. If provided, the absence of this pattern in the output will be considered a failure. Defaults to None.
        fail_pattern (str, optional): A regular expression pattern to match against the command output, indicating a failure condition. If provided, the presence of this pattern in the output will be considered a failure. Defaults to None.
        pass_message (str, optional): An optional message to log when the command is successful. Defaults to None.
        fail_message (str, optional): An optional message to log when the command fails. Defaults to None.

    Raises:
        Exception: If the XR CLI command execution fails, or the expected patterns are not found in the command output.

    Returns:
        list: The list of lines representing the output of the XR CLI command.

    """
    try:
        log_msg("Execute XR CLI command: {}".format(cmd), "DEBUG")
        xr_cli_result = xr_cli.xrcmd({"exec_cmd": cmd})
        if xr_cli_result["status"] != "success":
            raise Exception(
                "XR CLI command execution failure: {}".format(xr_cli_result["output"])
            )
        else:
            # Extract regex
            xr_cli_output = "\n".join(xr_cli_result["output"])
            if fail_pattern:
                fail_match = re.search(fail_pattern, xr_cli_output, flags=re.MULTILINE)
                if fail_match:
                    raise Exception(
                        "XR CLI command failure: CLI output matching pattern '{fail_pattern}' was found indicating error condition\nXR CLI command output:\n{xr_cli_output}".format(
                            fail_pattern=fail_pattern, xr_cli_output=xr_cli_output
                        )
                    )
            if pass_pattern:
                pass_match = re.search(pass_pattern, xr_cli_output, flags=re.MULTILINE)
                if not pass_match:
                    raise Exception(
                        "XR CLI command failure: expected CLI output matching pattern '{pass_pattern}' was not found\nXR CLI command output:\n{xr_cli_output}".format(
                            pass_pattern=pass_pattern, xr_cli_output=xr_cli_output
                        )
                    )
        if pass_message:
            log_msg(pass_message)
        return xr_cli_result["output"]
    except Exception as err:
        log_msg(err, "ERROR", return_code)
        if fail_message:
            log_msg(fail_message, "ERROR", return_code)
        exit_script(return_code=return_code)


def xr_cli_cfg(config, pass_message=None, fail_message=None):
    """
    This function applies the provided XR configuration using xr_cli.xrapply_string and handles the result. It checks for success or failure of the configuration change based on the output. If the configuration change fails, an Exception is raised, and the script is exited with a return code of 1.

    Args:
        config (str): The XR configuration string to be applied.
        pass_message (str, optional): An optional message to log when the configuration change is successful. Defaults to None.
        fail_message (str, optional): An optional message to log when the configuration change fails. Defaults to None.

    Raises:
        Exception: If the XR configuration change fails.

    Returns:
        list: The list of lines representing the output of the XR configuration change.

    """
    try:
        log_msg("Apply XR configuration: {}".format(config))
        xr_cli_result = xr_cli.xrapply_string(config)
        if xr_cli_result["status"] != "success":
            raise Exception(
                "XR config change failure:\n{}".format(
                    "\n".join(xr_cli_result["output"])
                )
            )
        if pass_message:
            log_msg(pass_message)
        return xr_cli_result["output"]
    except Exception as err:
        log_msg(err, "ERROR", "033")
        if fail_message:
            log_msg(fail_message, "ERROR", "033")
        exit_script(return_code="033")


def xr_cli_replace(filepath):
    """
    This function applies the XR commit-replace operation using the specified file and handles the result. It checks for success or failure of the operation based on the output. If the commit-replace operation fails, an Exception is raised, and the script is exited with a return code of 1.

    Args:
        filepath (str): The path to the file containing the configuration to be replaced.

    Raises:
        Exception: If the XR commit-replace operation fails.

    Returns:
        list: The list of lines representing the output of the XR commit-replace operation.

    """
    try:
        log_msg("Apply commit-replace")
        xr_cli_result = xr_cli.xrreplace(filename=filepath)
        if xr_cli_result["status"] != "success":
            raise Exception(
                "XR commit-replace failure: {}".format(xr_cli_result["output"])
            )
        return xr_cli_result["output"]
    except Exception as err:
        log_msg(err, "ERROR", "034")
        exit_script(return_code="034")


def shell_cmd(
    cmd,
    pass_pattern=None,
    fail_pattern=None,
    pass_message=None,
    fail_message=None,
    error_code="036",
    force_console_output=False,
    ignore_return_code=False,
):
    """
    This function executes a shell command and handles the output and return code. It checks for success or failure of the command based on specified patterns. If the command fails and has a non-zero return code, an Exception is raised, and the script is exited with a return code of 1.

    Args:
        cmd (str): The shell command to be executed.
        pass_pattern (str, optional): A regular expression pattern to match in the output for successful execution. Defaults to None.
        fail_pattern (str, optional): A regular expression pattern to match in the output for command failure. Defaults to None.
        pass_message (str, optional): A message to log when the pass_pattern is matched. Defaults to None.
        fail_message (str, optional): A message to log when the fail_pattern is matched. Defaults to None.
        error_code (str, optional): Error code used for logging and exiting the script in case of failure. Defaults to "036".
        force_console_output (bool, optional): If True, continuously print the output of the command to the console while it's being executed. Defaults to False.
        ignore_return_code (bool, optional): If True, ignore the return code and do not raise an Exception for non-zero return code. Defaults to False.

    Raises:
        Exception: If the shell command fails, if the pass_pattern is not found in the output, or if the fail_pattern is matched in the output.

    Returns:
        tuple: A tuple containing the stdout and stderr of the shell command.

    """
    global log_context
    try:
        log_msg("Execute shell command: {}".format(cmd), "DEBUG")
        sp = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        if force_console_output:
            # Loop to continuously read the output of the command until the process completes
            while True:
                # Read a line from the subprocess' stdout
                output = sp.stdout.readline()
                # If the output is empty (end of stream) and the subprocess has finished, exit the loop
                if not output and sp.poll() is not None:
                    break
                # If there is actual output (not an empty string)
                if output:
                    log_msg(output.strip().decode())
                    if "INFO  all LCs are published their inventory" in output.decode():
                        exit_script(exit=False)
                        log_context = "SONIC_MIGRATION_LC"
                    if "Reload RP card to internal ipxe" in output.decode():
                        exit_script(exit=False)
                        log_context = "ROLLBACK_SONIC"
        stdout, stderr = sp.communicate()
        return_code = sp.wait()
        if (
            "RuntimeError: Sonic database config file doesn't exist at /var/run/redis/sonic-db/database_config.json"
            in stderr.decode("utf-8")
        ):
            log_msg("Device will sleep for 300 second for SONiC database to update")
            time.sleep(300)
            sp = subprocess.Popen(
                cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            stdout, stderr = sp.communicate()
            return_code = sp.wait()
        if return_code != 0 and not ignore_return_code:
            raise Exception(
                "Shell command failure - non-zero return code for shell command: {}".format(
                    cmd
                )
            )
        else:
            # fail_pattern and pass_pattern will evaluate content across both stdout and stderr text to look for matches
            if fail_pattern:
                fail_match_stdout = re.search(
                    fail_pattern, stdout.decode("utf-8"), flags=re.MULTILINE
                )
                fail_match_stderr = re.search(
                    fail_pattern, stderr.decode("utf-8"), flags=re.MULTILINE
                )
                if fail_match_stdout:
                    raise Exception(
                        "Shell command failure: output matching pattern '{fail_pattern}' was found indicating error condition\nShell command output:\n{stdout}".format(
                            fail_pattern=fail_pattern, stdout=stdout
                        )
                    )
                elif fail_match_stderr:
                    raise Exception(
                        "Shell command failure: output matching pattern '{fail_pattern}' was found indicating error condition\nShell command output:\n{stderr}".format(
                            fail_pattern=fail_pattern, stderr=stderr
                        )
                    )
            if pass_pattern:
                pass_match_stdout = re.search(
                    pass_pattern, stdout.decode("utf-8"), flags=re.MULTILINE
                )
                pass_match_stderr = re.search(
                    pass_pattern, stderr.decode("utf-8"), flags=re.MULTILINE
                )
                if not pass_match_stdout and not pass_match_stderr:
                    raise Exception(
                        "Shell command failure: output matching pattern '{}' was not found".format(
                            pass_pattern
                        )
                    )
        if pass_message:
            log_msg(pass_message)
        return stdout, stderr
    except Exception as err:
        if len(stdout) > 0:
            log_msg(
                "Shell command failure description: {}".format(stdout),
                "ERROR",
                error_code,
            )
        log_msg(err, "ERROR", error_code)
        if fail_message:
            log_msg(fail_message, "ERROR", error_code)
        if stderr:
            log_msg("Shell command failure - stderr output received for shell command: {}".format(stderr), "ERROR", error_code)
        exit_script(return_code=error_code)


def sonic_rollback_file_check(file_list=[]):
    """
    Validates the presence of specified XR image files in the working directory and determines the version of the XR image.
    This function checks for the existence of the specified files and attempts to determine the XR image version.
    If multiple supported XR images are found, or if none are found, the script will exit with a specific return code.

    Args:
        file_list (list): A list of filenames to check for existence.

    Returns:
        str: The version key of the XR image if a supported image is found.

    """
    log_msg(
        "Validate that the following files are present in {wd_sonic}: {file_list}".format(
            wd_sonic=wd_sonic, file_list=" or ".join(file_list)
        )
    )
    version = None
    missing_files = []
    for file_name in file_list:
        cmd = "ls -l {wd_sonic}{file_name}".format(
            wd_sonic=wd_sonic, file_name=file_name
        )
        sp = subprocess.Popen(
            cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, stderr = sp.communicate()
        return_code = sp.wait()
        if return_code != 0:
            missing_files.append(file_name)
        else:
            if version is None:
                for version_key, version_data in RELEASE_MAPPINGS.items():
                    if file_name in version_data.values():
                        version = version_key
                        break
            else:
                exit_script(
                    return_code="042",
                    exit_reason="Multiple supported XR images were found in {wd_sonic}. Only a single XR image should be present to proceed with migration.".format(
                        wd_sonic=wd_sonic
                    ),
                )
    if version:
        return version
    else:
        exit_script(
            return_code="043",
            exit_reason="No supported XR image files were found in {wd_sonic}. Supported images: {missing_files}".format(
                wd_sonic=wd_sonic, missing_files=", ".join(missing_files)
            ),
        )


def get_serial_numbers():
    """
    This function retrieves the serial numbers of active modules that are in "IOS XR RUN" state by executing "show platform" and "show inventory location" commands.

    Raises:
        Exception: If there is any issue with executing XR CLI commands or parsing the output.

    Returns:
        list: A list containing the serial numbers of active modules.

    """
    module_locations = []
    serial_number_list = []

    platform_modules = parse_show_platform()
    for module in platform_modules:
        if module["state"] == "IOS XR RUN":
            module_locations.append(module["node"])

    for i in range(0, len(module_locations)):
        command_result = xr_cli_cmd(
            "show inventory location {}".format(module_locations[i])
        )
        xr_cli_output = list(command_result)
        for line in xr_cli_output:
            m = re.search(r"SN: (\S+)", line)
            if m:
                serial_number_list.append(m.group(1))
                break
    return serial_number_list


def find_matching_version(xr_cli_output, release_versions):
    """
    Finds a matching version string in the given CLI output.

    This function searches for any release version from the provided list
    in the given CLI output string using a regular expression pattern.

    Args:
        xr_cli_output (str): The CLI output to search for a matching version.
        release_versions (list): A list of release version strings to match.

    Returns:
        str or None: The first matching release version string if found,
                     otherwise None.
    """
    for release_version in release_versions:
        if re.search(
            r"Version[ :]+" + release_version, xr_cli_output, flags=re.MULTILINE
        ):
            return release_version
    return None


def xr_rollback_file_check(file_list=[]):
    """
    Validates the presence of specified XR image files in the working directory and determines the version of the XR image.
    This function checks for the existence of the specified files and attempts to determine the XR image version.
    If multiple supported XR images are found, or if none are found, the script will exit with a specific return code.

    Args:
        file_list (list): A list of filenames to check for existence.

    Returns:
        str: The version key of the XR image if a supported image is found.

    """
    log_msg(
        "Validate that the following files are present in {wd_xr}: {file_list}".format(
            wd_xr=wd_xr, file_list=" or ".join(file_list)
        )
    )
    version = None
    missing_files = []
    for file_name in file_list:
        if not os.path.exists(file_name):
            missing_files.append(file_name)
        else:
            if version is None:
                for version_key, version_data in RELEASE_MAPPINGS.items():
                    if file_name in version_data.values():
                        version = version_key
                        break
            else:
                exit_script(
                    return_code="040",
                    exit_reason="Multiple supported XR images were found in {wd_xr}. Only a single XR image should be present to proceed with migration.".format(
                        wd_xr=wd_xr
                    ),
                )
    if version:
        return version
    else:
        exit_script(
            return_code="041",
            exit_reason="No supported XR image files were found in {wd_xr}. Supported images: {missing_files}".format(
                wd_xr=wd_xr, missing_files=", ".join(missing_files)
            ),
        )


def minigraph_files_list():
    """
    Generate a list of minigraph file names based on the platform modules' states and slots.
    This function parses the output of `parse_show_platform()` to identify modules with the
    state `IOS XR RUN`. For each such module, it extracts the slot information and constructs
    a filename for the corresponding minigraph file. The filenames follow the format:
    "minigraph-<router_hostname>-<suffix>.xml", where the suffix depends on the slot type.

    If a minigraph file for a required module is missing, the script will exit with a specific
    return code and list the missing files.

    Returns:
        list: A list of strings, each representing a minigraph file name.
    """
    # Creating minigraph files list
    platform_modules = parse_show_platform()
    minigraph_files = []
    missing_files = []
    file_found = 0
    for module in platform_modules:
        if module["state"] == "IOS XR RUN":
            slot_pattern = r"^\S+/(\S+)/\S+$"
            match = re.match(slot_pattern, module["node"])
            slot = match.group(1).lower()
            # Determine prefix based on slot type
            if "rp" in slot:
                suffix = "sup00"
            else:
                slot_number = slot.zfill(2)
                suffix = "lc{}".format(slot_number)
            pattern = r"^minigraph-.*-{}.xml".format(suffix)
            file_found = 0
            for file_name in os.listdir(wd_xr):
                if re.match(pattern, file_name):
                    minigraph_files.append(file_name)
                    file_found = 1
                    break
            if file_found == 0:
                missing_files.append(suffix)
    if len(missing_files) > 0:
        exit_script(
            return_code="045",
            exit_reason="Minigraph file missing for: {missing_files}".format(
                missing_files=missing_files
            ),
        )
    else:
        return minigraph_files


def file_check(file_list=[]):
    """
    This function checks if the given list of files exists in the working directory (wd_xr). If any file is missing, 
    the script will exit with a specific return code and an error message.

    Args:
        file_list (list): A list of file names to be checked for existence. Defaults to an empty list.

    Returns:
        None.

    """
    log_msg(
        "Validate that the following files are present in {wd_xr}: {file_list}".format(
            wd_xr=wd_xr, file_list=" ".join(file_list)
        )
    )
    missing_files = []
    for file_name in file_list:
        if not os.path.exists(file_name):
            missing_files.append(file_name)
    if missing_files:
        exit_script(
            return_code="004",
            exit_reason="The following required files were not found in {wd_xr}: {missing_files}".format(
                wd_xr=wd_xr, missing_files=" ".join(missing_files)
            ),
        )
    log_msg("File check successful")

def extract_clock_output(command_result):
    """
    Extracts and parses the 'show clock' timestamp from a list of command output lines.

    Args:
        command_result (list of str): The output of the 'show clock' command, where one of the lines contains the timestamp.

    Returns:
        datetime: The parsed timestamp extracted from the command output.
    """
    for line in command_result:
        try:
            return datetime.strptime(line, "%H:%M:%S.%f UTC %a %b %d %Y")
        except ValueError:
            continue  # Ignore lines that do not match the expected format
    exit_script(return_code="048", exit_reason="Failed to extract clock output")

def get_md5_from_file(filename):
    """
    Reads the contents of a file and extracts the first word, which is expected to be an MD5 checksum.
    Args:
        filename (str): The path to the file from which the MD5 checksum needs to be extracted.
    Returns:
        str: The extracted MD5 checksum from the file. Returns an empty string if the file is empty or does not contain valid content.
    """
    md5sum = ""
    with open(filename, "r") as file:
        content = file.read().strip()
        if content:
            md5sum = content.split()[0]
    return md5sum


def exit_script(return_code="0", exit_reason=None, exit=True):
    """
    This function is used to gracefully exit the SONiC migration script. It sets the log context based on the return code and logs the exit reason if provided.

    Args:
        return_code (str, optional): The return code to be used when exiting the script. Defaults to 0.
        exit_reason (str, optional): An optional exit reason message. If provided, it will be logged. Defaults to None.
        exit (bool, optional): Indicates whether to exit the script. If `True`, the script will terminate. If `False`, the script will continue running. Defaults to True.

    Returns:
        None. The script exits if `exit` is True, otherwise it continues execution.

    """
    global log_context
 
    if return_code == "0":
        if exit_reason:
            log_msg(exit_reason)
        log_context = "EXIT_ON_SUCCESS"
        log_msg("SONiC migration script exiting due to successful completion")
        if exit:
            sys.exit(0)
    else:
        if exit_reason:
            log_msg(exit_reason, "ERROR", return_code)
        temp_log_context = log_context
        log_context = "EXIT_ON_FAILURE"
        log_msg(
            "SONiC migration script exiting due to error",
            "ERROR",
            return_code,
            temp_log_context,
        )
        sys.exit(1)


def main():
    """
    SONiC Migration Main Script

    This script is the entry point for the SONiC migration process for a Cisco 8000 Series router from IOS XR to SONiC. It parses the command-line arguments, orchestrates the migration steps, and performs prechecks, installation, migration, and postchecks based on the provided options.

    Command Line Arguments:
        --path: Specifies the path on the device where all required migration files are stored (defaults to 'wd_xr' for IOS XR and 'wd_sonic' for SONiC).
        --check: Execute the script in 'Check Mode' to perform prechecks without executing migration actions.
        --xr_upgrade: Upgrade to IOS XR 7.5.41 interim release Migration Image.
        --ov_install: Install Ownership Vouchers from the OV tarball.
        --av_install: Install Authenticated Variable from the AV file.
        --sonic_migration_rp: Migrate RP from IOS XR 7.5.41 to SONiC
        --sonic_migration_lc: Migrate all LCs from IOS XR 7.5.41 to SONiC after completion of RP SONiC migration
        --sonic_migration_postcheck: Verify the health of the device following migration to SONiC.
        --check_lc_on_xr: Check RMA/Partial Migration is required or not
        --sonic_filename: Specify the SONiC Filename to be used. If argument is not used, script will fall back to the sonic_filename global variable.
        --rollback: Rollback to IOS XR (initial version) and restore the original configuration.
        --module_healthcheck_override: Override the default module healthcheck behavior to allow the script to continue if any modules are in a failed state.
        --lc_recovery: Executes RMA/Partial LC Migration Workflow

    """
    global on_sonic, log_context, args, wd_xr, wd_sonic, module_healthcheck_override, sonic_filename

    # Parse the command line arguments

    parser = argparse.ArgumentParser(
        description="Migrate Cisco 8000 Series router from IOS XR to SONiC."
    )
    if not on_sonic:
        parser.add_argument(
            "--path",
            type=str,
            help="Path on device where all required migration files are stored (defaults to '{wd_xr}')".format(
                wd_xr=wd_xr
            ),
        )
    else:
        parser.add_argument(
            "--path",
            type=str,
            help="Path on device where all required migration files are stored (defaults to '{wd_sonic}')".format(
                wd_sonic=wd_sonic
            ),
        )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Execute in 'Check Mode' to perform prechecks without executing migration actions",
    )
    parser.add_argument(
        "--default_config",
        action="store_true",
        help="Proceeds with default config without considering minigraph.xml",
    )
    parser.add_argument(
        "--xr_upgrade",
        action="store_true",
        help="Upgrade to IOS XR 7.5.41 interim release Migration Image.",
    )
    parser.add_argument(
        "--zeroization",
        action="store_true",
        help="Completes Zeroization of the device from auth files",
    )
    parser.add_argument(
        "--ov_install",
        action="store_true",
        help="Install Ownership Vouchers from OV tarball",
    )
    parser.add_argument(
        "--av_install",
        action="store_true",
        help="Install Authenticated Variable from AV file",
    )
    parser.add_argument(
        "--sonic_migration_rp",
        action="store_true",
        help="Migrate RP from IOS XR 7.5.41 to SONiC",
    )
    parser.add_argument(
        "--sonic_migration_lc",
        action="store_true",
        help="Migrate all LCs from IOS XR 7.5.41 to SONiC after completion of RP SONiC migration",
    )
    parser.add_argument(
        "--sonic_migration_postcheck",
        action="store_true",
        help="Verify health of device follwoing migration to SONiC",
    )
    parser.add_argument(
        "--check_lc_on_xr",
        action="store_true",
        help="Check RMA/Partial Migration is required or not",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Rollback to IOS XR (initial version) and restore the original configuration.",
    )
    parser.add_argument(
        "--module_healthcheck_override",
        type=str,
        required=False,
        help="Override default module healthcheck behavior to allow script to continue if any modules are in a failed state",
    )
    parser.add_argument(
        "--sonic_filename",
        type=str,
        required=False,
        help="Specify the SONiC Filename to be used. If argument is not used, script will fall back to the sonic_filename global variable",
    )
    parser.add_argument(
        "--lc_recovery",
        action="store_true",
        help="Executes RMA/Partial LC Migration Workflow.",
    )

    args = parser.parse_args()

    try:

        # Set working directory
        if not on_sonic:
            # Set logging settings for XR
            configure_logger(log_file_path_xr)
            log_msg("Log file set to {}sonic_migration.log".format(log_file_path_xr))
            # Set working directory
            if args.path:
                wd_xr = args.path
            os.chdir(wd_xr)
            log_msg("Working directory has been set to {}".format(wd_xr))
            xr_cli_cmd("cd {}".format(wd_xr))
        else:
            # Set logging settings for SONiC
            configure_logger(log_file_path_sonic)
            log_msg("Log file set to {}sonic_migration.log".format(log_file_path_sonic))
            # Set working directory
            if args.path:
                wd_sonic = args.path
            os.chdir(wd_sonic)
            log_msg("Working directory has been set to {}".format(wd_sonic))
            shell_cmd("cd {}".format(wd_sonic))

        if args.module_healthcheck_override:
            # Check if the input is a list or a single string
            try:
                module_healthcheck_override = ast.literal_eval(
                    args.module_healthcheck_override
                )
            except (ValueError, SyntaxError):
                module_healthcheck_override = [args.module_healthcheck_override]

        if args.sonic_filename:
            sonic_filename = args.sonic_filename

        if args.rollback:
            if not on_sonic:
                rollback_action = rollback_precheck_xr()
                if not args.check:
                    rollback_xr(rollback_action)
                    rollback_postcheck_xr()
            else:
                rollback_precheck_sonic()
                if not args.check:
                    rollback_sonic()
        if args.xr_upgrade:
            execution_precheck()
            if not args.check:
                xr_upgrade()
        if args.zeroization:
            zeroize_precheck()
            if not args.check:
                zeroize_install()
        if args.ov_install:
            xr_upgrade_postcheck()
            ov_precheck()
            if not args.check:
                ov_install()
        if args.av_install:
            ov_postcheck()
            av_precheck()
            if not args.check:
                av_install()
                av_postcheck()
        if args.sonic_migration_rp and not args.av_install:
            av_postcheck()
        if args.sonic_migration_rp:
            sonic_migration_precheck()
            if not args.check:
                sonic_migration()
        if args.sonic_migration_lc:
            sonic_migration_precheck_lc()
            if not args.check:
                sonic_migration_lc()
        if args.sonic_migration_postcheck:
            sonic_migration_postcheck()
        if args.check_lc_on_xr:
            sonic_check_lc_on_xr()
        if args.lc_recovery:
            lc_recovery_on_xr()
        exit_script(return_code="0")

    except Exception as err:
        log_msg(err, "ERROR", "999")
        exit_script(
            return_code="999", exit_reason="Exiting script due to unhandled exception"
        )


if __name__ == "__main__":
    """
    This function serves as the main entry point for the SONiC migration script.
    """
    main()
