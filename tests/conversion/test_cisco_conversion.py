"""
Cisco Conversion Testing - Full Cycle SONiC ↔ XR Migration

This test suite supports the complete conversion cycle for Cisco 8800 T2 devices:
1. SONiC → XR Rollback (via console)
2. XR → SONiC Migration (via console)

Test Flow:
- Console Line Testing (this module)
- SONiC to XR Rollback
- XR to SONiC Migration
- Full Cycle Validation

Console Implementation:
- Uses duthost_console fixture for serial console access
- Supports both SONiC and XR command execution
- File transfers via SCP (SSH), commands via console
- Pattern-based response validation

Password Rotation After Test:
After test completion, you may need to rotate passwords on all DUTs (Supervisor, LCs, RPs).
This can be done in several ways:

1. RECOMMENDED: Use the standalone test (easiest):
   pytest tests/conversion/test_rotate_passwords.py \\
       --inventory=<inventory_file> \\
       --host-pattern=<testbed_name> \\
       --username=admin \\
       --new-password=<new_password>

2. Manual Python shell:
   from tests.conversion.test_cisco_conversion import rotate_passwords_on_all_duts
   results = rotate_passwords_on_all_duts(duthosts, 'admin', 'new_password')

3. Direct SSH commands (for each DUT):
   ssh admin@<dut-hostname> "echo admin:new_password | sudo chpasswd"

Helper functions available:
- rotate_password_on_dut(duthost, username, password) - Single DUT
- rotate_passwords_on_all_duts(duthosts, username, password) - All DUTs
"""

# Standard library imports
import logging
import re
import time
import traceback
import crypt
from pathlib import Path

# Third-party imports
import pytest

# Local imports
from tests.common.helpers.assertions import pytest_assert
from tests.common.devices.sonic import SonicHost

logger = logging.getLogger(__name__)

# Suppress verbose console library logging (netmiko, paramiko, etc.)
# This prevents log flooding from base_connection._read_channel_expect and other debug messages
logging.getLogger('netmiko').setLevel(logging.WARNING)
logging.getLogger('paramiko').setLevel(logging.WARNING)
logging.getLogger('ansible_host').setLevel(logging.INFO)
logging.getLogger('ncclient').setLevel(logging.WARNING)  # Suppress ncclient debug logs

# Suppress all base.* loggers (base._run, base_connection, etc.)
for logger_name in logging.root.manager.loggerDict:
    if logger_name.startswith('base'):
        logging.getLogger(logger_name).setLevel(logging.WARNING)

pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

# ============================================================================
# CONSTANTS - Console and Command Configuration
# ============================================================================

# Console timeouts (in seconds)
CONSOLE_LOGIN_TIMEOUT = 60
CONSOLE_COMMAND_TIMEOUT = 120
CONSOLE_LONG_COMMAND_TIMEOUT = 2000  # 33 minutes for device reload/boot operations

# SONiC Console Prompts and Patterns
SONIC_LOGIN_PROMPT = r"login:"
SONIC_PASSWORD_PROMPT = r"Password:"
SONIC_SHELL_PROMPT = r"admin@.*:.*\$"
SONIC_ROOT_PROMPT = r"root@.*:.*#"

# SONiC factory default credentials present immediately after RP migration to SONiC.
# Phase 4 rotates this to a secure password sourced from creds (sonicadmin_password
# or ansible_altpasswords). Do not use this constant for anything else.
SONIC_FACTORY_DEFAULT_USER = "admin"
SONIC_FACTORY_DEFAULT_PASSWORD = "password"  # nosec B105 - documented vendor default

# XR Console Prompts and Patterns
XR_LOGIN_PROMPT = r"Username:"
XR_PASSWORD_PROMPT = r"Password:"
XR_SHELL_PROMPT = r"RP/\d+/RP\d+/CPU\d+:.*#"
XR_CONFIG_PROMPT = r"RP/\d+/RP\d+/CPU\d+:.*\(config\)#"
XR_PROMPT = r"RP/0/RP0/CPU0:.*#"  # Specific prompt pattern for supervisor

# Common command patterns
COMMAND_SUCCESS_PATTERNS = [
    r"admin@.*:.*\$",  # SONiC shell prompt
    r"root@.*:.*#",    # SONiC root prompt
    r"RP/\d+/RP\d+/CPU\d+:.*#"  # XR exec prompt
]

# ============================================================================
# CONSTANTS - File Paths and Repository Configuration
# ============================================================================

# Supervisor storage directory
SUPERVISOR_STORAGE_DIR = "/host"

# Temporary directory for file transfers
TEMP_STORAGE_DIR = "/tmp"

# SONiC minigraph location
SONIC_MINIGRAPH_PATH = "/etc/sonic/minigraph.xml"

# Migration script
MIGRATION_SCRIPT_NAME = "sonic_migration_xr.py"
MIGRATION_SCRIPT_LOCAL_SUBPATH = "files/common"

# ACS Repository configuration
ACS_REPO_BASE_URL = "http://10.20.17.0/networkfirmware/"

# Phase 2: XR rollback files (full download paths)
XR_ROLLBACK_ISO_PATH = "Cisco/8000-goldenk9-x64-7.3.5-fabric_2.iso"
XR_ROLLBACK_MD5_PATH = "Cisco/8000-goldenk9-x64-7.3.5-fabric_2.iso.md5"

# Download timeouts (in seconds)
DOWNLOAD_ISO_TIMEOUT = 600
DOWNLOAD_MD5_TIMEOUT = 60

# ============================================================================
# CONSTANTS - XR Credentials
# ============================================================================

# XR root-system credentials
# Cisco golden-image factory bootstrap credential (publicly documented)
XR_ROOT_USERNAME = "cisco"
XR_ROOT_PASSWORD = "cisco123"

# ============================================================================
# CONSTANTS - Phase 3: XR to SONiC Migration
# ============================================================================

# Phase 3: SONiC Image (full download path)
# Validated reachable: curl -O http://10.20.17.0/networkfirmware/SONiC-20240532/sonic-cisco-8000-20240532.69.bin
SONIC_IMAGE_DOWNLOAD_PATH = "SONiC-20240532/sonic-cisco-8000-20240532.69.bin"
SONIC_IMAGE_NAME = "sonic-cisco-8000.bin"  # Required name on XR device

# Phase 3: Intermediate XR and firmware files (full download paths)
INTERMEDIATE_XR_IMAGE_PATH = "ACS/8000-golden-x86_64-7.5.41.04I-SONIC_CON_K9SEC_UPD.iso"
ONIE_IMAGE_PATH = "ACS/onie-recovery-x86_64-cisco_8000-r0.efi64.pxe"

# Phase 3: Voucher files (full download paths)
VOUCHER_TARBALL_PATH = "ACS/sonic-certs/msft-8800/vouchers.tar.gz"
VOUCHER_TARBALL_MD5_PATH = "ACS/sonic-certs/msft-8800/vouchers.tar.gz.md5"

# Phase 3: Authenticated variable files (full download paths)
AUTHENTICATED_VARIABLE_PATH = "ACS/sonic-certs/avs/dbcustomer_onie_sonic_rel.auth"
AUTHENTICATED_VARIABLE_MD5_PATH = "ACS/sonic-certs/avs/dbcustomer_onie_sonic_rel.md5"

# Local filenames on XR device (extracted from paths)
INTERMEDIATE_XR_IMAGE_NAME = Path(INTERMEDIATE_XR_IMAGE_PATH).name
ONIE_IMAGE_NAME = Path(ONIE_IMAGE_PATH).name
VOUCHER_TARBALL_NAME = Path(VOUCHER_TARBALL_PATH).name
VOUCHER_TARBALL_MD5_NAME = Path(VOUCHER_TARBALL_MD5_PATH).name
AUTHENTICATED_VARIABLE_NAME = Path(AUTHENTICATED_VARIABLE_PATH).name
AUTHENTICATED_VARIABLE_MD5_NAME = Path(AUTHENTICATED_VARIABLE_MD5_PATH).name

# Migration utility script (needed for XR to SONiC)
MIGRATION_UTIL_SCRIPT_NAME = "sonic-migutil.py"

# XR → SONiC Migration Commands
INTERMEDIATE_XR_UPGRADE_CHECK_CMD = "run python /harddisk:/{0} --xr_upgrade --check --sonic_filename {1}"
INTERMEDIATE_XR_INSTALL_CMD = "run python /harddisk:/{0} --xr_upgrade --sonic_filename {1}"
OV_INSTALL_CMD = "run python /harddisk:/{0} --ov_install --sonic_filename {1}"
AV_INSTALL_RP_MIGRATION_CMD = "run python /harddisk:/{0} --av_install --sonic_migration_rp --sonic_filename {1}"
LC_MIGRATION_CMD = "sudo python /mnt/obfl/{0} --sonic_migration_lc --sonic_filename {1}"
POST_MIGRATION_CHECK_CMD = "sudo python /mnt/obfl/{0} --sonic_migration_postcheck --sonic_filename {1}"

# Success/Failure Messages
INSTALL_SUCCESS_MESSAGE = "EXIT_ON_SUCCESS"
INSTALL_FAILURE_MESSAGE = "EXIT_ON_FAILURE"
ERROR_MESSAGE = "[ERROR]"
UPGRADE_NOT_REQUIRED_MESSAGE = "Upgrade not required"
OV_INSTALL_NOT_REQUIRED_MESSAGE = "OV installation not required"
LC_MIGRATION_SUCCESS_MESSAGE = "INFO  all LCs are published their inventory"
POST_MIGRATION_SUCCESS_REGEX = "All modules are migrated to sonic"
POST_MIGRATION_FAILURE_REGEX = "All modules are not migrated to sonic"
XR_UPGRADE_RELOAD_MESSAGE = "XR_UPGRADE: Device will now reload for IOS XR upgrade to"

# Phase 3 Timeouts (in seconds)
INTERMEDIATE_XR_UPGRADE_WAIT = 20 * 60  # 20 minutes
OV_INSTALL_WAIT = 5 * 60  # 5 minutes
AV_INSTALL_RP_MIGRATION_WAIT = 35 * 60  # 35 minutes
LC_MIGRATION_WAIT = 20 * 60  # 20 minutes

# ============================================================================
# HELPER FUNCTIONS - Console Operations
# ============================================================================


def read_con(duthost_console, prompt, max_idle_time=1200):
    """
    Read console output until a specific pattern is found.

    This function continuously reads from the console line by line until
    the specified prompt pattern is matched. Includes timeout protection
    and keepalive mechanism to prevent console server disconnection.

    Args:
        duthost_console: Console connection object
        prompt: Regex pattern to search for (indicates completion)
        max_idle_time: Maximum seconds without output before timing out (default: 1200 = 20 minutes)

    Returns:
        str: All output read from console until prompt was found

    Raises:
        TimeoutError: If no output received for max_idle_time seconds
    """

    output = ''
    line_count = 0
    last_output_time = time.time()
    keepalive_interval = 60  # Send keepalive every 60 seconds
    last_keepalive_time = time.time()

    logger.info(f"Reading console until pattern: {prompt}")
    logger.info(f"Timeout: {max_idle_time}s of inactivity, Keepalive: every {keepalive_interval}s")

    while True:
        try:
            # Check if we need to send keepalive (to prevent idle timeout)
            current_time = time.time()
            if (current_time - last_keepalive_time) >= keepalive_interval:
                elapsed_total = int(current_time - last_output_time)
                logger.debug(f"Sending keepalive (no output for {elapsed_total}s)...")
                try:
                    # Send a harmless RETURN to keep connection alive
                    duthost_console.write_channel(duthost_console.RETURN)
                    last_keepalive_time = current_time
                except Exception as ka_error:
                    logger.error(f"Keepalive failed: {ka_error}")
                    raise

            # Check for timeout
            elapsed_since_output = current_time - last_output_time
            if elapsed_since_output > max_idle_time:
                logger.error(f"TIMEOUT: No console output for {int(elapsed_since_output)}s (max: {max_idle_time}s)")
                logger.error(f"Last output received at line {line_count}")
                logger.error(f"Pattern being searched: {prompt}")
                logger.error(f"Last 500 chars of output: {output[-500:]}")
                raise TimeoutError(
                    f"No console output for {int(elapsed_since_output)}s while waiting for pattern: {prompt}"
                )

            # Try to read a line
            try:
                line = duthost_console.read_until_pattern(duthost_console.RETURN)
            except Exception as e:
                # Check if it's a socket closed error (fatal)
                if "Socket is closed" in str(e):
                    logger.error(f"✗ Console socket closed after {line_count} lines")
                    logger.error(f"Last 500 chars of output: {output[-500:]}")
                    raise
                # For other exceptions (timeout, no data), just treat as no line available
                line = None

            if line:
                # We got output, reset timeout
                last_output_time = time.time()

                # Only log every 100th line to avoid massive logs
                line_count += 1
                if line_count % 100 == 0:
                    logger.info(
                        f"Read {line_count} lines from console "
                        f"(elapsed: {int(time.time() - last_output_time)}s since last output)...")
                logger.debug(line)

                # Check for error messages in the line
                if ERROR_MESSAGE in line:
                    logger.error(f"✗ ERROR detected in console output at line {line_count}")
                    logger.error(f"Error line: {line}")
                    logger.error(f"Full output so far (last 1000 chars): {output[-1000:]}")
                    raise RuntimeError(f"Console operation failed - {ERROR_MESSAGE} detected in output: {line}")

                # Accumulate output
                output = output + line

                # Performance optimization: Search only in the last ~2000 chars
                # This handles patterns split across reads without searching entire output
                # Most patterns are <500 chars, so 2000 gives plenty of buffer
                search_window = output[-2000:] if len(output) > 2000 else output
                found = re.search(prompt, search_window)
                if found:
                    logger.info(f"✓ Found matching pattern after {line_count} lines: {prompt}")
                    break
            else:
                # No output, but not necessarily an error - might just be waiting
                time.sleep(1)

        except TimeoutError:
            # Re-raise timeout errors
            raise

    return output


def download_file_from_repo(localhost, url, dest_path, proxy="", connect_timeout=30, max_time=600):
    """
    Download a file from repository using curl with automatic proxy fallback.

    Strategy: Try without proxy first, then retry with proxy if it fails.
    This handles both local network access and external downloads gracefully.

    Args:
        localhost: Localhost ansible connection
        url: Full URL to download from
        dest_path: Local destination path for the downloaded file
        proxy: Proxy server URL (optional, e.g., 'http://proxy.example.com:8080')
        connect_timeout: Connection timeout in seconds (default: 30)
        max_time: Maximum time for the entire operation in seconds (default: 600)

    Returns:
        dict: {'success': bool, 'rc': int, 'stdout': str, 'stderr': str, 'method': str}
    """
    logger.info(f"Downloading {Path(url).name} from {url}")

    # Use /usr/bin/curl explicitly to bypass any shell aliases or functions
    # Also add --create-dirs to ensure destination directory exists
    curl_binary = "/usr/bin/curl"

    # Attempt 1: Try without proxy (works for local network access)
    logger.info("Attempting download without proxy...")
    curl_cmd = (
        f"{curl_binary} -k -L -f --create-dirs --connect-timeout {connect_timeout} "
        f"--max-time {max_time} -o {dest_path} {url}"
    )
    logger.debug(f"Curl command: {curl_cmd}")

    # Use 'executable=/bin/bash' to ensure we're in bash and 'unalias curl' won't affect us
    result = localhost.shell(curl_cmd, module_ignore_errors=True, executable="/bin/bash")

    if result['rc'] == 0:
        # Verify file was actually downloaded
        verify_result = localhost.shell(f"test -f {dest_path} && ls -lh {dest_path}", module_ignore_errors=True)
        if verify_result['rc'] == 0:
            logger.info(f"✓ Successfully downloaded to {dest_path} (direct connection)")
            logger.debug(f"File info: {verify_result.get('stdout', '')}")
            return {
                'success': True,
                'rc': result['rc'],
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'method': 'direct'
            }
        else:
            logger.warning(f"Curl returned success but file not found at {dest_path}")

    # Attempt 2: If direct download failed and proxy is available, retry with proxy
    if proxy:
        logger.warning(f"Direct download failed, retrying with proxy: {proxy}")
        curl_cmd_with_proxy = (
            f"{curl_binary} -k -L -f --create-dirs --connect-timeout {connect_timeout} "
            f"--max-time {max_time} -x {proxy} -o {dest_path} {url}"
        )
        logger.debug(f"Curl command with proxy: {curl_cmd_with_proxy}")

        result = localhost.shell(curl_cmd_with_proxy, module_ignore_errors=True, executable="/bin/bash")

        if result['rc'] == 0:
            # Verify file was actually downloaded
            verify_result = localhost.shell(f"test -f {dest_path} && ls -lh {dest_path}", module_ignore_errors=True)
            if verify_result['rc'] == 0:
                logger.info(f"✓ Successfully downloaded to {dest_path} (via proxy)")
                logger.debug(f"File info: {verify_result.get('stdout', '')}")
                return {
                    'success': True,
                    'rc': result['rc'],
                    'stdout': result.get('stdout', ''),
                    'stderr': result.get('stderr', ''),
                    'method': 'proxy'
                }
            else:
                logger.warning(f"Curl with proxy returned success but file not found at {dest_path}")

    # Attempt 3: Try with wget as fallback (some environments have wget but not working curl)
    logger.warning("Both curl attempts failed, trying wget as fallback...")
    wget_cmd = f"/usr/bin/wget --no-check-certificate --timeout={connect_timeout} -T {max_time} -O {dest_path} {url}"
    if proxy:
        # Set proxy environment variable for wget
        wget_cmd = f"https_proxy={proxy} http_proxy={proxy} {wget_cmd}"

    logger.debug(f"Wget command: {wget_cmd}")
    result = localhost.shell(wget_cmd, module_ignore_errors=True, executable="/bin/bash")

    if result['rc'] == 0:
        verify_result = localhost.shell(f"test -f {dest_path} && ls -lh {dest_path}", module_ignore_errors=True)
        if verify_result['rc'] == 0:
            logger.info(f"✓ Successfully downloaded to {dest_path} (via wget)")
            logger.debug(f"File info: {verify_result.get('stdout', '')}")
            return {
                'success': True,
                'rc': result['rc'],
                'stdout': result.get('stdout', ''),
                'stderr': result.get('stderr', ''),
                'method': 'wget'
            }

    # All attempts failed
    error_msg = result.get('stderr', result.get('stdout', 'Unknown error'))
    logger.error(f"✗ Download failed (tried curl direct, curl proxy, and wget): {error_msg}")
    logger.error(f"Last return code: {result['rc']}")
    return {
        'success': False,
        'rc': result['rc'],
        'stdout': result.get('stdout', ''),
        'stderr': result.get('stderr', ''),
        'method': 'failed'
    }


# ============================================================================
# TEST FUNCTIONS
# ============================================================================

def check_migration_eligibility(duthost, tbinfo):
    """
    Check if the device is eligible for XR migration.

    Args:
        duthost: DUT host object
        tbinfo: Testbed information

    Returns:
        str: HWSKU of the device

    Raises:
        pytest.skip: If device is not Cisco hardware
    """
    logger.info("Step 1: Checking migration eligibility...")

    hwsku = duthost.get_extended_minigraph_facts(tbinfo)['minigraph_hwsku'].lower()
    logger.info(f"Device HWSKU: {hwsku}")

    if 'cisco' not in hwsku:
        logger.warning(f"Test must be run on Cisco hardware. Current HWSKU: {hwsku}")
        pytest.skip(f"Test skipped - not Cisco hardware (HWSKU: {hwsku})")

    logger.info(f"✓ Device is Cisco hardware: {hwsku}")
    return hwsku


def parse_chassis_modules(output):
    """
    Parse chassis module information from 'show chassis modules midplane-status' output.

    Args:
        output: Command output string

    Returns:
        list: List of dicts with module info {'slot', 'ip', 'type', 'name', 'original_slot_id'}
    """
    module_info = []

    for line in output.split('\n'):
        # Skip header lines and empty lines
        if not line.strip() or 'Slot' in line or '---' in line:
            continue

        # Split by whitespace and check if last column is "True" (midplane connected)
        parts = line.split()
        if len(parts) >= 2 and parts[-1].strip() == "True":
            slot_identifier = parts[0]  # Could be "LINE-CARD0", "RP0", etc.
            ip_address = parts[-2]  # IP is second to last column
            name = parts[1] if len(parts) > 1 else ""

            # Determine module type and extract slot number
            if "RP" in slot_identifier:
                module_type = "sup"
                slot_num = ''.join(filter(str.isdigit, slot_identifier))
            elif "LINE-CARD" in slot_identifier or "LC" in slot_identifier:
                module_type = "lc"
                slot_num = ''.join(filter(str.isdigit, slot_identifier))
            elif slot_identifier.isdigit():
                module_type = "lc"
                slot_num = slot_identifier
            else:
                logger.warning(f"Unknown slot identifier format: {slot_identifier}")
                continue

            module_info.append({
                'slot': slot_num,
                'ip': ip_address,
                'type': module_type,
                'name': name,
                'original_slot_id': slot_identifier
            })
            logger.info(
                f"Found module: Slot {slot_identifier} -> {module_type}{slot_num}, "
                f"IP: {ip_address}, Name: {name}")

    return module_info


def collect_minigraph_via_scp(duthost_console, console_user, console_password, ip_address,
                              module_type, slot_num, dest_path):
    """
    Collect minigraph file from a module via SCP through console.

    Args:
        duthost_console: Console connection object
        console_user: Username for SCP
        console_password: Password for SCP
        ip_address: Module IP address
        module_type: Module type ('lc' or 'sup')
        slot_num: Slot number
        dest_path: Final destination path on supervisor

    Returns:
        bool: True if successful, False otherwise
    """
    temp_filename = Path(dest_path).name
    temp_path = f"{TEMP_STORAGE_DIR}/{temp_filename}"

    scp_cmd = (f"scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
               f"{console_user}@{ip_address}:{SONIC_MINIGRAPH_PATH} {temp_path}")

    logger.info(f"Executing SCP via console: {scp_cmd}")

    try:
        # Send the SCP command
        duthost_console.write_channel(scp_cmd + duthost_console.RETURN)

        # Wait for password prompt
        password_prompt = duthost_console.read_until_pattern(r"password:")
        if "password:" not in password_prompt.lower():
            logger.warning(f"Did not receive password prompt for slot {slot_num}")
            return False

        # Send password
        duthost_console.write_channel(console_password + duthost_console.RETURN)

        # Wait for command to complete (shell prompt returns)
        completion_output = duthost_console.read_until_pattern(r"[$#]")

        # Check if SCP was successful
        if "permission denied" in completion_output.lower():
            logger.warning(f"Permission denied when copying minigraph from slot {slot_num}")
            return False

        return True

    except (ConnectionError, TimeoutError, IOError) as e:
        logger.warning(f"Connection/IO error during SCP from slot {slot_num}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during SCP from slot {slot_num}: {e}")
        logger.debug(traceback.format_exc())
        return False


def collect_module_minigraphs(duthost, duthost_console, console_user, console_password,
                              module_info, base_hostname, supervisor_minigraph_dir):
    """
    Collect minigraph files from all remote modules (line cards).

    Args:
        duthost: DUT host object
        duthost_console: Console connection object
        console_user: Console username
        console_password: Console password
        module_info: List of module information dicts
        base_hostname: Base hostname for file naming
        supervisor_minigraph_dir: Directory on supervisor to store files

    Returns:
        list: List of collected minigraph file paths
    """
    logger.info("Collecting minigraph files from remote modules...")
    minigraph_files = []

    for module in module_info:
        # Skip supervisor - will collect it separately
        if module['type'] == 'sup':
            continue

        slot_num = module['slot']
        ip_address = module['ip']
        module_type = module['type']

        minigraph_filename = f"minigraph-{base_hostname}-{module_type}{slot_num.zfill(2)}.xml"
        minigraph_sup_path = f"{supervisor_minigraph_dir}/{minigraph_filename}"
        temp_minigraph_path = f"{TEMP_STORAGE_DIR}/{minigraph_filename}"

        logger.info(f"Collecting minigraph from {module_type.upper()} slot {slot_num} (IP: {ip_address})...")

        # SCP the file to /tmp
        if not collect_minigraph_via_scp(duthost_console, console_user, console_password,
                                         ip_address, module_type, slot_num, minigraph_sup_path):
            continue

        # Move the file from /tmp to /host with sudo
        logger.info(f"Moving minigraph from {TEMP_STORAGE_DIR} to {SUPERVISOR_STORAGE_DIR}...")
        move_result = duthost.shell(f"sudo mv {temp_minigraph_path} {minigraph_sup_path}",
                                    module_ignore_errors=True)

        if move_result['rc'] != 0:
            logger.warning(
                f"Failed to move minigraph to {SUPERVISOR_STORAGE_DIR}: "
                f"{move_result.get('stderr', move_result.get('stdout', ''))}")
            continue

        logger.info(f"✓ Minigraph copied from {module_type.upper()} slot {slot_num} to {minigraph_sup_path}")
        minigraph_files.append(minigraph_sup_path)

    logger.info(f"✓ Collected {len(minigraph_files)} minigraph files from remote modules")
    for minigraph_file in minigraph_files:
        logger.info(f"  - {minigraph_file}")

    return minigraph_files


def collect_supervisor_minigraph(duthost, module_info, base_hostname, supervisor_minigraph_dir):
    """
    Collect minigraph file from the supervisor (local copy).

    Args:
        duthost: DUT host object
        module_info: List of module information dicts
        base_hostname: Base hostname for file naming
        supervisor_minigraph_dir: Directory on supervisor to store files

    Returns:
        str or None: Path to collected minigraph file, or None if failed
    """
    logger.info("Collecting supervisor's minigraph locally...")

    # Find the supervisor slot number from module_info
    sup_slot_num = None
    for module in module_info:
        if module['type'] == 'sup':
            sup_slot_num = module['slot']
            break

    # If supervisor wasn't found in module list, default to slot 0
    if sup_slot_num is None:
        logger.warning("Supervisor not found in module list, defaulting to slot 0")
        sup_slot_num = "0"

    sup_minigraph_filename = f"minigraph-{base_hostname}-sup{sup_slot_num.zfill(2)}.xml"
    sup_minigraph_final_path = f"{supervisor_minigraph_dir}/{sup_minigraph_filename}"

    # Copy supervisor's minigraph from /etc/sonic/minigraph.xml to /host/
    logger.info(f"Copying supervisor minigraph to {sup_minigraph_final_path}...")
    copy_result = duthost.shell(f"sudo cp {SONIC_MINIGRAPH_PATH} {sup_minigraph_final_path}",
                                module_ignore_errors=True)

    if copy_result['rc'] == 0:
        logger.info(f"✓ Supervisor minigraph copied to {sup_minigraph_final_path}")
        return sup_minigraph_final_path
    else:
        logger.warning(
            f"Failed to copy supervisor minigraph: "
            f"{copy_result.get('stderr', copy_result.get('stdout', ''))}")
        return None


def collect_all_minigraphs(duthost, duthost_console, console_user, console_password,
                           dut_hostname, module_info):
    """
    Collect minigraph files from all modules (supervisor and line cards).

    Args:
        duthost: DUT host object
        duthost_console: Console connection object
        console_user: Console username
        console_password: Console password
        dut_hostname: Full DUT hostname
        module_info: List of module information dicts

    Returns:
        list: List of collected minigraph file paths
    """
    logger.info("Step 2: Collecting minigraph files from all modules...")

    supervisor_minigraph_dir = SUPERVISOR_STORAGE_DIR

    # Extract base hostname (e.g., "svcstr-8800" from "svcstr-8800-sup-1")
    hostname_parts = dut_hostname.rsplit('-', 2)
    base_hostname = hostname_parts[0] if len(hostname_parts) >= 3 else dut_hostname
    logger.info(f"Using base hostname for minigraph naming: {base_hostname}")

    # Collect from remote modules (line cards)
    minigraph_files = collect_module_minigraphs(
        duthost, duthost_console, console_user, console_password,
        module_info, base_hostname, supervisor_minigraph_dir
    )

    # Collect from supervisor
    sup_minigraph = collect_supervisor_minigraph(
        duthost, module_info, base_hostname, supervisor_minigraph_dir
    )

    if sup_minigraph:
        minigraph_files.append(sup_minigraph)

    logger.info(f"✓ Total minigraph files collected: {len(minigraph_files)}")
    for minigraph_file in minigraph_files:
        logger.info(f"  - {minigraph_file}")

    return minigraph_files


def download_xr_rollback_files(duthost, https_proxy):
    """
    Download XR rollback ISO and MD5 files from ACS repository.

    Args:
        duthost: DUT host object
        https_proxy: HTTPS proxy URL (optional)

    Returns:
        tuple: (xr_iso_path, xr_md5_path) - Paths to downloaded files

    Raises:
        pytest.fail: If download fails
    """
    logger.info("Step 3: Downloading XR rollback files from ACS repo...")

    # ACS Repository configuration
    xr_iso_url = f"{ACS_REPO_BASE_URL}{XR_ROLLBACK_ISO_PATH}"
    xr_md5_url = f"{ACS_REPO_BASE_URL}{XR_ROLLBACK_MD5_PATH}"

    xr_iso_sup_path = f"{SUPERVISOR_STORAGE_DIR}/{Path(XR_ROLLBACK_ISO_PATH).name}"
    xr_md5_sup_path = f"{SUPERVISOR_STORAGE_DIR}/{Path(XR_ROLLBACK_MD5_PATH).name}"

    # Download XR ISO
    result = download_file_from_repo(
        localhost=duthost,
        url=xr_iso_url,
        dest_path=xr_iso_sup_path,
        proxy=https_proxy,
        max_time=DOWNLOAD_ISO_TIMEOUT
    )

    if not result['success']:
        pytest.fail(f"Failed to download XR ISO: {result.get('stderr', result.get('stdout', 'Unknown error'))}")

    # Download XR MD5
    result = download_file_from_repo(
        localhost=duthost,
        url=xr_md5_url,
        dest_path=xr_md5_sup_path,
        proxy=https_proxy,
        max_time=DOWNLOAD_MD5_TIMEOUT
    )

    if not result['success']:
        pytest.fail(f"Failed to download XR MD5: {result.get('stderr', result.get('stdout', 'Unknown error'))}")

    logger.info(f"✓ XR rollback files downloaded successfully to supervisor {SUPERVISOR_STORAGE_DIR}/")

    return xr_iso_sup_path, xr_md5_sup_path


def copy_migration_script(duthost):
    """
    Copy migration script from local test files to supervisor.

    Args:
        duthost: DUT host object

    Returns:
        str: Path to migration script on supervisor

    Raises:
        pytest.fail: If script not found locally or copy fails
    """
    logger.info("Step 4: Copying migration script to supervisor...")

    # Check migration script exists locally
    base_path = Path(__file__).resolve().parent
    migration_script_path = base_path / MIGRATION_SCRIPT_LOCAL_SUBPATH / MIGRATION_SCRIPT_NAME

    if not migration_script_path.exists():
        pytest.fail(f"Migration script not found locally: {migration_script_path}")

    logger.info(f"Found local migration script: {migration_script_path}")

    # Copy to supervisor
    migration_script_sup_path = f"{SUPERVISOR_STORAGE_DIR}/{MIGRATION_SCRIPT_NAME}"
    logger.info(f"Copying migration script to supervisor: {migration_script_sup_path}")

    duthost.copy(src=str(migration_script_path), dest=migration_script_sup_path)

    # Verify the copy
    result = duthost.shell(f"test -f {migration_script_sup_path}", module_ignore_errors=True)
    if result['rc'] != 0:
        pytest.fail(f"Failed to copy migration script to supervisor: {migration_script_sup_path}")

    # Make the script executable
    logger.info("Making migration script executable...")
    result = duthost.shell(f"sudo chmod +x {migration_script_sup_path}", module_ignore_errors=True)
    if result['rc'] != 0:
        logger.warning(f"Failed to set executable permission on migration script: {result.get('stderr', '')}")
        logger.warning("Continuing anyway - Python can still execute it with 'python script.py'")
    else:
        logger.info("✓ Migration script is now executable")

    logger.info(f"✓ Migration script copied to supervisor: {migration_script_sup_path}")

    return migration_script_sup_path


def verify_all_files(duthost, minigraph_files, xr_iso_path, xr_md5_path, migration_script_path):
    """
    Verify all required files are present on supervisor.

    Args:
        duthost: DUT host object
        minigraph_files: List of minigraph file paths
        xr_iso_path: Path to XR ISO file
        xr_md5_path: Path to XR MD5 file
        migration_script_path: Path to migration script

    Raises:
        pytest.fail: If any required file is missing
    """
    logger.info("Step 5: Verifying all required files on supervisor...")

    # Check XR files and migration script
    required_files = {
        'XR ISO': xr_iso_path,
        'XR MD5': xr_md5_path,
        'Migration Script': migration_script_path
    }

    for file_desc, file_path in required_files.items():
        result = duthost.shell(f"test -f {file_path}", module_ignore_errors=True)
        if result['rc'] != 0:
            pytest.fail(f"Required file missing: {file_desc} at {file_path}")
        logger.info(f"✓ {file_desc}: {file_path}")

    # Check minigraph files
    logger.info(f"✓ Minigraph files collected: {len(minigraph_files)}")
    for minigraph_file in minigraph_files:
        result = duthost.shell(f"test -f {minigraph_file}", module_ignore_errors=True)
        if result['rc'] != 0:
            logger.warning(f"Minigraph file missing on supervisor: {minigraph_file}")
        else:
            logger.info(f"  ✓ {minigraph_file}")

    logger.info(f"✓ All required files verified successfully on supervisor {SUPERVISOR_STORAGE_DIR}!")


def backup_minigraphs_to_localhost(duthost, localhost, minigraph_files):
    """
    Backup minigraph files from DUT to localhost /tmp/.

    This is necessary because after XR rollback, the SONiC filesystem (/host/)
    will no longer be accessible, but we need these minigraph files for
    Phase 3 (XR → SONiC migration).

    Args:
        duthost: DUT host object
        localhost: Localhost ansible connection
        minigraph_files: List of minigraph file paths on DUT (in /host/)

    Returns:
        list: List of localhost paths where minigraphs were backed up
    """
    logger.info("Backing up minigraph files to localhost /tmp/...")
    localhost_minigraph_paths = []

    for minigraph_path in minigraph_files:
        minigraph_filename = Path(minigraph_path).name
        localhost_path = f"/tmp/{minigraph_filename}"

        logger.info(f"Copying {minigraph_filename} from DUT to localhost...")
        try:
            # Use fetch module to copy from DUT to localhost
            duthost.fetch(src=minigraph_path, dest=localhost_path, flat=True)

            # Verify the file was copied on localhost
            result = localhost.shell(f"test -f {localhost_path}", module_ignore_errors=True)
            if result['rc'] == 0:
                logger.info(f"  ✓ Backed up to {localhost_path}")
                localhost_minigraph_paths.append(localhost_path)
            else:
                logger.warning(f"  ✗ Backup verification failed for {minigraph_filename}")
        except (ConnectionError, TimeoutError, IOError) as e:
            logger.warning(f"Connection/IO error backing up {minigraph_filename}: {e}")
            # Continue - not all minigraphs may be critical
        except Exception as e:
            logger.error(f"Unexpected error backing up {minigraph_filename}: {e}")
            logger.debug(traceback.format_exc())
            # Continue - not all minigraphs may be critical

    logger.info(f"✓ Backed up {len(localhost_minigraph_paths)} minigraph files to localhost /tmp/")
    return localhost_minigraph_paths


# ============================================================================
# PHASE 3 HELPER FUNCTIONS - XR to SONiC Migration (SSH-based)
# ============================================================================

def copy_file_with_retry(cisco_host, src, dest, file_description, max_retries=3, delay_between_retries=5):
    """
    Copy a file to Cisco device with retry logic.

    Retries the copy operation if it fails, with delays between attempts.
    Also verifies the file exists on the device after transfer.

    Args:
        cisco_host: The Cisco host instance
        src: Source file path (local)
        dest: Destination file path (on device)
        file_description: Human-readable description for logging
        max_retries: Maximum number of retry attempts (default: 3)
        delay_between_retries: Seconds to wait between retries (default: 5)

    Returns:
        bool: True if successful, False otherwise
    """
    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Transferring {file_description} (attempt {attempt}/{max_retries})...")

            # Attempt the copy
            result = cisco_host.copy(src=src, dest=dest)

            # Check if copy reported failure
            if result.get('failed', False):
                logger.warning(f"Copy reported failure: {result}")
                if attempt < max_retries:
                    logger.info(f"Waiting {delay_between_retries} seconds before retry...")
                    time.sleep(delay_between_retries)
                    continue
                else:
                    logger.error(f"Failed to transfer {file_description} after {max_retries} attempts")
                    return False

            # Verify file exists on device with SSH retry logic
            logger.info(f"Verifying {file_description} on device...")
            dest_filename = dest.split('/')[-1]

            # Try verification with retries (SSH might not be immediately ready)
            verification_attempts = 3
            verification_successful = False

            for verify_attempt in range(1, verification_attempts + 1):
                try:
                    logger.info(f"Verification attempt {verify_attempt}/{verification_attempts}...")
                    verify_result = cisco_host.commands(commands=[f'dir {dest}'])
                    verify_stdout = verify_result.get('stdout')
                    if isinstance(verify_stdout, list):
                        verify_output = verify_stdout[0] if verify_stdout else ''
                    else:
                        verify_output = verify_stdout or ''

                    if dest_filename in verify_output or 'No such file' not in verify_output:
                        logger.info(f"✓ {file_description} transferred and verified successfully")
                        verification_successful = True
                        break
                    else:
                        logger.warning(f"File not found in dir output (verify attempt {verify_attempt})")
                        if verify_attempt < verification_attempts:
                            time.sleep(3)

                except Exception as verify_error:
                    # SSH connection errors are common - retry with backoff
                    if "SSH protocol banner" in str(verify_error) or "Socket is closed" in str(verify_error):
                        logger.warning(
                            f"SSH connection issue during verification "
                            f"(attempt {verify_attempt}): {verify_error}")
                        if verify_attempt < verification_attempts:
                            logger.info("Waiting 5 seconds for SSH to stabilize...")
                            time.sleep(5)
                        else:
                            logger.warning(
                                f"SSH verification failed after {verification_attempts} attempts - "
                                f"assuming file transfer succeeded")
                            # If copy succeeded but SSH verification failed, trust the copy operation
                            # This is safer than failing the entire test
                            verification_successful = True
                            break
                    else:
                        # Other exceptions should be re-raised
                        raise

            if verification_successful:
                return True
            else:
                logger.warning(f"File verification inconclusive for {file_description}")
                if attempt < max_retries:
                    logger.info(f"Retrying entire copy operation after {delay_between_retries} seconds...")
                    time.sleep(delay_between_retries)
                    continue
                else:
                    logger.error(f"Failed to verify {file_description} after {max_retries} copy attempts")
                    return False

        except (ConnectionError, TimeoutError, IOError, OSError) as e:
            logger.error(f"Connection/IO error during file transfer of {file_description}: {e}")
            if attempt < max_retries:
                logger.info(f"Waiting {delay_between_retries} seconds before retry...")
                time.sleep(delay_between_retries)
                continue
            else:
                logger.error(f"Failed to transfer {file_description} after {max_retries} attempts")
                return False
        except Exception as e:
            logger.error(f"Unexpected error during file transfer of {file_description}: {e}")
            logger.error(traceback.format_exc())
            if attempt < max_retries:
                logger.info(f"Retrying after unexpected error in {delay_between_retries} seconds...")
                time.sleep(delay_between_retries)
                continue
            else:
                logger.error(f"Failed to transfer {file_description} after {max_retries} attempts")
                return False

    return False


def download_and_transfer_sonic_artifacts(cisco_host, localhost, https_proxy, existing_minigraphs):
    """
    Download and transfer all required files for XR to SONiC conversion.

    Downloads from ACS repo to localhost, then transfers to XR device via SCP.
    Uses minigraph files previously backed up to localhost from Phase 1.

    Args:
        cisco_host: CiscoHost SSH connection
        localhost: Localhost ansible connection
        https_proxy: HTTPS proxy URL
        existing_minigraphs: List of minigraph paths on LOCALHOST (in /tmp/)

    Returns:
        bool: True if all transfers successful
    """
    logger.info("Downloading SONiC artifacts from ACS repo...")

    xr_artifacts_dir = "/harddisk:/"

    # 1. Copy migration scripts (both are needed)
    base_path = Path(__file__).resolve().parent
    scripts_path = base_path / MIGRATION_SCRIPT_LOCAL_SUBPATH

    # Copy sonic_migration_xr.py (main migration script used in commands)
    success = copy_file_with_retry(
        cisco_host,
        src=str(scripts_path / MIGRATION_SCRIPT_NAME),
        dest=f"{xr_artifacts_dir}{MIGRATION_SCRIPT_NAME}",
        file_description="migration script"
    )
    if not success:
        logger.error(f"Failed to transfer {MIGRATION_SCRIPT_NAME}")
        return False
    time.sleep(2)

    # Copy sonic-migutil.py (utility script used by main script)
    success = copy_file_with_retry(
        cisco_host,
        src=str(scripts_path / MIGRATION_UTIL_SCRIPT_NAME),
        dest=f"{xr_artifacts_dir}{MIGRATION_UTIL_SCRIPT_NAME}",
        file_description="migration utility script"
    )
    if not success:
        logger.error(f"Failed to transfer {MIGRATION_UTIL_SCRIPT_NAME}")
        return False
    time.sleep(2)

    # 2. Download SONiC image
    sonic_download_filename = Path(SONIC_IMAGE_DOWNLOAD_PATH).name
    logger.info(f"Downloading SONiC image: {sonic_download_filename}")
    temp_sonic_path = f"/tmp/{sonic_download_filename}"
    sonic_url = f"{ACS_REPO_BASE_URL}{SONIC_IMAGE_DOWNLOAD_PATH}"

    result = download_file_from_repo(localhost, sonic_url, temp_sonic_path, https_proxy, max_time=600)
    if not result['success']:
        logger.error(f"Failed to download SONiC image: {result.get('stderr', '')}")
        return False

    logger.info(f"SONiC image downloaded to localhost (method: {result['method']})")

    # Transfer with required name and retry logic
    logger.info(f"Transferring SONiC image to XR device as {SONIC_IMAGE_NAME}...")
    success = copy_file_with_retry(
        cisco_host,
        src=temp_sonic_path,
        dest=f"{xr_artifacts_dir}{SONIC_IMAGE_NAME}",
        file_description="SONiC image",
        max_retries=3,
        delay_between_retries=10  # Longer delay for large file
    )

    # Cleanup temp file on localhost
    localhost.shell(f"rm -f {temp_sonic_path}", module_ignore_errors=True)

    if not success:
        logger.error("Failed to transfer SONiC image after retries")
        return False

    # Wait to avoid SSH rate limiting
    logger.info("Waiting 5 seconds to avoid SSH rate limiting...")
    time.sleep(5)

    # 3. Download firmware files with retry logic
    firmware_files = [
        (INTERMEDIATE_XR_IMAGE_PATH, INTERMEDIATE_XR_IMAGE_NAME, "intermediate_xr"),
        (ONIE_IMAGE_PATH, ONIE_IMAGE_NAME, "onie"),
        (VOUCHER_TARBALL_PATH, VOUCHER_TARBALL_NAME, "vouchers"),
        (VOUCHER_TARBALL_MD5_PATH, VOUCHER_TARBALL_MD5_NAME, "vouchers_md5"),
        (AUTHENTICATED_VARIABLE_PATH, AUTHENTICATED_VARIABLE_NAME, "auth_variable"),
        (AUTHENTICATED_VARIABLE_MD5_PATH, AUTHENTICATED_VARIABLE_MD5_NAME, "auth_variable_md5")
    ]

    for download_path, dest_filename, file_type in firmware_files:
        # Download from ACS repo to localhost
        file_url = f"{ACS_REPO_BASE_URL}{download_path}"
        temp_path = f"/tmp/{dest_filename}"

        logger.info(f"Downloading {file_type} from {file_url}")
        result = download_file_from_repo(localhost, file_url, temp_path, https_proxy, max_time=600)
        if not result['success']:
            logger.error(f"Failed to download {file_type}: {result.get('stderr', '')}")
            return False

        logger.info(f"{file_type} downloaded to localhost (method: {result['method']})")

        # Transfer from localhost to XR device using SCP with retry
        success = copy_file_with_retry(
            cisco_host,
            src=temp_path,
            dest=f"{xr_artifacts_dir}{dest_filename}",
            file_description=file_type,
            max_retries=3,
            delay_between_retries=5
        )

        # Cleanup temp file on localhost
        localhost.shell(f"rm -f {temp_path}", module_ignore_errors=True)

        if not success:
            logger.error(f"Failed to transfer {file_type} after retries")
            return False

        # Wait between transfers to avoid SSH rate limiting
        logger.info("Waiting 3 seconds to avoid SSH rate limiting...")
        time.sleep(3)

    # 4. Transfer existing minigraph files from localhost to XR with retry
    logger.info("Transferring minigraph files from localhost to XR device...")
    transferred_minigraphs = []
    for localhost_minigraph_path in existing_minigraphs:
        minigraph_filename = Path(localhost_minigraph_path).name
        logger.info(f"Transferring {minigraph_filename}...")

        success = copy_file_with_retry(
            cisco_host,
            src=localhost_minigraph_path,
            dest=f"{xr_artifacts_dir}{minigraph_filename}",
            file_description=f"minigraph {minigraph_filename}",
            max_retries=3,
            delay_between_retries=5
        )

        if success:
            transferred_minigraphs.append(minigraph_filename)
        else:
            logger.warning(f"Failed to transfer {minigraph_filename} - continuing with other files")
            # Continue - not all minigraphs may be critical

        time.sleep(2)  # Brief delay between minigraph transfers

    # 5. Verify all critical files exist on XR device
    logger.info("Verifying all files are present on XR device...")

    critical_files = [
        MIGRATION_SCRIPT_NAME,
        MIGRATION_UTIL_SCRIPT_NAME,
        SONIC_IMAGE_NAME,
        INTERMEDIATE_XR_IMAGE_NAME,
        ONIE_IMAGE_NAME,
        VOUCHER_TARBALL_NAME,
        VOUCHER_TARBALL_MD5_NAME,
        AUTHENTICATED_VARIABLE_NAME,
        AUTHENTICATED_VARIABLE_MD5_NAME
    ]

    all_files = critical_files + transferred_minigraphs

    for filename in all_files:
        logger.info(f"Checking {filename}...")
        # Use XR CLI command 'dir' to check file existence
        result = cisco_host.commands(commands=[f"dir /harddisk:/{filename}"], module_ignore_errors=True)
        stdout_val = result.get('stdout', [])
        if isinstance(stdout_val, list):
            output = stdout_val[0] if stdout_val else ''
        else:
            output = stdout_val or ''

        if result.get('failed', False) or 'No such file' in output or 'Error' in output:
            if filename in critical_files:
                logger.error(f"Critical file missing on XR device: {filename}")
                logger.error(f"Dir output: {output[:200]}")
                return False
            else:
                logger.warning(f"Minigraph file missing on XR device: {filename}")
        else:
            # Try to extract file size from dir output
            logger.info(f"  ✓ {filename} present on XR device")

    logger.info("✓ All SONiC artifacts downloaded, transferred, and verified successfully")
    return True


def execute_intermediate_xr_upgrade(cisco_host):
    """
    Stage 1: Upgrade chassis to intermediate XR version.

    This upgrades the device to a specific XR version (e.g., 7.5.41) that
    supports the migration to SONiC.

    Uses pattern-based waiting (mimics C# WriteLineAndWaitForRegexV2) to ensure
    the upgrade command completes and produces expected output before proceeding.
    """
    logger.info("Starting Intermediate XR Upgrade...")

    # Step 1: Run upgrade check
    logger.info("Running XR upgrade pre-check...")
    check_cmd = INTERMEDIATE_XR_UPGRADE_CHECK_CMD.format(MIGRATION_SCRIPT_NAME, SONIC_IMAGE_NAME)
    result = cisco_host.exec_interactive(
        command=check_cmd,
        expect_pattern=None,
        timeout=300,  # 5 minutes for check
        read_delay=2
    )

    output = result.get('stdout', '') + "\n" + result.get('stderr', '')

    if result.get('failed', False) or ERROR_MESSAGE in output or INSTALL_SUCCESS_MESSAGE not in output:
        logger.error(f"XR upgrade pre-check failed: {output}")
        return False

    logger.info("XR upgrade pre-check passed")

    # Step 2: Execute the upgrade
    # Similar to test_xr_migration.py console flow:
    # 1. Send upgrade command
    # 2. Wait for "XR_UPGRADE: Device will now reload" message
    # 3. Device reboots (SSH connection will drop)
    # 4. Wait for device to come back online
    # 5. SSH reconnects automatically (handled by Ansible connection)
    logger.info("Executing intermediate XR upgrade command...")
    cmd = INTERMEDIATE_XR_INSTALL_CMD.format(MIGRATION_SCRIPT_NAME, SONIC_IMAGE_NAME)

    result = cisco_host.exec_interactive(
        command=cmd,
        expect_pattern=XR_UPGRADE_RELOAD_MESSAGE,  # Wait for reload message
        timeout=600,  # 10 minutes to wait for command to trigger reload
        read_delay=2
    )

    output = result.get('stdout', '') + "\n" + result.get('stderr', '')

    # Check for errors first
    if ERROR_MESSAGE in output or INSTALL_FAILURE_MESSAGE in output:
        logger.error(f"Intermediate XR upgrade failed: {output}")
        return False

    # Check what happened
    if UPGRADE_NOT_REQUIRED_MESSAGE in output:
        logger.info("Intermediate XR upgrade not required - already at correct version")
        return True

    # If we got the reload message or success message, device will reboot
    if result.get('pattern_found') or INSTALL_SUCCESS_MESSAGE in output or XR_UPGRADE_RELOAD_MESSAGE in output:
        logger.info("Intermediate XR upgrade initiated - device will reboot")
        logger.info("SSH connection will be disconnected during reload")

        # Wait for device to reload and come back online
        # test_xr_migration.py uses 2000 second timeout for reload + login
        # After reload, it waits for boot, does login sequence, then sleeps 120 seconds
        logger.info(f"Waiting {INTERMEDIATE_XR_UPGRADE_WAIT} seconds for device to reload and stabilize...")
        time.sleep(INTERMEDIATE_XR_UPGRADE_WAIT)

        # Verify device is accessible after upgrade
        # SSH connection should automatically reconnect via Ansible
        logger.info("Verifying device accessibility after XR upgrade...")
        max_retries = 10
        retry_interval = 5 * 60  # 5 minute between retries

        for attempt in range(1, max_retries + 1):
            try:
                logger.info(f"Attempting to connect (attempt {attempt}/{max_retries})...")
                version_result = cisco_host.commands(commands=["show version"], module_ignore_errors=True)

                if not version_result.get('failed', False):
                    logger.info("Device accessible after XR upgrade")
                    # Additional 120 second stabilization like test_xr_migration.py
                    logger.info("Waiting 120 seconds for system to stabilize...")
                    time.sleep(120)
                    logger.info("Intermediate XR upgrade completed successfully")
                    return True
                else:
                    logger.warning(f"Device returned error: {version_result.get('msg', 'Unknown error')}")
                    if attempt < max_retries:
                        logger.info(f"Waiting {retry_interval} seconds before retry...")
                        time.sleep(retry_interval)
                    continue

            except (ConnectionError, TimeoutError) as e:
                logger.warning(f"Connection timeout on attempt {attempt}: {e}")
                if attempt < max_retries:
                    logger.info(f"Waiting {retry_interval} seconds before retry...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Failed to reconnect after {max_retries} attempts due to connection errors")
                    return False
            except Exception as e:
                logger.error(f"Unexpected error on connection attempt {attempt}: {e}")
                logger.debug(traceback.format_exc())
                if attempt < max_retries:
                    logger.info(f"Retrying after unexpected error in {retry_interval} seconds...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Failed to reconnect after {max_retries} attempts")
                    return False

        logger.error("Failed to verify device accessibility after XR upgrade")
        return False

    logger.error(f"Unexpected response from intermediate XR upgrade: {output[:500]}")
    return False


def execute_ov_installation(cisco_host):
    """
    Stage 2: Ownership Voucher (OV) Installation.

    Installs ownership vouchers to enable customer mode on the chassis.

    Similar to C# HwCiscoSpitfireSwitch.OvInstallation():
    1. Execute OV install command
    2. Wait for success/failure message (15 min timeout)
    3. If success and not already installed:
       - Sleep for OV_INSTALL_WAIT (5 min) for installation and reboot
       - Reconnect via SSH (device reboots during OV installation)
    """
    logger.info("Starting Ownership Voucher (OV) Installation...")

    cmd = OV_INSTALL_CMD.format(MIGRATION_SCRIPT_NAME, SONIC_IMAGE_NAME)

    # C# uses WriteLineAndWaitForRegexV2 with expectedRegex =
    # FexRegex.Join(InstallSuccessMessage, InstallFailureMessage)
    # Wait for either EXIT_ON_SUCCESS or EXIT_ON_FAILURE during execution
    pattern = f"({INSTALL_SUCCESS_MESSAGE}|{INSTALL_FAILURE_MESSAGE})"

    result = cisco_host.exec_interactive(
        command=cmd,
        expect_pattern=pattern,
        timeout=15 * 60,  # 15 minutes (WaitForSuccessMessageTimeoutMs in C#)
        read_delay=2
    )

    output = result.get('stdout', '') + "\n" + result.get('stderr', '')

    logger.info(f"OV installation output: {output[:500]}...")

    # Check if pattern was found
    if not result.get('pattern_found'):
        logger.error(f"Expected pattern '{pattern}' not found in OV installation output: {output}")
        return False

    # Check for failure messages
    if INSTALL_FAILURE_MESSAGE in output:
        logger.error(f"OV installation failed: {output}")
        return False

    # At this point we have EXIT_ON_SUCCESS
    if INSTALL_SUCCESS_MESSAGE not in output:
        logger.error(f"No success message found in OV installation output: {output}")
        return False

    # Check if OV installation was already done
    if OV_INSTALL_NOT_REQUIRED_MESSAGE in output:
        logger.info("OV installation not required - already installed on device")
        return True

    # OV installation will proceed - device will reboot
    logger.info("Successfully executed OV installation script. OV Installation and device reboot will take place.")

    # C# sleeps for OvInstallTimeoutMs (5 min) before login to give time for install and reboot
    logger.info(f"Sleeping for {OV_INSTALL_WAIT} seconds before reconnecting (device is rebooting)...")
    time.sleep(OV_INSTALL_WAIT)

    # C# calls Login() to reconnect after OV installation reboot
    # SSH connection should automatically reconnect via Ansible, but we verify
    logger.info("Attempting to reconnect after OV installation and reboot...")
    max_retries = 5
    retry_interval = 60  # 1 minute between retries

    for attempt in range(1, max_retries + 1):
        try:
            logger.info(f"Connection attempt {attempt}/{max_retries}...")
            version_result = cisco_host.commands(commands=["show version"], module_ignore_errors=True)

            if not version_result.get('failed', False):
                logger.info("Successfully logged into device after OV installation and reboot")
                return True
            else:
                logger.warning(f"Device returned error: {version_result.get('msg', 'Unknown error')}")
                if attempt < max_retries:
                    logger.info(f"Waiting {retry_interval} seconds before retry...")
                    time.sleep(retry_interval)
                continue

        except (ConnectionError, TimeoutError) as e:
            logger.warning(f"Connection timeout on attempt {attempt}: {e}")
            if attempt < max_retries:
                logger.info(f"Waiting {retry_interval} seconds before retry...")
                time.sleep(retry_interval)
            else:
                logger.error(f"Unable to login after OV installation - connection failed after {max_retries} attempts")
                return False
        except Exception as e:
            logger.error(f"Unexpected error on connection attempt {attempt}: {e}")
            logger.debug(traceback.format_exc())
            if attempt < max_retries:
                logger.info(f"Retrying after unexpected error in {retry_interval} seconds...")
                time.sleep(retry_interval)
            else:
                logger.error("Unable to login after OV installation and reboot of the device")
                return False

    logger.error("Failed to reconnect after OV installation")
    return False


def execute_av_installation_and_rp_migration(cisco_host):
    """
    Stage 3: Authenticated Variable (AV) Installation + Route Processor (RP) SONiC Migration.

    This is a critical stage that:
    1. Installs authenticated variables
    2. Migrates the Route Processor (supervisor) to SONiC

    Similar to C# HwCiscoSpitfireSwitch.AvInstallationAndRpSonicMigration():
    - Uses WriteLineAndWaitForRegexV2() with TimeoutScope(WaitForSuccessMessageTimeoutMs = 15 min)
    - Waits for ExecPromptRegex (command completion prompt)
    - Checks buffer for InstallSuccessMessage
    - Returns immediately after success (no sleep/login in this function)
    - Calling code handles 35-minute wait and login verification
    """
    logger.info("Starting AV Installation and RP SONiC Migration...")

    cmd = AV_INSTALL_RP_MIGRATION_CMD.format(MIGRATION_SCRIPT_NAME, SONIC_IMAGE_NAME)

    # C# uses TimeoutScope(WaitForSuccessMessageTimeoutMs) = 15 minutes
    # and waits for ExecPromptRegex (not a success/failure pattern)
    result = cisco_host.exec_interactive(
        command=cmd,
        expect_pattern=None,  # C# waits for ExecPromptRegex which is just the prompt returning
        timeout=15 * 60,  # 15 minutes (WaitForSuccessMessageTimeoutMs in C#)
        read_delay=2
    )

    output = result.get('stdout', '') + "\n" + result.get('stderr', '')

    logger.info(f"AV installation and RP migration output: {output[:500]}...")

    # C# checks if buffer contains InstallSuccessMessage after command returns
    if INSTALL_SUCCESS_MESSAGE in output:
        logger.info("Script execution is success. AV installation and RP sonic migration starts.")
        # C# returns true immediately here - no sleep, no login verification
        # The calling code (test_xr2sonic_migration) will:
        # 1. Sleep for AV_INSTALL_RP_MIGRATION_WAIT (35 min)
        # 2. Attempt login to verify RP migration
        return True

    # Check for failure
    if INSTALL_FAILURE_MESSAGE in output or ERROR_MESSAGE in output:
        logger.error(f"AV installation and RP Sonic Migration failed: {output}")
        return False

    logger.error(f"AV installation and RP migration failed - no success message found: {output}")
    return False


def execute_lc_migration(sonic_host):
    """
    Stage 4: Line Card (LC) SONiC Migration.

    Migrates all line cards to SONiC OS.

    C# equivalent: WriteLineAndWaitForRegexV2(lcSonicMigrationCommand, LCMigrationSuccessMessage)
    with TimeoutScope(LCMigrationTimeoutMs = 20 min)

    Matches C# LcSonicMigration() at lines 887-924:
    - Uses pattern matching during execution (waits for LC_MIGRATION_SUCCESS_MESSAGE)
    - Timeout: 20 minutes
    - After success: Sleep 5 min (WaitBeforeLoginAfterLcMigration)
    - Verify login successful
    """
    logger.info("Starting Line Card (LC) SONiC Migration...")

    cmd = LC_MIGRATION_CMD.format(MIGRATION_SCRIPT_NAME, SONIC_IMAGE_NAME)

    # Execute command and wait for LC migration success message DURING execution
    # C#: WriteLineAndWaitForRegexV2(..., LCMigrationSuccessMessage)
    result = sonic_host.exec_interactive(
        command=cmd,
        expect_pattern=LC_MIGRATION_SUCCESS_MESSAGE,  # Wait for pattern during execution
        timeout=20 * 60,  # 20 minutes (LCMigrationTimeoutMs)
        read_delay=2
    )

    output = result.get('stdout', '') + "\n" + result.get('stderr', '')

    # Check if pattern was found
    if result.get('pattern_found') is not True:
        logger.error(f"LC migration failed - did not find success message: {output}")
        return False

    if result.get('failed', False) or ERROR_MESSAGE in output:
        logger.error(f"LC migration failed: {output}")
        return False

    logger.info("LC migration completed successfully - all LCs published their inventory")

    # C#: Sleep(WaitBeforeLoginAfterLcMigration) = 5 minutes
    logger.info(f"Sleeping for {5 * 60} seconds before login (WaitBeforeLoginAfterLcMigration)...")
    time.sleep(5 * 60)

    # C# attempts login after LC migration: supervisorSwitch.Login()
    logger.info("Attempting login after LC migration...")
    try:
        # Use a basic Linux command that should work on SONiC
        result = sonic_host.shell("whoami", module_ignore_errors=True)
        if result.get('rc') == 0:
            logger.info("Successfully logged in after LC migration")
            return True
        else:
            logger.error("Unable to login after LC migration")
            return False
    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Connection error during login after LC migration: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during login after LC migration: {e}")
        logger.debug(traceback.format_exc())
        return False


def rotate_admin_password_post_migration(ansible_adhoc, dut_hostname,
                                         new_password,
                                         lc_hostnames=None,
                                         factory_user=SONIC_FACTORY_DEFAULT_USER,
                                         factory_password=SONIC_FACTORY_DEFAULT_PASSWORD):
    """
    Rotate the admin password on every module of a freshly XR->SONiC
    converted chassis off the vendor factory default.

    The XR->SONiC migration script (sonic_migration_xr.py) is responsible
    for staging /etc/sonic/minigraph.xml and applying the SONiC config on
    each module. This helper deliberately does NOT run load_minigraph /
    config save; it only performs the credential rotation that the test
    framework needs in order to talk to the chassis with its real
    (non-factory) password going forward.

    Per-module operation:
      Use the Ansible 'user' module with a locally-computed SHA-512 hash so
      the plaintext password never appears in argv/process list/logs on the
      remote module (consistent with rotate_password_on_dut() below).

    Order across the chassis (atomic password rotation):
      a.1. Rotate the admin password on every line card via direct SSH
           (Ansible) using the factory password. LCs are rotated first,
           while the SUP still has the factory password, so any failure
           leaves the chassis recoverable for retry.
      a.2. Rotate the admin password on the supervisor itself. After this
           step factory_password is no longer valid anywhere on the chassis.
      b.   Reconnect to the SUP with the rotated credentials and verify
           that SSH + sudo work, so the caller can hand the returned
           SonicHost off to subsequent steps.

    Args:
        ansible_adhoc: Ansible adhoc fixture
        dut_hostname: Supervisor hostname (used to (re)create SonicHost)
        new_password: Rotated admin password (typically ansible_altpasswords[0])
        lc_hostnames: Iterable of line card hostnames (Ansible inventory
                      names) to rotate password on in Step A.1. If None or
                      empty, line card rotation is skipped (use only when
                      testing on a non-chassis device).
        factory_user: Factory-default SONiC username
        factory_password: Factory-default SONiC password

    Returns:
        SonicHost or None: Rotated supervisor SonicHost on success, None on
        failure. Callers should replace their existing sonic_host reference
        with the returned object since the factory-default one is no longer
        valid.
    """
    logger.info("Step A: Rotating admin password atomically across the "
                "chassis (each line card via direct SSH, then supervisor)...")
    factory_sup = SonicHost(
        ansible_adhoc=ansible_adhoc,
        hostname=dut_hostname,
        ssh_user=factory_user,
        ssh_passwd=factory_password,
    )

    # A.1: Rotate password on every line card by SSH'ing directly to it as
    # admin@<lc-hostname> via Ansible (same path the test infrastructure
    # already uses to reach the SUP). Direct SSH is more reliable than
    # rexec from the SUP right after a fresh XR->SONiC conversion, where
    # midplane / chassisdb state can still be settling. We do this BEFORE
    # the SUP rotates itself so that any failure leaves the SUP on the
    # factory password and the chassis recoverable for retry.
    #
    # Hash the new password locally and use the Ansible 'user' module so the
    # plaintext password never appears in argv (visible in remote ps, audit
    # logs, and Ansible command logs even with verbose=False).
    salt = crypt.mksalt(crypt.METHOD_SHA512)
    hashed_password = crypt.crypt(new_password, salt)
    if lc_hostnames:
        logger.info(f"Step A.1: Rotating admin password on {len(lc_hostnames)} "
                    f"line card(s) via direct SSH: {list(lc_hostnames)}")
        for lc_hostname in lc_hostnames:
            logger.info(f"  Rotating password on line card {lc_hostname}...")
            try:
                factory_lc = SonicHost(
                    ansible_adhoc=ansible_adhoc,
                    hostname=lc_hostname,
                    ssh_user=factory_user,
                    ssh_passwd=factory_password,
                )
                lc_rotate = factory_lc.user(
                    name=factory_user,
                    password=hashed_password,
                    update_password='always',
                    module_ignore_errors=True,
                )
            except Exception as e:
                logger.error(f"  user-module raised exception on line card "
                             f"{lc_hostname}: {type(e).__name__}: {e}")
                return None
            logger.info(f"  LC {lc_hostname} user-module raw result: "
                        f"failed={lc_rotate.get('failed')} "
                        f"unreachable={lc_rotate.get('unreachable')} "
                        f"msg={lc_rotate.get('msg', '')!r}")
            if lc_rotate.get('failed', False):
                logger.error(f"Password rotation failed on line card "
                             f"{lc_hostname}: "
                             f"{lc_rotate.get('msg', lc_rotate.get('stderr', ''))}")
                return None
            try:
                del factory_lc
            except NameError:
                pass
        logger.info(f"✓ Line card admin passwords rotated on "
                    f"{len(lc_hostnames)} module(s)")
    else:
        logger.warning("Step A.1: No line card hostnames provided; skipping "
                       "line card password rotation. This is only safe on "
                       "non-chassis devices.")

    # A.2: Rotate password on the supervisor itself. After this point,
    # factory_password is no longer valid anywhere on the chassis.
    logger.info("Step A.2: Rotating admin password on supervisor...")
    rotate_result = factory_sup.user(
        name=factory_user,
        password=hashed_password,
        update_password='always',
        module_ignore_errors=True,
    )
    logger.info(f"SUP user-module raw result: "
                f"failed={rotate_result.get('failed')} "
                f"unreachable={rotate_result.get('unreachable')} "
                f"msg={rotate_result.get('msg', '')!r}")
    if rotate_result.get('failed', False):
        logger.error(f"Supervisor password rotation failed (LCs already "
                     f"rotated -- chassis is now in asymmetric state and "
                     f"will require manual recovery before retry): "
                     f"{rotate_result.get('msg', rotate_result.get('stderr', ''))}")
        return None
    logger.info("✓ Supervisor admin password rotated -- chassis credentials "
                "are symmetric on the new password")

    # Drop the factory-default SonicHost reference so any persistent SSH
    # control socket / connection cached against the old password is not
    # reused for the rotated session below.
    try:
        del factory_sup
    except NameError:
        pass

    logger.info("Step B: Reconnecting to supervisor with rotated credentials "
                "(post-chpasswd settle + retry)...")
    # Brief settle to let sshd pick up the new shadow entry. Without this,
    # the very next SSH attempt occasionally races and gets auth-rejected
    # or simply gets no response (Ansible returns failed=True with no rc /
    # stdout / stderr, which is what we saw in the previous run).
    time.sleep(15)

    sup = None
    whoami = None
    max_reconnect_attempts = 6
    reconnect_backoff = 20  # seconds
    for attempt in range(1, max_reconnect_attempts + 1):
        logger.info(f"Reconnect attempt {attempt}/{max_reconnect_attempts} "
                    f"as {factory_user}@{dut_hostname} with rotated password...")
        sup = SonicHost(
            ansible_adhoc=ansible_adhoc,
            hostname=dut_hostname,
            ssh_user=factory_user,
            ssh_passwd=new_password,
        )
        # NOTE: SonicHost.shell() runs through ansible_adhoc(become=True), so
        # `whoami` returns 'root' (not the SSH user). To verify the SSH login
        # actually succeeded with the rotated password, query $SUDO_USER which
        # is set by sudo to the real login user, and additionally rely on
        # rc/failed/unreachable as the primary signals.
        try:
            whoami = sup.shell("whoami; echo SUDO_USER=$SUDO_USER",
                               module_ignore_errors=True)
        except Exception as e:
            logger.warning(f"  whoami raised exception on attempt {attempt}: "
                           f"{type(e).__name__}: {e}")
            whoami = {'rc': -1, 'stdout': '', 'stderr': str(e),
                      'failed': True, 'unreachable': True, 'msg': str(e)}

        # Success = SSH connected + sudo command ran cleanly.
        # rc=0, not failed, not unreachable, and we got some stdout back.
        # When this passes, the rotated password is verified to work.
        stdout = whoami.get('stdout', '') or ''
        if (whoami.get('rc', 1) == 0
                and not whoami.get('failed', False)
                and not whoami.get('unreachable', False)
                and stdout.strip()):
            logger.info(f"✓ Reconnected to supervisor on attempt {attempt} "
                        f"(stdout={stdout.strip()!r})")
            break

        logger.warning(f"Reconnect attempt {attempt} did not return clean "
                       f"whoami; sleeping {reconnect_backoff}s before retry...")
        time.sleep(reconnect_backoff)
    else:
        logger.error("Failed to reconnect to supervisor with rotated password "
                     f"after {max_reconnect_attempts} attempts. "
                     f"Last whoami: rc={whoami.get('rc') if whoami else 'n/a'} "
                     f"failed={whoami.get('failed') if whoami else 'n/a'} "
                     f"unreachable={whoami.get('unreachable') if whoami else 'n/a'} "
                     f"msg={(whoami or {}).get('msg', '')!r} "
                     f"stdout={(whoami or {}).get('stdout', '')!r} "
                     f"stderr={(whoami or {}).get('stderr', '')!r}")
        return None

    logger.info("Step C: Skipping load_minigraph / config save -- the XR->SONiC "
                "migration script (sonic_migration_xr.py) is responsible for "
                "applying the staged minigraph.xml on each module. This helper "
                "only rotates the admin password.")
    return sup


def execute_post_migration_checks(sonic_host):
    """
    Stage 5: Post-Migration Validation.

    Verifies that all modules (supervisor + line cards) have been
    successfully migrated to SONiC.

    Matches C# PostMigrationChecks() at lines 926-960:
    - Uses pattern matching during execution
    - Pattern: PostMigrationCheckSuccessRegex OR PostMigrationCheckFailureRegex
    - Timeout: 10 minutes (PostMigrationCheckTimeoutMs)
    """
    logger.info("Running post-migration checks...")

    cmd = POST_MIGRATION_CHECK_CMD.format(MIGRATION_SCRIPT_NAME, SONIC_IMAGE_NAME)

    # C#: expectedRegex = FexRegex.Join(PostMigrationCheckSuccessRegex, PostMigrationCheckFailureRegex)
    # C#: WriteLineAndWaitForRegexV2(postCheckCommand, expectedRegex) with TimeoutScope(10 min)
    pattern = f"({POST_MIGRATION_SUCCESS_REGEX}|{POST_MIGRATION_FAILURE_REGEX})"

    result = sonic_host.exec_interactive(
        command=cmd,
        expect_pattern=pattern,
        timeout=10 * 60,  # 10 minutes (PostMigrationCheckTimeoutMs)
        read_delay=2
    )

    output = result.get('stdout', '') + "\n" + result.get('stderr', '')

    # Check if pattern was found
    if result.get('pattern_found') is not True:
        logger.error(f"Post-migration checks timed out - no success/failure message found: {output}")
        return False

    # Check for errors
    if result.get('failed', False) or ERROR_MESSAGE in output:
        logger.error(f"Error occurred during post-migration checks: {output}")
        return False

    # Check which pattern matched
    if POST_MIGRATION_SUCCESS_REGEX in output:
        logger.info("Post-migration checks PASSED - all modules migrated to SONiC")
        return True

    if POST_MIGRATION_FAILURE_REGEX in output:
        logger.error("Post-migration checks FAILED - not all modules migrated")
        return False

    logger.error(f"Unable to determine post-migration check status: {output}")
    return False


def test_xr_migration(duthost_console, duthosts, enum_supervisor_dut_hostname, creds, tbinfo, localhost, ansible_adhoc):
    """
    Test complete SONiC ↔ XR migration cycle on Cisco 8800 T2 device.

    This test performs a full conversion cycle:

    PHASE 1: Pre-check and File Preparation
    1. Check migration eligibility (Cisco hardware)
    2. Collect minigraph files from all modules (RPs and LCs)
    3. Download required XR rollback files from ACS repo
    4. Copy migration script to supervisor
    5. Verify all required files are present

    PHASE 2: SONiC → XR Rollback
    6. Execute XR Rollback (SONiC → XR with credential setup)
    7. Execute FPD Rollback for Line Cards
    8. Verify Rollback Completion

    PHASE 3: XR → SONiC Migration
    9. Download and transfer SONiC artifacts
    10. Execute Intermediate XR Upgrade
    11. Execute OV Installation
    12. Execute AV Installation + RP Migration
    13. Execute LC Migration
    14. Execute Post-Migration Checks

    Args:
        duthost_console: Console connection fixture
        duthosts: All DUT hosts
        enum_supervisor_dut_hostname: Supervisor hostname
        creds: Credentials fixture (includes proxy_env)
        tbinfo: Testbed information
        localhost: Localhost ansible connection
        ansible_adhoc: Ansible adhoc fixture for SonicHost creation
    """
    logger.info("=== Starting XR Migration (SONiC → XR Rollback) Test ===")

    # Get supervisor duthost
    duthost = duthosts[enum_supervisor_dut_hostname]
    dut_hostname = duthost.hostname

    # Get proxy configuration from creds
    https_proxy = creds.get('proxy_env', {}).get('https_proxy', '')

    # Get console credentials
    console_user = 'admin'
    console_password = creds.get('ansible_altpasswords', ['admin'])[0]

    # Set console timeout
    duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT

    # Step 1: Check migration eligibility
    hwsku = check_migration_eligibility(duthost, tbinfo)

    # Get chassis module information
    logger.info("Getting chassis module information via console...")
    try:
        output = duthost_console.send_command(
            command_string="show chassis modules midplane-status",
            expect_string=r".*[$#]",
            max_loops=1200,  # 120 seconds timeout (0.1s per loop)
            strip_prompt=False,
            strip_command=False
        )
        logger.info("Chassis module information retrieved successfully")
    except (ConnectionError, TimeoutError) as e:
        pytest.fail(f"Connection/timeout error getting chassis module information: {e}")
    except Exception as e:
        logger.error(f"Unexpected error getting chassis module information: {e}")
        logger.error(traceback.format_exc())
        pytest.fail(f"Failed to get chassis module information: {e}")

    module_info = parse_chassis_modules(output)

    if not module_info:
        pytest.fail("No active modules found in chassis")

    logger.info(f"Found {len(module_info)} active modules")

    # Step 2: Collect all minigraphs
    minigraph_files = collect_all_minigraphs(
        duthost, duthost_console, console_user, console_password,
        dut_hostname, module_info
    )

    # Step 3: Download XR rollback files
    xr_iso_path, xr_md5_path = download_xr_rollback_files(duthost, https_proxy)

    # Step 4: Copy migration script
    migration_script_path = copy_migration_script(duthost)

    # Step 5: Verify all files
    verify_all_files(duthost, minigraph_files, xr_iso_path, xr_md5_path, migration_script_path)

    # Step 5.5: Backup minigraphs to localhost (needed for Phase 3)
    logger.info("Step 5.5: Backing up minigraphs to localhost for Phase 3...")
    localhost_minigraph_paths = backup_minigraphs_to_localhost(duthost, localhost, minigraph_files)

    if not localhost_minigraph_paths:
        logger.warning("No minigraph files backed up to localhost - Phase 3 may fail")

    # Summary
    logger.info("=" * 80)
    logger.info("XR Migration Pre-check Summary:")
    logger.info(f"  Device: {dut_hostname}")
    logger.info(f"  HWSKU: {hwsku}")
    logger.info(f"  Modules found: {len(module_info)}")
    logger.info(f"  Minigraphs collected: {len(minigraph_files)}")
    logger.info(f"  Minigraphs backed up to localhost: {len(localhost_minigraph_paths)}")
    logger.info(f"  XR ISO: {Path(XR_ROLLBACK_ISO_PATH).name}")
    logger.info(f"  XR MD5: {Path(XR_ROLLBACK_MD5_PATH).name}")
    logger.info(f"  Migration Script: {MIGRATION_SCRIPT_NAME}")
    logger.info(f"  Storage Location: {SUPERVISOR_STORAGE_DIR}/")
    logger.info("=" * 80)

    logger.info(f"✅ All required files verified successfully on supervisor {SUPERVISOR_STORAGE_DIR}/!")
    logger.info("=== XR Migration Pre-check Completed ===")

    # ========================================================================
    # PHASE 2: Execute XR Rollback (SONiC → XR)
    # ========================================================================

    logger.info("")
    logger.info("=" * 80)
    logger.info("PHASE 2: Executing XR Rollback (SONiC → XR)")
    logger.info("=" * 80)

    # Step 6: Execute XR Rollback (SONiC -> XR with credential setup)
    logger.info("Step 6: Executing XR Rollback (SONiC → XR)")
    success = execute_xr_rollback(duthost_console)
    if not success:
        duthost_console.disconnect()
        pytest.fail("XR rollback execution failed")

    # Step 7: Execute FPD Rollback for Line Cards
    logger.info("Step 7: Executing FPD Rollback for Line Cards")
    success = execute_xr_rollback_fpd(duthost_console)
    if not success:
        duthost_console.disconnect()
        pytest.fail("XR FPD rollback failed")

    # Step 8: Verify Rollback Completion
    logger.info("Step 8: Verifying Rollback Completion")
    success = verify_xr_rollback(duthost_console)
    if not success:
        duthost_console.disconnect()
        pytest.fail("XR rollback verification failed")

    logger.info("=" * 80)
    logger.info("PHASE 2 Summary:")
    logger.info("    ✅ SONiC → XR Rollback completed")
    logger.info("    ✅ FPD Rollback completed")
    logger.info("    ✅ Verification passed")
    logger.info("=" * 80)

    # ========================================================================
    # PHASE 3: Execute XR → SONiC Migration
    # ========================================================================

    logger.info("")
    logger.info("=" * 80)
    logger.info("PHASE 3: Executing XR → SONiC Migration")
    logger.info("=" * 80)
    logger.info("Converting device back from IOS XR to SONiC OS...")

    # For Phase 3, we'll use SSH-based CiscoHost approach (similar to test_xr2sonic.py)
    # Console is not needed for XR→SONiC migration stages
    logger.info("Creating SSH connection to XR device for migration...")

    # Import CiscoHost dynamically to avoid dependency in console-only scenarios
    from tests.common.devices.cisco import CiscoHost

    cisco_host = CiscoHost(
        ansible_adhoc=ansible_adhoc,
        hostname=duthost.hostname,
        ansible_user=XR_ROOT_USERNAME,
        ansible_passwd=XR_ROOT_PASSWORD
    )
    logger.info(f"SSH connection established to {duthost.hostname} as {XR_ROOT_USERNAME}")

    # Step 9: Download and transfer SONiC artifacts
    logger.info("Step 9: Downloading and transferring SONiC artifacts...")
    success = download_and_transfer_sonic_artifacts(cisco_host, localhost, https_proxy, localhost_minigraph_paths)
    if not success:
        pytest.fail("Failed to download and transfer SONiC artifacts")

    # Step 10: Execute Intermediate XR Upgrade
    logger.info("Step 10: Executing Intermediate XR Upgrade...")
    success = execute_intermediate_xr_upgrade(cisco_host)
    if not success:
        pytest.fail("Intermediate XR upgrade failed")

    # Step 11: Execute OV Installation
    logger.info("Step 11: Executing OV Installation...")
    success = execute_ov_installation(cisco_host)
    if not success:
        pytest.fail("OV installation failed")

    # Step 12: Execute AV Installation + RP Migration
    logger.info("Step 12: Executing AV Installation + RP Migration...")
    success = execute_av_installation_and_rp_migration(cisco_host)
    if not success:
        pytest.fail("AV installation and RP migration failed")

    # Wait for RP migration to complete and switch to SONiC
    logger.info(f"Waiting {AV_INSTALL_RP_MIGRATION_WAIT} seconds for RP migration to complete...")
    time.sleep(AV_INSTALL_RP_MIGRATION_WAIT)

    # After RP migration, device is running SONiC with vendor factory default
    # credentials. These get rotated to a secure password later in Phase 4.
    logger.info("Creating SonicHost instance after RP migration...")
    sonic_host = SonicHost(
        ansible_adhoc=ansible_adhoc,
        hostname=duthost.hostname,
        ssh_user=SONIC_FACTORY_DEFAULT_USER,
        ssh_passwd=SONIC_FACTORY_DEFAULT_PASSWORD
    )

    # Verify SONiC is accessible
    logger.info("Verifying RP migration to SONiC...")
    version_result = sonic_host.shell("show version", module_ignore_errors=True)
    current_version = version_result.get('stdout', '')
    pytest_assert("SONiC" in current_version, f"RP migration failed - not running SONiC: {current_version}")
    logger.info(f"✓ RP successfully migrated to SONiC: {current_version[:100]}")

    # Step 13: Execute LC Migration
    logger.info("Step 13: Executing LC Migration...")
    success = execute_lc_migration(sonic_host)
    if not success:
        pytest.fail("LC migration failed")

    # Wait before post-migration checks
    logger.info("Waiting 5 minutes before post-migration checks...")
    time.sleep(5 * 60)

    # Step 13.5: Rotate admin password on SUP and all LCs off the vendor
    # factory default. The XR->SONiC migration script (sonic_migration_xr.py)
    # already staged /etc/sonic/minigraph.xml on each module and is
    # responsible for applying the SONiC config; this helper only rotates
    # the admin password so the test framework can talk to the chassis with
    # its real (non-factory) credentials going forward.
    logger.info("Step 13.5: Rotating admin password on supervisor and "
                "line cards (no load_minigraph -- migration script "
                "already applied minigraph.xml on each module)...")
    new_admin_password = creds.get('ansible_altpasswords', ['admin'])[0]
    # Build list of line card hostnames (everything in duthosts except the
    # supervisor) so chpasswd can SSH directly to each LC, rather than
    # rexec'ing through the SUP.
    lc_hostnames = [d.hostname for d in duthosts
                    if d.hostname != duthost.hostname]
    logger.info(f"Line cards discovered for password rotation: {lc_hostnames}")
    rotated_sup = rotate_admin_password_post_migration(
        ansible_adhoc=ansible_adhoc,
        dut_hostname=duthost.hostname,
        new_password=new_admin_password,
        lc_hostnames=lc_hostnames,
    )
    if rotated_sup is None:
        pytest.fail("Failed to rotate admin password on modules after migration")
    # Replace sonic_host with the rotated-credentials handle for all
    # subsequent steps; the factory-default one is no longer valid.
    sonic_host = rotated_sup

    # Step 13.6: Reboot the chassis from the supervisor. On a Cisco T2
    # chassis, rebooting the SUP also reboots all line cards. After the
    # XR->SONiC migration + password rotation, CONFIG_DB on each module is
    # still at vendor factory defaults (CHASSIS_MODULE_TABLE empty), which
    # causes the postcheck (`show chassis modules status`) to fail with
    # EC14046. A full chassis reboot lets each module come up clean and
    # apply its staged /etc/sonic/minigraph.xml so CHASSIS_MODULE_TABLE is
    # populated before Step 14 runs.
    logger.info("Step 13.6: Rebooting chassis from supervisor "
                "(SUP reboot also reboots all LCs on T2)...")
    try:
        sonic_host.shell("/opt/cisco/bin/reload.py -ALL", module_ignore_errors=True)
    except Exception as e:
        logger.warning(f"Reboot command raised exception (expected as SSH "
                       f"is dropped): {type(e).__name__}: {e}")
    reboot_wait_secs = 10 * 60
    logger.info(f"Waiting {reboot_wait_secs}s ({reboot_wait_secs // 60} "
                f"minutes) for chassis to reboot and all modules to come up...")
    time.sleep(reboot_wait_secs)

    # Reconnect to SUP with the rotated password and verify it is
    # responsive before running postcheck. Retry a few times in case the
    # SUP is still finishing boot.
    logger.info("Reconnecting to supervisor after chassis reboot...")
    post_reboot_sup = None
    max_post_reboot_attempts = 10
    post_reboot_backoff = 30
    for attempt in range(1, max_post_reboot_attempts + 1):
        try:
            candidate = SonicHost(
                ansible_adhoc=ansible_adhoc,
                hostname=duthost.hostname,
                ssh_user=SONIC_FACTORY_DEFAULT_USER,
                ssh_passwd=new_admin_password,
            )
            whoami = candidate.shell("whoami", module_ignore_errors=True)
            stdout = (whoami.get('stdout', '') or '').strip()
            if (whoami.get('rc', 1) == 0
                    and not whoami.get('failed', False)
                    and not whoami.get('unreachable', False)
                    and stdout):
                logger.info(f"✓ Supervisor reachable on attempt {attempt} "
                            f"(whoami={stdout!r})")
                post_reboot_sup = candidate
                break
        except Exception as e:
            logger.warning(f"Post-reboot reconnect attempt {attempt} raised: "
                           f"{type(e).__name__}: {e}")
        logger.warning(f"Supervisor not yet reachable (attempt "
                       f"{attempt}/{max_post_reboot_attempts}); sleeping "
                       f"{post_reboot_backoff}s...")
        time.sleep(post_reboot_backoff)
    if post_reboot_sup is None:
        pytest.fail("Supervisor did not come back up after chassis reboot")
    sonic_host = post_reboot_sup

    # Step 14: Execute Post-Migration Checks
    logger.info("Step 14: Executing Post-Migration Checks...")
    success = execute_post_migration_checks(sonic_host)
    if not success:
        pytest.fail("Post-migration checks failed")

    # Final validation
    logger.info("Performing final SONiC validation...")
    version_result = sonic_host.shell("show version", module_ignore_errors=True)
    final_version = version_result.get('stdout', '')
    pytest_assert("SONiC" in final_version, f"Final validation failed - not running SONiC: {final_version}")

    # ========================================================================
    # PHASE 4: Security - Rotate Passwords on All DUTs
    # ========================================================================

    logger.info("")
    logger.info("=" * 80)
    logger.info("PHASE 4: Security - Rotating Passwords on All DUTs")
    logger.info("=" * 80)
    logger.info("Changing default credentials (admin/password) to secure password...")

    # Get new password from creds; fail fast if not configured (do not fall back to a literal)
    new_password = creds.get('sonicadmin_password')
    if not new_password:
        alt_passwords = creds.get('ansible_altpasswords') or []
        new_password = alt_passwords[0] if alt_passwords else None
    if not new_password:
        pytest.fail(
            "No password available for rotation: set 'sonicadmin_password' or "
            "'ansible_altpasswords' in creds before running Phase 4."
        )

    # Rotate passwords on all DUTs (supervisor, line cards, etc.)
    password_results = rotate_passwords_on_all_duts(duthosts, 'admin', new_password)

    # Check if all password rotations succeeded
    all_success = all(password_results.values())

    if not all_success:
        failed_hosts = [host for host, success in password_results.items() if not success]
        logger.warning(f"Password rotation failed on some DUTs: {failed_hosts}")
        logger.warning("These DUTs are still using default credentials (admin/password)")
    else:
        logger.info("✓ All DUT passwords successfully rotated")

    # Final Summary - Complete Cycle
    logger.info("")
    logger.info("=" * 80)
    logger.info("COMPLETE MIGRATION CYCLE TEST SUMMARY")
    logger.info("=" * 80)
    logger.info(f"  Device: {dut_hostname}")
    logger.info(f"  HWSKU: {hwsku}")
    logger.info("")
    logger.info("  PHASE 1 - Pre-check:")
    logger.info(f"    ✅ Minigraphs collected: {len(minigraph_files)}")
    logger.info("    ✅ XR rollback files downloaded")
    logger.info("    ✅ Migration script copied")
    logger.info("")
    logger.info("  PHASE 2 - SONiC → XR Rollback:")
    logger.info("    ✅ SONiC → XR Rollback completed")
    logger.info("    ✅ FPD Rollback completed")
    logger.info("    ✅ Verification passed")
    logger.info("")
    logger.info("  PHASE 3 - XR → SONiC Migration:")
    logger.info("    ✅ SONiC artifacts transferred")
    logger.info("    ✅ Intermediate XR Upgrade completed")
    logger.info("    ✅ OV Installation completed")
    logger.info("    ✅ AV Installation + RP Migration completed")
    logger.info("    ✅ LC Migration completed")
    logger.info("    ✅ Post-Migration Checks passed")
    logger.info("")
    logger.info("  PHASE 4 - Security:")
    if all_success:
        logger.info(f"    ✅ Password rotated on all {len(password_results)} DUTs")
        logger.info("    ✅ New credentials: admin/********")
    else:
        logger.info(f"    ⚠️  Password rotation: {sum(password_results.values())}/{len(password_results)} successful")
        logger.info("    ⚠️  Some DUTs still using: admin/password")
    logger.info("")
    logger.info("  Final State: Running SONiC OS")
    if all_success:
        logger.info("  Final Credentials: admin/******** (password rotated)")
    else:
        logger.info("  Final Credentials: Mixed (check logs above)")
    logger.info("=" * 80)

    logger.info("✅ Complete migration cycle test passed successfully!")
    logger.info("=== Test Complete - Device cycled: SONiC → XR → SONiC ===")

    if not all_success:
        logger.warning("⚠️  WARNING: Some DUTs still have default credentials - manual password rotation recommended")


def execute_xr_rollback(duthost_console):
    """
    Execute the XR rollback process from SONiC.

    This function:
    1. Triggers the rollback with --rollback flag
    2. Waits for device reload
    3. Handles XR initial credential setup with cisco/cisco123
    4. Logs in to XR after credential reset

    Args:
        duthost_console: Console connection fixture

    Returns:
        bool: True if rollback succeeded, False otherwise
    """
    logger.info("=== Starting XR Rollback Execution ===")

    try:
        # Set timeout for initial command
        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT

        # Step 1: Trigger rollback
        logger.info(f"Triggering rollback: sudo python {SUPERVISOR_STORAGE_DIR}/{MIGRATION_SCRIPT_NAME} --rollback")
        duthost_console.write_channel(
            f"sudo python {SUPERVISOR_STORAGE_DIR}/{MIGRATION_SCRIPT_NAME} --rollback{duthost_console.RETURN}"
        )

        # Wait for the script to start xrmigration.sh
        logger.info("Waiting for rollback script to execute xrmigration.sh...")
        read_con(duthost_console, "ROLLBACK_SONIC: Execute xrmigration.sh - device will reload")
        logger.info("Rollback script started successfully - device will reload")

        # Step 2: Wait for device reload and XR boot (this takes a long time)
        logger.info("Waiting for device to reload and boot to XR...")
        duthost_console.timeout = CONSOLE_LONG_COMMAND_TIMEOUT  # 2000 seconds

        read_con(duthost_console, "Press RETURN to get started.")
        logger.info("Device has booted to XR - reached initial setup prompt")

        # Step 3: Initial XR credential setup
        logger.info("Performing initial XR credential setup (sleeping 10 minutes for system stabilization)...")
        duthost_console.timeout = CONSOLE_LONG_COMMAND_TIMEOUT
        time.sleep(600)  # 10 minute wait for system to stabilize

        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT

        logger.info(f"Setting up root-system username as '{XR_ROOT_USERNAME}'...")
        duthost_console.write_and_poll(duthost_console.RETURN, "Enter root-system username:")
        duthost_console.write_and_poll(XR_ROOT_USERNAME, "Enter secret:")
        duthost_console.write_and_poll(XR_ROOT_PASSWORD, "Enter secret again:")
        duthost_console.write_and_poll(XR_ROOT_PASSWORD, "Username:")

        logger.info("Logging in with new credentials...")
        duthost_console.write_and_poll(XR_ROOT_USERNAME, "Password:")
        duthost_console.write_and_poll(XR_ROOT_PASSWORD, XR_PROMPT)

        logger.info(f"Successfully logged in to XR as '{XR_ROOT_USERNAME}' after rollback")
        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT
        time.sleep(60)  # Wait for system to settle

        logger.info("=== XR Rollback Execution Completed Successfully ===")
        return True

    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Connection/timeout error during XR rollback execution: {e}")
        return False
    except RuntimeError as e:
        logger.error(f"Runtime error during XR rollback execution: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during XR rollback execution: {e}")
        logger.error(traceback.format_exc())
        return False


def execute_xr_rollback_fpd(duthost_console):
    """
    Execute the XR rollback FPD update for line cards.

    This function:
    1. Runs rollback script again in XR to update FPD
    2. Waits for line card reloads
    3. Logs back in to XR

    Args:
        duthost_console: Console connection fixture

    Returns:
        bool: True if FPD rollback succeeded, False otherwise
    """
    logger.info("=== Starting XR Rollback FPD Update ===")

    try:
        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT

        # Step 1: Execute rollback script for FPD update
        logger.info(f"Executing FPD rollback: run python /mnt/mtd0/{MIGRATION_SCRIPT_NAME} --rollback")
        duthost_console.write_channel(
            f"run python /mnt/mtd0/{MIGRATION_SCRIPT_NAME} --rollback{duthost_console.RETURN}"
        )

        # Wait for line card reload message
        logger.info("Waiting for line card reload notification...")
        try:
            output = read_con(
                duthost_console,
                "XR_ROLLBACK: Reloading line cards to initiate migration of line cards to IOS XR",
                max_idle_time=300)
            logger.info("Line card reload initiated")
        except TimeoutError as te:
            logger.error(f"Timeout waiting for line card reload message: {te}")
            return False
        except Exception as e:
            if "Socket is closed" in str(e):
                logger.error("Console socket closed while waiting for reload message")
            logger.error(f"Error during FPD rollback: {e}")
            return False

        # Check for errors in the output so far
        if "[ERROR]" in output:
            logger.error("Error detected in FPD rollback output")
            return False

        # Step 2: Wait for line cards to reload and system to come back
        logger.info("Waiting for line cards to reload and system to stabilize...")
        logger.info("This can take several minutes. Keepalives will maintain the connection.")
        duthost_console.timeout = CONSOLE_LONG_COMMAND_TIMEOUT

        try:
            output2 = read_con(duthost_console, "Press RETURN to get started.", max_idle_time=1200)
            logger.info("System has reloaded after FPD update")
            logger.info(f"✓ Console connection alive after reading boot message (last 100 chars: {output2[-100:]})")
        except TimeoutError as te:
            logger.error(f"Timeout waiting for system reload: {te}")
            return False
        except Exception as e:
            if "Socket is closed" in str(e):
                logger.error("Console socket closed during system reload")
            logger.error(f"Error waiting for system reload: {e}")
            return False

        # Check for errors in reload output
        combined_output = output + output2
        if "[ERROR]" in combined_output:
            logger.error("Error detected during FPD rollback")
            return False

        # Step 3: Log back in to XR
        logger.info(f"Logging back in to XR as '{XR_ROOT_USERNAME}' after FPD update...")
        logger.info("Waiting briefly for system to settle...")
        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT
        time.sleep(10)  # Short 10-second wait

        logger.info("Attempting XR login...")
        try:
            duthost_console.write_and_poll(duthost_console.RETURN, "Username:")
            duthost_console.write_and_poll(XR_ROOT_USERNAME, "Password:")
            duthost_console.write_and_poll(XR_ROOT_PASSWORD, XR_PROMPT)
            logger.info("Successfully logged in to XR after FPD update")
        except (ConnectionError, TimeoutError) as e:
            logger.error(f"Connection/timeout error during login: {e}")
            if "Socket is closed" in str(e):
                logger.error("Console socket closed during login attempt")
                logger.error("The system may have rebooted successfully, but we lost connection")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during login attempt: {e}")
            logger.debug(traceback.format_exc())
            return False

        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT
        time.sleep(10)  # Brief wait for system to settle

        logger.info("=== XR Rollback FPD Update Completed Successfully ===")
        return True

    except (ConnectionError, TimeoutError, RuntimeError) as e:
        logger.error(f"Connection/timeout/runtime error during XR rollback FPD update: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during XR rollback FPD update: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def verify_xr_rollback(duthost_console):
    """
    Verify the XR rollback was successful.

    This function:
    1. Runs rollback script again to verify all modules are operational
    2. Waits for verification to complete
    3. Checks for successful completion message

    Args:
        duthost_console: Console connection fixture

    Returns:
        bool: True if verification succeeded, False otherwise
    """
    logger.info("=== Starting XR Rollback Verification ===")

    try:
        duthost_console.timeout = CONSOLE_COMMAND_TIMEOUT

        # Step 1: Execute rollback script for verification
        logger.info(f"Executing rollback verification: run python /mnt/mtd0/{MIGRATION_SCRIPT_NAME} --rollback")
        duthost_console.write_channel(
            f"run python /mnt/mtd0/{MIGRATION_SCRIPT_NAME} --rollback{duthost_console.RETURN}"
        )

        # Wait for module healthcheck message
        logger.info("Waiting for module healthcheck...")
        try:
            output = read_con(
                duthost_console,
                "XR_ROLLBACK: Performing module healthcheck for IOS XR",
                max_idle_time=300)
            logger.info("Module healthcheck started")
        except TimeoutError as te:
            logger.error(f"Timeout waiting for healthcheck message: {te}")
            return False
        except Exception as e:
            if "Socket is closed" in str(e):
                logger.error("Console socket closed while waiting for healthcheck message")
                logger.error("This likely means the console server timed out the idle connection")
                logger.error("Consider reducing wait times or adding more frequent keepalives")
            logger.error(f"Error waiting for healthcheck: {e}")
            return False

        # Step 2: Wait for verification completion (this can take up to 600 seconds)
        logger.info("Waiting for verification to complete (healthcheck runs for up to 600s)...")
        logger.info("Keepalives will be sent automatically every 60s to maintain connection")
        duthost_console.timeout = CONSOLE_LONG_COMMAND_TIMEOUT

        try:
            output2 = read_con(
                duthost_console,
                "EXIT_ON_SUCCESS: SONiC migration script exiting due to successful completion",
                max_idle_time=1200  # 20 minutes max
            )
            logger.info("Verification completed successfully")
        except TimeoutError as te:
            logger.error(f"Timeout waiting for verification completion: {te}")
            logger.error("The healthcheck may still be running or may have failed")
            return False
        except Exception as e:
            if "Socket is closed" in str(e):
                logger.error("Console socket closed during verification")
                logger.error("The verification may have completed, but we lost connection")
                logger.error("You may need to manually verify the rollback status")
            logger.error(f"Error during verification: {e}")
            return False

        # Check for errors
        combined_output = output + output2
        if "[ERROR]" in combined_output:
            logger.error("Error detected during rollback verification")
            return False

        time.sleep(5)  # Brief wait before next steps

        logger.info("=== XR Rollback Verification Completed Successfully ===")
        return True

    except (ConnectionError, TimeoutError, RuntimeError) as e:
        logger.error(f"Connection/timeout/runtime error during XR rollback verification: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during XR rollback verification: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def rotate_password_on_dut(duthost, username, new_password):
    """
    Rotate password for a user on a DUT (supports both SONiC and XR).

    This function can be called manually after test completion to update passwords
    on all DUTs including line cards (LCs) and route processors (RPs).

    Args:
        duthost: DUT host object
        username: Username to change password for
        new_password: New password to set

    Returns:
        bool: True if successful, False otherwise

    Usage:
        # For a single DUT
        rotate_password_on_dut(duthosts['supervisor'], 'admin', 'new_password')

        # For all DUTs in a multi-DUT setup
        for name, dut in duthosts.nodes.items():
            rotate_password_on_dut(dut, 'admin', 'new_password')
    """
    try:
        logger.info(f"Rotating password for user '{username}' on {duthost.hostname}")

        # Use the Ansible 'user' module instead of 'echo ... | chpasswd' so the
        # plaintext password never appears in argv (visible in remote ps, audit
        # logs, and Ansible's command logs even with verbose=False). The user
        # module hashes locally and sends only the hash over the wire.
        salt = crypt.mksalt(crypt.METHOD_SHA512)
        hashed_password = crypt.crypt(new_password, salt)
        result = duthost.user(
            name=username,
            password=hashed_password,
            update_password='always',
            module_ignore_errors=True,
        )

        if not result.get('failed', False):
            logger.info(f"Successfully rotated password for '{username}' on {duthost.hostname}")
            return True
        else:
            logger.error(
                f"Failed to rotate password on {duthost.hostname}: "
                f"{result.get('msg', result.get('stderr', 'Unknown error'))}"
            )
            return False

    except (ConnectionError, TimeoutError) as e:
        logger.error(f"Connection/timeout error while rotating password on {duthost.hostname}: {e}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error while rotating password on {duthost.hostname}: {e}")
        logger.debug(traceback.format_exc())
        return False


def rotate_passwords_on_all_duts(duthosts, username, new_password):
    """
    Rotate password on all DUTs including supervisor, line cards, and route processors.

    Args:
        duthosts: DutHosts object containing all DUTs
        username: Username to change password for
        new_password: New password to set

    Returns:
        dict: Results for each DUT {hostname: success_bool}

    Usage:
        # After test completion
        results = rotate_passwords_on_all_duts(duthosts, 'admin', 'new_password')
        for hostname, success in results.items():
            print(f"{hostname}: {'Success' if success else 'Failed'}")
    """
    results = {}

    logger.info("=" * 80)
    logger.info("Starting password rotation on all DUTs")
    logger.info("=" * 80)

    # Rotate password on all DUTs
    for duthost in duthosts:
        logger.info(f"Processing DUT: {duthost.hostname}")
        results[duthost.hostname] = rotate_password_on_dut(duthost, username, new_password)

    # Summary
    logger.info("=" * 80)
    logger.info("Password Rotation Summary:")
    success_count = sum(1 for success in results.values() if success)
    total_count = len(results)

    for hostname, success in results.items():
        status = "✓ SUCCESS" if success else "✗ FAILED"
        logger.info(f"  {hostname}: {status}")

    logger.info(f"\nTotal: {success_count}/{total_count} successful")
    logger.info("=" * 80)

    return results
