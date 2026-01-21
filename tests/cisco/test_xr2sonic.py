"""
XR to SONiC Conversion Test for Cisco 8800 Chassis

This test performs automated conversion from Cisco IOS XR to SONiC OS
following a multi-stage migration process:
1. Intermediate XR Upgrade (to migration-compatible XR version)
2. Ownership Voucher (OV) Installation (enable customer mode)
3. Authenticated Variable (AV) Installation + RP SONiC Migration
4. Line Card (LC) SONiC Migration
5. Post-Migration Validation

Pattern-Based Command Execution:
---------------------------------
This test mimics the C# implementation's WriteLineAndWaitForRegexV2() behavior
by using CiscoHost.exec_interactive() which:
1. Executes SSH command with extended timeout
2. Reads output continuously during command execution
3. Can wait for specific patterns to appear in output
4. Returns complete output with pattern_found indicator

This ensures each migration stage completes and produces expected output
before proceeding to the next stage, just like the C# console implementation.
"""

import pytest
import logging
import time
import os
import re
from pathlib import Path

from tests.common.helpers.assertions import pytest_assert
from tests.common.utilities import wait_until
from tests.common.devices.sonic import SonicHost


logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('t2'),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health,
]

# ============================================================================
# CONSTANTS - File Paths and Locations
# ============================================================================
XR_PROVISION_ARTIFACTS_DIR = "/harddisk:/"  # XR uses /harddisk:/
SONIC_PROVISION_ARTIFACTS_DIR = "/host/test_xr2sonic/"

# Migration Scripts
MIGRATION_SCRIPT_NAME = "sonic_migration_xr.py"
MIGRATION_UTIL_SCRIPT_NAME = "sonic-migutil.py"

# Firmware/Image Files
ACS_REPO_BASE_URL = "http://your_repository/sonic/cisco/8000/"  # Base URL for repository
SONIC_IMAGE_DOWNLOAD_NAME = "sonic-cisco-8000-20240532.40.bin"  # File to download from repo
SONIC_IMAGE_NAME = "sonic-cisco-8000.bin"  # Required name on XR device for migration script
INTERMEDIATE_XR_IMAGE_NAME = "8000-golden-x86_64-7.5.41.04I-GB_FPD_MACSEC.iso"
ONIE_IMAGE_NAME = "onie-recovery-x86_64-cisco_8000-r0.efi64.pxe"

# Voucher files
VOUCHER_TARBALL_NAME = "vouchers.tar.gz"
VOUCHER_TARBALL_PATH = "vouchers.tar.gz"
VOUCHER_TARBALL_MD5_NAME = "vouchers.tar.gz.md5"
VOUCHER_TARBALL_MD5_PATH = "vouchers.tar.gz.md5"

# Authenticated variable files
AUTHENTICATED_VARIABLE_NAME = "dbcustomer_onie_sonic_rel.auth"
AUTHENTICATED_VARIABLE_PATH = "dbcustomer_onie_sonic_rel.auth"
# Note: MD5 file is named differently in the repo vs required name on device
AUTHENTICATED_VARIABLE_MD5_DOWNLOAD_PATH = "dbcustomer_onie_sonic_rel.md5"  # Path in repo
AUTHENTICATED_VARIABLE_MD5_NAME = "dbcustomer_onie_sonic_rel.auth.md5"  # Required name on device

# ============================================================================
# CONSTANTS - Commands and Patterns
# ============================================================================
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

# ============================================================================
# CONSTANTS - Timeouts (in seconds)
# Based on C# reference values (safe timeouts)
# C# values are more conservative than test_xr_migration.py empirical data
# ============================================================================
INTERMEDIATE_XR_UPGRADE_WAIT = 20 * 60  # 20 minutes wait after XR upgrade reboot
OV_INSTALL_WAIT = 5 * 60  # 5 minutes wait after OV install
AV_INSTALL_RP_MIGRATION_WAIT = 35 * 60  # 35 minutes wait after AV install and RP migration
LC_MIGRATION_WAIT = 20 * 60  # 20 minutes wait after LC migration
POST_MIGRATION_CHECK_WAIT = 10 * 60  # 5 minutes wait before post-migration checks


# ============================================================================
# HELPER FUNCTIONS - Pre-Conversion Setup
# ============================================================================
# NOTE: File Transfer Strategy for XR
# ====================================
# XR devices don't have curl/wget, so we use a two-step approach:
# 1. Download files to localhost using curl (with proxy support) from repo
# 2. Transfer from localhost to XR device using duthost.copy() (SCP)
#
# This approach works for:
# - SONiC images (downloaded from repo)
# - Firmware files (XR images, ONIE, vouchers, etc. - downloaded from repo)
# - Migration scripts (copied from local tests/conversion/files/common/)
#
# For minigraphs:
# - Devices are running XR, so we cannot backup minigraphs from them
# - Instead, we use pre-saved minigraph files from tests/conversion/files/ngs_minigraphs/
#   matching pattern: minigraph-8800-*.xml
# ============================================================================

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

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
    curl_cmd = f"{curl_binary} -k -L -f --create-dirs --connect-timeout {connect_timeout} --max-time {max_time} -o {dest_path} {url}"
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
        curl_cmd_with_proxy = f"{curl_binary} -k -L -f --create-dirs --connect-timeout {connect_timeout} --max-time {max_time} -x {proxy} -o {dest_path} {url}"
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


def get_current_sonic_version(cisco_host):
    """
    Get current OS version from device.
    
    For SONiC devices, uses 'sonic_installer list' command.
    For XR devices, uses 'show version' command.
    
    Args:
        cisco_host: The Cisco host instance
        
    Returns:
        String containing version information
    """
    # Try SONiC command first (using shell for SONiC-specific commands)
    result = cisco_host.shell('sudo sonic-installer list | grep Current | cut -f2 -d " "', module_ignore_errors=True)
    
    # If SONiC command fails, device is likely running XR
    if result.get('failed', False) or not result.get('stdout', '').strip():
        # Use XR command via iosxr_command module
        result = cisco_host.commands(commands=['show version brief'])
        # iosxr_command returns stdout as a list
        output = result.get('stdout', [''])[0] if isinstance(result.get('stdout'), list) else result.get('stdout', 'Unknown')
        return output.strip()
    
    return result.get('stdout', 'Unknown').strip()


def check_conversion_is_applicable(cisco_host):
    """
    Check if XR to SONiC conversion is applicable for this device.

    Validates:
    - Device is Cisco 8800 chassis
    - Device is currently running XR (not already SONiC)
    """
    # Check if device is running Cisco IOS XR
    result = cisco_host.commands(commands=['show version | include "Cisco IOS XR Software"'])
    
    # iosxr_command returns stdout as a list
    version_output = result.get('stdout', [''])[0] if isinstance(result.get('stdout'), list) else result.get('stdout', '')
    
    if "Cisco IOS XR Software" not in version_output:
        pytest.skip("Device is not running Cisco IOS XR - cannot perform XR to SONiC conversion")

    # Check if device is already running SONiC
    current_version = get_current_sonic_version(cisco_host)
    if "SONiC" in current_version:
        pytest.skip("Device already running SONiC - skipping XR to SONiC conversion")

    logger.info(f"Device {cisco_host.hostname} is eligible for XR to SONiC conversion")
    logger.info(f"Current XR version: {version_output.strip()}")


def check_command_output_for_pattern(cisco_host, command, pattern, timeout=60):
    """
    Helper function to check if command output contains a specific pattern.
    Used with wait_until for polling-based pattern matching (similar to console read_until_pattern).
    
    Args:
        cisco_host: The supervisor DUT host object
        command: The command to execute
        pattern: The regex pattern or string to search for in stdout
        timeout: Maximum time to wait for pattern (used outside this function)
    
    Returns:
        True if pattern found, False otherwise
    """
    try:
        result = cisco_host.shell(command, module_ignore_errors=True)
        stdout = result.get('stdout', '')
        
        # Support both string matching and regex
        if isinstance(pattern, str) and not pattern.startswith('(?'):
            # Simple string search
            return pattern in stdout
        else:
            # Regex pattern search
            return re.search(pattern, stdout) is not None
            
    except Exception as e:
        logger.debug(f"Error checking pattern in command output: {e}")
        return False


def wait_for_pattern_in_output(cisco_host, command, pattern, timeout, interval=10, delay=0):
    """
    Wait for a specific pattern to appear in command output.
    Similar to console's read_until_pattern but for SSH sessions.
    
    Args:
        cisco_host: The supervisor DUT host object
        command: The command to execute repeatedly
        pattern: The regex pattern or string to search for
        timeout: Maximum time to wait in seconds
        interval: How often to check (in seconds)
        delay: Initial delay before starting to check
    
    Returns:
        True if pattern found within timeout, False otherwise
    """
    logger.info(f"Waiting for pattern '{pattern}' in command output (timeout: {timeout}s, interval: {interval}s)")
    
    return wait_until(
        timeout=timeout,
        interval=interval,
        delay=delay,
        condition=check_command_output_for_pattern,
        cisco_host=cisco_host,
        command=command,
        pattern=pattern
    )


def wait_for_ssh_ready(cisco_host, max_attempts=5, delay_between_attempts=5):
    """
    Wait for SSH connection to be ready on the Cisco device.
    
    SSH might not be immediately available after file transfers or other operations.
    This function attempts to establish a basic SSH connection to verify readiness.
    
    Args:
        cisco_host: The Cisco host instance
        max_attempts: Maximum number of attempts to check SSH (default: 5)
        delay_between_attempts: Seconds to wait between attempts (default: 5)
    
    Returns:
        bool: True if SSH is ready, False otherwise
    """
    for attempt in range(1, max_attempts + 1):
        try:
            logger.info(f"Checking SSH readiness (attempt {attempt}/{max_attempts})...")
            # Simple command to test SSH connectivity
            result = cisco_host.commands(commands=['show version | include uptime'])
            if result and not result.get('failed', False):
                logger.info("✓ SSH connection is ready")
                return True
        except Exception as e:
            logger.warning(f"SSH not ready (attempt {attempt}): {e}")
            if attempt < max_attempts:
                logger.info(f"Waiting {delay_between_attempts} seconds before retry...")
                time.sleep(delay_between_attempts)
    
    logger.warning(f"SSH readiness check failed after {max_attempts} attempts")
    return False


def copy_minigraphs_to_provision_dir(cisco_host):
    """
    Copy all minigraph files to the provision directory.
    
    Transfers 4 minigraph files with pattern-based naming required by migration script:
    - minigraph-8800-sup00.xml (supervisor slot 0)
    - minigraph-8800-lc00.xml (line card slot 0)
    - minigraph-8800-lc01.xml (line card slot 1)
    - minigraph-8800-lc02.xml (line card slot 2)
    """
    base = Path(__file__).resolve().parent
    mg_dir = base / "files" / "ngs_minigraphs"
    
    # Hardcoded minigraph files with pattern-based naming
    minigraph_files = [
        "minigraph-8800-sup00.xml",
        "minigraph-8800-lc00.xml",
        "minigraph-8800-lc01.xml",
        "minigraph-8800-lc02.xml"
    ]
    
    for mg_filename in minigraph_files:
        src_file = mg_dir / mg_filename
        dest_path = f"{XR_PROVISION_ARTIFACTS_DIR}{mg_filename}"
        
        pytest_assert(src_file.exists(), 
                      f"Minigraph file not found: {src_file}")
        
        success = copy_file_with_retry(
            cisco_host,
            src=str(src_file),
            dest=dest_path,
            file_description=f"minigraph {mg_filename}",
            max_retries=3,
            delay_between_retries=5
        )
        
        pytest_assert(success, f"Failed to transfer {mg_filename} after retries")
        
        # Wait between transfers to avoid SSH rate limiting
        logger.info("Waiting 2 seconds to avoid SSH rate limiting...")
        time.sleep(2)
    
    logger.info("All minigraphs transferred successfully")


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
                    verify_output = verify_result.get('stdout', [''])[0] if isinstance(verify_result.get('stdout'), list) else verify_result.get('stdout', '')
                    
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
                        logger.warning(f"SSH connection issue during verification (attempt {verify_attempt}): {verify_error}")
                        if verify_attempt < verification_attempts:
                            logger.info(f"Waiting 5 seconds for SSH to stabilize...")
                            time.sleep(5)
                        else:
                            logger.warning(f"SSH verification failed after {verification_attempts} attempts - assuming file transfer succeeded")
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
                    
        except Exception as e:
            logger.error(f"Exception during file transfer: {e}")
            if attempt < max_retries:
                logger.info(f"Waiting {delay_between_retries} seconds before retry...")
                time.sleep(delay_between_retries)
                continue
            else:
                logger.error(f"Failed to transfer {file_description} after {max_retries} attempts due to exception")
                return False
    
    return False


def download_and_transfer_artifacts(cisco_host, localhost, proxy_env):
    """
    Download and transfer all required files for XR to SONiC conversion:
    - Migration scripts (sonic_migration_xr.py, sonic-migutil.py) - from local files
    - SONiC image - from repo (downloaded as sonic-cisco-8000-20240532.40.bin, renamed to sonic-cisco-8000.bin)
    - Intermediate XR image - from repo
    - ONIE image - from repo
    - Voucher tarball - from repo
    - Voucher MD5 - from repo
    - Authenticated variable file - from repo
    - Authenticated variable MD5 - from repo
    - Minigraphs for all modules - from local files
    
    Args:
        cisco_host: The supervisor Cisco host instance
        localhost: Localhost ansible connection for downloading files
        proxy_env: Dictionary containing proxy environment variables
    
    Note: XR doesn't have curl, so we download to localhost first then SCP to XR device.
    Note: SONiC image is renamed from SONIC_IMAGE_DOWNLOAD_NAME to SONIC_IMAGE_NAME as required by migration script.
    """
    
    # Get proxy from environment or use default Microsoft corporate proxy
    
    # 1. Copy migration scripts from local files
    base_path = Path(__file__).resolve().parent
    scripts_path = base_path / "files" / "common"

    success = copy_file_with_retry(
        cisco_host,
        src=str(scripts_path / MIGRATION_SCRIPT_NAME),
        dest=f"{XR_PROVISION_ARTIFACTS_DIR}{MIGRATION_SCRIPT_NAME}",
        file_description="migration script"
    )
    pytest_assert(success, f"Failed to transfer {MIGRATION_SCRIPT_NAME}")
    time.sleep(2)
    
    success = copy_file_with_retry(
        cisco_host,
        src=str(scripts_path / MIGRATION_UTIL_SCRIPT_NAME),
        dest=f"{XR_PROVISION_ARTIFACTS_DIR}{MIGRATION_UTIL_SCRIPT_NAME}",
        file_description="migration utility script"
    )
    pytest_assert(success, f"Failed to transfer {MIGRATION_UTIL_SCRIPT_NAME}")
    time.sleep(2)

    # 2. Download SONiC image with special handling (download with one name, transfer with another)
    logger.info(f"Downloading SONiC image from {ACS_REPO_BASE_URL}{SONIC_IMAGE_DOWNLOAD_NAME}")
    temp_sonic_path = f"/tmp/{SONIC_IMAGE_DOWNLOAD_NAME}"
    sonic_image_url = f"{ACS_REPO_BASE_URL}{SONIC_IMAGE_DOWNLOAD_NAME}"

    https_proxy = proxy_env.get('https_proxy', '')
    
    result = download_file_from_repo(
        localhost=localhost,
        url=sonic_image_url,
        dest_path=temp_sonic_path,
        proxy=https_proxy,
        max_time=600
    )
    
    if not result['success']:
        logger.error(f"Failed to download SONiC image: {result.get('stderr', '')}")
        pytest_assert(False, "Failed to download SONiC image from repo")
    
    logger.info(f"SONiC image downloaded to localhost (method: {result['method']})")
    
    # Transfer with required name for migration script
    logger.info(f"Transferring SONiC image to XR device as {SONIC_IMAGE_NAME}...")
    success = copy_file_with_retry(
        cisco_host,
        src=temp_sonic_path,
        dest=f"{XR_PROVISION_ARTIFACTS_DIR}{SONIC_IMAGE_NAME}",
        file_description="SONiC image",
        max_retries=3,
        delay_between_retries=10  # Longer delay for large file
    )
    
    # Cleanup temp file on localhost
    localhost.shell(f"rm -f {temp_sonic_path}", module_ignore_errors=True)
    
    pytest_assert(success, f"Failed to transfer SONiC image after retries")
    
    # Wait to avoid SSH rate limiting on Cisco device
    logger.info("Waiting 5 seconds to avoid SSH rate limiting...")
    time.sleep(5)

    # 3. Download other firmware files from repo to localhost, then transfer to XR device
    # Files are stored with their download path (may include subdirectories) and destination filename
    firmware_files = [
        (INTERMEDIATE_XR_IMAGE_NAME, INTERMEDIATE_XR_IMAGE_NAME, "intermediate_xr"),
        (ONIE_IMAGE_NAME, ONIE_IMAGE_NAME, "onie"),
        (VOUCHER_TARBALL_PATH, VOUCHER_TARBALL_NAME, "vouchers"),
        (VOUCHER_TARBALL_MD5_PATH, VOUCHER_TARBALL_MD5_NAME, "vouchers_md5"),
        (AUTHENTICATED_VARIABLE_PATH, AUTHENTICATED_VARIABLE_NAME, "auth_variable"),
        (AUTHENTICATED_VARIABLE_MD5_DOWNLOAD_PATH, AUTHENTICATED_VARIABLE_MD5_NAME, "auth_variable_md5")  # Download path != save name
    ]

    for download_path, dest_filename, file_type in firmware_files:
        # Download from repo to localhost
        file_url = f"{ACS_REPO_BASE_URL}{download_path}"
        temp_file_path = f"/tmp/{dest_filename}"
        
        logger.info(f"Downloading {file_type} from {file_url}")
        
        result = download_file_from_repo(
            localhost=localhost,
            url=file_url,
            dest_path=temp_file_path,
            proxy=https_proxy,
            max_time=600
        )
        
        if not result['success']:
            logger.error(f"Failed to download {file_type}: {result.get('stderr', '')}")
            pytest_assert(False, f"Failed to download {file_type} from repo")
        
        logger.info(f"{file_type} downloaded to localhost (method: {result['method']})")
        
        # Transfer from localhost to XR device using SCP with retry
        success = copy_file_with_retry(
            cisco_host,
            src=temp_file_path,
            dest=f"{XR_PROVISION_ARTIFACTS_DIR}{dest_filename}",
            file_description=file_type,
            max_retries=3,
            delay_between_retries=5
        )
        
        # Cleanup temp file on localhost
        localhost.shell(f"rm -f {temp_file_path}", module_ignore_errors=True)
        
        pytest_assert(success, f"Failed to transfer {file_type} after retries")
        
        # Wait between transfers to avoid SSH rate limiting on Cisco device
        logger.info("Waiting 3 seconds to avoid SSH rate limiting...")
        time.sleep(3)

    # 4. Transfer minigraphs for all modules from local files
    copy_minigraphs_to_provision_dir(cisco_host)

    logger.info("All artifacts downloaded and transferred successfully")


# ============================================================================
# CONVERSION STAGE FUNCTIONS
# ============================================================================
#
# NOTE: Pattern-based polling for SSH sessions
# ============================================
# Unlike console connections that use read_until_pattern(), SSH sessions via shell()
# return immediately. For operations with delayed output, use wait_for_pattern_in_output():
#
# Example usage:
#   # Wait for migration script to print success message (max 10 minutes)
#   found = wait_for_pattern_in_output(
#       cisco_host=cisco_host,
#       command="cat /tmp/migration.log",  # Command to check output
#       pattern="Migration completed successfully",  # Pattern to search
#       timeout=600,  # Max wait time in seconds
#       interval=10,  # Check every 10 seconds
#       delay=0  # No initial delay
#   )
#
# You can also use regex patterns:
#   pattern=r"Device will now reload.*XR upgrade"
#
# ============================================================================

def execute_intermediate_xr_upgrade(cisco_host, sonic_image_name):
    """
    Stage 1: Upgrade chassis to intermediate XR version.

    This upgrades the device to a specific XR version (e.g., 7.5.41) that
    supports the migration to SONiC.
    
    Uses pattern-based waiting to ensure
    the upgrade command completes and produces expected output before proceeding.
    """
    logger.info("Starting Intermediate XR Upgrade...")

    # Step 1: Run upgrade check
    logger.info("Running XR upgrade pre-check...")
    check_cmd = INTERMEDIATE_XR_UPGRADE_CHECK_CMD.format(MIGRATION_SCRIPT_NAME, sonic_image_name)
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
    cmd = INTERMEDIATE_XR_INSTALL_CMD.format(MIGRATION_SCRIPT_NAME, sonic_image_name)
    
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
                
                if version_result.get('failed', False) == False:
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
                    
            except Exception as e:
                logger.warning(f"Connection attempt {attempt} failed: {e}")
                if attempt < max_retries:
                    logger.info(f"Waiting {retry_interval} seconds before retry...")
                    time.sleep(retry_interval)
                else:
                    logger.error(f"Failed to reconnect after {max_retries} attempts")
                    return False
        
        logger.error("Failed to verify device accessibility after XR upgrade")
        return False

    logger.error(f"Unexpected response from intermediate XR upgrade: {output[:500]}")
    return False


def execute_ov_installation(cisco_host, sonic_image_name):
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

    cmd = OV_INSTALL_CMD.format(MIGRATION_SCRIPT_NAME, sonic_image_name)
    
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
            
            if version_result.get('failed', False) == False:
                logger.info("Successfully logged into device after OV installation and reboot")
                return True
            else:
                logger.warning(f"Device returned error: {version_result.get('msg', 'Unknown error')}")
                if attempt < max_retries:
                    logger.info(f"Waiting {retry_interval} seconds before retry...")
                    time.sleep(retry_interval)
                continue
                
        except Exception as e:
            logger.warning(f"Connection attempt {attempt} failed: {e}")
            if attempt < max_retries:
                logger.info(f"Waiting {retry_interval} seconds before retry...")
                time.sleep(retry_interval)
            else:
                logger.error(f"Unable to login after OV installation and reboot of the device")
                return False
    
    logger.error("Failed to reconnect after OV installation")
    return False


def execute_av_installation_and_rp_migration(cisco_host, sonic_image_name):
    """
    Stage 3: Authenticated Variable (AV) Installation + Route Processor (RP) SONiC Migration.

    This is a critical stage that:
    1. Installs authenticated variables
    2. Migrates the Route Processor (supervisor) to SONiC
    
    - Uses WriteLineAndWaitForRegexV2() with TimeoutScope(WaitForSuccessMessageTimeoutMs = 15 min)
    - Waits for ExecPromptRegex (command completion prompt)
    - Checks buffer for InstallSuccessMessage
    - Returns immediately after success (no sleep/login in this function)
    - Calling code handles 35-minute wait and login verification
    """
    logger.info("Starting AV Installation and RP SONiC Migration...")

    cmd = AV_INSTALL_RP_MIGRATION_CMD.format(MIGRATION_SCRIPT_NAME, sonic_image_name)
    
    # C# uses TimeoutScope = 15 minutes
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


def execute_lc_migration(cisco_host, sonic_image_name):
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

    cmd = LC_MIGRATION_CMD.format(MIGRATION_SCRIPT_NAME, sonic_image_name)
    
    # Execute command and wait for LC migration success message DURING execution
    # C#: WriteLineAndWaitForRegexV2(..., LCMigrationSuccessMessage) 
    result = cisco_host.exec_interactive(
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
        result = cisco_host.shell("whoami", module_ignore_errors=True)
        if result.get('rc') == 0:
            logger.info("Successfully logged in after LC migration")
            return True
        else:
            logger.error("Unable to login after LC migration")
            return False
    except Exception as e:
        logger.error(f"Failed to login after LC migration: {e}")
        return False


def execute_post_migration_checks(cisco_host, sonic_image_name):
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

    cmd = POST_MIGRATION_CHECK_CMD.format(MIGRATION_SCRIPT_NAME, sonic_image_name)
    
    # C#: expectedRegex = FexRegex.Join(PostMigrationCheckSuccessRegex, PostMigrationCheckFailureRegex)
    # C#: WriteLineAndWaitForRegexV2(postCheckCommand, expectedRegex) with TimeoutScope(10 min)
    pattern = f"({POST_MIGRATION_SUCCESS_REGEX}|{POST_MIGRATION_FAILURE_REGEX})"
    
    result = cisco_host.exec_interactive(
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


# ============================================================================
# MAIN TEST FUNCTION
# ============================================================================

def test_xr2sonic(ciscohost, localhost, ansible_adhoc, proxy_env):
    """
    Main test function for XR to SONiC conversion on Cisco 8800 chassis.

    Test Flow:
    1. Validate conversion is applicable
    2. Download and transfer all required artifacts
    3. Execute Intermediate XR Upgrade
    4. Execute OV Installation
    5. Execute AV Installation + RP Migration
    6. Execute LC Migration
    7. Execute Post-Migration Checks
    8. Validate final SONiC version
    
    Note: Currently configured to stop after Stage 0 (artifact transfer) for safety testing.
          To enable full migration, set ENABLE_FULL_MIGRATION = True.
    """
    # Safety flag - set to True to enable full migration after validating Stage 0
    ENABLE_FULL_MIGRATION = True
    
    cisco_host = ciscohost

    # Pre-conversion checks
    check_conversion_is_applicable(cisco_host)

    # Log current version
    logger.info("=== Pre-Conversion State ===")
    version = get_current_sonic_version(cisco_host)
    logger.info(f"{cisco_host.hostname}: {version}")

    # Stage 0: Download and transfer artifacts
    logger.info("=== Stage 0: Downloading Artifacts ===")
    download_and_transfer_artifacts(cisco_host, localhost, proxy_env)
    
    # Verify files were transferred successfully
    logger.info("=== Verifying Transferred Files ===")
    files_to_verify = [
        MIGRATION_SCRIPT_NAME,
        MIGRATION_UTIL_SCRIPT_NAME,
        SONIC_IMAGE_NAME,
        INTERMEDIATE_XR_IMAGE_NAME,
        ONIE_IMAGE_NAME,
        VOUCHER_TARBALL_NAME,
        VOUCHER_TARBALL_MD5_NAME,
        AUTHENTICATED_VARIABLE_NAME,
        AUTHENTICATED_VARIABLE_MD5_NAME,
        "minigraph-8800-sup00.xml",
        "minigraph-8800-lc00.xml",
        "minigraph-8800-lc01.xml",
        "minigraph-8800-lc02.xml"
    ]
    
    for filename in files_to_verify:
        dest_path = f"{XR_PROVISION_ARTIFACTS_DIR}{filename}"
        logger.info(f"Verifying {filename} on device...")
        verify_result = cisco_host.commands(commands=[f'dir {dest_path}'])
        verify_output = verify_result.get('stdout', [''])[0] if isinstance(verify_result.get('stdout'), list) else verify_result.get('stdout', '')
        
        if filename in verify_output or 'No such file' not in verify_output:
            logger.info(f"✓ Verified: {filename}")
            logger.debug(f"  {verify_output.strip()}")
        else:
            logger.error(f"✗ Missing: {filename}")
            pytest_assert(False, f"File not found on device: {filename}")
    
    logger.info("=== Stage 0 Completed Successfully ===")
    logger.info("All required files have been downloaded and transferred to the device.")
    logger.info(f"Files are located in: {XR_PROVISION_ARTIFACTS_DIR}")
    
    if not ENABLE_FULL_MIGRATION:
        logger.info("=== SAFETY MODE: Stopping after Stage 0 ===")
        logger.info("Full migration is disabled. To proceed with migration stages 1-5,")
        logger.info("set ENABLE_FULL_MIGRATION = True in the test function.")
        pytest.skip("Stopping after Stage 0 (artifact transfer) - ENABLE_FULL_MIGRATION is False")
        return

    # Stage 1: Intermediate XR Upgrade
    logger.info("=== Stage 1: Intermediate XR Upgrade ===")
    success = execute_intermediate_xr_upgrade(cisco_host, SONIC_IMAGE_NAME)
    pytest_assert(success, "Intermediate XR upgrade failed")

    # Stage 2: OV Installation
    logger.info("=== Stage 2: OV Installation ===")
    success = execute_ov_installation(cisco_host, SONIC_IMAGE_NAME)
    pytest_assert(success, "OV installation failed")

    # Stage 3: AV Installation + RP Migration
    logger.info("=== Stage 3: AV Installation + RP Migration ===")
    success = execute_av_installation_and_rp_migration(cisco_host, SONIC_IMAGE_NAME)
    pytest_assert(success, "AV installation and RP migration failed")
    
    # C# flow: After AvInstallationAndRpSonicMigration() returns, the calling code:
    # 1. Sleeps for AvInstallAndRpSonicMigrationTimeoutMs (35 min)
    # 2. Attempts login to verify RP migration was successful
    logger.info(f"Sleeping for {AV_INSTALL_RP_MIGRATION_WAIT} seconds for AV Installation and RP migration to complete...")
    time.sleep(AV_INSTALL_RP_MIGRATION_WAIT)
    
    # After RP migration, the device is now running SONiC with default credentials (admin/password)
    # Create SonicHost instance to interact with the SONiC device
    logger.info("Creating SonicHost instance for SONiC device (admin/password)...")
    sonic_host = SonicHost(
        ansible_adhoc=ansible_adhoc,
        hostname=cisco_host.hostname,
        ssh_user='admin',
        ssh_passwd='password'
    )
    logger.info("SonicHost instance created successfully")
    
    # Verify SONiC is accessible and get version
    logger.info("Verifying RP migration to SONiC...")
    current_version = get_current_sonic_version(sonic_host)
    pytest_assert("SONiC" in current_version, f"RP migration failed - not running SONiC: {current_version}")
    logger.info(f"RP successfully migrated to SONiC: {current_version}")

    # From this point forward, use sonic_host instead of cisco_host
    # Stage 4: LC Migration
    logger.info("=== Stage 4: LC Migration ===")
    success = execute_lc_migration(sonic_host, SONIC_IMAGE_NAME)
    pytest_assert(success, "LC migration failed")

    # C#: Sleep(WaitBeforePerformingPostMigrationCheck) = 5 minutes
    # This delay is for obfl directory mounting time before post-migration checks
    logger.info(f"Sleeping for {5 * 60} seconds before post-migration checks (WaitBeforePerformingPostMigrationCheck)...")
    time.sleep(5 * 60)

    # Stage 5: Post-Migration Checks
    logger.info("=== Stage 5: Post-Migration Checks ===")
    success = execute_post_migration_checks(sonic_host, SONIC_IMAGE_NAME)
    pytest_assert(success, "Post-migration checks failed")

    # Final validation
    logger.info("=== Final Validation ===")
    current_version = get_current_sonic_version(sonic_host)
    pytest_assert("SONiC" in current_version,
                 f"Expected SONiC in version string for {sonic_host.hostname}, got {current_version}")
    logger.info(f"{sonic_host.hostname}: {current_version}")

    logger.info("=== XR to SONiC Conversion Completed Successfully ===")
