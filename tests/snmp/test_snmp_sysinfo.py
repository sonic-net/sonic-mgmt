import pytest
import re
import logging
import json

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.topology('any'),
    pytest.mark.snmp
]

def test_snmp_system_info_matches_show_version(duthosts, rand_one_dut_hostname, creds_all_duts, localhost):
    """
    Verify that system information retrieved via SNMP matches the output of 'show version' command.
    
    This test performs the following steps:
    1. Retrieves system information using 'show version' command
    2. Performs SNMP walk to get system information
    3. Compares both outputs to ensure consistency
    
    Args:
        duthosts: Fixture providing access to all DUT hosts
        rand_one_dut_hostname: Fixture selecting a random DUT
        creds_all_duts: Fixture providing SNMP credentials for all DUTs
        localhost: Fixture providing access to localhost
    
    Raises:
        pytest.fail: If any verification step fails
    """
    duthost = duthosts[rand_one_dut_hostname]
    community = creds_all_duts[duthost.hostname]["snmp_rocommunity"]
    
    logger.info("\n" + "="*50)
    logger.info("STARTING SNMP SYSTEM INFO TEST")
    logger.info("="*50)

    # Log test parameters
    logger.info("\nTEST PARAMETERS:")
    logger.info("-"*30)
    logger.info(f"DUT Hostname: {duthost.hostname}")
    logger.info(f"DUT Management IP: {duthost.mgmt_ip}")
    logger.info(f"SNMP Community: {community}")

    # 1. Get and parse show version
    logger.info("\nSTEP 1: EXECUTING SHOW VERSION")
    logger.info("-"*30)
    
    show_version_cmd = 'show version'
    logger.info(f"Executing command: {show_version_cmd}")
    
    show_version_result = duthost.shell(show_version_cmd)
    logger.info("\nCommand Result:")
    logger.info(f"RC: {show_version_result['rc']}")
    logger.info(f"Stdout:\n{show_version_result['stdout']}")
    if show_version_result['stderr']:
        logger.warning(f"Stderr:\n{show_version_result['stderr']}")

    show_version_output = show_version_result['stdout']

    # Parse with detailed logging
    logger.info("\nPARSING SHOW VERSION OUTPUT")
    logger.info("-"*30)
    
    try:
        # Define all regex patterns
        patterns = {
            'hwsku': r"HwSKU:\s+(\S+)",
            'sonic_version': r"SONiC Software Version:\s+(\S+)",
            'platform': r"Platform:\s+(\S+)",
            'asic': r"ASIC:\s+(\S+)",
            'serial': r"Serial Number:\s+(\S+)"
        }

        # Try to extract all values
        parsed_values = {}
        for key, pattern in patterns.items():
            match = re.search(pattern, show_version_output)
            if match:
                parsed_values[key] = match.group(1)
                logger.info(f"Found {key}: {parsed_values[key]}")
            else:
                parsed_values[key] = "N/A"
                logger.warning(f"{key} not found in output")

        # Required values assertion
        assert 'hwsku' in parsed_values and parsed_values['hwsku'] != "N/A", "HwSKU not found"
        assert 'sonic_version' in parsed_values and parsed_values['sonic_version'] != "N/A", "SONiC version not found"

        logger.info("\nParsed Values Summary:")
        logger.info(json.dumps(parsed_values, indent=2))

    except Exception as e:
        logger.error(f"Error parsing 'show version':")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception message: {str(e)}")
        logger.error(f"Raw output that failed parsing:\n{show_version_output}")
        pytest.fail(f"Error parsing 'show version': {e}")

    # 2. Get SNMP facts using Ansible module
    logger.info("\nSTEP 2: GATHERING SNMP FACTS")
    logger.info("-"*30)
    
    try:
        logger.info("Executing snmp_facts module with parameters:")
        logger.info(f"Host: {duthost.mgmt_ip}")
        logger.info(f"Version: v2c")
        logger.info(f"Community: {community}")
        
        snmp_facts = localhost.snmp_facts(
            host=duthost.mgmt_ip,
            version='v2c',
            community=community
        )['ansible_facts']
        
        logger.info("\nSNMP Facts Results:")
        logger.info("-"*20)
        logger.info(f"System Description: {snmp_facts.get('ansible_sysdescr', 'N/A')}")
        logger.info(f"System Name: {snmp_facts.get('ansible_sysname', 'N/A')}")
        logger.info(f"System Object ID: {snmp_facts.get('ansible_sysobjectid', 'N/A')}")
        logger.info(f"System Contact: {snmp_facts.get('ansible_syscontact', 'N/A')}")
        logger.info(f"System Location: {snmp_facts.get('ansible_syslocation', 'N/A')}")
        logger.info(f"System Uptime: {snmp_facts.get('ansible_sysuptime', 'N/A')}")

        assert 'ansible_sysdescr' in snmp_facts, "System description not found in SNMP facts"

    except Exception as e:
        logger.error("SNMP facts gathering failed:")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception message: {str(e)}")
        pytest.fail(f"SNMP facts gathering failed: {e}")

    # 3. Verification
    logger.info("\nSTEP 3: VERIFYING SNMP DATA")
    logger.info("-"*30)
    
    try:
        sysdescr = snmp_facts['ansible_sysdescr']
        logger.info("Verification Details:")
        logger.info(f"SNMP System Description:\n{sysdescr}")
        
        # Verify each value
        for key, value in parsed_values.items():
            if value != "N/A":
                found = value in sysdescr
                logger.info(f"Checking {key}: '{value}' - {'Found' if found else 'Not Found'}")
                if key in ['hwsku', 'sonic_version']:  # Required checks
                    assert found, f"{key} ({value}) not found in system description"

        logger.info("\nAll verifications completed successfully!")

    except Exception as e:
        logger.error("Verification failed:")
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception message: {str(e)}")
        logger.error(f"SNMP System Description: {sysdescr}")
        pytest.fail(f"SNMP data verification failed: {e}")

    logger.info("\n" + "="*50)
    logger.info("TEST COMPLETED SUCCESSFULLY")
    logger.info("="*50 + "\n")

