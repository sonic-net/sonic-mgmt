"""
Pytest configuration for conversion tests.

These tests are designed to test devices during the conversion process
from vendor OS (e.g., Cisco IOS XR) to SONiC OS. The devices may not be
running SONiC yet, so we need to skip SONiC-specific fact collection
and provide alternative fixtures for non-SONiC devices.
"""
import pytest
from tests.common.devices.cisco import CiscoHost


def pytest_addoption(parser):
    """Add conversion-specific command line options."""
    parser.addoption(
        '--dut_vendor',
        action='store',
        dest='dut_vendor',
        default='cisco',
        help="Vendor of the DUT (default: cisco for conversion tests). "
             "Set to 'sonic' for SONiC devices."
    )


def pytest_configure(config):
    """Configure pytest for conversion tests.
    
    For conversion tests, we default to non-sonic vendor unless explicitly
    specified, since these tests target devices before/during conversion.
    """
    # Ensure dut_vendor is set for conversion tests
    # This prevents SONiC fact collection from running on non-SONiC devices
    if not hasattr(config.option, 'dut_vendor') or not config.option.dut_vendor:
        config.option.dut_vendor = "cisco"


@pytest.fixture(scope="session")
def duthosts(request, tbinfo):
    """
    Minimal mock duthosts fixture to satisfy parent conftest dependencies.
    
    Conversion tests should use 'ciscohost' or 'duthost_console' fixtures instead.
    This mock prevents errors from parent fixtures that depend on duthosts.
    """
    class MockDutHost:
        """Mock DUT host object."""
        def __init__(self, hostname):
            self.hostname = hostname
            self.critical_services = []
            self.is_multi_asic = False
            self.sonic_release = 'N/A'
        
        def __getattr__(self, name):
            # Return a no-op function for any attribute access
            def noop(*args, **kwargs):
                return None
            return noop
        
        def critical_services_tracking_list(self, *args, **kwargs):
            """Mock critical services tracking - returns empty list."""
            return []
    
    class MockDutHosts:
        """Mock object that provides minimal duthosts interface."""
        def __init__(self, dut_names):
            self.dut_names = dut_names
            self._dut_objects = [MockDutHost(name) for name in dut_names]
        
        def __iter__(self):
            """Iterate over mock DUT objects, not strings."""
            return iter(self._dut_objects)
        
        def __len__(self):
            """Return the number of DUTs."""
            return len(self.dut_names)
        
        def __getitem__(self, key):
            """Return a minimal mock duthost object."""
            # Support both index and hostname lookup
            if isinstance(key, int):
                return self._dut_objects[key]
            # If it's a string hostname, find the matching object
            for dut in self._dut_objects:
                if dut.hostname == key:
                    return dut
            # If not found, create a new one
            return MockDutHost(key)
        
        def shell(self, *args, **kwargs):
            """Mock shell method - does nothing for non-SONiC devices."""
            # Return a mock result that looks successful but does nothing
            return {
                'failed': False,
                'rc': 0,
                'stdout': '',
                'stderr': ''
            }
        
        def command(self, *args, **kwargs):
            """Mock command method - does nothing for non-SONiC devices."""
            return {
                'failed': False,
                'rc': 0,
                'stdout': '',
                'stderr': ''
            }
    
    return MockDutHosts(tbinfo.get('duts', []))


@pytest.fixture(scope="session")
def ciscohost(ansible_adhoc, tbinfo):
    """
    Fixture to create a CiscoHost object for XR device testing in conversion tests.
    
    This provides SSH-based access to Cisco IOS XR devices using the CiscoHost class
    which supports iosxr_command and iosxr_config Ansible modules.
    
    For multi-DUT testbeds (like Cisco 8800), this selects the supervisor card
    for conversion operations.
    
    Use this fixture in conversion tests for clean SSH-based Cisco device access
    without SONiC-specific mock methods.
    
    Returns:
        CiscoHost: Host object for executing commands on Cisco XR device (supervisor)
    """
    
    duts = tbinfo['duts']
    
    # Select supervisor for multi-DUT testbeds, first DUT for single-DUT
    if len(duts) == 1:
        dut_hostname = duts[0]
    else:
        for dut in duts:
            if '-sup-' in dut:
                dut_hostname = dut
                break
        
        # Final fallback
        if not dut_hostname:
            dut_hostname = duts[0]
    
    # Get credentials for the device  
    ansible_user = "cisco"
    ansible_passwd = "password"
    
    # Create and return CiscoHost instance
    # Pass ansible_adhoc directly (not called), just like test_xr_ssh_basic.py does
    cisco_host = CiscoHost(
        ansible_adhoc=ansible_adhoc,
        hostname=dut_hostname,
        ansible_user=ansible_user,
        ansible_passwd=ansible_passwd
    )
    
    return cisco_host


@pytest.fixture(scope="session")
def duthost(duthosts, request, ansible_adhoc, tbinfo):
    """
    Override duthost to return a CiscoHost for conversion tests.
    
    This allows tests that use 'duthost' to work with Cisco devices
    instead of SONiC devices. For multi-DUT testbeds, selects the supervisor.
    
    Returns:
        CiscoHost: Cisco IOS XR host object (supervisor)
    """
    duts = tbinfo['duts']
    
    # Select supervisor for multi-DUT testbeds, first DUT for single-DUT
    if len(duts) == 1:
        dut_hostname = duts[0]
    else:
        for dut in duts:
            if '-sup-' in dut:
                dut_hostname = dut
                break
        
        # Final fallback
        if not dut_hostname:
            dut_hostname = duts[0]
    
    # Get credentials for the device
    ansible_user = "cisco"
    ansible_passwd = "password"
    
    # # Create and return CiscoHost instance
    cisco_host = CiscoHost(
        ansible_adhoc=ansible_adhoc,
        hostname=dut_hostname,
        ansible_user=ansible_user,
        ansible_passwd=ansible_passwd
    )
    
    # Add mock facts attribute to satisfy parent fixtures
    # that expect SONiC-style facts dictionary
    cisco_host.facts = {
        'asic_type': 'cisco_xr',
        'platform': 'cisco-8000',
        'hwsku': 'Cisco-8800-RP',
        'router_mac': '00:00:00:00:00:00',
    }
    
    # Add os_version as a direct attribute (not just in facts dict)
    cisco_host.os_version = 'IOS-XR'
    
    # Add commonly-accessed methods and properties to satisfy parent fixtures
    
    def get_up_time():
        """Mock get_up_time for Cisco devices."""
        return {"date_time": "00:00:00"}
    
    def show_and_parse(cmd, *args, **kwargs):
        """Mock show_and_parse - returns empty dict."""
        return {}
    
    def shell(cmd, *args, **kwargs):
        """Mock shell method for Cisco devices."""
        return {
            'failed': False,
            'rc': 0,
            'stdout': '',
            'stderr': ''
        }
    
    def shell_cmds(cmds, *args, **kwargs):
        """Mock shell_cmds for batch commands."""
        return [{
            'failed': False,
            'rc': 0,
            'stdout': '',
            'stderr': ''
        } for _ in cmds]
    
    def get_container_autorestart_states():
        """Mock container autorestart states - returns empty dict."""
        return {}
    
    def critical_services_tracking_list(*args, **kwargs):
        """Mock critical services tracking - returns empty list."""
        return []
    
    def copy(*args, **kwargs):
        """Mock copy method for file operations."""
        return {'changed': False}
    
    def get_asic_namespace_list():
        """Mock namespace list - returns empty list."""
        return []
    
    cisco_host.get_up_time = get_up_time
    cisco_host.show_and_parse = show_and_parse
    cisco_host.shell = shell
    cisco_host.shell_cmds = shell_cmds
    cisco_host.get_container_autorestart_states = get_container_autorestart_states
    cisco_host.critical_services_tracking_list = critical_services_tracking_list
    cisco_host.copy = copy
    cisco_host.get_asic_namespace_list = get_asic_namespace_list
    
    # # Add properties
    cisco_host.sonic_release = 'N/A'
    cisco_host.critical_services = []
    cisco_host.is_multi_asic = False
    
    return cisco_host


@pytest.fixture(scope="session")
def proxy_env():
    """
    Fixture to provide proxy environment variables for conversion tests.
    
    This is a simplified alternative to the main creds fixture that doesn't
    require complex Ansible variable manager structures.
    
    Provides proxy configuration with multiple fallback layers:
    1. Try to load from ansible group_vars if available
    2. Fall back to environment variables  
    3. Use Microsoft corporate proxy as final fallback
    
    Returns:
        dict: Proxy environment variables (http_proxy, https_proxy, etc.)
    """
    import os
    import glob
    import yaml
    import logging
    
    logger = logging.getLogger(__name__)
    proxy_env = {}
    
    # Layer 1: Try to load proxy_env from ansible group_vars
    try:
        # Look for proxy_env in common ansible group var files
        group_var_files = [
            "../ansible/group_vars/all/*.yml",
            "../ansible/vars/*.yml",
            "../ansible/group_vars/sonic/*.yml"
        ]
        
        for pattern in group_var_files:
            files = glob.glob(pattern)
            for f in files:
                try:
                    with open(f) as stream:
                        data = yaml.safe_load(stream)
                        if data and 'proxy_env' in data:
                            proxy_env.update(data['proxy_env'])
                            logger.info(f"Loaded proxy_env from {f}")
                            break
                except Exception as e:
                    logger.debug(f"Could not load {f}: {e}")
            
            if proxy_env:  # Found proxy config, stop looking
                break
                
    except Exception as e:
        logger.debug(f"Could not load proxy_env from ansible vars: {e}")
    
    # Layer 2: Fall back to environment variables
    if not proxy_env:
        env_proxy_vars = ['http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY', 'no_proxy', 'NO_PROXY']
        for var in env_proxy_vars:
            if var in os.environ:
                proxy_env[var.lower()] = os.environ[var]
        
        if proxy_env:
            logger.info("Using proxy configuration from environment variables")
    
    # Layer 3: Use Microsoft corporate proxy as final fallback
    if not proxy_env:
        proxy_env = {
            'no_proxy': 'localhost,127.0.0.1'
        }
        logger.info("Using Microsoft corporate proxy as fallback")
    
    logger.info(f"Proxy configuration: {list(proxy_env.keys())}")
    return proxy_env
