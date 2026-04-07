#!/usr/bin/python
"""
Ansible module for gathering basic facts for a SONiC host.

Comparing with the dut_basic_facts module, this module is called by __init__ of SonicHost
defined in tests/common/devices/sonic.py to gather facts when creating a SonicHost object.

The dut_basic_facts module is used by the conditional mark plugin to gather facts to be used
while evaluating the conditions of conditional mark plugin.
"""

import json
import os
import yaml

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text
from sonic_py_common import device_info
from swsscommon.swsscommon import ConfigDBConnector

DOCUMENTATION = '''
---
module: sonic_basic_facts
author: Xin Wang (xiwang5@microsoft.com)
short_description: Retrieve basic facts from SONiC host.
description:
    - Retrieve basic facts from SONiC host. This module should only be applied to a SONiC device.
options:
    N/A
'''

EXAMPLES = '''
# Gather SONiC basic facts
- name: Gathering SONiC basic facts
  sonic_basic_facts:

Example output:
{
    "ansible_facts": {
        "basic_facts": {
            "asic_count": 1,
            "asic_type": "vs",
            "hwsku": "Force10-S6100",
            "mgmt_interface": [
                "10.250.0.114/24",
                "fec0::ffff:afa:e/64"
            ],
            "modular_chassis": false,
            "num_asic": 1,
            "platform": "x86_64-kvm_x86_64-r0",
            "platform_asic": "vs",
            "router_mac": "22:84:f5:7c:ed:84",
            "router_subtype": "",
            "router_type": "ToRRouter",
            "switch_type": ""
        },
        "discovered_interpreter_python": "/usr/bin/python3.11",
        "features": {
            "bgp": {
                "auto_restart": "enabled",
                "check_up_status": "false",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "bmp": {
                "auto_restart": "enabled",
                "check_up_status": "false",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "set_owner": "local",
                "state": "enabled",
                "support_syslog_rate_limit": "false"
            },
            "database": {
                "auto_restart": "always_enabled",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "always_enabled",
                "support_syslog_rate_limit": "true"
            },
            "dhcp_relay": {
                "auto_restart": "enabled",
                "check_up_status": "False",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "set_owner": "local",
                "state": "enabled",
                "support_syslog_rate_limit": "True"
            },
            "dhcp_server": {
                "auto_restart": "enabled",
                "check_up_status": "False",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "set_owner": "local",
                "state": "disabled",
                "support_syslog_rate_limit": "False"
            },
            "eventd": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "frr_bmp": {
                "auto_restart": "disabled",
                "check_up_status": "false",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "set_owner": "local",
                "state": "enabled",
                "support_syslog_rate_limit": "false"
            },
            "gbsyncd": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "gnmi": {
                "auto_restart": "enabled",
                "delayed": "True",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "lldp": {
                "auto_restart": "enabled",
                "delayed": "True",
                "has_global_scope": "True",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "macsec": {
                "auto_restart": "enabled",
                "check_up_status": "False",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "set_owner": "local",
                "state": "disabled",
                "support_syslog_rate_limit": "True"
            },
            "mgmt-framework": {
                "auto_restart": "enabled",
                "delayed": "True",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "mux": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "always_disabled",
                "support_syslog_rate_limit": "true"
            },
            "nat": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "disabled",
                "support_syslog_rate_limit": "true"
            },
            "pmon": {
                "auto_restart": "enabled",
                "check_up_status": "false",
                "delayed": "True",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "radv": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "sflow": {
                "auto_restart": "enabled",
                "delayed": "True",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "disabled",
                "support_syslog_rate_limit": "true"
            },
            "snmp": {
                "auto_restart": "enabled",
                "delayed": "True",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "swss": {
                "auto_restart": "enabled",
                "check_up_status": "false",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "syncd": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "teamd": {
                "auto_restart": "enabled",
                "delayed": "False",
                "has_global_scope": "False",
                "has_per_asic_scope": "True",
                "high_mem_alert": "disabled",
                "state": "enabled",
                "support_syslog_rate_limit": "true"
            },
            "telemetry": {
                "delayed": "False",
                "has_global_scope": "True",
                "has_per_asic_scope": "False",
                "state": "disabled"
            }
        },
        "versions": {
            "asic_subtype": "vs",
            "asic_type": "vs",
            "branch": "master",
            "build_date": "Tue Oct 14 12:50:35 UTC 2025",
            "build_number": 963173,
            "build_version": "master.963173-0d6aace3b",
            "built_by": "azureuser@5e07c093c000000",
            "commit_id": "0d6aace3b",
            "debian_version": "12.12",
            "kernel_version": "6.1.0-29-2-amd64",
            "libswsscommon": "1.0.0",
            "release": "none",
            "secure_boot_image": "no",
            "sonic-ctrmgrd-rs": "1.0.0",
            "sonic_os_version": 12,
            "sonic_utilities": 1.2
        }
    },
    "changed": false
}
'''


def sanitize_value(value):
    """
    Convert AnsibleUnsafeText to regular Python strings recursively.

    Args:
        value: Any value that may contain AnsibleUnsafeText strings.

    Returns:
        The same value structure with all strings converted to native Python strings.
    """
    if isinstance(value, dict):
        return {k: sanitize_value(v) for k, v in value.items()}
    elif isinstance(value, list):
        return [sanitize_value(item) for item in value]
    elif isinstance(value, str):
        return to_text(value, errors='surrogate_or_strict')
    else:
        return value


def read_json_file(file_path):
    """Read and parse a JSON file, returning empty dict on error.
    Converts all string values to native Python strings."""
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return sanitize_value(data)
    except (IOError, json.JSONDecodeError):
        return {}


def read_yaml_file(file_path):
    """Read and parse a YAML file, returning empty dict on error.
    Converts all string values to native Python strings."""
    if not os.path.exists(file_path):
        return {}

    try:
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f) or {}
        return sanitize_value(data)
    except (IOError, yaml.YAMLError):
        return {}


def read_text_file(file_path):
    """Read a text file and return its content stripped, or None on error.
    Converts the string to native Python string."""
    if not os.path.exists(file_path):
        return None

    try:
        with open(file_path, 'r') as f:
            content = f.read().strip()
            return to_text(content, errors='surrogate_or_strict') if content else None
    except IOError:
        return None


def get_basic_facts():
    """
    Get basic platform facts from device_info.

    Returns:
        dict: Platform information including platform, hwsku, asic_type, and asic_count.
              Example: {'platform': 'x86_64-kvm_x86_64-r0', 'hwsku': 'Force10-S6000',
                       'asic_type': 'vs', 'asic_count': 1}
    """
    basic_facts = device_info.get_platform_info()

    # Augment with platform.json if available
    platform = basic_facts.get('platform', '')
    if platform:
        platform_json_path = f"/usr/share/sonic/device/{platform}/platform.json"
        platform_json = read_json_file(platform_json_path)
        basic_facts.update(platform_json)

    return basic_facts


def is_chassis(asic_type):
    """
    Check if the device is a modular chassis.

    Args:
        asic_type (str): The ASIC type of the device.

    Returns:
        bool: True if device is a modular chassis, False otherwise.
    """
    try:
        if asic_type == 'vs':
            return device_info.is_chassis()

        import sonic_platform.platform as platform_module
        chassis = platform_module.Platform().get_chassis()
        return chassis.is_modular_chassis()
    except Exception:
        return False


def get_platform_asic(platform):
    """
    Get the platform ASIC type from platform_asic file.

    Args:
        platform (str): The platform name.

    Returns:
        str or None: The ASIC type if found, None otherwise.
    """
    if not platform:
        return None

    platform_asic_path = f"/usr/share/sonic/device/{platform}/platform_asic"
    return read_text_file(platform_asic_path)


def get_sonic_version():
    """
    Get SONiC version information from sonic_version.yml.

    Returns:
        dict: Version information from sonic_version.yml.
    """
    return read_yaml_file('/etc/sonic/sonic_version.yml')


def gather_config_db_facts(config_db, basic_facts):
    """
    Gather facts from ConfigDB and update basic_facts.

    Args:
        config_db (ConfigDBConnector): Connected ConfigDB instance.
        basic_facts (dict): Dictionary to update with ConfigDB facts.
    """
    # Get device metadata
    # Example: {"localhost": {"mac": "...", "hostname": "...", "type": "LeafRouter", ...}}
    metadata = config_db.get_table('DEVICE_METADATA')
    localhost_metadata = metadata.get('localhost', {})

    # Update basic facts with metadata
    basic_facts['num_asic'] = basic_facts.get('asic_count', 1)
    basic_facts['router_mac'] = localhost_metadata.get('mac', '')
    basic_facts['modular_chassis'] = is_chassis(basic_facts.get('asic_type', ''))
    basic_facts['switch_type'] = localhost_metadata.get('switch_type', '')
    basic_facts['router_type'] = localhost_metadata.get('type', '')
    basic_facts['router_subtype'] = localhost_metadata.get('subtype', '')

    # Extract management interface addresses
    # Example: {('eth0', '10.250.0.52/24'): {'gwaddr': '10.250.0.1'}}
    mgmt_interface = config_db.get_table('MGMT_INTERFACE')
    basic_facts['mgmt_interface'] = [key[1] for key in mgmt_interface.keys()]

    # Add platform ASIC if available
    platform_asic = get_platform_asic(basic_facts.get('platform', ''))
    if platform_asic:
        basic_facts['platform_asic'] = platform_asic


def main():
    """Main entry point for the Ansible module."""
    module = AnsibleModule(argument_spec=dict(), supports_check_mode=False)

    try:
        # Gather basic platform facts
        basic_facts = get_basic_facts()

        # Connect to ConfigDB and gather additional facts
        config_db = ConfigDBConnector()
        config_db.connect()
        gather_config_db_facts(config_db, basic_facts)

        # Prepare results
        results = {
            'basic_facts': basic_facts,
            'versions': get_sonic_version(),
            'features': config_db.get_table('FEATURE')
        }

        module.exit_json(ansible_facts=results)

    except Exception as e:
        module.fail_json(msg=str(e))


if __name__ == '__main__':
    main()
