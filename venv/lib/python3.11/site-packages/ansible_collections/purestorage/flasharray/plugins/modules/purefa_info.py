#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_info
version_added: '1.0.0'
short_description: Collect information from Pure Storage FlashArray
description:
  - Collect information from a Pure Storage Flasharray running the
    Purity//FA operating system. By default, the module will collect basic
    information including hosts, host groups, protection
    groups and volume counts. Additional information can be collected
    based on the configured set of arguments.
author:
  - Pure Storage ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  gather_subset:
    description:
      - When supplied, this argument will define the information to be collected.
        Possible values for this include all, minimum, config, performance,
        capacity, network, subnet, interfaces, hgroups, pgroups, hosts,
        admins, volumes, snapshots, pods, replication, vgroups, offload, apps,
        arrays, certs, kmip, clients, policies, dir_snaps, filesystems,
        alerts, virtual_machines, subscriptions, realms, fleet, presets and
        workloads.
    type: list
    elements: str
    required: false
    default: minimum
extends_documentation_fragment:
  - purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: collect default set of information
  purestorage.flasharray.purefa_info:
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: array_info
- name: show default information
  debug:
    msg: "{{ array_info['purefa_info']['default'] }}"

- name: collect configuration and capacity information
  purestorage.flasharray.purefa_info:
    gather_subset:
      - config
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
  register: array_info
- name: show configuration information
  debug:
    msg: "{{ array_info['purefa_info']['config'] }}"

- name: collect all information
  purestorage.flasharray.purefa_info:
    gather_subset:
      - all
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
- name: show all information
  debug:
    msg: "{{ array_info['purefa_info'] }}"
"""

RETURN = r"""
purefa_info:
  description: Returns the information collected from the FlashArray
  returned: always
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

from datetime import datetime
import time

SEC_TO_DAY = 86400000
ENCRYPTION_STATUS_API_VERSION = "2.6"
DIR_QUOTA_API_VERSION = "2.7"
SHARED_CAP_API_VERSION = "2.9"
PURE_OUI = "naa.624a9370"
SAFE_MODE_VERSION = "2.10"
PER_PG_VERSION = "2.13"
SAML2_VERSION = "2.11"
NFS_USER_MAP_VERSION = "2.15"
DEFAULT_PROT_API_VERSION = "2.16"
VM_VERSION = "2.14"
VLAN_VERSION = "2.17"
NEIGHBOR_API_VERSION = "2.22"
POD_QUOTA_VERSION = "2.23"
AUTODIR_API_VERSION = "2.24"
SUBS_API_VERSION = "2.26"
NSID_API_VERSION = "2.27"
NFS_SECURITY_VERSION = "2.29"
UPTIME_API_VERSION = "2.30"
TLS_CONNECTION_API_VERSION = "2.33"
PWD_POLICY_API_VERSION = "2.34"
RA_API_VERSION = "2.35"
DSROLE_POLICY_API_VERSION = "2.36"
CONTEXT_API_VERSION = "2.38"
QUOTA_API_VERSION = "2.42"


def _is_cbs(array):
    """Is the selected array a Cloud Block Store"""
    model = list(array.get_hardware(filter="type='controller'").items)[0].model
    is_cbs = bool("CBS" in model)
    return is_cbs


def generate_default_dict(array):
    default_info = {}
    api_version = array.get_rest_version()
    default_info["api_versions"] = api_version
    if LooseVersion(VM_VERSION) <= LooseVersion(api_version):
        default_info["virtual_machines"] = len(
            getattr(array.get_virtual_machines(vm_type="vvol"), "items", [])
        )
        default_info["virtual_machine_snaps"] = len(
            getattr(array.get_virtual_machine_snapshots(vm_type="vvol"), "items", [])
        )
    default_info["snapshot_policies"] = len(array.get_policies_snapshot().items)
    default_info["nfs_policies"] = len(array.get_policies_nfs().items)
    default_info["smb_policies"] = len(array.get_policies_smb().items)
    default_info["filesystems"] = len(array.get_file_systems().items)
    default_info["directories"] = len(array.get_directories().items)
    default_info["exports"] = len(array.get_directory_exports().items)
    default_info["directory_snapshots"] = len(array.get_directory_snapshots().items)
    if LooseVersion(DIR_QUOTA_API_VERSION) <= LooseVersion(api_version):
        default_info["quota_policies"] = len(array.get_policies_quota().items)
    if LooseVersion(PWD_POLICY_API_VERSION) <= LooseVersion(api_version):
        default_info["password_policies"] = len(array.get_policies_password().items)
    if LooseVersion(ENCRYPTION_STATUS_API_VERSION) <= LooseVersion(api_version):
        array_data = list(array.get_arrays().items)[0]
        encryption = array_data.encryption
        default_info["encryption_enabled"] = encryption.data_at_rest.enabled
        if default_info["encryption_enabled"]:
            default_info["encryption_algorithm"] = encryption.data_at_rest.algorithm
            default_info["encryption_module_version"] = encryption.module_version
        eradication = array_data.eradication_config
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(api_version):
            default_info["service_mode"] = list(array.get_subscriptions().items)[
                0
            ].service
            default_info["eradication_disabled_days_timer"] = int(
                eradication.disabled_delay / SEC_TO_DAY
            )
            default_info["eradication_enabled_days_timer"] = int(
                eradication.enabled_delay / SEC_TO_DAY
            )
        eradication_delay = getattr(eradication, "eradication_delay", None)
        if eradication_delay is not None:
            default_info["eradication_days_timer"] = int(eradication_delay / SEC_TO_DAY)
        if LooseVersion(SAFE_MODE_VERSION) <= LooseVersion(api_version):
            if eradication.manual_eradication == "all-enabled":
                default_info["safe_mode"] = "Disabled"
            else:
                default_info["safe_mode"] = "Enabled"
        if LooseVersion(UPTIME_API_VERSION) <= LooseVersion(api_version):
            default_info["controller_uptime"] = []
            controllers = list(array.get_controllers().items)
            timenow = datetime.fromtimestamp(time.time())
            for controller in range(0, len(controllers)):
                boottime = datetime.fromtimestamp(
                    controllers[controller].mode_since / 1000
                )
                delta = timenow - boottime
                default_info["controller_uptime"].append(
                    {
                        "controller": controllers[controller].name,
                        "uptime": str(delta),
                    }
                )
    default_info["volume_groups"] = len(list(array.get_volume_groups().items))
    default_info["connected_arrays"] = len(list(array.get_array_connections().items))
    default_info["pods"] = len(list(array.get_pods().items))
    default_info["connection_key"] = list(
        array.get_array_connections_connection_key().items
    )[0].connection_key
    if (
        LooseVersion(TLS_CONNECTION_API_VERSION) <= LooseVersion(api_version)
        and default_info["connected_arrays"] > 0
    ):
        default_info["connection_paths"] = []
        connection_paths = list(array.get_array_connections_path().items)
        for path in range(0, len(connection_paths)):
            default_info["connection_paths"].append(
                {
                    connection_paths[path].name: {
                        "local_port": getattr(
                            connection_paths[path], "local_port", None
                        ),
                        "local_address": getattr(
                            connection_paths[path], "local_address", None
                        ),
                        "remote_port": getattr(
                            connection_paths[path], "remote_port", None
                        ),
                        "remote_address": getattr(
                            connection_paths[path], "remote_address", None
                        ),
                        "status": getattr(connection_paths[path], "status", None),
                        "transport": getattr(
                            connection_paths[path], "replication_transport", None
                        ),
                        "encryption": getattr(
                            connection_paths[path], "encryption", None
                        ),
                        "encryption_mode": getattr(
                            connection_paths[path], "encryption_mode", None
                        ),
                    }
                }
            )
    default_info["array_model"] = list(array.get_controllers().items)[0].model
    default_info["array_name"] = list(array.get_arrays().items)[0].name
    default_info["purity_version"] = list(array.get_arrays().items)[0].version
    default_info["hosts"] = len(list(array.get_hosts().items))
    default_info["snapshots"] = len(list(array.get_volume_snapshots().items))
    default_info["volumes"] = len(list(array.get_volumes().items))
    default_info["protection_groups"] = len(list(array.get_protection_groups().items))
    default_info["hostgroups"] = len(list(array.get_host_groups().items))
    default_info["admins"] = len(list(array.get_admins().items))
    support_info = list(array.get_support().items)[0]
    default_info["remote_assist"] = support_info.remote_assist_status
    if LooseVersion(RA_API_VERSION) <= LooseVersion(api_version):
        default_info["remote_assist_detail"] = {
            "remote_assist_duration": str(
                int(support_info.remote_assist_duration / 3600000)
            )
            + " hours",
        }
        if support_info.remote_assist_expires != 0:
            default_info["remote_assist_detail"]["remote_assist_expires"] = (
                time.strftime(
                    "%Y-%m-%d %H:%M:%S %Z",
                    time.gmtime(support_info.remote_assist_expires / 1000),
                )
            )
        else:
            default_info["remote_assist_detail"]["remote_assist_expires"] = None
        if support_info.remote_assist_opened != 0:
            default_info["remote_assist_detail"]["remote_assist_opened"] = (
                time.strftime(
                    "%Y-%m-%d %H:%M:%S %Z",
                    time.gmtime(support_info.remote_assist_opened / 1000),
                )
            )
        else:
            default_info["remote_assist_detail"]["remote_assist_opened"] = None

    maint_info = list(array.get_maintenance_windows().items)
    if maint_info:
        default_info["maintenance_window"] = [
            {
                "name": maint_info[0].name,
                "created": time.strftime(
                    "%a, %d %b %Y %H:%M:%S %Z",
                    time.localtime(maint_info[0].created / 1000),
                ),
                "expires": time.strftime(
                    "%a, %d %b %Y %H:%M:%S %Z",
                    time.localtime(maint_info[0].expires / 1000),
                ),
            }
        ]
    else:
        default_info["maintenance_window"] = []
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        res = array.get_fleets()
        if res.status_code == 200:
            if len(res.items) > 0:
                default_info["fleet"] = getattr(list(res.items)[0], "name", None)
    else:
        default_info["fleet"] = "Fusion not supported"
    return default_info


def generate_perf_dict(array):
    perf_data = list(array.get_arrays_performance().items)[0]
    perf_info = {
        "bytes_per_mirrored_write": perf_data.bytes_per_mirrored_write,
        "bytes_per_op": perf_data.bytes_per_op,
        "bytes_per_read": perf_data.bytes_per_read,
        "bytes_per_write": perf_data.bytes_per_write,
        "local_queue_usec_per_op": perf_data.bytes_per_write,
        "mirrored_write_bytes_per_sec": perf_data.mirrored_write_bytes_per_sec,
        "mirrored_writes_per_sec": perf_data.mirrored_writes_per_sec,
        "others_per_sec": perf_data.others_per_sec,
        "qos_rate_limit_usec_per_mirrored_write_op": perf_data.qos_rate_limit_usec_per_mirrored_write_op,
        "qos_rate_limit_usec_per_read_op": perf_data.qos_rate_limit_usec_per_read_op,
        "qos_rate_limit_usec_per_write_op": perf_data.qos_rate_limit_usec_per_write_op,
        "queue_usec_per_mirrored_write_op": perf_data.queue_usec_per_mirrored_write_op,
        "queue_usec_per_read_op": perf_data.queue_usec_per_read_op,
        "queue_usec_per_write_op": perf_data.queue_usec_per_write_op,
        "read_bytes_per_sec": perf_data.read_bytes_per_sec,
        "reads_per_sec": perf_data.reads_per_sec,
        "san_usec_per_mirrored_write_op": perf_data.san_usec_per_mirrored_write_op,
        "san_usec_per_read_op": perf_data.san_usec_per_read_op,
        "san_usec_per_write_op": perf_data.san_usec_per_write_op,
        "service_usec_per_mirrored_write_op": perf_data.service_usec_per_mirrored_write_op,
        "service_usec_per_read_op": perf_data.service_usec_per_read_op,
        "service_usec_per_write_op": perf_data.service_usec_per_write_op,
        "usec_per_mirrored_write_op": perf_data.usec_per_mirrored_write_op,
        "usec_per_other_op": perf_data.usec_per_other_op,
        "usec_per_read_op": perf_data.usec_per_read_op,
        "usec_per_write_op": perf_data.usec_per_write_op,
        "write_bytes_per_sec": perf_data.write_bytes_per_sec,
        "writes_per_sec": perf_data.writes_per_sec,
        # These are legacy values. Return 0 for backwards compatability
        "input_per_sec": 0,
        "output_per_sec": 0,
        "queue_depth": 0,
    }
    return perf_info


def generate_config_dict(module, array):
    config_info = {}
    api_version = array.get_rest_version()
    array_info = list(array.get_arrays().items)[0]
    config_info["console_lock"] = ("disabled", "enabled")[
        array_info.console_lock_enabled
    ]
    alert_info = list(array.get_alert_watchers().items)
    config_info["smtp"] = []
    for watcher in range(0, len(alert_info)):
        config_info["smtp"].append(
            {"name": alert_info[watcher].name, "enabled": alert_info[watcher].enabled}
        )
    snmp_info = list(array.get_snmp_managers().items)
    config_info["snmp"] = []
    snmp_agent = list(array.get_snmp_agents().items)[0]
    config_info["snmp"].append(
        {
            "name": snmp_agent.name,
            "host": "localhost",
            "version": snmp_agent.version,
            "user": getattr(snmp_agent.v3, "user", None),
            "auth_password": getattr(snmp_agent.v3, "auth_password", None),
            "auth_protocol": getattr(snmp_agent.v3, "auth_protocol", None),
            "privacy_password": getattr(snmp_agent.v3, "privacy_password", None),
            "privacy_protocol": getattr(snmp_agent.v3, "privacy_protocol", None),
            "notification": getattr(snmp_agent, "notification", None),
            "community": getattr(snmp_agent.v2c, "community", None),
        }
    )
    for manager in range(0, len(snmp_info)):
        config_info["snmp"].append(
            {
                "name": snmp_info[manager].name,
                "host": snmp_info[manager].host,
                "version": snmp_info[manager].version,
                "user": getattr(snmp_info[manager].v3, "user", None),
                "auth_password": getattr(snmp_info[manager].v3, "auth_password", None),
                "auth_protocol": getattr(snmp_info[manager].v3, "auth_protocol", None),
                "privacy_password": getattr(
                    snmp_info[manager].v3, "privacy_password", None
                ),
                "privacy_protocol": getattr(
                    snmp_info[manager].v3, "privacy_protocol", None
                ),
                "notification": snmp_info[manager].notification,
                "community": getattr(snmp_info[manager].v2c, "community", None),
            }
        )
    config_info["snmp_v3_engine_id"] = snmp_agent.engine_id
    smtp_info = list(array.get_smtp_servers().items)[0]
    config_info["smtp_servers"] = {
        "name": smtp_info.name,
        "password": getattr(smtp_info, "password", ""),
        "user_name": getattr(smtp_info, "user_name", ""),
        "encryption_mode": getattr(smtp_info, "encryption_mode", ""),
        "relay_host": getattr(smtp_info, "relay_host", ""),
        "sender_domain": getattr(smtp_info, "sender_domain", ""),
    }
    config_info["directory_service"] = {}
    services = list(array.get_directory_services().items)
    for service in range(0, len(services)):
        service_type = services[service].name
        config_info["directory_service"][service_type] = {
            "base_dn": getattr(services[service], "base_dn", "None"),
            "bind_user": getattr(services[service], "bind_user", "None"),
            "enabled": services[service].enabled,
            "services": services[service].services,
            "uris": services[service].uris,
        }
    config_info["directory_service_roles"] = {}
    roles = list(array.get_directory_services_roles().items)
    for role in range(0, len(roles)):
        role_name = roles[role].role.name
        config_info["directory_service_roles"][role_name] = {
            "group": getattr(roles[role], "group", None),
            "group_base": getattr(roles[role], "group_base", None),
            "management_access_policies": None,
        }
        if LooseVersion(DSROLE_POLICY_API_VERSION) <= LooseVersion(api_version):
            config_info["directory_service_roles"][role_name][
                "management_access_policies"
            ] = getattr(roles[role].management_access_policies[0], "name", None)
    smi_s = list(array.get_smi_s().items)[0]
    config_info["smi-s"] = {
        "slp_enabled": smi_s.slp_enabled,
        "wbem_https_enabled": smi_s.wbem_https_enabled,
    }
    # Add additional SMI-S section to help with formatting
    # issues caused by `-` in the dict name.
    config_info["smi_s"] = {
        "slp_enabled": smi_s.slp_enabled,
        "wbem_https_enabled": smi_s.wbem_https_enabled,
    }
    config_info["dns"] = {}
    dns_configs = list(array.get_dns().items)
    for config in range(0, len(dns_configs)):
        config_info["dns"][dns_configs[config].services[0]] = {
            "nameservers": dns_configs[config].nameservers,
            "domain": dns_configs[config].domain,
        }
        config_info["dns"][dns_configs[config].services[0]]["source"] = getattr(
            dns_configs[config].source, "name", None
        )
    if LooseVersion(SAML2_VERSION) <= LooseVersion(api_version):
        config_info["saml2sso"] = {}
        saml2 = list(array.get_sso_saml2_idps().items)
        if saml2:
            config_info["saml2sso"] = {
                "enabled": saml2[0].enabled,
                "array_url": saml2[0].array_url,
                "name": saml2[0].name,
                "idp": {},
                "sp": {},
            }
            if hasattr(saml2[0], "idp"):
                config_info["saml2sso"]["idp"] = {
                    "url": getattr(saml2[0].idp, "url", None),
                    "encrypt_enabled": saml2[0].idp.encrypt_assertion_enabled,
                    "sign_enabled": saml2[0].idp.sign_request_enabled,
                    "metadata_url": saml2[0].idp.metadata_url,
                }
            if hasattr(saml2[0], "sp"):
                if hasattr(saml2[0].sp, "decryption_credential"):
                    decrypt = getattr(saml2[0].sp.decryption_credential, "name", None)
                else:
                    decrypt = None
                if hasattr(saml2[0].sp, "signing_credential"):
                    sign = getattr(saml2[0].sp.signing_credential, "name", None)
                else:
                    sign = None
                config_info["saml2sso"]["sp"] = {
                    "decrypt_cred": decrypt,
                    "sign_cred": sign,
                }
    config_info["active_directory"] = {}
    res = array.get_active_directory()
    if res.status_code != 200:
        module.warn("FA-Files is not enabled on this array")
    else:
        ad_accounts = list(res.items)
        for ad_account in range(0, len(ad_accounts)):
            ad_name = ad_accounts[ad_account].name
            config_info["active_directory"][ad_name] = {
                "computer_name": ad_accounts[ad_account].computer_name,
                "domain": ad_accounts[ad_account].domain,
                "directory_servers": getattr(
                    ad_accounts[ad_account], "directory_servers", None
                ),
                "kerberos_servers": getattr(
                    ad_accounts[ad_account], "kerberos_servers", None
                ),
                "service_principal_names": getattr(
                    ad_accounts[ad_account], "service_principal_names", None
                ),
                "tls": getattr(ad_accounts[ad_account], "tls", None),
            }
    if LooseVersion(DEFAULT_PROT_API_VERSION) <= LooseVersion(api_version):
        config_info["default_protections"] = {}
        default_prots = list(array.get_container_default_protections().items)
        for prot in range(0, len(default_prots)):
            container = getattr(default_prots[prot], "name", "-")
            config_info["default_protections"][container] = {
                "protections": [],
                "type": getattr(default_prots[prot], "type", "array"),
            }
            for container_prot in range(
                0, len(default_prots[prot].default_protections)
            ):
                config_info["default_protections"][container]["protections"].append(
                    {
                        "type": default_prots[prot]
                        .default_protections[container_prot]
                        .type,
                        "name": default_prots[prot]
                        .default_protections[container_prot]
                        .name,
                    }
                )
    if LooseVersion(SUBS_API_VERSION) <= LooseVersion(api_version):
        array_info = list(array.get_arrays().items)[0]
        config_info["ntp_keys"] = bool(getattr(array_info, "ntp_symmetric_key", None))
        config_info["timezone"] = array_info.time_zone
    config_info["directory_service"] = {}
    ds_info = list(array.get_directory_services().items)
    for dss in range(0, len(ds_info)):
        config_info["directory_service"][ds_info[dss].name] = {
            "base_dn": getattr(ds_info[dss], "base_dn", None),
            "bind_user": getattr(ds_info[dss], "bind_user", None),
            "check_peer": ds_info[dss].check_peer,
            "enabled": ds_info[dss].enabled,
            "services": getattr(ds_info[dss], "services", None),
            "uri": getattr(ds_info[dss], "uris", None),
        }
    config_info["directory_service_roles"] = {}
    roles = list(array.get_directory_services_roles().items)
    for role in range(0, len(roles)):
        role_name = roles[role].name
        config_info["directory_service_roles"][role_name] = {
            "group": getattr(roles[role], "group", None),
            "group_base": getattr(roles[role], "group_base", None),
        }
    config_info["ntp"] = array_info.ntp_servers
    syslog_info = list(array.get_syslog_servers().items)
    config_info["syslog"] = {}
    for syslog in range(0, len(syslog_info)):
        config_info["syslog"][syslog_info[syslog].name] = {
            "uri": syslog_info[syslog].uri,
            "services": syslog_info[syslog].services,
        }
    support_info = list(array.get_support().items)[0]
    config_info["phonehome"] = ("disabled", "enabled")[support_info.phonehome_enabled]
    config_info["proxy"] = support_info.proxy
    config_info["relayhost"] = getattr(smtp_info, "relay_host", "")
    config_info["senderdomain"] = getattr(smtp_info, "sender_domain", "")
    config_info["idle_timeout"] = array_info.idle_timeout
    config_info["scsi_timeout"] = array_info.scsi_timeout
    admin_info = list(array.get_admins_settings().items)[0]
    config_info["global_admin"] = {
        "lockout_duration": getattr(admin_info, "lockout_duration", None),
        "max_login_attempts": getattr(admin_info, "max_login_attempts", None),
        "min_password_length": getattr(admin_info, "min_password_length", None),
        "single_sign_on_enabled": getattr(admin_info, "single_sign_on_enabled", None),
        "active_management_enabled": None,
        "active_management_role": None,
    }
    if (
        config_info["global_admin"]["lockout_duration"]
        and config_info["global_admin"]["lockout_duration"] > 0
    ):
        config_info["global_admin"]["lockout_duration"] = int(
            config_info["global_admin"]["lockout_duration"] / 1000
        )
    return config_info


def generate_filesystems_dict(array, performance):
    files_info = {}
    filesystems = list(array.get_file_systems().items)
    for filesystem in range(0, len(filesystems)):
        fs_name = filesystems[filesystem].name
        files_info[fs_name] = {
            "destroyed": filesystems[filesystem].destroyed,
            "directories": {},
        }
        directories = list(array.get_directories(file_system_names=[fs_name]).items)
        for directory in range(0, len(directories)):
            d_name = directories[directory].directory_name
            files_info[fs_name]["directories"][d_name] = {
                "path": directories[directory].path,
                "data_reduction": directories[directory].space.data_reduction,
                "snapshots_space": getattr(
                    directories[directory].space, "snapshots", None
                ),
                "thin_provisioning": getattr(
                    directories[directory].space, "thin_provisioning", None
                ),
                "total_physical_space": getattr(
                    directories[directory].space, "total_physical", None
                ),
                "total_provisioned_space": getattr(
                    directories[directory].space, "total_provisioned", None
                ),
                "total_reduction": getattr(
                    directories[directory].space, "total_reduction", None
                ),
                "total_used": getattr(directories[directory].space, "total_used", None),
                "unique_space": getattr(directories[directory].space, "unique", None),
                "virtual_space": getattr(directories[directory].space, "virtual", None),
                "destroyed": directories[directory].destroyed,
                "full_name": directories[directory].name,
                "used_provisioned": getattr(
                    directories[directory].space, "used_provisioned", None
                ),
                "exports": [],
                "policies": [],
                "limited_by": None,
                "performance": [],
            }
            if LooseVersion(QUOTA_API_VERSION) <= LooseVersion(
                array.get_rest_version()
            ):
                if hasattr(directories[directory].limited_by, "member"):
                    files_info[fs_name]["directories"][d_name]["limited_by"] = getattr(
                        directories[directory].limited_by.member, "name", None
                    )
            policies = list(
                array.get_directories_policies(
                    member_names=[
                        files_info[fs_name]["directories"][d_name]["full_name"]
                    ]
                ).items
            )
            for policy in range(0, len(policies)):
                files_info[fs_name]["directories"][d_name]["policies"].append(
                    {
                        "enabled": policies[policy].enabled,
                        "policy": {
                            "name": policies[policy].policy.name,
                            "type": policies[policy].policy.resource_type,
                        },
                    }
                )
            exports = list(
                array.get_directory_exports(
                    directory_names=[
                        files_info[fs_name]["directories"][d_name]["full_name"]
                    ]
                ).items
            )
            for export in range(0, len(exports)):
                files_info[fs_name]["directories"][d_name]["exports"].append(
                    {
                        "enabled": exports[export].enabled,
                        "export_name": exports[export].export_name,
                        "policy": {
                            "name": exports[export].policy.name,
                            "type": exports[export].policy.resource_type,
                        },
                    }
                )
            if performance:
                perf_stats = list(
                    array.get_directories_performance(
                        names=[files_info[fs_name]["directories"][d_name]["full_name"]]
                    ).items
                )[0]
                files_info[fs_name]["directories"][d_name]["performance"] = {
                    "bytes_per_op": perf_stats.bytes_per_op,
                    "bytes_per_read": perf_stats.bytes_per_read,
                    "bytes_per_write": perf_stats.bytes_per_write,
                    "others_per_sec": perf_stats.others_per_sec,
                    "read_bytes_per_sec": perf_stats.read_bytes_per_sec,
                    "reads_per_sec": perf_stats.reads_per_sec,
                    "usec_per_other_op": perf_stats.usec_per_other_op,
                    "usec_per_read_op": perf_stats.usec_per_read_op,
                    "usec_per_write_op": perf_stats.usec_per_write_op,
                    "write_bytes_per_sec": perf_stats.write_bytes_per_sec,
                    "writes_per_sec": perf_stats.writes_per_sec,
                }
    return files_info


def generate_pgsnaps_dict(array):
    pgsnaps_info = {}
    snapshots = list(array.get_protection_group_snapshots().items)
    for snapshot in range(0, len(snapshots)):
        s_name = snapshots[snapshot].name
        pgsnaps_info[s_name] = {
            "destroyed": snapshots[snapshot].destroyed,
            "source": snapshots[snapshot].source.name,
            "suffix": snapshots[snapshot].suffix,
            "snapshot_space": snapshots[snapshot].space.snapshots,
            "used_provisioned": getattr(
                snapshots[snapshot].space, "used_provisioned", None
            ),
        }
        try:
            if pgsnaps_info[s_name]["destroyed"]:
                pgsnaps_info[s_name]["time_remaining"] = snapshots[
                    snapshot
                ].time_remaining
        except AttributeError:
            pass
        try:
            pgsnaps_info[s_name]["manual_eradication"] = snapshots[
                snapshot
            ].eradication_config.manual_eradication
        except AttributeError:
            pass
    return pgsnaps_info


def generate_dir_snaps_dict(array):
    dir_snaps_info = {}
    snapshots = list(array.get_directory_snapshots().items)
    for snapshot in range(0, len(snapshots)):
        s_name = snapshots[snapshot].name
        if hasattr(snapshots[snapshot], "suffix"):
            suffix = snapshots[snapshot].suffix
        else:
            suffix = snapshots[snapshot].name.split(".")[-1]
        dir_snaps_info[s_name] = {
            "destroyed": snapshots[snapshot].destroyed,
            "source": snapshots[snapshot].source.name,
            "suffix": suffix,
            "client_name": snapshots[snapshot].client_name,
            "snapshot_space": snapshots[snapshot].space.snapshots,
            "total_physical_space": snapshots[snapshot].space.total_physical,
            "unique_space": snapshots[snapshot].space.unique,
            "used_provisioned": getattr(
                snapshots[snapshot].space, "used_provisioned", None
            ),
        }
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
            dir_snaps_info[s_name]["total_used"] = snapshots[snapshot].space.total_used
        if hasattr(snapshots[snapshot], "policy"):
            dir_snaps_info[s_name]["policy"] = getattr(
                snapshots[snapshot].policy, "name", None
            )
        if dir_snaps_info[s_name]["destroyed"] or hasattr(
            snapshots[snapshot], "time_remaining"
        ):
            dir_snaps_info[s_name]["time_remaining"] = snapshots[
                snapshot
            ].time_remaining
    return dir_snaps_info


def generate_policies_dict(array, quota_available, autodir_available, nfs_user_mapping):
    policy_info = {}
    policies = list(array.get_policies().items)
    for policy in range(0, len(policies)):
        p_name = policies[policy].name
        policy_info[p_name] = {
            "type": policies[policy].policy_type,
            "enabled": policies[policy].enabled,
            "members": [],
            "rules": [],
        }
        members = list(array.get_directories_policies(policy_names=[p_name]).items)
        for member in range(0, len(members)):
            m_name = members[member].member.name
            policy_info[p_name]["members"].append(m_name)
        if policies[policy].policy_type == "smb":
            rules = list(
                array.get_policies_smb_client_rules(policy_names=[p_name]).items
            )
            for rule in range(0, len(rules)):
                smb_rules_dict = {
                    "client": rules[rule].client,
                    "smb_encryption_required": rules[rule].smb_encryption_required,
                    "anonymous_access_allowed": rules[rule].anonymous_access_allowed,
                }
                policy_info[p_name]["rules"].append(smb_rules_dict)
        if policies[policy].policy_type == "nfs":
            if nfs_user_mapping:
                nfs_policy = list(array.get_policies_nfs(names=[p_name]).items)[0]
                policy_info[p_name][
                    "user_mapping_enabled"
                ] = nfs_policy.user_mapping_enabled
                if LooseVersion(SUBS_API_VERSION) <= LooseVersion(
                    array.get_rest_version()
                ):
                    policy_info[p_name]["nfs_version"] = getattr(
                        nfs_policy, "nfs_version", None
                    )
                if LooseVersion(NFS_SECURITY_VERSION) <= LooseVersion(
                    array.get_rest_version()
                ):
                    policy_info[p_name]["security"] = getattr(
                        nfs_policy, "security", None
                    )
            rules = list(
                array.get_policies_nfs_client_rules(policy_names=[p_name]).items
            )
            for rule in range(0, len(rules)):
                nfs_rules_dict = {
                    "access": rules[rule].access,
                    "permission": rules[rule].permission,
                    "client": rules[rule].client,
                }
                if LooseVersion(SUBS_API_VERSION) <= LooseVersion(
                    array.get_rest_version()
                ):
                    nfs_rules_dict["nfs_version"] = rules[rule].nfs_version
                policy_info[p_name]["rules"].append(nfs_rules_dict)
        if policies[policy].policy_type == "snapshot":
            suffix_enabled = bool(
                LooseVersion(array.get_rest_version())
                >= LooseVersion(SHARED_CAP_API_VERSION)
            )
            rules = list(array.get_policies_snapshot_rules(policy_names=[p_name]).items)
            for rule in range(0, len(rules)):
                try:
                    snap_rules_dict = {
                        "at": str(int(rules[rule].at / 3600000)).zfill(2) + ":00",
                        "client_name": rules[rule].client_name,
                        "every": str(int(rules[rule].every / 60000)) + " mins",
                        "keep_for": str(int(rules[rule].keep_for / 60000)) + " mins",
                    }
                except AttributeError:
                    snap_rules_dict = {
                        "at": None,
                        "client_name": rules[rule].client_name,
                        "every": str(int(rules[rule].every / 60000)) + " mins",
                        "keep_for": str(int(rules[rule].keep_for / 60000)) + " mins",
                    }
                if suffix_enabled:
                    try:
                        snap_rules_dict["suffix"] = rules[rule].suffix
                    except AttributeError:
                        snap_rules_dict["suffix"] = ""
                policy_info[p_name]["rules"].append(snap_rules_dict)
        if policies[policy].policy_type == "quota" and quota_available:
            rules = list(array.get_policies_quota_rules(policy_names=[p_name]).items)
            for rule in range(0, len(rules)):
                quota_rules_dict = {
                    "enforced": rules[rule].enforced,
                    "quota_limit": rules[rule].quota_limit,
                    "notifications": rules[rule].notifications,
                }
                policy_info[p_name]["rules"].append(quota_rules_dict)
        if policies[policy].policy_type == "autodir" and autodir_available:
            pass  # there are currently no rules for autodir policies
        if policies[policy].policy_type == "password":
            pwd_policy = list(array.get_policies_password(names=[p_name]).items)[0]
            policy_info[p_name] |= {
                "enabled": pwd_policy.enabled,
                "enforce_dictionary_check": pwd_policy.enforce_dictionary_check,
                "enforce_username_check": pwd_policy.enforce_username_check,
                "lockout_duration": getattr(pwd_policy, "lockout_duration", None),
                "password_history": getattr(pwd_policy, "password_history", None),
                "min_character_groups": pwd_policy.min_character_groups,
                "min_characters_per_group": pwd_policy.min_characters_per_group,
                "min_password_length": pwd_policy.min_password_length,
            }
    return policy_info


def generate_clients_dict(array):
    clients_info = {}
    clients = list(array.get_api_clients().items)
    for client in range(0, len(clients)):
        c_name = clients[client].name
        clients_info[c_name] = {
            "enabled": clients[client].enabled,
            "TTL(seconds)": clients[client].access_token_ttl_in_ms / 1000,
            "key_id": clients[client].key_id,
            "client_id": clients[client].id,
            "max_role": clients[client].max_role,
            "public_key": clients[client].public_key,
        }
    return clients_info


def generate_admin_dict(array):
    admin_info = {}
    admins = list(array.get_admins().items)
    for admin in range(0, len(admins)):
        admin_name = admins[admin].name
        admin_info[admin_name] = {
            "type": ("remote", "local")[admins[admin].is_local],
            "locked": admins[admin].locked,
            "role": getattr(admins[admin].role, "name", None),
            "management_access_policy": None,
        }
        if admins[admin].is_local and LooseVersion(
            array.get_rest_version()
        ) >= LooseVersion(DSROLE_POLICY_API_VERSION):
            if hasattr(admins[admin], "management_access_policies"):
                admin_info[admin_name]["management_access_policy"] = getattr(
                    admins[admin].management_access_policies[0], "name", None
                )
    return admin_info


def generate_subnet_dict(array):
    sub_info = {}
    subnets = list(array.get_subnets().items)
    for sub in range(0, len(subnets)):
        sub_name = subnets[sub].name
        sub_info[sub_name] = {
            "enabled": subnets[sub].enabled,
            "gateway": getattr(subnets[sub], "gateway", None),
            "mtu": subnets[sub].mtu,
            "vlan": subnets[sub].vlan,
            "prefix": subnets[sub].prefix,
            "interfaces": [],
            "services": subnets[sub].services,
        }
        if subnets[sub].interfaces:
            for iface in range(0, len(subnets[sub].interfaces)):
                sub_info[sub_name]["interfaces"].append(
                    subnets[sub].interfaces[iface].name
                )
    return sub_info


def generate_network_dict(array, performance):
    net_info = {}
    ports = list(array.get_network_interfaces().items)
    for port in range(0, len(ports)):
        int_name = ports[port].name
        if ports[port].interface_type == "eth":
            net_info[int_name] = {
                "hwaddr": getattr(ports[port].eth, "mac_address", None),
                "mac_address": getattr(ports[port].eth, "mac_address", None),
                "mtu": getattr(ports[port].eth, "mtu", None),
                "enabled": ports[port].enabled,
                "speed": ports[port].speed,
                "address": getattr(ports[port].eth, "address", None),
                "subinterfaces": [],
                "slaves": [],
                "subnet": getattr(ports[port].eth.subnet, "name", None),
                "services": ports[port].services,
                "gateway": getattr(ports[port].eth, "gateway", None),
                "netmask": getattr(ports[port].eth, "netmask", None),
                "subtype": getattr(ports[port].eth, "subtype", None),
                "vlan": getattr(ports[port].eth, "vlan", None),
                "performance": [],
            }
            if ports[port].eth.subinterfaces:
                for subi in range(0, len(ports[port].eth.subinterfaces)):
                    net_info[int_name]["subinterfaces"].append(
                        ports[port].eth.subinterfaces[subi].name
                    )
                net_info[int_name]["slaves"] = net_info[int_name]["subinterfaces"]
        else:
            net_info[int_name] = {
                "port_name": ports[port].fc.wwn,
                "services": ports[port].services,
                "enabled": ports[port].enabled,
                "performance": [],
            }
    if performance:
        perf_stats = list(array.get_network_interfaces_performance().items)
        for perf_stat in range(0, len(perf_stats)):
            try:
                if perf_stats[perf_stat].interface_type == "fc":
                    net_info[perf_stats[perf_stat].name]["performance"] = {
                        "received_bytes_per_sec": getattr(
                            perf_stats[perf_stat].fc, "received_bytes_per_sec", 0
                        ),
                        "received_crc_errors_per_sec": getattr(
                            perf_stats[perf_stat].fc, "received_crc_errors_per_sec", 0
                        ),
                        "received_frames_per_sec": getattr(
                            perf_stats[perf_stat].fc, "received_frames_per_sec", 0
                        ),
                        "received_link_failures_per_sec": getattr(
                            perf_stats[perf_stat].fc,
                            "received_link_failures_per_sec",
                            0,
                        ),
                        "received_loss_of_signal_per_sec": getattr(
                            perf_stats[perf_stat].fc,
                            "received_loss_of_signal_per_sec",
                            0,
                        ),
                        "received_loss_of_sync_per_sec": getattr(
                            perf_stats[perf_stat].fc, "received_loss_of_sync_per_sec", 0
                        ),
                        "total_errors_per_sec": getattr(
                            perf_stats[perf_stat].fc, "total_errors_per_sec", 0
                        ),
                        "transmitted_bytes_per_sec": getattr(
                            perf_stats[perf_stat].fc, "transmitted_bytes_per_sec", 0
                        ),
                        "transmitted_frames_per_sec": getattr(
                            perf_stats[perf_stat].fc, "transmitted_frames_per_sec", 0
                        ),
                        "transmitted_invalid_words_per_sec": getattr(
                            perf_stats[perf_stat].fc,
                            "transmitted_invalid_words_per_sec",
                            0,
                        ),
                    }
                else:
                    net_info[perf_stats[perf_stat].name]["performance"] = {
                        "received_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth, "received_bytes_per_sec", 0
                        ),
                        "received_crc_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth, "received_crc_errors_per_sec", 0
                        ),
                        "received_frame_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "received_frame_errors_per_sec",
                            0,
                        ),
                        "received_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth, "received_packets_per_sec", 0
                        ),
                        "total_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth, "total_errors_per_sec", 0
                        ),
                        "transmitted_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth, "transmitted_bytes_per_sec", 0
                        ),
                        "transmitted_dropped_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "transmitted_dropped_errors_per_sec",
                            0,
                        ),
                        "transmitted_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth, "transmitted_packets_per_sec", 0
                        ),
                        "rdma_received_req_cqe_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "rdma_received_req_cqe_errors_per_sec",
                            0,
                        ),
                        "rdma_received_sequence_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "rdma_received_sequence_errors_per_sec",
                            0,
                        ),
                        "rdma_transmitted_local_ack_timeout_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "rdma_transmitted_local_ack_timeout_errors_per_sec",
                            0,
                        ),
                        "flow_control_received_congestion_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_congestion_packets_per_sec",
                            0,
                        ),
                        "flow_control_received_discarded_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_discarded_packets_per_sec",
                            0,
                        ),
                        "flow_control_received_lossless_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_lossless_bytes_per_sec",
                            0,
                        ),
                        "flow_control_received_pause_frames_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_pause_frames_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_congestion_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_congestion_packets_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_discarded_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_discarded_packets_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_lossless_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_lossless_bytes_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_pause_frames_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_pause_frames_per_sec",
                            0,
                        ),
                    }
            except KeyError:
                net_info[perf_stats[perf_stat].name] = {
                    "hwaddr": None,
                    "mtu": None,
                    "enabled": None,
                    "speed": None,
                    "address": None,
                    "slaves": None,
                    "services": None,
                    "gateway": None,
                    "netmask": None,
                    "subnet": None,
                    "performance": {
                        "received_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth, "received_bytes_per_sec", 0
                        ),
                        "received_crc_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth, "received_crc_errors_per_sec", 0
                        ),
                        "received_frame_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "received_frame_errors_per_sec",
                            0,
                        ),
                        "received_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth, "received_packets_per_sec", 0
                        ),
                        "total_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth, "total_errors_per_sec", 0
                        ),
                        "transmitted_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth, "transmitted_bytes_per_sec", 0
                        ),
                        "transmitted_dropped_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "transmitted_dropped_errors_per_sec",
                            0,
                        ),
                        "transmitted_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth, "transmitted_packets_per_sec", 0
                        ),
                        "rdma_received_req_cqe_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "rdma_received_req_cqe_errors_per_sec",
                            0,
                        ),
                        "rdma_received_sequence_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "rdma_received_sequence_errors_per_sec",
                            0,
                        ),
                        "rdma_transmitted_local_ack_timeout_errors_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "rdma_transmitted_local_ack_timeout_errors_per_sec",
                            0,
                        ),
                        "flow_control_received_congestion_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_congestion_packets_per_sec",
                            0,
                        ),
                        "flow_control_received_discarded_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_discarded_packets_per_sec",
                            0,
                        ),
                        "flow_control_received_lossless_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_lossless_bytes_per_sec",
                            0,
                        ),
                        "flow_control_received_pause_frames_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_received_pause_frames_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_congestion_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_congestion_packets_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_discarded_packets_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_discarded_packets_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_lossless_bytes_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_lossless_bytes_per_sec",
                            0,
                        ),
                        "flow_control_transmitted_pause_frames_per_sec": getattr(
                            perf_stats[perf_stat].eth,
                            "flow_control_transmitted_pause_frames_per_sec",
                            0,
                        ),
                    },
                }
    if LooseVersion(NEIGHBOR_API_VERSION) <= LooseVersion(array.get_rest_version()):
        neighbors = list(array.get_network_interfaces_neighbors().items)
        for neighbor in range(0, len(neighbors)):
            neighbor_info = neighbors[neighbor]
            int_name = neighbor_info.local_port.name
            try:
                net_info[int_name].update(
                    {
                        "neighbor": {
                            "initial_ttl_in_sec": neighbor_info.initial_ttl_in_sec,
                            "neighbor_port": {
                                "description": getattr(
                                    neighbor_info.neighbor_port, "description", None
                                ),
                                "name": getattr(
                                    neighbor_info.neighbor_chassis, "name", None
                                ),
                                "id": getattr(
                                    neighbor_info.neighbor_port.id, "value", None
                                ),
                            },
                            "neighbor_chassis": {
                                "addresses": getattr(
                                    neighbor_info.neighbor_chassis, "addresses", None
                                ),
                                "description": getattr(
                                    neighbor_info.neighbor_chassis, "description", None
                                ),
                                "name": getattr(
                                    neighbor_info.neighbor_chassis, "name", None
                                ),
                                "bridge": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.bridge,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.bridge,
                                        "supported",
                                        False,
                                    ),
                                },
                                "repeater": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.repeater,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.repeater,
                                        "supported",
                                        False,
                                    ),
                                },
                                "router": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.router,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.router,
                                        "supported",
                                        False,
                                    ),
                                },
                                "station_only": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.station_only,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.station_only,
                                        "supported",
                                        False,
                                    ),
                                },
                                "telephone": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.telephone,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.telephone,
                                        "supported",
                                        False,
                                    ),
                                },
                                "wlan_access_point": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.wlan_access_point,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.wlan_access_point,
                                        "supported",
                                        False,
                                    ),
                                },
                                "docsis_cable_device": {
                                    "enabled": getattr(
                                        neighbor_info.neighbor_chassis.docsis_cable_device,
                                        "enabled",
                                        False,
                                    ),
                                    "supported": getattr(
                                        neighbor_info.neighbor_chassis.docsis_cable_device,
                                        "supported",
                                        False,
                                    ),
                                },
                                "id": {
                                    "type": getattr(
                                        neighbor_info.neighbor_chassis.id,
                                        "type",
                                        None,
                                    ),
                                    "value": getattr(
                                        neighbor_info.neighbor_chassis.id,
                                        "value",
                                        None,
                                    ),
                                },
                            },
                        }
                    }
                )
            except KeyError:
                net_info[int_name] = {
                    "hwaddr": None,
                    "mtu": None,
                    "enabled": None,
                    "speed": None,
                    "address": None,
                    "slaves": None,
                    "services": None,
                    "gateway": None,
                    "netmask": None,
                    "subnet": None,
                    "neighbor": {
                        "initial_ttl_in_sec": neighbor_info.initial_ttl_in_sec,
                        "neighbor_port": {
                            "description": getattr(
                                neighbor_info.neighbor_port, "description", None
                            ),
                            "name": getattr(
                                neighbor_info.neighbor_chassis, "name", None
                            ),
                            "id": getattr(
                                neighbor_info.neighbor_port.id, "value", None
                            ),
                        },
                        "neighbor_chassis": {
                            "addresses": getattr(
                                neighbor_info.neighbor_chassis, "addresses", None
                            ),
                            "description": getattr(
                                neighbor_info.neighbor_chassis, "description", None
                            ),
                            "name": getattr(
                                neighbor_info.neighbor_chassis, "name", None
                            ),
                            "bridge": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.bridge,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.bridge,
                                    "supported",
                                    False,
                                ),
                            },
                            "repeater": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.repeater,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.repeater,
                                    "supported",
                                    False,
                                ),
                            },
                            "router": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.router,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.router,
                                    "supported",
                                    False,
                                ),
                            },
                            "station_only": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.station_only,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.station_only,
                                    "supported",
                                    False,
                                ),
                            },
                            "telephone": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.telephone,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.telephone,
                                    "supported",
                                    False,
                                ),
                            },
                            "wlan_access_point": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.wlan_access_point,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.wlan_access_point,
                                    "supported",
                                    False,
                                ),
                            },
                            "docsis_cable_device": {
                                "enabled": getattr(
                                    neighbor_info.neighbor_chassis.docsis_cable_device,
                                    "enabled",
                                    False,
                                ),
                                "supported": getattr(
                                    neighbor_info.neighbor_chassis.docsis_cable_device,
                                    "supported",
                                    False,
                                ),
                            },
                            "id": {
                                "type": getattr(
                                    neighbor_info.neighbor_chassis.id,
                                    "type",
                                    None,
                                ),
                                "value": getattr(
                                    neighbor_info.neighbor_chassis.id,
                                    "value",
                                    None,
                                ),
                            },
                        },
                    },
                }

    return net_info


def generate_capacity_dict(array):
    capacity_info = {}
    total_capacity = list(array.get_arrays().items)[0].capacity
    capacity = list(array.get_arrays_space().items)[0]
    capacity_info["total_capacity"] = total_capacity
    capacity_info["parity"] = getattr(capacity, "parity", None)
    capacity_info["capacity_installed"] = getattr(capacity, "capacity_installed", None)
    if LooseVersion(SHARED_CAP_API_VERSION) <= LooseVersion(array.get_rest_version()):
        capacity_info["provisioned_space"] = getattr(
            capacity.space, "total_provisioned", 0
        )
        capacity_info["free_space"] = total_capacity - getattr(
            capacity.space, "total_physical", 0
        )
        capacity_info["data_reduction"] = getattr(capacity.space, "data_reduction", 0)
        capacity_info["system_space"] = getattr(capacity.space, "system", 0)
        capacity_info["volume_space"] = getattr(capacity.space, "unique", 0)
        capacity_info["shared_space"] = getattr(capacity.space, "shared", 0)
        capacity_info["snapshot_space"] = getattr(capacity.space, "snapshots", 0)
        capacity_info["thin_provisioning"] = getattr(
            capacity.space, "thin_provisioning", 0
        )
        capacity_info["total_reduction"] = getattr(capacity.space, "total_reduction", 0)
        capacity_info["replication"] = getattr(capacity.space, "replication", 0)
        capacity_info["shared_effective"] = getattr(
            capacity.space, "shared_effective", 0
        )
        capacity_info["snapshots_effective"] = getattr(
            capacity.space, "snapshots_effective", 0
        )
        capacity_info["unique_effective"] = getattr(
            capacity.space, "total_effective", 0
        )
        capacity_info["total_effective"] = getattr(capacity.space, "total_effective", 0)
        capacity_info["used_provisioned"] = getattr(
            capacity.space, "used_provisioned", 0
        )
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
            capacity_info["total_used"] = capacity.space.total_used
    else:
        capacity_info["provisioned_space"] = capacity.space["total_provisioned"]
        capacity_info["free_space"] = total_capacity - capacity.space["total_physical"]
        capacity_info["data_reduction"] = capacity.space["data_reduction"]
        capacity_info["system_space"] = capacity.space["system"]
        capacity_info["volume_space"] = capacity.space["unique"]
        capacity_info["shared_space"] = capacity.space["shared"]
        capacity_info["snapshot_space"] = capacity.space["snapshots"]
        capacity_info["thin_provisioning"] = capacity.space["thin_provisioning"]
        capacity_info["total_reduction"] = capacity.space["total_reduction"]
        capacity_info["replication"] = capacity.space["replication"]
    if LooseVersion(NFS_SECURITY_VERSION) <= LooseVersion(
        array.get_rest_version()
    ) and _is_cbs(array):
        cloud = list(array.get_arrays_cloud_capacity().items)[0]
        capacity_info["cloud_capacity"] = {
            "current_capacity": cloud.current_capacity,
            "requested_capacity": cloud.requested_capacity,
            "status": cloud.status,
        }
    return capacity_info


def generate_snap_dict(array):
    snap_info = {}
    snaps = list(array.get_volume_snapshots(destroyed=False).items)
    for snap in range(0, len(snaps)):
        snapshot = snaps[snap].name
        snap_info[snapshot] = {
            "size": snaps[snap].space.total_provisioned,
            "source": getattr(snaps[snap].source, "name", None),
            "created_epoch": snaps[snap].created,
            "created": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(snaps[snap].created / 1000)
            ),
            "tags": [],
            "is_local": True,
            "remote": [],
        }
        if ":" in snapshot and "::" not in snapshot:
            snap_info[snapshot]["is_local"] = False
        snap_info[snapshot]["snapshot_space"] = snaps[snap].space.snapshots
        snap_info[snapshot]["used_provisioned"] = (
            getattr(snaps[snap].space, "used_provisioned", None),
        )
        snap_info[snapshot]["total_physical"] = snaps[snap].space.total_physical
        snap_info[snapshot]["total_provisioned"] = snaps[snap].space.total_provisioned
        snap_info[snapshot]["unique_space"] = snaps[snap].space.unique
        if LooseVersion(SHARED_CAP_API_VERSION) <= LooseVersion(
            array.get_rest_version()
        ):
            snap_info[snapshot]["snapshots_effective"] = getattr(
                snaps[snap].space, "snapshots_effective", None
            )
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
            snap_info[snapshot]["total_used"] = snaps[snap].space.total_used
    offloads = list(array.get_offloads().items)
    for offload in range(0, len(offloads)):
        offload_name = offloads[offload].name
        check_offload = array.get_remote_volume_snapshots(on=offload_name)
        if check_offload.status_code == 200:
            remote_snaps = list(
                array.get_remote_volume_snapshots(
                    on=offload_name, destroyed=False
                ).items
            )
            for remote_snap in range(0, len(remote_snaps)):
                remote_snap_name = remote_snaps[remote_snap].name.split(":")[1]
                remote_transfer = list(
                    array.get_remote_volume_snapshots_transfer(
                        on=offload_name, names=[remote_snaps[remote_snap].name]
                    ).items
                )[0]
                remote_dict = {
                    "source": remote_snaps[remote_snap].source.name,
                    "suffix": remote_snaps[remote_snap].suffix,
                    "size": remote_snaps[remote_snap].provisioned,
                    "data_transferred": remote_transfer.data_transferred,
                    "completed": time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.gmtime(remote_transfer.completed / 1000),
                    )
                    + " UTC",
                    "physical_bytes_written": remote_transfer.physical_bytes_written,
                    "progress": remote_transfer.progress,
                    "created": time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.gmtime(remote_snaps[remote_snap].created / 1000),
                    )
                    + " UTC",
                }
                try:
                    snap_info[remote_snap_name]["remote"].append(remote_dict)
                except KeyError:
                    snap_info[remote_snap_name] = {"remote": []}
                    snap_info[remote_snap_name]["remote"].append(remote_dict)
    snaps_tags = list(array.get_volume_snapshots_tags(resource_destroyed=False).items)
    for tag in range(len(snaps_tags)):
        snap_info[snaps_tags[tag].resource.name]["tags"].append(
            {
                "key": snaps_tags[tag].key,
                "value": snaps_tags[tag].value,
                "copyable": snaps_tags[tag].copyable,
                "namespace": snaps_tags[tag].namespace,
            }
        )
    return snap_info


def generate_del_snap_dict(array):
    snap_info = {}
    snaps = list(array.get_volume_snapshots(destroyed=True).items)
    for snap in range(0, len(snaps)):
        snapshot = snaps[snap].name
        snap_info[snapshot] = {
            "size": snaps[snap].space.total_provisioned,
            "source": getattr(snaps[snap].source, "name", None),
            "created_epoch": snaps[snap].created,
            "created": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(snaps[snap].created / 1000)
            ),
            "tags": [],
            "is_local": True,
            "remote": [],
            "time_remaining": getattr(snaps[snap], "time_remaining", None),
        }
        snap_info[snapshot]["snapshot_space"] = snaps[snap].space.snapshots
        snap_info[snapshot]["used_provisioned"] = (
            getattr(snaps[snap].space, "used_provisioned", None),
        )
        snap_info[snapshot]["total_physical"] = snaps[snap].space.total_physical
        snap_info[snapshot]["total_provisioned"] = snaps[snap].space.total_provisioned
        snap_info[snapshot]["unique_space"] = snaps[snap].space.unique
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
            snap_info[snapshot]["total_used"] = snaps[snap].space.total_used
    offloads = list(array.get_offloads().items)
    for offload in range(0, len(offloads)):
        offload_name = offloads[offload].name
        check_offload = array.get_remote_volume_snapshots(on=offload_name)
        if check_offload.status_code == 200:
            remote_snaps = list(
                array.get_remote_volume_snapshots(on=offload_name, destroyed=True).items
            )
            for remote_snap in range(0, len(remote_snaps)):
                remote_snap_name = remote_snaps[remote_snap].name.split(":")[1]
                remote_transfer = list(
                    array.get_remote_volume_snapshots_transfer(
                        on=offload_name, names=[remote_snaps[remote_snap].name]
                    ).items
                )[0]
                remote_dict = {
                    "source": remote_snaps[remote_snap].source.name,
                    "suffix": remote_snaps[remote_snap].suffix,
                    "size": remote_snaps[remote_snap].provisioned,
                    "data_transferred": remote_transfer.data_transferred,
                    "completed": time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.gmtime(remote_transfer.completed / 1000),
                    )
                    + " UTC",
                    "physical_bytes_written": remote_transfer.physical_bytes_written,
                    "progress": remote_transfer.progress,
                    "created": time.strftime(
                        "%Y-%m-%d %H:%M:%S",
                        time.gmtime(remote_snaps[remote_snap].created / 1000),
                    )
                    + " UTC",
                }
                try:
                    snap_info[remote_snap_name]["remote"].append(remote_dict)
                except KeyError:
                    snap_info[remote_snap_name] = {"remote": []}
                    snap_info[remote_snap_name]["remote"].append(remote_dict)
    snaps_tags = list(array.get_volume_snapshots_tags(resource_destroyed=True).items)
    for tag in range(len(snaps_tags)):
        snap_info[snaps_tags[tag].resource.name]["tags"].append(
            {
                "key": snaps_tags[tag].key,
                "value": snaps_tags[tag].value,
                "copyable": snaps_tags[tag].copyable,
                "namespace": snaps_tags[tag].namespace,
            }
        )
    return snap_info


def generate_del_vol_dict(array):
    volume_info = {}
    vols = list(array.get_volumes(destroyed=True).items)
    for vol in range(0, len(vols)):
        volume = vols[vol].name
        volume_info[volume] = {
            "protocol_endpoint": bool(vols[vol].subtype == "protocol_endpoint"),
            "protocol_endpoint_version": getattr(
                vols[vol].protocol_endpoint, "container_version", None
            ),
            "size": vols[vol].provisioned,
            "source": getattr(vols[vol].source, "name", None),
            "created_epoch": vols[vol].created,
            "created": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(vols[vol].created / 1000)
            ),
            "serial": vols[vol].serial,
            "page83_naa": PURE_OUI + vols[vol].serial,
            "nvme_nguid": "eui.00"
            + vols[vol].serial[0:14].lower()
            + "24a937"
            + vols[vol].serial[-10:].lower(),
            "time_remaining": vols[vol].time_remaining,
            "tags": [],
            "promotion_status": vols[vol].promotion_status,
            "requested_promotion_state": vols[vol].requested_promotion_state,
            "bandwidth": getattr(vols[vol].qos, "bandwidth_limit", None),
            "iops_limit": getattr(vols[vol].qos, "iops_limit", None),
            "snapshots_space": vols[vol].space.snapshots,
            # Provide system as this matches the old naming convention
            "system": vols[vol].space.unique,
            "unique_space": vols[vol].space.unique,
            "virtual_space": vols[vol].space.virtual,
            "total_physical_space": vols[vol].space.total_physical,
            "data_reduction": vols[vol].space.data_reduction,
            "total_reduction": vols[vol].space.total_reduction,
            "total_provisioned": vols[vol].space.total_provisioned,
            "thin_provisioning": vols[vol].space.thin_provisioning,
            "host_encryption_key_status": vols[vol].host_encryption_key_status,
            "subtype": vols[vol].subtype,
        }
        if LooseVersion(SAFE_MODE_VERSION) <= LooseVersion(array.get_rest_version()):
            volume_info[volume]["subtype"] = vols[vol].subtype
            volume_info[volume]["priority"] = vols[vol].priority
            volume_info[volume]["priority_adjustment"] = vols[
                vol
            ].priority_adjustment.priority_adjustment_operator + str(
                vols[vol].priority_adjustment.priority_adjustment_value
            )
        if LooseVersion(SHARED_CAP_API_VERSION) <= LooseVersion(
            array.get_rest_version()
        ):
            volume_info[volume]["snapshots_effective"] = getattr(
                vols[vol].space, "snapshots_effective", None
            )
            volume_info[volume]["unique_effective"] = getattr(
                vols[vol].space, "unique_effective", None
            )
            volume_info[volume]["used_provisioned"] = (
                getattr(vols[vol].space, "used_provisioned", None),
            )
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
            volume_info[volume]["total_used"] = vols[vol].space.total_used
    volume_tags = list(array.get_volumes_tags(resource_destroyed=True).items)
    for tag in range(len(volume_tags)):
        volume_info[volume_tags[tag].resource.name]["tags"].append(
            {
                "key": volume_tags[tag].key,
                "value": volume_tags[tag].value,
                "copyable": volume_tags[tag].copyable,
                "namespace": volume_tags[tag].namespace,
            }
        )
    return volume_info


def generate_vol_dict(array, performance):
    volume_info = {}
    vols = list(array.get_volumes(destroyed=False).items)
    for vol in range(0, len(vols)):
        volume = vols[vol].name
        volume_info[volume] = {
            "protocol_endpoint": bool(vols[vol].subtype == "protocol_endpoint"),
            "protocol_endpoint_version": getattr(
                getattr(vols[vol], "protocol_endpoint", None), "container_version", None
            ),
            "size": vols[vol].provisioned,
            "source": getattr(vols[vol].source, "name", None),
            "created_epoch": vols[vol].created,
            "created": time.strftime(
                "%Y-%m-%dT%H:%M:%S", time.localtime(vols[vol].created / 1000)
            ),
            "serial": vols[vol].serial,
            "page83_naa": PURE_OUI + vols[vol].serial,
            "nvme_nguid": "eui.00"
            + vols[vol].serial[0:14].lower()
            + "24a937"
            + vols[vol].serial[-10:].lower(),
            "tags": [],
            "promotion_status": vols[vol].promotion_status,
            "requested_promotion_state": vols[vol].requested_promotion_state,
            "hosts": [],
            "host_groups": [],
            "bandwidth": getattr(vols[vol].qos, "bandwidth_limit", None),
            "iops_limit": getattr(vols[vol].qos, "iops_limit", None),
            "snapshots_space": vols[vol].space.snapshots,
            # Provide system as this matches the old naming convention
            "system": vols[vol].space.unique,
            "unique_space": vols[vol].space.unique,
            "virtual_space": vols[vol].space.virtual,
            "total_physical_space": vols[vol].space.total_physical,
            "data_reduction": vols[vol].space.data_reduction,
            "total_reduction": vols[vol].space.total_reduction,
            "total_provisioned": vols[vol].space.total_provisioned,
            "thin_provisioning": vols[vol].space.thin_provisioning,
            "performance": [],
            "host_encryption_key_status": vols[vol].host_encryption_key_status,
            "subtype": vols[vol].subtype,
        }
        if LooseVersion(SHARED_CAP_API_VERSION) <= LooseVersion(
            array.get_rest_version()
        ):
            volume_info[volume]["snapshots_effective"] = getattr(
                vols[vol].space, "snapshots_effective", None
            )
            volume_info[volume]["unique_effective"] = getattr(
                vols[vol].space, "unique_effective", None
            )
            volume_info[volume]["total_effective"] = getattr(
                vols[vol].space, "total_effective", None
            )
            volume_info[volume]["used_provisioned"] = (
                getattr(vols[vol].space, "used_provisioned", None),
            )
        if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
            volume_info[volume]["total_used"] = vols[vol].space.total_used
        if LooseVersion(SAFE_MODE_VERSION) <= LooseVersion(array.get_rest_version()):
            volume_info[volume]["priority"] = vols[vol].priority
            volume_info[volume]["priority_adjustment"] = vols[
                vol
            ].priority_adjustment.priority_adjustment_operator + str(
                vols[vol].priority_adjustment.priority_adjustment_value
            )
        connections = list(array.get_connections(volume_names=[vols[vol].name]).items)
        voldict = {}
        for connection in range(0, len(connections)):
            voldict = {
                "host": getattr(connections[connection].host, "name", None),
                "lun": getattr(connections[connection], "lun", None),
            }
            if voldict["host"]:
                volume_info[volume]["hosts"].append(voldict)
        voldict = {}
        for connection in range(0, len(connections)):
            voldict = {
                "host_group": getattr(connections[connection].host_group, "name", None),
                "lun": getattr(connections[connection], "lun", None),
            }
            if voldict["host_group"]:
                volume_info[volume]["host_groups"].append(voldict)
        volume_info[volume]["host_groups"] = [
            dict(t)
            for t in set(tuple(d.items()) for d in volume_info[volume]["host_groups"])
        ]
    volume_tags = list(array.get_volumes_tags(resource_destroyed=False).items)
    for tag in range(len(volume_tags)):
        volume_info[volume_tags[tag].resource.name]["tags"].append(
            {
                "key": volume_tags[tag].key,
                "value": volume_tags[tag].value,
                "copyable": volume_tags[tag].copyable,
                "namespace": volume_tags[tag].namespace,
            }
        )
    if performance:
        vols_performance = list(array.get_volumes_performance(destroyed=False).items)
        for perf in range(0, len(vols_performance)):
            volume_info[vols_performance[perf].name]["performance"] = {
                "bytes_per_mirrored_write": vols_performance[
                    perf
                ].bytes_per_mirrored_write,
                "bytes_per_op": vols_performance[perf].bytes_per_op,
                "bytes_per_read": vols_performance[perf].bytes_per_read,
                "bytes_per_write": vols_performance[perf].bytes_per_write,
                "mirrored_write_bytes_per_sec": vols_performance[
                    perf
                ].mirrored_write_bytes_per_sec,
                "mirrored_writes_per_sec": vols_performance[
                    perf
                ].mirrored_writes_per_sec,
                "qos_rate_limit_usec_per_mirrored_write_op": vols_performance[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_read_op": vols_performance[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_write_op": vols_performance[
                    perf
                ].qos_rate_limit_usec_per_read_op,
                "queue_usec_per_mirrored_write_op": vols_performance[
                    perf
                ].queue_usec_per_mirrored_write_op,
                "queue_usec_per_read_op": vols_performance[perf].queue_usec_per_read_op,
                "queue_usec_per_write_op": vols_performance[
                    perf
                ].queue_usec_per_write_op,
                "read_bytes_per_sec": vols_performance[perf].read_bytes_per_sec,
                "reads_per_sec": vols_performance[perf].reads_per_sec,
                "san_usec_per_mirrored_write_op": vols_performance[
                    perf
                ].san_usec_per_mirrored_write_op,
                "san_usec_per_read_op": vols_performance[perf].san_usec_per_read_op,
                "san_usec_per_write_op": vols_performance[perf].san_usec_per_write_op,
                "service_usec_per_mirrored_write_op": vols_performance[
                    perf
                ].service_usec_per_mirrored_write_op,
                "service_usec_per_read_op": vols_performance[
                    perf
                ].service_usec_per_read_op,
                "service_usec_per_write_op": vols_performance[
                    perf
                ].service_usec_per_write_op,
                "usec_per_mirrored_write_op": vols_performance[
                    perf
                ].usec_per_mirrored_write_op,
                "usec_per_read_op": vols_performance[perf].usec_per_read_op,
                "usec_per_write_op": vols_performance[perf].usec_per_write_op,
                "write_bytes_per_sec": vols_performance[perf].write_bytes_per_sec,
                "writes_per_sec": vols_performance[perf].writes_per_sec,
            }
    return volume_info


def generate_host_dict(array, performance):
    host_info = {}
    hosts = list(array.get_hosts().items)
    hosts_balance = list(array.get_hosts_performance_balance().items)
    if performance:
        hosts_performance = list(array.get_hosts_performance().items)
    for host in range(0, len(hosts)):
        hostname = hosts[host].name
        host_info[hostname] = {
            "hgroup": getattr(hosts[host].host_group, "name", None),
            "nqn": getattr(hosts[host], "nqns", None),
            "iqn": getattr(hosts[host], "iqns", None),
            "wwn": getattr(hosts[host], "wwns", None),
            "personality": getattr(hosts[host], "personality", None),
            "host_user": getattr(hosts[host].chap, "host_user", None),
            "target_user": getattr(hosts[host].chap, "target_user", None),
            "target_port": [],
            "volumes": [],
            "tags": [],
            "performance": [],
            "performance_balance": [],
            "preferred_array": [],
            "destroyed": getattr(hosts[host], "destroyed", None),
            "time_remaining": getattr(hosts[host], "time_remaining", None),
            "vlan": getattr(hosts[host], "vlan", None),
        }
        host_connections = list(array.get_connections(host_names=[hostname]).items)
        for connection in range(0, len(host_connections)):
            connection_dict = {
                "hostgroup": getattr(
                    host_connections[connection].host_group, "name", None
                ),
                "volume": host_connections[connection].volume.name,
                "lun": getattr(host_connections[connection], "lun", None),
                "nsid": getattr(host_connections[connection], "nsid", None),
            }
            host_info[hostname]["volumes"].append(connection_dict)
        for pref_array in range(0, len(hosts[host].preferred_arrays)):
            host_info[hostname]["preferred_array"].append(
                hosts[host].preferred_arrays[pref_array].name
            )

        if hosts[host].is_local:
            host_info[hosts[host].name]["port_connectivity"] = hosts[
                host
            ].port_connectivity.details
            host_perf_balance = []
            for balance in range(0, len(hosts_balance)):
                if hosts[host]["name"] == hosts_balance[balance].name:
                    host_balance = {
                        "fraction_relative_to_max": getattr(
                            hosts_balance[balance],
                            "fraction_relative_to_max",
                            None,
                        ),
                        "op_count": getattr(hosts_balance[balance], "op_count", 0),
                        "target": getattr(hosts_balance[balance].target, "name", None),
                        "failed": bool(
                            getattr(hosts_balance[balance].target, "failover", 0)
                        ),
                    }
                    if host_balance["target"]:
                        host_perf_balance.append(host_balance)
                    host_info[hostname]["target_port"].append(
                        getattr(hosts_balance[balance].target, "name", None)
                    )
            host_info[hosts[host]["name"]]["performance_balance"].append(
                host_perf_balance
            )
    host_tags = list(array.get_hosts_tags(resource_destroyed=False).items)
    for tag in range(len(host_tags)):
        host_info[host_tags[tag].resource.name]["tags"].append(
            {
                "key": host_tags[tag].key,
                "value": host_tags[tag].value,
                "copyable": host_tags[tag].copyable,
                "namespace": host_tags[tag].namespace,
            }
        )
    if performance:
        for perf in range(0, len(hosts_performance)):
            if ":" not in hosts_performance[perf].name:
                host_info[hosts_performance[perf].name]["performance"] = {
                    "bytes_per_mirrored_write": hosts_performance[
                        perf
                    ].bytes_per_mirrored_write,
                    "bytes_per_op": hosts_performance[perf].bytes_per_op,
                    "bytes_per_read": hosts_performance[perf].bytes_per_read,
                    "bytes_per_write": hosts_performance[perf].bytes_per_write,
                    "mirrored_write_bytes_per_sec": hosts_performance[
                        perf
                    ].mirrored_write_bytes_per_sec,
                    "mirrored_writes_per_sec": hosts_performance[
                        perf
                    ].mirrored_writes_per_sec,
                    "qos_rate_limit_usec_per_mirrored_write_op": hosts_performance[
                        perf
                    ].qos_rate_limit_usec_per_mirrored_write_op,
                    "qos_rate_limit_usec_per_read_op": hosts_performance[
                        perf
                    ].qos_rate_limit_usec_per_mirrored_write_op,
                    "qos_rate_limit_usec_per_write_op": hosts_performance[
                        perf
                    ].qos_rate_limit_usec_per_read_op,
                    "queue_usec_per_mirrored_write_op": hosts_performance[
                        perf
                    ].queue_usec_per_mirrored_write_op,
                    "queue_usec_per_read_op": hosts_performance[
                        perf
                    ].queue_usec_per_read_op,
                    "queue_usec_per_write_op": hosts_performance[
                        perf
                    ].queue_usec_per_write_op,
                    "read_bytes_per_sec": hosts_performance[perf].read_bytes_per_sec,
                    "reads_per_sec": hosts_performance[perf].reads_per_sec,
                    "san_usec_per_mirrored_write_op": hosts_performance[
                        perf
                    ].san_usec_per_mirrored_write_op,
                    "san_usec_per_read_op": hosts_performance[
                        perf
                    ].san_usec_per_read_op,
                    "san_usec_per_write_op": hosts_performance[
                        perf
                    ].san_usec_per_write_op,
                    "service_usec_per_mirrored_write_op": hosts_performance[
                        perf
                    ].service_usec_per_mirrored_write_op,
                    "service_usec_per_read_op": hosts_performance[
                        perf
                    ].service_usec_per_read_op,
                    "service_usec_per_write_op": hosts_performance[
                        perf
                    ].service_usec_per_write_op,
                    "usec_per_mirrored_write_op": hosts_performance[
                        perf
                    ].usec_per_mirrored_write_op,
                    "usec_per_read_op": hosts_performance[perf].usec_per_read_op,
                    "usec_per_write_op": hosts_performance[perf].usec_per_write_op,
                    "write_bytes_per_sec": hosts_performance[perf].write_bytes_per_sec,
                    "writes_per_sec": hosts_performance[perf].writes_per_sec,
                }
    return host_info


def generate_del_pgroups_dict(array):
    pgroups_info = {}
    api_version = array.get_rest_version()
    pgroups = list(array.get_protection_groups(destroyed=True).items)
    for pgroup in range(0, len(pgroups)):
        protgroup = pgroups[pgroup].name

        pgroups_info[protgroup] = {
            "hgroups": [],
            "hosts": [],
            "source": getattr(pgroups[pgroup].source, "name", None),
            "targets": [],
            "volumes": [],
            "time_remaining": pgroups[pgroup].time_remaining,
            "snap_frequency": pgroups[pgroup].snapshot_schedule.frequency,
            "replicate_frequency": pgroups[pgroup].replication_schedule.frequency,
            "snap_enabled": pgroups[pgroup].snapshot_schedule.enabled,
            "replicate_enabled": pgroups[pgroup].replication_schedule.enabled,
            "snap_at": getattr(pgroups[pgroup].snapshot_schedule, "at", None),
            "replicate_at": getattr(pgroups[pgroup].replication_schedule, "at", None),
            "replicate_blackout": {
                "start": getattr(
                    pgroups[pgroup].replication_schedule.blackout, "start", None
                ),
                "end": getattr(
                    pgroups[pgroup].replication_schedule.blackout, "end", None
                ),
            },
            "per_day": pgroups[pgroup].source_retention.per_day,
            "target_per_day": pgroups[pgroup].target_retention.per_day,
            "target_days": pgroups[pgroup].target_retention.days,
            "days": pgroups[pgroup].source_retention.days,
            "all_for": pgroups[pgroup].source_retention.all_for_sec,
            "target_all_for": pgroups[pgroup].target_retention.all_for_sec,
            "snaps": {},
            "snapshots": getattr(pgroups[pgroup].space, "snapshots", None),
            "shared": getattr(pgroups[pgroup].space, "shared", None),
            "data_reduction": getattr(pgroups[pgroup].space, "data_reduction", None),
            "thin_provisioning": getattr(
                pgroups[pgroup].space, "thin_provisioning", None
            ),
            "total_physical": getattr(pgroups[pgroup].space, "total_physical", None),
            "total_provisioned": getattr(
                pgroups[pgroup].space, "total_provisioned", None
            ),
            "total_reduction": getattr(pgroups[pgroup].space, "total_reduction", None),
            "unique": getattr(pgroups[pgroup].space, "unique", None),
            "virtual": getattr(pgroups[pgroup].space, "virtual", None),
            "replication": getattr(pgroups[pgroup].space, "replication", None),
            "used_provisioned": getattr(
                pgroups[pgroup].space, "used_provisioned", None
            ),
            "tags": [],
        }
        pgroup_transfers_res = array.get_protection_group_snapshots_transfer(
            names=[protgroup + ".*"]
        )
        if pgroup_transfers_res.status_code == 200:
            pgroup_transfers = list(pgroup_transfers_res.items)
            for pgroup_transfer in range(0, len(pgroup_transfers)):
                snap = pgroup_transfers[pgroup_transfer]["name"]
                pgroups_info[protgroup]["snaps"][snap] = {
                    "time_remaining": None,  # Backwards compatability
                    "created": None,  # Backwards compatability
                    "started": getattr(
                        pgroup_transfers[pgroup_transfer], "started", None
                    ),
                    "completed": getattr(
                        pgroup_transfers[pgroup_transfer], "completed", None
                    ),
                    "physical_bytes_written": getattr(
                        pgroup_transfers[pgroup_transfer],
                        "physical_bytes_written",
                        None,
                    ),
                    "data_transferred": getattr(
                        pgroup_transfers[pgroup_transfer], "data_transferred", None
                    ),
                    "progress": getattr(
                        pgroup_transfers[pgroup_transfer], "progress", None
                    ),
                    "destroyed": pgroup_transfers[pgroup_transfer].destroyed,
                }
        pgroup_volumes = list(
            array.get_protection_groups_volumes(group_names=[protgroup]).items
        )
        for pg_vol in range(0, len(pgroup_volumes)):
            pgroups_info[protgroup]["volumes"].append(
                pgroup_volumes[pg_vol].member.name
            )
        pgroup_hosts = list(
            array.get_protection_groups_hosts(group_names=[protgroup]).items
        )
        for pg_host in range(0, len(pgroup_hosts)):
            pgroups_info[protgroup]["hosts"].append(pgroup_hosts[pg_host].member.name)
        pgroup_hgs = list(
            array.get_protection_groups_host_groups(group_names=[protgroup]).items
        )
        for pg_hg in range(0, len(pgroup_hgs)):
            pgroups_info[protgroup]["hgroups"].append(pgroup_hgs[pg_hg].member.name)
        pgroup_targets = list(
            array.get_protection_groups_targets(group_names=[protgroup]).items
        )
        for pg_target in range(0, len(pgroup_targets)):
            pgroups_info[protgroup]["targets"].append(
                pgroup_targets[pg_target].member.name
            )
        if LooseVersion(SHARED_CAP_API_VERSION) <= LooseVersion(api_version):
            pgroups_info[protgroup]["deleted_volumes"] = []
            volumes = list(
                array.get_protection_groups_volumes(group_names=[protgroup]).items
            )
            if volumes:
                for volume in range(0, len(volumes)):
                    if volumes[volume].member["destroyed"]:
                        pgroups_info[protgroup]["deleted_volumes"].append(
                            volumes[volume].member["name"]
                        )
            else:
                pgroups_info[protgroup]["deleted_volumes"] = None
        if LooseVersion(PER_PG_VERSION) <= LooseVersion(api_version):
            res = array.get_protection_groups(names=[protgroup])
            if res.status_code == 200:
                pg_info = list(res.items)[0]
                pgroups_info[protgroup]["retention_lock"] = getattr(
                    pg_info, "retention_lock", None
                )
                pgroups_info[protgroup]["manual_eradication"] = getattr(
                    pg_info.eradication_config, "manual_eradication", None
                )
    pgroup_tags = list(array.get_protection_groups_tags(resource_destroyed=True).items)
    for tag in range(len(pgroup_tags)):
        pgroups_info[pgroup_tags[tag].resource.name]["tags"].append(
            {
                "key": pgroup_tags[tag].key,
                "value": pgroup_tags[tag].value,
                "copyable": pgroup_tags[tag].copyable,
                "namespace": pgroup_tags[tag].namespace,
            }
        )
    return pgroups_info


def generate_pgroups_dict(array):
    pgroups_info = {}
    api_version = array.get_rest_version()
    pgroups = list(array.get_protection_groups(destroyed=False).items)
    for pgroup in range(0, len(pgroups)):
        protgroup = pgroups[pgroup]["name"]
        pgroups_info[protgroup] = {
            "hgroups": [],
            "hosts": [],
            "source": getattr(pgroups[pgroup].source, "name", None),
            "targets": [],
            "volumes": [],
            "snap_frequency": pgroups[pgroup].snapshot_schedule.frequency,
            "replicate_frequency": pgroups[pgroup].replication_schedule.frequency,
            "snap_enabled": pgroups[pgroup].snapshot_schedule.enabled,
            "replicate_enabled": pgroups[pgroup].replication_schedule.enabled,
            "snap_at": getattr(pgroups[pgroup].snapshot_schedule, "at", None),
            "replicate_at": getattr(pgroups[pgroup].replication_schedule, "at", None),
            "replicate_blackout": {
                "start": getattr(
                    pgroups[pgroup].replication_schedule.blackout, "start", None
                ),
                "end": getattr(
                    pgroups[pgroup].replication_schedule.blackout, "end", None
                ),
            },
            "per_day": pgroups[pgroup].source_retention.per_day,
            "target_per_day": pgroups[pgroup].target_retention.per_day,
            "target_days": pgroups[pgroup].target_retention.days,
            "days": pgroups[pgroup].source_retention.days,
            "all_for": pgroups[pgroup].source_retention.all_for_sec,
            "target_all_for": pgroups[pgroup].target_retention.all_for_sec,
            "snaps": {},
            "snapshots": getattr(pgroups[pgroup].space, "snapshots", None),
            "shared": getattr(pgroups[pgroup].space, "shared", None),
            "data_reduction": getattr(pgroups[pgroup].space, "data_reduction", None),
            "thin_provisioning": getattr(
                pgroups[pgroup].space, "thin_provisioning", None
            ),
            "total_physical": getattr(pgroups[pgroup].space, "total_physical", None),
            "total_provisioned": getattr(
                pgroups[pgroup].space, "total_provisioned", None
            ),
            "total_reduction": getattr(pgroups[pgroup].space, "total_reduction", None),
            "unique": getattr(pgroups[pgroup].space, "unique", None),
            "virtual": getattr(pgroups[pgroup].space, "virtual", None),
            "replication": getattr(pgroups[pgroup].space, "replication", None),
            "used_provisioned": getattr(
                pgroups[pgroup].space, "used_provisioned", None
            ),
            "tags": [],
        }
        pgroup_transfers_res = array.get_protection_group_snapshots_transfer(
            names=[protgroup + ".*"]
        )
        if pgroup_transfers_res.status_code == 200:
            pgroup_transfers = list(pgroup_transfers_res.items)
            for pgroup_transfer in range(0, len(pgroup_transfers)):
                snap = pgroup_transfers[pgroup_transfer]["name"]
                pgroups_info[protgroup]["snaps"][snap] = {
                    "time_remaining": None,  # Backwards compatability
                    "created": None,  # Backwards compatability
                    "started": getattr(
                        pgroup_transfers[pgroup_transfer], "started", None
                    ),
                    "completed": getattr(
                        pgroup_transfers[pgroup_transfer], "completed", None
                    ),
                    "physical_bytes_written": getattr(
                        pgroup_transfers[pgroup_transfer],
                        "physical_bytes_written",
                        None,
                    ),
                    "data_transferred": getattr(
                        pgroup_transfers[pgroup_transfer], "data_transferred", None
                    ),
                    "progress": getattr(
                        pgroup_transfers[pgroup_transfer], "progress", None
                    ),
                    "destroyed": pgroup_transfers[pgroup_transfer].destroyed,
                }
        pgroup_volumes = list(
            array.get_protection_groups_volumes(group_names=[protgroup]).items
        )
        for pg_vol in range(0, len(pgroup_volumes)):
            pgroups_info[protgroup]["volumes"].append(
                pgroup_volumes[pg_vol].member.name
            )
        pgroup_hosts = list(
            array.get_protection_groups_hosts(group_names=[protgroup]).items
        )
        for pg_host in range(0, len(pgroup_hosts)):
            pgroups_info[protgroup]["hosts"].append(pgroup_hosts[pg_host].member.name)
        pgroup_hgs = list(
            array.get_protection_groups_host_groups(group_names=[protgroup]).items
        )
        for pg_hg in range(0, len(pgroup_hgs)):
            pgroups_info[protgroup]["hgroups"].append(pgroup_hgs[pg_hg].member.name)
        pgroup_targets = list(
            array.get_protection_groups_targets(group_names=[protgroup]).items
        )
        for pg_target in range(0, len(pgroup_targets)):
            pgroups_info[protgroup]["targets"].append(
                pgroup_targets[pg_target].member.name
            )
        if LooseVersion(SHARED_CAP_API_VERSION) <= LooseVersion(api_version):
            pgroups_info[protgroup]["deleted_volumes"] = []
            volumes = list(
                array.get_protection_groups_volumes(group_names=[protgroup]).items
            )
            if volumes:
                for volume in range(0, len(volumes)):
                    if volumes[volume].member["destroyed"]:
                        pgroups_info[protgroup]["deleted_volumes"].append(
                            volumes[volume].member["name"]
                        )
            else:
                pgroups_info[protgroup]["deleted_volumes"] = None
        if LooseVersion(PER_PG_VERSION) <= LooseVersion(api_version):
            res = array.get_protection_groups(names=[protgroup])
            if res.status_code == 200:
                pg_info = list(res.items)[0]
                pgroups_info[protgroup]["retention_lock"] = getattr(
                    pg_info, "retention_lock", None
                )
                pgroups_info[protgroup]["manual_eradication"] = getattr(
                    pg_info.eradication_config, "manual_eradication", None
                )
    pgroup_tags = list(array.get_protection_groups_tags(resource_destroyed=False).items)
    for tag in range(len(pgroup_tags)):
        pgroups_info[pgroup_tags[tag].resource.name]["tags"].append(
            {
                "key": pgroup_tags[tag].key,
                "value": pgroup_tags[tag].value,
                "copyable": pgroup_tags[tag].copyable,
                "namespace": pgroup_tags[tag].namespace,
            }
        )
    return pgroups_info


def generate_rl_dict(array):
    rl_info = {}
    rlinks = list(array.get_pod_replica_links().items)
    for rlink in range(0, len(rlinks)):
        link_name = rlinks[rlink]["local_pod"]["name"]
        if rlinks[rlink]["recovery_point"]:
            since_epoch = rlinks[rlink]["recovery_point"] / 1000
            recovery_datatime = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(since_epoch)
            )
        else:
            recovery_datatime = None
        if rlinks[rlink]["lag"]:
            lag = str(rlinks[rlink]["lag"] / 1000) + "s"
        rl_info[link_name] = {
            "status": rlinks[rlink]["status"],
            "direction": rlinks[rlink]["direction"],
            "lag": lag,
            "remote_pod_name": rlinks[rlink]["remote_pod"]["name"],
            "remote_names": rlinks[rlink]["remotes"][0]["name"],
            "recovery_point": recovery_datatime,
        }
    return rl_info


def generate_del_pods_dict(array):
    pods_info = {}
    pods = list(array.get_pods(destroyed=True).items)
    for pod in range(0, len(pods)):
        name = pods[pod].name
        pods_info[name] = {
            "arrays": [],
            "mediator": pods[pod].mediator,
            "mediator_version": getattr(pods[pod], "mediator_version", None),
            "time_remaining": pods[pod].time_remaining,
            "link_source_count": pods[pod].link_source_count,
            "link_target_count": pods[pod].link_target_count,
            "promotion_status": pods[pod].promotion_status,
            "requested_promotion_state": pods[pod].requested_promotion_state,
            "failover_preference": [],
            "snapshots": getattr(pods[pod].space, "snapshots", None),
            "shared": getattr(pods[pod].space, "shared", None),
            "data_reduction": getattr(pods[pod].space, "data_reduction", None),
            "thin_provisioning": getattr(pods[pod].space, "thin_provisioning", None),
            "total_physical": getattr(pods[pod].space, "total_physical", None),
            "total_provisioned": getattr(pods[pod].space, "total_provisioned", None),
            "total_reduction": getattr(pods[pod].space, "total_reduction", None),
            "unique": getattr(pods[pod].space, "unique", None),
            "virtual": getattr(pods[pod].space, "virtual", None),
            "replication": pods[pod].space.replication,
            "used_provisioned": getattr(pods[pod].space, "used_provisioned", None),
            "quota_limit": getattr(pods[pod], "quota_limit", None),
            "total_used": pods[pod].space.total_used,
            "tags": [],
        }
        for preferences in range(0, len(pods[pod].failover_preferences)):
            pods_info[name]["failover_preference"].append(
                {
                    "array_id": pods[pod].arrays[preferences].id,
                    "name": pods[pod].arrays[preferences].name,
                }
            )
        for pod_array in range(0, len(pods[pod].arrays)):
            frozen_datetime = None
            if hasattr(pods[pod].arrays[pod_array], "frozen_at"):
                frozen_time = pods[pod].arrays[pod_array].frozen_at / 1000
                frozen_datetime = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(frozen_time)
                )
            pods_info[name]["arrays"].append(
                {
                    "name": pods[pod].arrays[pod_array].member.name,
                    "type": pods[pod].arrays[pod_array].member.resource_type,
                    "pre_elected": pods[pod].arrays[pod_array].pre_elected,
                    "frozen_at": frozen_datetime,
                    "progress": getattr(pods[pod].arrays[pod_array], "progress", None),
                    "status": getattr(pods[pod].arrays[pod_array], "status", None),
                }
            )
    pods_tags = list(array.get_pods_tags(resource_destroyed=True).items)
    for tag in range(len(pods_tags)):
        pods_info[pods_tags[tag].resource.name]["tags"].append(
            {
                "key": pods_tags[tag].key,
                "value": pods_tags[tag].value,
                "copyable": pods_tags[tag].copyable,
                "namespace": pods_tags[tag].namespace,
            }
        )
    return pods_info


def generate_pods_dict(array, performance):
    pods_info = {}
    pods = list(array.get_pods(destroyed=False).items)
    for pod in range(0, len(pods)):
        name = pods[pod].name
        pods_info[name] = {
            "arrays": [],
            "mediator": pods[pod].mediator,
            "mediator_version": getattr(pods[pod], "mediator_version", None),
            "link_source_count": pods[pod].link_source_count,
            "link_target_count": pods[pod].link_target_count,
            "promotion_status": pods[pod].promotion_status,
            "requested_promotion_state": pods[pod].requested_promotion_state,
            "failover_preference": [],
            "snapshots": getattr(pods[pod].space, "snapshots", None),
            "shared": getattr(pods[pod].space, "shared", None),
            "data_reduction": getattr(pods[pod].space, "data_reduction", None),
            "thin_provisioning": getattr(pods[pod].space, "thin_provisioning", None),
            "total_physical": getattr(pods[pod].space, "total_physical", None),
            "total_provisioned": getattr(pods[pod].space, "total_provisioned", None),
            "total_reduction": getattr(pods[pod].space, "total_reduction", None),
            "unique": getattr(pods[pod].space, "unique", None),
            "virtual": getattr(pods[pod].space, "virtual", None),
            "replication": pods[pod].space.replication,
            "used_provisioned": getattr(pods[pod].space, "used_provisioned", None),
            "quota_limit": getattr(pods[pod], "quota_limit", None),
            "total_used": pods[pod].space.total_used,
            "tags": [],
        }
        for preferences in range(0, len(pods[pod].failover_preferences)):
            pods_info[name]["failover_preference"].append(
                {
                    "array_id": pods[pod].arrays[preferences].id,
                    "name": pods[pod].arrays[preferences].name,
                }
            )
        for pod_array in range(0, len(pods[pod].arrays)):
            frozen_datetime = None
            if hasattr(pods[pod].arrays[pod_array], "frozen_at"):
                frozen_time = pods[pod].arrays[pod_array].frozen_at / 1000
                frozen_datetime = time.strftime(
                    "%Y-%m-%d %H:%M:%S", time.localtime(frozen_time)
                )
            pods_info[name]["arrays"].append(
                {
                    "array_id": pods[pod].arrays[pod_array].id,
                    "name": pods[pod].arrays[pod_array].member.name,
                    "type": pods[pod].arrays[pod_array].member.resource_type,
                    "pre_elected": pods[pod].arrays[pod_array].pre_elected,
                    "frozen_at": frozen_datetime,
                    "progress": getattr(pods[pod].arrays[pod_array], "progress", None),
                    "mediator_status": getattr(
                        pods[pod].arrays[0], "mediator_status", None
                    ),
                    "status": getattr(pods[pod].arrays[pod_array], "status", None),
                }
            )
    pods_tags = list(array.get_pods_tags(resource_destroyed=False).items)
    for tag in range(len(pods_tags)):
        pods_info[pods_tags[tag].resource.name]["tags"].append(
            {
                "key": pods_tags[tag].key,
                "value": pods_tags[tag].value,
                "copyable": pods_tags[tag].copyable,
                "namespace": pods_tags[tag].namespace,
            }
        )
    if performance:
        pods_performance = list(array.get_pods_performance().items)
        for perf in range(0, len(pods_performance)):
            pods_info[pods_performance[perf].name]["performance"] = {
                "bytes_per_mirrored_write": pods_performance[
                    perf
                ].bytes_per_mirrored_write,
                "bytes_per_op": pods_performance[perf].bytes_per_op,
                "bytes_per_read": pods_performance[perf].bytes_per_read,
                "bytes_per_write": pods_performance[perf].bytes_per_write,
                "mirrored_write_bytes_per_sec": pods_performance[
                    perf
                ].mirrored_write_bytes_per_sec,
                "mirrored_writes_per_sec": pods_performance[
                    perf
                ].mirrored_writes_per_sec,
                "others_per_sec": pods_performance[perf].others_per_sec,
                "qos_rate_limit_usec_per_mirrored_write_op": pods_performance[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_read_op": pods_performance[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_write_op": pods_performance[
                    perf
                ].qos_rate_limit_usec_per_read_op,
                "queue_usec_per_mirrored_write_op": pods_performance[
                    perf
                ].queue_usec_per_mirrored_write_op,
                "queue_usec_per_read_op": pods_performance[perf].queue_usec_per_read_op,
                "queue_usec_per_write_op": pods_performance[
                    perf
                ].queue_usec_per_write_op,
                "read_bytes_per_sec": pods_performance[perf].read_bytes_per_sec,
                "reads_per_sec": pods_performance[perf].reads_per_sec,
                "san_usec_per_mirrored_write_op": pods_performance[
                    perf
                ].san_usec_per_mirrored_write_op,
                "san_usec_per_read_op": pods_performance[perf].san_usec_per_read_op,
                "san_usec_per_write_op": pods_performance[perf].san_usec_per_write_op,
                "service_usec_per_mirrored_write_op": pods_performance[
                    perf
                ].service_usec_per_mirrored_write_op,
                "service_usec_per_read_op": pods_performance[
                    perf
                ].service_usec_per_read_op,
                "service_usec_per_write_op": pods_performance[
                    perf
                ].service_usec_per_write_op,
                "usec_per_mirrored_write_op": pods_performance[
                    perf
                ].usec_per_mirrored_write_op,
                "usec_per_read_op": pods_performance[perf].usec_per_read_op,
                "usec_per_write_op": pods_performance[perf].usec_per_write_op,
                "write_bytes_per_sec": pods_performance[perf].write_bytes_per_sec,
                "writes_per_sec": pods_performance[perf].writes_per_sec,
            }
    return pods_info


def generate_conn_array_dict(array):
    conn_array_info = {}
    carrays = list(array.get_array_connections().items)
    for carray in range(0, len(carrays)):
        arrayname = carrays[carray].name
        conn_array_info[arrayname] = {
            "array_id": carrays[carray].id,
            "version": getattr(carrays[carray], "version", None),
            "status": carrays[carray].status,
            "type": carrays[carray].type,
            "mgmt_ip": getattr(carrays[carray], "management_address", "-"),
            "repl_ip": getattr(carrays[carray], "replication_addresses", "-"),
            "transport": getattr(carrays[carray], "replication_transport", "Unknown"),
            "throttling": {},
        }
        if hasattr(carrays[carray], "throttle"):
            if bool(carrays[carray].throttle.to_dict()):
                conn_array_info[arrayname]["throttled"] = True
                if hasattr(carrays[carray].throttle, "window"):
                    conn_array_info[arrayname]["throttling"]["window"] = carrays[
                        carray
                    ].throttle.window.to_dict()
                if hasattr(carrays[carray].throttle, "default_limit"):
                    conn_array_info[arrayname]["throttling"]["default_limit"] = carrays[
                        carray
                    ].throttle.default_limit
                if hasattr(carrays[carray].throttle, "window_limit"):
                    conn_array_info[arrayname]["throttling"]["window_limit"] = carrays[
                        carray
                    ].throttle.window_limit
    return conn_array_info


def generate_apps_dict(array):
    apps_info = {}
    apps = list(array.get_apps().items)
    for app in range(0, len(apps)):
        appname = apps[app].name
        apps_info[appname] = {
            "enabled": getattr(apps[app], "enabled", None),
            "version": getattr(apps[app], "version", None),
            "status": getattr(apps[app], "status", None),
            "description": getattr(apps[app], "description", None),
            "details": getattr(apps[app], "details", None),
            "vnc_enabled": getattr(apps[app], "vnc_enabled", None),
        }
    app_nodes = list(array.get_apps_nodes().items)
    for app in range(0, len(app_nodes)):
        appname = app_nodes[app].name
        apps_info[appname]["index"] = app_nodes[app].index
        apps_info[appname]["vnc"] = getattr(app_nodes[app], "vnc", None)
    return apps_info


def generate_vgroups_dict(array, performance):
    vgroups_info = {}
    vgroups = list(array.get_volume_groups(destroyed=False).items)
    for vgroup in range(0, len(vgroups)):
        name = vgroups[vgroup].name
        vgroups_info[name] = {
            "volumes": [],
            "performance": [],
            "snapshots_space": vgroups[vgroup].space.snapshots,
            "system": vgroups[vgroup].space.unique,  # Backwards compatability
            "unique_space": vgroups[vgroup].space.unique,
            "virtual_space": vgroups[vgroup].space.virtual,
            "data_reduction": (getattr(vgroups[vgroup].space, "data_reduction", None),),
            "total_reduction": (
                getattr(vgroups[vgroup].space, "total_reduction", None),
            ),
            "total_provisioned": vgroups[vgroup].space.total_provisioned,
            "thin_provisioning": vgroups[vgroup].space.thin_provisioning,
            "used_provisioned": (
                getattr(vgroups[vgroup].space, "used_provisioned", None),
            ),
            "bandwidth_limit": getattr(vgroups[vgroup].qos, "bandwidth_limit", ""),
            "iops_limit": getattr(vgroups[vgroup].qos, "iops_limit", ""),
            "total_used": getattr(vgroups[vgroup].space, "total_used", None),
            "tags": [],
        }
        if hasattr(vgroups_info[name], "priority_adjustment"):
            vgroups_info[name]["priority_adjustment"] = vgroups[
                vgroup
            ].priority_adjustment.priority_adjustment_operator + str(
                vgroups[vgroup].priority_adjustment.priority_adjustment_value
            )
    vgroup_tags = list(array.get_volume_groups_tags(resource_destroyed=False).items)
    for tag in range(len(vgroup_tags)):
        vgroups_info[vgroup_tags[tag].resource.name]["tags"].append(
            {
                "key": vgroup_tags[tag].key,
                "value": vgroup_tags[tag].value,
                "copyable": vgroup_tags[tag].copyable,
                "namespace": vgroup_tags[tag].namespace,
            }
        )
    if performance:
        vgs_performance = list(array.get_volume_groups_performance().items)
        for perf in range(0, len(vgs_performance)):
            vgroups_info[vgs_performance[perf].name]["performance"] = {
                "bytes_per_mirrored_write": vgs_performance[
                    perf
                ].bytes_per_mirrored_write,
                "bytes_per_op": vgs_performance[perf].bytes_per_op,
                "bytes_per_read": vgs_performance[perf].bytes_per_read,
                "bytes_per_write": vgs_performance[perf].bytes_per_write,
                "mirrored_write_bytes_per_sec": vgs_performance[
                    perf
                ].mirrored_write_bytes_per_sec,
                "mirrored_writes_per_sec": vgs_performance[
                    perf
                ].mirrored_writes_per_sec,
                "qos_rate_limit_usec_per_mirrored_write_op": vgs_performance[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_read_op": vgs_performance[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_write_op": vgs_performance[
                    perf
                ].qos_rate_limit_usec_per_read_op,
                "queue_usec_per_mirrored_write_op": vgs_performance[
                    perf
                ].queue_usec_per_mirrored_write_op,
                "queue_usec_per_read_op": vgs_performance[perf].queue_usec_per_read_op,
                "queue_usec_per_write_op": vgs_performance[
                    perf
                ].queue_usec_per_write_op,
                "read_bytes_per_sec": vgs_performance[perf].read_bytes_per_sec,
                "reads_per_sec": vgs_performance[perf].reads_per_sec,
                "san_usec_per_mirrored_write_op": vgs_performance[
                    perf
                ].san_usec_per_mirrored_write_op,
                "san_usec_per_read_op": vgs_performance[perf].san_usec_per_read_op,
                "san_usec_per_write_op": vgs_performance[perf].san_usec_per_write_op,
                "service_usec_per_mirrored_write_op": vgs_performance[
                    perf
                ].service_usec_per_mirrored_write_op,
                "service_usec_per_read_op": vgs_performance[
                    perf
                ].service_usec_per_read_op,
                "service_usec_per_write_op": vgs_performance[
                    perf
                ].service_usec_per_write_op,
                "usec_per_mirrored_write_op": vgs_performance[
                    perf
                ].usec_per_mirrored_write_op,
                "usec_per_read_op": vgs_performance[perf].usec_per_read_op,
                "usec_per_write_op": vgs_performance[perf].usec_per_write_op,
                "write_bytes_per_sec": vgs_performance[perf].write_bytes_per_sec,
                "writes_per_sec": vgs_performance[perf].writes_per_sec,
            }
    vg_volumes = list(array.get_volume_groups_volumes().items)
    for vg_vol in range(0, len(vg_volumes)):
        group_name = vg_volumes[vg_vol].group.name
        vgroups_info[group_name]["volumes"].append(vg_volumes[vg_vol].member.name)
    return vgroups_info


def generate_del_vgroups_dict(array):
    vgroups_info = {}
    vgroups = list(array.get_volume_groups(destroyed=True).items)
    for vgroup in range(0, len(vgroups)):
        name = vgroups[vgroup].name
        vgroups_info[name] = {
            "volumes": [],
            "performance": [],
            "snapshots_space": vgroups[vgroup].space.snapshots,
            "system": vgroups[vgroup].space.unique,  # Backwards compatability
            "unique_space": vgroups[vgroup].space.unique,
            "virtual_space": vgroups[vgroup].space.virtual,
            "data_reduction": (getattr(vgroups[vgroup].space, "data_reduction", None),),
            "total_reduction": (
                getattr(vgroups[vgroup].space, "total_reduction", None),
            ),
            "total_provisioned": vgroups[vgroup].space.total_provisioned,
            "thin_provisioning": vgroups[vgroup].space.thin_provisioning,
            "used_provisioned": (
                getattr(vgroups[vgroup].space, "used_provisioned", None),
            ),
            "bandwidth_limit": getattr(vgroups[vgroup].qos, "bandwidth_limit", ""),
            "iops_limit": getattr(vgroups[vgroup].qos, "iops_limit", ""),
            "total_used": getattr(vgroups[vgroup].space, "total_used", None),
            "tags": [],
        }
        if hasattr(vgroups_info[name], "priority_adjustment"):
            vgroups_info[name]["priority_adjustment"] = vgroups[
                vgroup
            ].priority_adjustment.priority_adjustment_operator + str(
                vgroups[vgroup].priority_adjustment.priority_adjustment_value
            )
    vg_volumes = list(array.get_volume_groups_volumes().items)
    for vg_vol in range(0, len(vg_volumes)):
        group_name = vg_volumes[vg_vol].group.name
        if group_name in vgroups_info:
            vgroups_info[group_name]["volumes"].append(vg_volumes[vg_vol].member.name)
    vgroup_tags = list(array.get_volume_groups_tags(resource_destroyed=True).items)
    for tag in range(len(vgroup_tags)):
        vgroups_info[vgroup_tags[tag].resource.name]["tags"].append(
            {
                "key": vgroup_tags[tag].key,
                "value": vgroup_tags[tag].value,
                "copyable": vgroup_tags[tag].copyable,
                "namespace": vgroup_tags[tag].namespace,
            }
        )
    return vgroups_info


def generate_certs_dict(array):
    certs_info = {}
    certs = list(array.get_certificates().items)
    for cert in range(0, len(certs)):
        certificate = certs[cert].name
        valid_from = time.strftime(
            "%a, %d %b %Y %H:%M:%S %Z",
            time.localtime(certs[cert].valid_from / 1000),
        )
        valid_to = time.strftime(
            "%a, %d %b %Y %H:%M:%S %Z",
            time.localtime(certs[cert].valid_to / 1000),
        )
        certs_info[certificate] = {
            "status": certs[cert].status,
            "issued_to": getattr(certs[cert], "issued_to", None),
            "valid_from": valid_from,
            "locality": getattr(certs[cert], "locality", None),
            "country": getattr(certs[cert], "country", None),
            "issued_by": getattr(certs[cert], "issued_by", None),
            "valid_to": valid_to,
            "state": getattr(certs[cert], "state", None),
            "key_algorithm": getattr(certs[cert], "key_algorithm", None),
            "key_size": getattr(certs[cert], "key_size", None),
            "org_unit": getattr(certs[cert], "organizational_unit", None),
            "common_name": getattr(certs[cert], "common_name", None),
            "organization": getattr(certs[cert], "organization", None),
            "email": getattr(certs[cert], "email", None),
            "certificate_type": getattr(certs[cert], "certificate_type", None),
            "alternative_names": getattr(
                certs[cert], "subject_alternative_names", None
            ),
        }
    return certs_info


def generate_kmip_dict(array):
    kmip_info = {}
    kmips = list(array.get_kmip().items)
    for kmip in range(0, len(kmips)):
        key = kmips[kmip].name
        kmip_info[key] = {
            "certificate": kmips[kmip].certificate.name,
            "ca_certificate": getattr(kmips[kmip], "ca_certificate", None),
            "ca_cert_configured": True,
            "uri": kmips[kmip].uris,
        }
    return kmip_info


def generate_nfs_offload_dict(array):
    offload_info = {}
    offloads_res = array.get_offloads(protocol="nfs")
    if offloads_res.status_code == 200:
        offloads = list(offloads_res.items)
        for offload in range(0, len(offloads)):
            name = offloads[offload].name
            offload_info[name] = {
                "status": offload[offload].status,
                "mount_point": getattr(offload[offload].nfs, "mount_point", None),
                "protocol": offload[offload].protocol,
                "profile": getattr(offloads[offload].nfs, "profile", None),
                "mount_options": getattr(offload[offload].nfs, "mount_options", None),
                "address": getattr(offload[offload].nfs, "address", None),
                "snapshots": getattr(offloads[offload].space, "snapshots", None),
                "shared": getattr(offloads[offload].space, "shared", None),
                "data_reduction": getattr(
                    offloads[offload].space, "data_reduction", None
                ),
                "thin_provisioning": getattr(
                    offloads[offload].space, "thin_provisioning", None
                ),
                "total_physical": getattr(
                    offloads[offload].space, "total_physical", None
                ),
                "total_provisioned": getattr(
                    offloads[offload].space, "total_provisioned", None
                ),
                "total_reduction": getattr(
                    offloads[offload].space, "total_reduction", None
                ),
                "unique": getattr(offloads[offload].space, "unique", None),
                "virtual": getattr(offloads[offload].space, "virtual", None),
                "replication": getattr(offloads[offload].space, "replication", None),
                "used_provisioned": getattr(
                    offloads[offload].space, "used_provisioned", None
                ),
                "total_used": getattr(offloads[offload].space, "total_used", None),
            }
    return offload_info


def generate_s3_offload_dict(array):
    offload_info = {}
    offloads_res = array.get_offloads(protocol="s3")
    if offloads_res.status_code == 200:
        offloads = list(offloads_res.items)
        for offload in range(0, len(offloads)):
            name = offloads[offload].name
            offload_info[name] = {
                "status": offloads[offload].status,
                "bucket": getattr(offloads[offload].s3, "bucket", None),
                "protocol": offloads[offload].protocol,
                "uri": getattr(offloads[offload].s3, "uri", None),
                "auth_region": getattr(offloads[offload].s3, "auth_region", None),
                "profile": getattr(offloads[offload].s3, "profile", None),
                "access_key_id": getattr(offloads[offload].s3, "access_key_id", None),
                "placement_strategy": offloads[offload].s3.placement_strategy,
                "snapshots": getattr(offloads[offload].space, "snapshots", None),
                "shared": getattr(offloads[offload].space, "shared", None),
                "data_reduction": getattr(
                    offloads[offload].space, "data_reduction", None
                ),
                "thin_provisioning": getattr(
                    offloads[offload].space, "thin_provisioning", None
                ),
                "total_physical": getattr(
                    offloads[offload].space, "total_physical", None
                ),
                "total_provisioned": getattr(
                    offloads[offload].space, "total_provisioned", None
                ),
                "total_reduction": getattr(
                    offloads[offload].space, "total_reduction", None
                ),
                "unique": getattr(offloads[offload].space, "unique", None),
                "virtual": getattr(offloads[offload].space, "virtual", None),
                "replication": getattr(offloads[offload].space, "replication", None),
                "used_provisioned": getattr(
                    offloads[offload].space, "used_provisioned", None
                ),
                "total_used": getattr(offloads[offload].space, "total_used", None),
            }
    return offload_info


def generate_azure_offload_dict(array):
    offload_info = {}
    offloads_res = array.get_offloads(protocol="azure")
    if offloads_res.status_code == 200:
        offloads = list(offloads_res.items)
        for offload in range(0, len(offloads)):
            name = offloads[offload].name
            offload_info[name] = {
                "status": offloads[offload].status,
                "account_name": getattr(offloads[offload].azure, "account_name", None),
                "profile": getattr(offloads[offload].azure, "profile", None),
                "protocol": offloads[offload].protocol,
                "secret_access_key": getattr(
                    offloads[offload].azure, "secret_access_key", None
                ),
                "container_name": getattr(
                    offloads[offload].azure, "container_name", None
                ),
                "snapshots": getattr(offloads[offload].space, "snapshots", None),
                "shared": getattr(offloads[offload].space, "shared", None),
                "data_reduction": getattr(
                    offloads[offload].space, "data_reduction", None
                ),
                "thin_provisioning": getattr(
                    offloads[offload].space, "thin_provisioning", None
                ),
                "total_physical": getattr(
                    offloads[offload].space, "total_physical", None
                ),
                "total_provisioned": getattr(
                    offloads[offload].space, "total_provisioned", None
                ),
                "total_reduction": getattr(
                    offloads[offload].space, "total_reduction", None
                ),
                "unique": getattr(offloads[offload].space, "unique", None),
                "virtual": getattr(offloads[offload].space, "virtual", None),
                "replication": getattr(offloads[offload].space, "replication", None),
                "used_provisioned": getattr(
                    offloads[offload].space, "used_provisioned", None
                ),
                "total_used": getattr(offloads[offload].space, "total_used", None),
            }
    return offload_info


def generate_google_offload_dict(array):
    offload_info = {}
    offloads_res = array.get_offloads(protocol="google-cloud")
    if offloads_res.status_code == 200:
        offloads = list(offloads_res.items)
        for offload in range(0, len(offloads)):
            name = offloads[offload].name
            offload_info[name] = {
                "access_key_id": getattr(
                    offloads[offload].google_cloud, "access_key_id", None
                ),
                "bucket": getattr(offloads[offload].google_cloud, "bucket", None),
                "profile": getattr(offloads[offload].google_cloud, "profile", None),
                "secret_access_key": getattr(
                    offloads[offload].google_cloud, "secret_access_key", None
                ),
                "snapshots": getattr(offloads[offload].space, "snapshots", None),
                "shared": getattr(offloads[offload].space, "shared", None),
                "data_reduction": getattr(
                    offloads[offload].space, "data_reduction", None
                ),
                "thin_provisioning": getattr(
                    offloads[offload].space, "thin_provisioning", None
                ),
                "total_physical": getattr(
                    offloads[offload].space, "total_physical", None
                ),
                "total_provisioned": getattr(
                    offloads[offload].space, "total_provisioned", None
                ),
                "total_reduction": getattr(
                    offloads[offload].space, "total_reduction", None
                ),
                "unique": getattr(offloads[offload].space, "unique", None),
                "virtual": getattr(offloads[offload].space, "virtual", None),
                "replication": getattr(offloads[offload].space, "replication", None),
                "used_provisioned": getattr(
                    offloads[offload].space, "used_provisioned", None
                ),
                "total_used": getattr(offloads[offload].space, "total_used", None),
            }
            if LooseVersion(SUBS_API_VERSION) <= LooseVersion(array.get_rest_version()):
                offload_info[name]["total_used"] = offloads[offload].space.total_used
    return offload_info


def generate_hgroups_dict(array, performance):
    hgroups_info = {}
    hgroups = list(array.get_host_groups().items)
    for hgroup in range(0, len(hgroups)):
        if hgroups[hgroup].is_local:
            name = hgroups[hgroup].name
            hgroups_info[name] = {
                "hosts": [],
                "pgs": [],
                "vols": [],
                "tags": [],
                "snapshots": getattr(hgroups[hgroup].space, "snapshots", None),
                "data_reduction": getattr(
                    hgroups[hgroup].space, "data_reduction", None
                ),
                "thin_provisioning": getattr(
                    hgroups[hgroup].space, "thin_provisioning", None
                ),
                "total_physical": getattr(
                    hgroups[hgroup].space, "total_physical", None
                ),
                "total_provisioned": getattr(
                    hgroups[hgroup].space, "total_provisioned", None
                ),
                "total_reduction": getattr(
                    hgroups[hgroup].space, "total_reduction", None
                ),
                "unique": getattr(hgroups[hgroup].space, "unique", None),
                "virtual": getattr(hgroups[hgroup].space, "virtual", None),
                "used_provisioned": getattr(
                    hgroups[hgroup].space, "used_provisioned", None
                ),
                "total_used": getattr(hgroups[hgroup].space, "total_used", None),
                "destroyed": getattr(hgroups[hgroup], "destroyed", False),
                "time_remaining": getattr(hgroups[hgroup], "time_remaining", None),
            }
    hgroup_tags = list(array.get_host_groups_tags(resource_destroyed=False).items)
    for tag in range(len(hgroup_tags)):
        hgroups_info[hgroup_tags[tag].resource.name]["tags"].append(
            {
                "key": hgroup_tags[tag].key,
                "value": hgroup_tags[tag].value,
                "copyable": hgroup_tags[tag].copyable,
                "namespace": hgroup_tags[tag].namespace,
            }
        )
    if performance:
        hgs_performance = list(array.get_host_groups_performance().items)
        for perf in range(0, len(hgs_performance)):
            if ":" not in hgs_performance[perf].name:
                hgroups_info[hgs_performance[perf].name]["performance"] = {
                    "bytes_per_mirrored_write": hgs_performance[
                        perf
                    ].bytes_per_mirrored_write,
                    "bytes_per_op": hgs_performance[perf].bytes_per_op,
                    "bytes_per_read": hgs_performance[perf].bytes_per_read,
                    "bytes_per_write": hgs_performance[perf].bytes_per_write,
                    "mirrored_write_bytes_per_sec": hgs_performance[
                        perf
                    ].mirrored_write_bytes_per_sec,
                    "mirrored_writes_per_sec": hgs_performance[
                        perf
                    ].mirrored_writes_per_sec,
                    "qos_rate_limit_usec_per_mirrored_write_op": hgs_performance[
                        perf
                    ].qos_rate_limit_usec_per_mirrored_write_op,
                    "qos_rate_limit_usec_per_read_op": hgs_performance[
                        perf
                    ].qos_rate_limit_usec_per_mirrored_write_op,
                    "qos_rate_limit_usec_per_write_op": hgs_performance[
                        perf
                    ].qos_rate_limit_usec_per_read_op,
                    "queue_usec_per_mirrored_write_op": hgs_performance[
                        perf
                    ].queue_usec_per_mirrored_write_op,
                    "queue_usec_per_read_op": hgs_performance[
                        perf
                    ].queue_usec_per_read_op,
                    "queue_usec_per_write_op": hgs_performance[
                        perf
                    ].queue_usec_per_write_op,
                    "read_bytes_per_sec": hgs_performance[perf].read_bytes_per_sec,
                    "reads_per_sec": hgs_performance[perf].reads_per_sec,
                    "san_usec_per_mirrored_write_op": hgs_performance[
                        perf
                    ].san_usec_per_mirrored_write_op,
                    "san_usec_per_read_op": hgs_performance[perf].san_usec_per_read_op,
                    "san_usec_per_write_op": hgs_performance[
                        perf
                    ].san_usec_per_write_op,
                    "service_usec_per_mirrored_write_op": hgs_performance[
                        perf
                    ].service_usec_per_mirrored_write_op,
                    "service_usec_per_read_op": hgs_performance[
                        perf
                    ].service_usec_per_read_op,
                    "service_usec_per_write_op": hgs_performance[
                        perf
                    ].service_usec_per_write_op,
                    "usec_per_mirrored_write_op": hgs_performance[
                        perf
                    ].usec_per_mirrored_write_op,
                    "usec_per_read_op": hgs_performance[perf].usec_per_read_op,
                    "usec_per_write_op": hgs_performance[perf].usec_per_write_op,
                    "write_bytes_per_sec": hgs_performance[perf].write_bytes_per_sec,
                    "writes_per_sec": hgs_performance[perf].writes_per_sec,
                }
    hg_vols = list(array.get_connections().items)
    for hg_vol in hg_vols:
        if (
            getattr(hg_vol.host_group, "name", None)
            and ":" not in hg_vol.host_group.name
        ):
            name = hg_vol.host_group.name
            vol_entry = {
                "name": hg_vol.volume.name,
                "lun": getattr(hg_vol, "lun", None),
                "nsid": getattr(hg_vol, "nsid", None),
            }
            vols_list = hgroups_info[name]["vols"]
            if vol_entry not in vols_list:
                vols_list.append(vol_entry)
    hg_hosts = list(array.get_host_groups_hosts().items)
    for hg_host in range(0, len(hg_hosts)):
        if hg_hosts[hg_host].group.name in hgroups_info:
            hgroups_info[hg_hosts[hg_host].group.name]["hosts"].append(
                hg_hosts[hg_host].member.name
            )
    hg_pgs = list(array.get_host_groups_protection_groups().items)
    for hg_pg in range(0, len(hg_pgs)):
        if hg_pgs[hg_pg].group.name in hgroups_info:
            hgroups_info[hg_pgs[hg_pg].group.name]["pgs"].append(
                hg_pgs[hg_pg].member.name
            )
    return hgroups_info


def generate_interfaces_dict(array):
    int_info = {}
    ports = list(array.get_ports().items)
    for port in range(0, len(ports)):
        int_name = ports[port].name
        if ports[port]["wwn"]:
            int_info[int_name] = {
                "wwn": getattr(ports[port], "wwn", None),
                "iqn": getattr(ports[port], "iqn", None),
                "nqn": getattr(ports[port], "nqn", None),
                "portal": getattr(ports[port], "portal", None),
            }
    return int_info


def generate_vm_dict(array):
    vm_info = {}
    virt_machines = list(array.get_virtual_machines(vm_type="vvol").items)
    for machine in range(0, len(virt_machines)):
        name = virt_machines[machine].name
        vm_info[name] = {
            "vm_type": virt_machines[machine].vm_type,
            "vm_id": virt_machines[machine].vm_id,
            "destroyed": virt_machines[machine].destroyed,
            "created": virt_machines[machine].created,
            "time_remaining": getattr(virt_machines[machine], "time_remaining", None),
            "latest_snapshot_name": getattr(
                virt_machines[machine].recover_context, "name", None
            ),
            "latest_snapshot_id": getattr(
                virt_machines[machine].recover_context, "id", None
            ),
        }
    return vm_info


def generate_alerts_dict(array):
    alerts_info = {}
    alerts = list(array.get_alerts().items)
    for alert in range(0, len(alerts)):
        name = alerts[alert].name
        try:
            notified_time = alerts[alert].notified / 1000
            notified_datetime = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(notified_time)
            )
        except AttributeError:
            notified_datetime = ""
        try:
            closed_time = alerts[alert].closed / 1000
            closed_datetime = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(closed_time)
            )
        except AttributeError:
            closed_datetime = ""
        try:
            updated_time = alerts[alert].updated / 1000
            updated_datetime = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(updated_time)
            )
        except AttributeError:
            updated_datetime = ""
        try:
            created_time = alerts[alert].created / 1000
            created_datetime = time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(created_time)
            )
        except AttributeError:
            updated_datetime = ""
        alerts_info[name] = {
            "flagged": alerts[alert].flagged,
            "category": alerts[alert].category,
            "code": alerts[alert].code,
            "issue": alerts[alert].issue,
            "kb_url": alerts[alert].knowledge_base_url,
            "summary": alerts[alert].summary,
            "id": alerts[alert].id,
            "state": alerts[alert].state,
            "severity": alerts[alert].severity,
            "component_name": alerts[alert].component_name,
            "component_type": alerts[alert].component_type,
            "created": created_datetime,
            "closed": closed_datetime,
            "notified": notified_datetime,
            "updated": updated_datetime,
            "actual": getattr(alerts[alert], "actual", ""),
            "expected": getattr(alerts[alert], "expected", ""),
        }
    return alerts_info


def generate_vmsnap_dict(array):
    vmsnap_info = {}
    virt_snaps = list(array.get_virtual_machine_snapshots(vm_type="vvol").items)
    for snap in range(0, len(virt_snaps)):
        name = virt_snaps[snap].name
        vmsnap_info[name] = {
            "vm_type": virt_snaps[snap].vm_type,
            "vm_id": virt_snaps[snap].vm_id,
            "destroyed": virt_snaps[snap].destroyed,
            "created": virt_snaps[snap].created,
            "time_remaining": getattr(virt_snaps[snap], "time_remaining", None),
            "latest_pgsnapshot_name": getattr(
                virt_snaps[snap].recover_context, "name", None
            ),
            "latest_pgsnapshot_id": getattr(
                virt_snaps[snap].recover_context, "id", None
            ),
        }
    return vmsnap_info


def generate_subs_dict(array):
    subs_info = {}
    subs = list(array.get_subscription_assets().items)
    for sub in range(0, len(subs)):
        name = subs[sub].name
        subs_info[name] = {
            "subscription_id": subs[sub].subscription.id,
        }
    return subs_info


def generate_fleet_dict(array):
    fleet_info = {}
    fleet = list(array.get_fleets().items)
    if fleet:
        fleet_name = list(array.get_fleets().items)[0].name
        fleet_info[fleet_name] = {
            "members": {},
        }
        members = list(array.get_fleets_members().items)
        for member in range(0, len(members)):
            name = members[member].member.name
            fleet_info[fleet_name]["members"][name] = {
                "status": members[member].status,
                "status_details": members[member].status_details,
                "role": (
                    "fleet_coordinator"
                    if hasattr(members[member], "coordinator_of")
                    else None
                ),
            }
    return fleet_info


def generate_preset_dict(array):
    preset_info = {}
    presets = list(array.get_presets_workload().items)
    if presets:
        for preset in range(0, len(presets)):
            preset_info[presets[preset].name] = {
                "description": getattr(presets[preset], "description", None),
                "workload_type": presets[preset].workload_type,
                "parameters": [],
            }
            for param in range(0, len(presets[preset].parameters)):
                preset_info[presets[preset].name]["parameters"].append(
                    {
                        "type": presets[preset].parameters[param].type,
                        "name": presets[preset].parameters[param].name,
                        "description": presets[preset]
                        .parameters[param]
                        .metadata.description,
                        "display_name": presets[preset]
                        .parameters[param]
                        .metadata.display_name,
                        "constraints": [],
                    }
                )
                if presets[preset].parameters[param].type == "integer":
                    preset_info[presets[preset].name]["parameters"][
                        "constraints"
                    ].append(
                        {
                            "allowed_values": presets[preset]
                            .parameters[param]
                            .constraints.integer.allowed_values,
                            "default": getattr(
                                presets[preset].parameters[param].constraints.integer,
                                "default",
                                None,
                            ),
                            "minimum": getattr(
                                presets[preset].parameters[param].constraints.integer,
                                "minimum",
                                None,
                            ),
                            "maximum": getattr(
                                presets[preset].parameters[param].constraints.integer,
                                "maximum",
                                None,
                            ),
                            "subtype": getattr(
                                presets[preset].parameters[param].constraints.integer,
                                "subtype",
                                None,
                            ),
                        }
                    )
                elif presets[preset].parameters[param].type == "boolean":
                    preset_info[presets[preset].name]["parameters"]["constraints"] = {}
                elif presets[preset].parameters[param].type == "string":
                    preset_info[presets[preset].name]["parameters"]["constraints"] = {}
                else:  # resource_reference
                    preset_info[presets[preset].name]["parameters"]["constraints"] = {}

    return preset_info


def generate_workload_dict(array):
    workload_info = {}
    workloads = list(array.get_workloads().items)
    if workloads:
        for workload in range(0, len(workloads)):
            workload_info[workloads[workload].name] = {
                "description": getattr(workloads[workload], "description", None),
                "context": workloads[workload].context.name,
                "destroyed": workloads[workload].destroyed,
                "preset": workloads[workload].preset.name,
                "status": workloads[workload].status,
                "status_details": workloads[workload].status_details,
                "created": time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.gmtime(workloads[workload].created / 1000),
                ),
                "time_remaining": getattr(workloads[workload], "time_remaining", None),
            }
    return workload_info


def generate_realms_dict(array, performance):
    realms_info = {}
    realms = list(array.get_realms().items)
    for realm in range(0, len(realms)):
        name = realms[realm].name
        realms_info[name] = {
            "created": time.strftime(
                "%Y-%m-%d %H:%M:%S", time.localtime(realms[realm].created / 1000)
            ),
            "destroyed": realms[realm].destroyed,
            "quota_limit": realms[realm].quota_limit,
            "data_reduction": getattr(realms[realm].space, "data_reduction", None),
            "footprint": getattr(realms[realm].space, "footprint", None),
            "shared": getattr(realms[realm].space, "shared", None),
            "snapshots": getattr(realms[realm].space, "snapshots", None),
            "thin_provisioning": getattr(
                realms[realm].space, "thin_provisioning", None
            ),
            "total_provisioned": getattr(
                realms[realm].space, "total_provisioned", None
            ),
            "total_reduction": getattr(realms[realm].space, "total_reduction", None),
            "total_used": getattr(realms[realm].space, "total_used", None),
            "unique": getattr(realms[realm].space, "unique", None),
            "used_provisioned": getattr(realms[realm].space, "used_provisioned", None),
            "virtual": getattr(realms[realm].space, "virtual", None),
            "performance": [],
            "qos": [],
            "tags": [],
        }
        realms_info[name]["qos"] = {
            "iops_limit": getattr(realms[realm].qos, "iops_limit", None),
            "bandwidth_limit": getattr(realms[realm].qos, "bandwidth_limit", None),
        }
        if realms_info[name]["destroyed"]:
            realms_info[name]["time_remaining"] = realms[realm].time_remaining
    realms_tags = list(array.get_realms_tags(resource_destroyed=False).items)
    for tag in range(len(realms_tags)):
        realms_info[realms_tags[tag].resource.name]["tags"].append(
            {
                "key": realms_tags[tag].key,
                "value": realms_tags[tag].value,
                "copyable": realms_tags[tag].copyable,
                "namespace": realms_tags[tag].namespace,
            }
        )
    if performance:
        r_perfs = list(array.get_realms_performance().items)
        for perf in range(0, len(r_perfs)):
            realms_info[r_perfs[perf].name]["performance"] = {
                "bytes_per_mirrored_write": r_perfs[perf].bytes_per_mirrored_write,
                "bytes_per_op": r_perfs[perf].bytes_per_op,
                "bytes_per_read": r_perfs[perf].bytes_per_read,
                "bytes_per_write": r_perfs[perf].bytes_per_write,
                "mirrored_write_bytes_per_sec": r_perfs[
                    perf
                ].mirrored_write_bytes_per_sec,
                "mirrored_writes_per_sec": r_perfs[perf].mirrored_writes_per_sec,
                "others_per_sec": r_perfs[perf].others_per_sec,
                "qos_rate_limit_usec_per_mirrored_write_op": r_perfs[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_read_op": r_perfs[
                    perf
                ].qos_rate_limit_usec_per_mirrored_write_op,
                "qos_rate_limit_usec_per_write_op": r_perfs[
                    perf
                ].qos_rate_limit_usec_per_read_op,
                "queue_usec_per_mirrored_write_op": r_perfs[
                    perf
                ].queue_usec_per_mirrored_write_op,
                "queue_usec_per_read_op": r_perfs[perf].queue_usec_per_read_op,
                "queue_usec_per_write_op": r_perfs[perf].queue_usec_per_write_op,
                "read_bytes_per_sec": r_perfs[perf].read_bytes_per_sec,
                "reads_per_sec": r_perfs[perf].reads_per_sec,
                "san_usec_per_mirrored_write_op": r_perfs[
                    perf
                ].san_usec_per_mirrored_write_op,
                "san_usec_per_read_op": r_perfs[perf].san_usec_per_read_op,
                "san_usec_per_write_op": r_perfs[perf].san_usec_per_write_op,
                "service_usec_per_mirrored_write_op": r_perfs[
                    perf
                ].service_usec_per_mirrored_write_op,
                "service_usec_per_read_op": r_perfs[perf].service_usec_per_read_op,
                "service_usec_per_write_op": r_perfs[perf].service_usec_per_write_op,
                "usec_per_mirrored_write_op": r_perfs[perf].usec_per_mirrored_write_op,
                "usec_per_other_op": r_perfs[perf].usec_per_other_op,
                "usec_per_read_op": r_perfs[perf].usec_per_read_op,
                "usec_per_write_op": r_perfs[perf].usec_per_write_op,
                "write_bytes_per_sec": r_perfs[perf].write_bytes_per_sec,
                "writes_per_sec": r_perfs[perf].writes_per_sec,
            }
    return realms_info


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(gather_subset=dict(default="minimum", type="list", elements="str"))
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)
    array = get_array(module)
    api_version = array.get_rest_version()
    subset = [test.lower() for test in module.params["gather_subset"]]
    valid_subsets = (
        "all",
        "minimum",
        "config",
        "performance",
        "capacity",
        "network",
        "subnet",
        "interfaces",
        "hgroups",
        "pgroups",
        "hosts",
        "admins",
        "volumes",
        "snapshots",
        "pods",
        "replication",
        "vgroups",
        "offload",
        "apps",
        "arrays",
        "certs",
        "kmip",
        "clients",
        "policies",
        "dir_snaps",
        "filesystems",
        "alerts",
        "virtual_machines",
        "subscriptions",
        "realms",
        "fleet",
        "presets",
        "workloads",
    )
    subset_test = (test in valid_subsets for test in subset)
    if not all(subset_test):
        module.fail_json(
            msg="value must gather_subset must be one or more of: %s, got: %s"
            % (",".join(valid_subsets), ",".join(subset))
        )

    info = {}
    performance = False
    if "minimum" in subset or "all" in subset or "apps" in subset:
        info["default"] = generate_default_dict(array)
    if "performance" in subset or "all" in subset:
        performance = True
        info["performance"] = generate_perf_dict(array)
    if "config" in subset or "all" in subset:
        info["config"] = generate_config_dict(module, array)
    if "capacity" in subset or "all" in subset:
        info["capacity"] = generate_capacity_dict(array)
    if "network" in subset or "all" in subset:
        info["network"] = generate_network_dict(array, performance)
    if "subnet" in subset or "all" in subset:
        info["subnet"] = generate_subnet_dict(array)
    if "interfaces" in subset or "all" in subset:
        info["interfaces"] = generate_interfaces_dict(array)
    if "hosts" in subset or "all" in subset:
        info["hosts"] = generate_host_dict(array, performance)
    if "volumes" in subset or "all" in subset:
        info["volumes"] = generate_vol_dict(array, performance)
        info["deleted_volumes"] = generate_del_vol_dict(array)
    if "snapshots" in subset or "all" in subset:
        info["snapshots"] = generate_snap_dict(array)
        info["deleted_snapshots"] = generate_del_snap_dict(array)
    if "hgroups" in subset or "all" in subset:
        info["hgroups"] = generate_hgroups_dict(array, performance)
    if "pgroups" in subset or "all" in subset:
        info["pgroups"] = generate_pgroups_dict(array)
        info["deleted_pgroups"] = generate_del_pgroups_dict(array)
    if "pods" in subset or "all" in subset or "replication" in subset:
        info["replica_links"] = generate_rl_dict(array)
        info["pods"] = generate_pods_dict(array, performance)
        info["deleted_pods"] = generate_del_pods_dict(array)
    if "admins" in subset or "all" in subset:
        info["admins"] = generate_admin_dict(array)
    if "vgroups" in subset or "all" in subset:
        info["vgroups"] = generate_vgroups_dict(array, performance)
        info["deleted_vgroups"] = generate_del_vgroups_dict(array)
    if "offload" in subset or "all" in subset:
        info["azure_offload"] = generate_azure_offload_dict(array)
        info["nfs_offload"] = generate_nfs_offload_dict(array)
        info["s3_offload"] = generate_s3_offload_dict(array)
    if "apps" in subset or "all" in subset:
        if "CBS" not in info["default"]["array_model"]:
            info["apps"] = generate_apps_dict(array)
        else:
            info["apps"] = {}
    if "arrays" in subset or "all" in subset:
        info["arrays"] = generate_conn_array_dict(array)
    if "certs" in subset or "all" in subset:
        info["certs"] = generate_certs_dict(array)
    if "kmip" in subset or "all" in subset:
        info["kmip"] = generate_kmip_dict(array)
    if "offload" in subset or "all" in subset:
        info["google_offload"] = generate_google_offload_dict(array)
    if "filesystems" in subset or "all" in subset:
        info["filesystems"] = generate_filesystems_dict(array, performance)
    if "policies" in subset or "all" in subset:
        user_map = bool(LooseVersion(NFS_USER_MAP_VERSION) <= LooseVersion(api_version))
        quota = bool(LooseVersion(DIR_QUOTA_API_VERSION) <= LooseVersion(api_version))
        autodir = bool(LooseVersion(AUTODIR_API_VERSION) <= LooseVersion(api_version))
        info["policies"] = generate_policies_dict(array, quota, autodir, user_map)
    if "clients" in subset or "all" in subset:
        info["clients"] = generate_clients_dict(array)
    if "dir_snaps" in subset or "all" in subset:
        info["dir_snaps"] = generate_dir_snaps_dict(array)
    if "snapshots" in subset or "all" in subset:
        info["pg_snapshots"] = generate_pgsnaps_dict(array)
    if "alerts" in subset or "all" in subset:
        info["alerts"] = generate_alerts_dict(array)
    if LooseVersion(SUBS_API_VERSION) <= LooseVersion(api_version) and (
        "subscriptions" in subset or "all" in subset
    ):
        info["subscriptions"] = generate_subs_dict(array)
    if LooseVersion(VM_VERSION) <= LooseVersion(api_version) and (
        "virtual_machines" in subset or "all" in subset
    ):
        info["virtual_machines"] = generate_vm_dict(array)
        info["virtual_machines_snaps"] = generate_vmsnap_dict(array)
    if LooseVersion(DSROLE_POLICY_API_VERSION) <= LooseVersion(api_version):
        if "realms" in subset or "all" in subset:
            info["realms"] = generate_realms_dict(array, performance)
    if LooseVersion(CONTEXT_API_VERSION) <= LooseVersion(api_version):
        if "fleet" in subset or "all" in subset:
            info["fleet"] = generate_fleet_dict(array)
        if "presets" in subset or "all" in subset:
            info["presets"] = generate_preset_dict(array)
        if "workloads" in subset or "all" in subset:
            info["workloads"] = generate_workload_dict(array)
    module.exit_json(changed=False, purefa_info=info)


if __name__ == "__main__":
    main()
