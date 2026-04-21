#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2019, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefb_info
version_added: '1.0.0'
short_description: Collect information from Pure Storage FlashBlade
description:
  - Collect information from a Pure Storage FlashBlade running the
    Purity//FB operating system. By default, the module will collect basic
    information including hosts, host groups, protection
    groups and volume counts. Additional information can be collected
    based on the configured set of arguements.
author:
  - Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  gather_subset:
    description:
      - When supplied, this argument will define the information to be collected.
        Possible values for this include all, minimum, config, performance,
        capacity, network, subnets, lags, filesystems, snapshots, buckets,
        replication, policies, arrays, accounts, admins, ad, kerberos,
        drives, servers and fleet.
    required: false
    type: list
    elements: str
    default: minimum
extends_documentation_fragment:
  - purestorage.flashblade.purestorage.fb
"""

EXAMPLES = r"""
- name: collect default set of info
  purestorage.flashblade.purefb_info:
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
  register: blade_info
- name: show default information
  debug:
    msg: "{{ blade_info['purefb_info']['default'] }}"

- name: collect configuration and capacity info
  purestorage.flashblade.purefb_info:
    gather_subset:
      - config
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
  register: blade_info
- name: show config information
  debug:
    msg: "{{ blade_info['purefb_info']['config'] }}"

- name: collect all info
  purestorage.flashblade.purefb_info:
    gather_subset:
      - all
    fb_url: 10.10.10.2
    api_token: T-55a68eb5-c785-4720-a2ca-8b03903bf641
  register: blade_info
- name: show all information
  debug:
    msg: "{{ blade_info['purefb_info'] }}"
"""

RETURN = r"""
purefb_info:
  description: Returns the information collected from the FlashBlade
  returned: always
  type: dict
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flashblade.plugins.module_utils.purefb import (
    get_system,
    purefb_argument_spec,
)
from datetime import datetime, timezone
import time


DRIVES_API_VERSION = "2.5"
SECURITY_API_VERSION = "2.7"
BUCKET_API_VERSION = "2.8"
SMB_CLIENT_API_VERSION = "2.10"
SPACE_API_VERSION = "2.11"
PUBLIC_API_VERSION = "2.12"
NAP_API_VERSION = "2.13"
RA_DURATION_API_VERSION = "2.14"
SMTP_ENCRYPT_API_VERSION = "2.15"
SERVERS_API_VERSION = "2.16"
FLEET_API_VERSION = "2.17"


def _millisecs_to_time(millisecs):
    if millisecs:
        return (str(int(millisecs / 3600000 % 24)).zfill(2) + ":00",)
    return None


def _bytes_to_human(bytes_number):
    if bytes_number:
        labels = ["B/s", "KB/s", "MB/s", "GB/s", "TB/s", "PB/s"]
        i = 0
        double_bytes = bytes_number
        while i < len(labels) and bytes_number >= 1024:
            double_bytes = bytes_number / 1024.0
            i += 1
            bytes_number = bytes_number / 1024
        return str(round(double_bytes, 2)) + " " + labels[i]
    return None


def generate_default_dict(blade):
    default_info = {}
    api_version = list(blade.get_versions().items)[0]
    defaults = list(blade.get_arrays().items)[0]
    default_info["flashblade_name"] = defaults.name
    default_info["purity_version"] = defaults.version
    default_info["filesystems"] = blade.get_file_systems().total_item_count
    default_info["snapshots"] = blade.get_file_system_snapshots().total_item_count
    default_info["buckets"] = blade.get_buckets().total_item_count
    default_info["object_store_users"] = blade.get_object_store_users().total_item_count
    default_info["object_store_accounts"] = (
        blade.get_object_store_accounts().total_item_count
    )
    default_info["blades"] = blade.get_blades().total_item_count
    default_info["certificates"] = blade.get_certificates().total_item_count
    default_info["total_capacity"] = list(blade.get_arrays_space().items)[0].capacity
    default_info["api_versions"] = api_version
    default_info["policies"] = blade.get_policies().total_item_count
    default_info["certificate_groups"] = blade.get_certificate_groups().total_item_count
    default_info["fs_replicas"] = blade.get_file_system_replica_links().total_item_count
    default_info["remote_credentials"] = (
        blade.get_object_store_remote_credentials().total_item_count
    )
    default_info["bucket_replicas"] = blade.get_bucket_replica_links().total_item_count
    default_info["connected_arrays"] = blade.get_array_connections().total_item_count
    default_info["targets"] = blade.get_targets().total_item_count
    default_info["kerberos_keytabs"] = blade.get_keytabs().total_item_count
    default_info["syslog_servers"] = len(blade.get_syslog_servers().items)
    default_info["object_store_virtual_hosts"] = len(
        blade.get_object_store_virtual_hosts().items
    )
    default_info["api_clients"] = len(blade.get_api_clients().items)
    default_info["idle_timeout"] = int(defaults.idle_timeout / 60000)
    if list(blade.get_arrays_eula().items)[0].signature.accepted:
        default_info["EULA"] = "Signed"
    else:
        default_info["EULA"] = "Not Signed"
    admin_settings = list(blade.get_admins_settings().items)[0]
    default_info["max_login_attempts"] = admin_settings.max_login_attempts
    default_info["min_password_length"] = admin_settings.min_password_length
    if admin_settings.lockout_duration:
        default_info["lockout_duration"] = (
            str(admin_settings.lockout_duration / 1000) + " seconds"
        )
    default_info["smb_mode"] = getattr(defaults, "smb_mode", None)
    default_info["timezone"] = defaults.time_zone
    default_info["product_type"] = getattr(defaults, "product_type", "Unknown")
    if SECURITY_API_VERSION in api_version:
        dar = defaults.encryption.data_at_rest
        default_info["encryption"] = {
            "data_at_rest_enabled": dar.enabled,
            "data_at_rest_algorithms": dar.algorithms,
            "data_at_rest_entropy_source": dar.entropy_source,
        }
        keys = list(blade.get_support_verification_keys().items)
        default_info["support_keys"] = {}
        for key in range(len(keys)):
            keyname = keys[key].name
            default_info["support_keys"][keyname] = {keys[key].verification_key}
        default_info["security_update"] = getattr(defaults, "security_update", None)
    if NAP_API_VERSION in api_version:
        default_info["network_access_protocol"] = getattr(
            defaults.network_access_policy, "name", "None"
        )
    ra_info = list(blade.get_support().items)[0]
    if ra_info.remote_assist_active:
        ra_expires = datetime.fromtimestamp(
            int(ra_info.remote_assist_expires) / 1000
        ).strftime("%Y-%m-%d %H:%M:%S")
        ra_opened = datetime.fromtimestamp(
            int(ra_info.remote_assist_opened) / 1000
        ).strftime("%Y-%m-%d %H:%M:%S")
    else:
        ra_expires = ra_opened = None
    default_info["remote_assist"] = {
        "phonehome_enabled": ra_info.phonehome_enabled,
        "proxy": ra_info.proxy,
        "ra_active": ra_info.remote_assist_active,
        "ra_expires": ra_expires,
        "ra_opened": ra_opened,
        "ra_status": ra_info.remote_assist_status,
    }
    if RA_DURATION_API_VERSION in api_version:
        default_info["remote_assist"]["ra_duration"] = ra_info.remote_assist_duration
    return default_info


def generate_perf_dict(blade):
    perf_info = {}
    total_perf = list(blade.get_arrays_performance().items)[0]
    http_perf = list(blade.get_arrays_performance(protocol="http").items)[0]
    s3_perf = list(blade.get_arrays_performance(protocol="s3").items)[0]
    nfs_perf = list(blade.get_arrays_performance(protocol="nfs").items)[0]
    perf_info["aggregate"] = {
        "bytes_per_op": total_perf.bytes_per_op,
        "bytes_per_read": total_perf.bytes_per_read,
        "bytes_per_write": total_perf.bytes_per_write,
        "read_bytes_per_sec": total_perf.read_bytes_per_sec,
        "reads_per_sec": total_perf.reads_per_sec,
        "usec_per_other_op": total_perf.usec_per_other_op,
        "usec_per_read_op": total_perf.usec_per_read_op,
        "usec_per_write_op": total_perf.usec_per_write_op,
        "write_bytes_per_sec": total_perf.write_bytes_per_sec,
        "writes_per_sec": total_perf.writes_per_sec,
    }
    perf_info["http"] = {
        "bytes_per_op": http_perf.bytes_per_op,
        "bytes_per_read": http_perf.bytes_per_read,
        "bytes_per_write": http_perf.bytes_per_write,
        "read_bytes_per_sec": http_perf.read_bytes_per_sec,
        "reads_per_sec": http_perf.reads_per_sec,
        "usec_per_other_op": http_perf.usec_per_other_op,
        "usec_per_read_op": http_perf.usec_per_read_op,
        "usec_per_write_op": http_perf.usec_per_write_op,
        "write_bytes_per_sec": http_perf.write_bytes_per_sec,
        "writes_per_sec": http_perf.writes_per_sec,
    }
    perf_info["s3"] = {
        "bytes_per_op": s3_perf.bytes_per_op,
        "bytes_per_read": s3_perf.bytes_per_read,
        "bytes_per_write": s3_perf.bytes_per_write,
        "read_bytes_per_sec": s3_perf.read_bytes_per_sec,
        "reads_per_sec": s3_perf.reads_per_sec,
        "usec_per_other_op": s3_perf.usec_per_other_op,
        "usec_per_read_op": s3_perf.usec_per_read_op,
        "usec_per_write_op": s3_perf.usec_per_write_op,
        "write_bytes_per_sec": s3_perf.write_bytes_per_sec,
        "writes_per_sec": s3_perf.writes_per_sec,
    }
    perf_info["nfs"] = {
        "bytes_per_op": nfs_perf.bytes_per_op,
        "bytes_per_read": nfs_perf.bytes_per_read,
        "bytes_per_write": nfs_perf.bytes_per_write,
        "read_bytes_per_sec": nfs_perf.read_bytes_per_sec,
        "reads_per_sec": nfs_perf.reads_per_sec,
        "usec_per_other_op": nfs_perf.usec_per_other_op,
        "usec_per_read_op": nfs_perf.usec_per_read_op,
        "usec_per_write_op": nfs_perf.usec_per_write_op,
        "write_bytes_per_sec": nfs_perf.write_bytes_per_sec,
        "writes_per_sec": nfs_perf.writes_per_sec,
    }
    if blade.get_array_connections_performance_replication().total_item_count > 0:
        file_repl_perf = list(
            blade.get_array_connections_performance_replication(
                type="file-system"
            ).items
        )[0]
        obj_repl_perf = list(
            blade.get_array_connections_performance_replication(
                type="object-store"
            ).items
        )[0]
        perf_info["file_replication"] = {
            "received_bytes_per_sec": getattr(
                file_repl_perf.periodic, "received_bytes_per_sec", None
            ),
            "transmitted_bytes_per_sec": getattr(
                file_repl_perf.periodic, "transmitted_bytes_per_sec", None
            ),
        }
        perf_info["object_replication"] = {
            "received_bytes_per_sec": getattr(
                obj_repl_perf.periodic, "received_bytes_per_sec", None
            ),
            "transmitted_bytes_per_sec": getattr(
                obj_repl_perf.periodic, "transmitted_bytes_per_sec", None
            ),
        }
    return perf_info


def generate_config_dict(blade):
    config_info = {}
    api_version = list(blade.get_versions().items)
    config_info["dns"] = {}
    dns_configs = list(blade.get_dns().items)
    for config in range(len(dns_configs)):
        config_info["dns"][dns_configs[config].name] = {
            "nameservers": dns_configs[config].nameservers,
            "domain": dns_configs[config].domain,
            "services": getattr(dns_configs[config], "services", None),
        }
        if hasattr(dns_configs[config], "sources"):
            config_info["dns"][dns_configs[config].name]["source"] = getattr(
                dns_configs[config].sources, "name", None
            )
    smtp_config = list(blade.get_smtp_servers().items)
    config_info["smtp"] = {}
    for config in range(len(smtp_config)):
        config_info["smtp"][smtp_config[config].name] = {
            "relay_host": getattr(smtp_config[config], "relay_host", None),
            "sender_domain": getattr(smtp_config[config], "sender_domain", None),
            "encryption_mode": getattr(smtp_config[config], "encryption_mode", None),
        }
    alert_config = list(blade.get_alert_watchers().items)
    config_info["alert_watchers"] = {}
    for config in range(len(alert_config)):
        config_info["alert_watchers"][alert_config[config].name] = {
            "enabled": alert_config[config].enabled,
            "minimum_notification_severity": alert_config[
                config
            ].minimum_notification_severity,
        }
    directory_services = list(blade.get_directory_services().items)
    for ds_service in range(len(directory_services)):
        service = directory_services[ds_service]
        if service.name in {"management", "nfs", "smb"}:
            key = f"{service.name}_directory_service"
            config_info[key] = {
                "base_dn": service.base_dn,
                "bind_user": service.bind_user,
                "ca_certificate": service.ca_certificate.name,
                "ca_certificate_group": service.ca_certificate_group.name,
                "enabled": service.enabled,
                "management": {
                    "user_login_attribute": service.management.user_login_attribute,
                    "user_object_class": service.management.user_object_class,
                },
                "nis_servers": service.nfs.nis_servers,
                "nis_domains": service.nfs.nis_domains,
                "services": service.services,
                "join_ou": service.smb.join_ou,
                "uris": service.uris,
            }
    # Forward backwards compatability
    config_info["array_management"] = config_info["management_directory_service"]

    config_info["directory_service_roles"] = {}
    roles = list(blade.get_directory_services_roles().items)
    for ds_role in range(len(roles)):
        role_name = roles[ds_role].name
        config_info["directory_service_roles"][role_name] = {
            "group": roles[ds_role].group,
            "group_base": roles[ds_role].group_base,
            "role": roles[ds_role].role.name,
        }
    config_info["ntp"] = list(blade.get_arrays().items)[0].ntp_servers
    certs = list(blade.get_certificates().items)
    config_info["ssl_certs"] = {}
    for cert in range(len(certs)):
        cert_name = certs[cert].name
        valid_from = time.strftime(
            "%a, %d %b %Y %H:%M:%S %Z",
            time.localtime(certs[cert].valid_from / 1000),
        )
        valid_to = time.strftime(
            "%a, %d %b %Y %H:%M:%S %Z",
            time.localtime(certs[cert].valid_to / 1000),
        )
        config_info["ssl_certs"][cert_name] = {
            "certificate": getattr(certs[cert], "certificate", None),
            "certificate_type": getattr(certs[cert], "certificatei_type", None),
            "common_name": getattr(certs[cert], "common_name", None),
            "country": getattr(certs[cert], "country", None),
            "email": getattr(certs[cert], "email", None),
            "intermediate_certificate": getattr(
                certs[cert], "intermeadiate_certificate", None
            ),
            "issued_by": getattr(certs[cert], "issued_by", None),
            "issued_to": getattr(certs[cert], "issued_to", None),
            "key_size": getattr(certs[cert], "key_size", None),
            "locality": getattr(certs[cert], "locality", None),
            "organization": getattr(certs[cert], "organization", None),
            "organizational_unit": getattr(certs[cert], "organizational_unit", None),
            "state": getattr(certs[cert], "state", None),
            "status": getattr(certs[cert], "status", None),
            "subject_alternative_names": getattr(
                certs[cert], "subject_alternative_names", None
            ),
            "valid_from": valid_from,
            "valid_to": valid_to,
        }
    crt_grps = list(blade.get_certificate_groups().items)
    config_info["certificate_groups"] = []
    for crt_grp in range(len(crt_grps)):
        config_info["certificate_groups"].append(crt_grps[crt_grp].name)
    config_info["syslog_servers"] = {}
    syslog_servers = list(blade.get_syslog_servers().items)
    for server in range(len(syslog_servers)):
        server_name = syslog_servers[server].name
        config_info["syslog_servers"][server_name] = {
            "uri": syslog_servers[server].uri,
            "services": getattr(syslog_servers[server], "services", None),
        }
    snmp_agents = list(blade.get_snmp_agents().items)
    config_info["snmp_agents"] = {}
    for agent in range(len(snmp_agents)):
        agent_name = snmp_agents[agent].name
        config_info["snmp_agents"][agent_name] = {
            "version": snmp_agents[agent].version,
            "engine_id": snmp_agents[agent].engine_id,
        }
        if config_info["snmp_agents"][agent_name]["version"] == "v3":
            config_info["snmp_agents"][agent_name]["auth_protocol"] = getattr(
                snmp_agents[agent].v3, "auth_protocol", None
            )
            config_info["snmp_agents"][agent_name]["privacy_protocol"] = getattr(
                snmp_agents[agent].v3, "privacy_protocol", None
            )
            config_info["snmp_agents"][agent_name]["user"] = getattr(
                snmp_agents[agent].v3, "user", None
            )
    config_info["snmp_managers"] = {}
    snmp_managers = list(blade.get_snmp_managers().items)
    for manager in range(len(snmp_managers)):
        mgr_name = snmp_managers[manager].name
        config_info["snmp_managers"][mgr_name] = {
            "version": snmp_managers[manager].version,
            "host": snmp_managers[manager].host,
            "notification": snmp_managers[manager].notification,
        }
        if config_info["snmp_managers"][mgr_name]["version"] == "v3":
            config_info["snmp_managers"][mgr_name]["auth_protocol"] = getattr(
                snmp_managers[manager].v3, "auth_protocol", None
            )
            config_info["snmp_managers"][mgr_name]["privacy_protocol"] = getattr(
                snmp_managers[manager].v3, "privacy_protocol", None
            )
            config_info["snmp_managers"][mgr_name]["user"] = getattr(
                snmp_managers[manager].v3, "user", None
            )
    if SMTP_ENCRYPT_API_VERSION in api_version:
        config_info["saml2sso"] = {}
        saml2 = list(blade.get_sso_saml2_idps().items)
        if saml2:
            config_info["saml2sso"] = {
                "enabled": saml2[0].enabled,
                "array_url": saml2[0].array_url,
                "name": saml2[0].name,
                "idp": {
                    "url": getattr(saml2[0].idp, "url", None),
                    "encrypt_enabled": saml2[0].idp.encrypt_assertion_enabled,
                    "sign_enabled": saml2[0].idp.sign_request_enabled,
                    "metadata_url": saml2[0].idp.metadata_url,
                },
                "sp": {
                    "decrypt_cred": getattr(
                        saml2[0].sp.decryption_credential, "name", None
                    ),
                    "sign_cred": getattr(saml2[0].sp.signing_credential, "name", None),
                },
            }
    return config_info


def generate_subnet_dict(blade):
    sub_info = {}
    subnets = list(blade.get_subnets().items)
    for sub in range(len(subnets)):
        sub_name = subnets[sub].name
        if subnets[sub].enabled:
            sub_info[sub_name] = {
                "gateway": subnets[sub].gateway,
                "mtu": subnets[sub].mtu,
                "vlan": subnets[sub].vlan,
                "prefix": subnets[sub].prefix,
                "services": subnets[sub].services,
            }
            sub_info[sub_name]["lag"] = subnets[sub].link_aggregation_group.name
            sub_info[sub_name]["interfaces"] = []
            for iface in range(len(subnets[sub].interfaces)):
                sub_info[sub_name]["interfaces"].append(
                    {"name": subnets[sub].interfaces[iface].name}
                )
    return sub_info


def generate_lag_dict(blade):
    lag_info = {}
    groups = list(blade.get_link_aggregation_groups().items)
    for groupcnt in range(len(groups)):
        lag_name = groups[groupcnt].name
        lag_info[lag_name] = {
            "lag_speed": groups[groupcnt].lag_speed,
            "port_speed": groups[groupcnt].port_speed,
            "status": groups[groupcnt].status,
        }
        lag_info[lag_name]["ports"] = []
        for port in range(len(groups[groupcnt].ports)):
            lag_info[lag_name]["ports"].append(
                {"name": groups[groupcnt].ports[port].name}
            )
    return lag_info


def generate_admin_dict(blade):
    admin_info = {}
    admins = list(blade.get_admins().items)
    for admin in range(len(admins)):
        admin_name = admins[admin].name
        admin_info[admin_name] = {
            "public_key": admins[admin].public_key,
            "local": admins[admin].is_local,
            "role": admins[admin].role.name,
            "locked": admins[admin].locked,
            "lockout_remaining": getattr(admins[admin], "lockout_remaining", None),
        }
        if hasattr(admins[admin].api_token, "expires_at"):
            if admins[admin].api_token.expires_at:
                admin_info[admin_name]["token_expires"] = datetime.fromtimestamp(
                    admins[admin].api_token.expires_at / 1000
                ).strftime("%Y-%m-%d %H:%M:%S")
        else:
            admin_info[admin_name]["token_expires"] = None
        if hasattr(admins[admin].api_token, "created_at"):
            if admins[admin].api_token.created_at:
                admin_info[admin_name]["token_created"] = datetime.fromtimestamp(
                    admins[admin].api_token.created_at / 1000
                ).strftime("%Y-%m-%d %H:%M:%S")
        else:
            admin_info[admin_name]["token_created"] = None
    return admin_info


def generate_targets_dict(blade):
    targets_info = {}
    targets = list(blade.get_targets().items)
    for target in range(len(targets)):
        target_name = targets[target].name
        targets_info[target_name] = {
            "address": targets[target].address,
            "status": targets[target].status,
            "status_details": targets[target].status_details,
            "ca_certificate_group": getattr(
                getattr(targets[target], "ca_certificate_group", None), "name", None
            ),
        }
    return targets_info


def generate_remote_creds_dict(blade):
    remote_creds_info = {}
    remote_creds = list(blade.get_object_store_remote_credentials().items)
    for cred_cnt in range(len(remote_creds)):
        cred_name = remote_creds[cred_cnt].name
        remote_creds_info[cred_name] = {
            "access_key": remote_creds[cred_cnt].access_key_id,
            "remote_array": remote_creds[cred_cnt].remote.name,
            "secret_access_key": remote_creds[cred_cnt].secret_access_key,
        }
    return remote_creds_info


def generate_file_repl_dict(blade):
    file_repl_info = {}
    file_links = list(blade.get_file_system_replica_links().items)
    for linkcnt in range(len(file_links)):
        fs_name = file_links[linkcnt].local_file_system.name
        file_repl_info[fs_name] = {
            "direction": file_links[linkcnt].direction,
            "link_type": file_links[linkcnt].link_type,
            "lag": file_links[linkcnt].lag,
            "status": file_links[linkcnt].status,
            "status_detail": file_links[linkcnt].status_detail,
            "remote_fs": file_links[linkcnt].remote.name
            + ":"
            + file_links[linkcnt].remote_file_system.name,
            "recovery_point": file_links[linkcnt].recovery_point,
        }
        file_repl_info[fs_name]["policies"] = []
        for policy_cnt in range(len(file_links[linkcnt].policies)):
            file_repl_info[fs_name]["policies"].append(
                file_links[linkcnt].policies[policy_cnt].display_name
            )
    return file_repl_info


def generate_bucket_repl_dict(blade):
    bucket_repl_info = {}
    bucket_links = list(blade.get_bucket_replica_links().items)
    for linkcnt in range(len(bucket_links)):
        bucket_name = bucket_links[linkcnt].local_bucket.name
        bucket_repl_info[bucket_name] = {
            "direction": bucket_links[linkcnt].direction,
            "lag": bucket_links[linkcnt].lag,
            "paused": bucket_links[linkcnt].paused,
            "status": bucket_links[linkcnt].status,
            "status_details": bucket_links[linkcnt].status_details,
            "remote_bucket": bucket_links[linkcnt].remote_bucket.name,
            "remote_array": bucket_links[linkcnt].remote.name,
            "remote_credentials": bucket_links[linkcnt].remote_credentials.name,
            "recovery_point": bucket_links[linkcnt].recovery_point,
            "object_backlog": {
                "bytes_count": bucket_links[linkcnt].object_backlog.bytes_count,
                "delete_ops_count": bucket_links[
                    linkcnt
                ].object_backlog.delete_ops_count,
                "other_ops_count": bucket_links[linkcnt].object_backlog.other_ops_count,
                "put_ops_count": bucket_links[linkcnt].object_backlog.put_ops_count,
            },
            "cascading_enabled": bucket_links[linkcnt].cascading_enabled,
        }
    return bucket_repl_info


def generate_network_dict(blade):
    net_info = {}
    ports = list(blade.get_network_interfaces().items)
    for portcnt in range(len(ports)):
        int_name = ports[portcnt].name
        net_info[int_name] = {
            "type": getattr(ports[portcnt], "type", None),
            "mtu": getattr(ports[portcnt], "mtu", None),
            "vlan": getattr(ports[portcnt], "vlan", None),
            "address": getattr(ports[portcnt], "address", None),
            "services": getattr(ports[portcnt], "services", None),
            "gateway": getattr(ports[portcnt], "gateway", None),
            "netmask": getattr(ports[portcnt], "netmask", None),
            "server": getattr(getattr(ports[portcnt], "server", None), "name", None),
            "subnet": getattr(getattr(ports[portcnt], "subnet", None), "name", None),
            "enabled": ports[portcnt].enabled,
        }
    return net_info


def generate_capacity_dict(blade):
    capacity_info = {}
    total_cap = list(blade.get_arrays_space().items)[0]
    file_cap = list(blade.get_arrays_space(type="file-system").items)[0]
    object_cap = list(blade.get_arrays_space(type="object-store").items)[0]
    capacity_info["total"] = total_cap.capacity
    capacity_info["aggregate"] = {
        "data_reduction": total_cap.space.data_reduction,
        "snapshots": total_cap.space.snapshots,
        "total_physical": total_cap.space.total_physical,
        "unique": total_cap.space.unique,
        "virtual": total_cap.space.virtual,
        "total_provisioned": total_cap.space.total_provisioned,
        "available_provisioned": total_cap.space.available_provisioned,
        "available_ratio": total_cap.space.available_ratio,
        "destroyed": total_cap.space.destroyed,
        "destroyed_virtual": total_cap.space.destroyed_virtual,
        "shared": getattr(total_cap.space, "shared", None),
    }
    capacity_info["file-system"] = {
        "data_reduction": file_cap.space.data_reduction,
        "snapshots": file_cap.space.snapshots,
        "total_physical": file_cap.space.total_physical,
        "unique": file_cap.space.unique,
        "virtual": file_cap.space.virtual,
        "total_provisioned": total_cap.space.total_provisioned,
        "available_provisioned": total_cap.space.available_provisioned,
        "available_ratio": total_cap.space.available_ratio,
        "destroyed": total_cap.space.destroyed,
        "destroyed_virtual": total_cap.space.destroyed_virtual,
        "shared": getattr(total_cap.space, "shared", None),
    }
    capacity_info["object-store"] = {
        "data_reduction": object_cap.space.data_reduction,
        "snapshots": object_cap.space.snapshots,
        "total_physical": object_cap.space.total_physical,
        "unique": object_cap.space.unique,
        "virtual": file_cap.space.virtual,
        "total_provisioned": total_cap.space.total_provisioned,
        "available_provisioned": total_cap.space.available_provisioned,
        "available_ratio": total_cap.space.available_ratio,
        "destroyed": total_cap.space.destroyed,
        "destroyed_virtual": total_cap.space.destroyed_virtual,
        "shared": getattr(total_cap.space, "shared", None),
    }

    return capacity_info


def generate_snap_dict(blade):
    snap_info = {}
    snaps = list(blade.get_file_system_snapshots().items)
    api_version = list(blade.get_versions().items)
    for snap in range(len(snaps)):
        snapshot = snaps[snap].name
        snap_info[snapshot] = {
            "destroyed": snaps[snap].destroyed,
            "source": snaps[snap].source.location.name,
            "suffix": snaps[snap].suffix,
            "created": datetime.fromtimestamp(
                snaps[snap].created / 1000,
                tz=timezone.utc,
            ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "time_remaining": getattr(snaps[snap], "time_remaining", None),
            "policy": getattr(getattr(snaps[snap], "policy", None), "name", None),
            "owner": snaps[snap].owner.name,
            "owner_destroyed": snaps[snap].owner_destroyed,
            "source_display_name": snaps[snap].source.display_name,
            "source_is_local": snaps[snap].source.is_local,
            "source_location": snaps[snap].source.location.name,
            "policies": [],
        }
        if PUBLIC_API_VERSION in api_version:
            if hasattr(snaps[snap], "policies"):
                for policy in range(len(snaps[snap].policies)):
                    snap_info[snapshot]["policies"].append(
                        {
                            "name": snaps[snap].policies[policy].name,
                            "location": snaps[snap].policies[policy].location.name,
                        }
                    )
    return snap_info


def generate_snap_transfer_dict(blade):
    snap_transfer_info = {}
    snap_transfers = list(blade.get_file_system_snapshots_transfer().items)
    for snap_transfer in range(len(snap_transfers)):
        transfer = snap_transfers[snap_transfer].name
        snap_transfer_info[transfer] = {
            "completed": snap_transfers[snap_transfer].completed,
            "data_transferred": snap_transfers[snap_transfer].data_transferred,
            "progress": snap_transfers[snap_transfer].progress,
            "direction": snap_transfers[snap_transfer].direction,
            "remote": snap_transfers[snap_transfer].remote.name,
            "remote_snapshot": snap_transfers[snap_transfer].remote_snapshot.name,
            "started": snap_transfers[snap_transfer].started,
            "status": snap_transfers[snap_transfer].status,
        }
    return snap_transfer_info


def generate_array_conn_dict(blade):
    array_conn_info = {}
    arrays = list(blade.get_array_connections().items)
    for arraycnt in range(len(arrays)):
        array = arrays[arraycnt].remote.name
        array_conn_info[array] = {
            "encrypted": arrays[arraycnt].encrypted,
            "replication_addresses": arrays[arraycnt].replication_addresses,
            "management_address": arrays[arraycnt].management_address,
            "status": arrays[arraycnt].status,
            "version": arrays[arraycnt].version,
            "ca_certificate_group": arrays[arraycnt].ca_certificate_group.name,
            "throttle": {
                "default_limit": _bytes_to_human(
                    getattr(arrays[arraycnt].throttle, "default_limit", None)
                ),
                "window_limit": _bytes_to_human(
                    getattr(arrays[arraycnt].throttle, "window_limit", None)
                ),
                "window_start": _millisecs_to_time(
                    getattr(arrays[arraycnt].throttle.window, "start", None)
                ),
                "window_end": _millisecs_to_time(
                    getattr(arrays[arraycnt].throttle.window, "end", None)
                ),
            },
        }
    return array_conn_info


def generate_policies_dict(blade):
    policies_info = {}
    policies = list(blade.get_policies().items)
    for policycnt in range(len(policies)):
        policy = policies[policycnt].name
        policies_info[policy] = {
            "enabled": policies[policycnt].enabled,
            "retention_lock": getattr(policies[policycnt], "retention_lock", None),
            "policy_type": policies[policycnt].policy_type,
            "rules": {},
        }
        if policies[policycnt].rules:
            policies_info[policy]["rules"] = {
                "at": getattr(policies[policycnt].rules[0], "at", None),
                "every": getattr(policies[policycnt].rules[0], "every", None),
                "keep_for": getattr(policies[policycnt].rules[0], "keep_for", None),
                "time_zone": getattr(policies[policycnt].rules[0], "time_zone", None),
            }
    return policies_info


def generate_bucket_dict(blade):
    bucket_info = {}
    buckets = list(blade.get_buckets().items)
    for bckt in range(len(buckets)):
        bucket = buckets[bckt].name
        bucket_info[bucket] = {
            "versioning": buckets[bckt].versioning,
            "bucket_type": getattr(buckets[bckt], "bucket_type", None),
            "object_count": buckets[bckt].object_count,
            "id": buckets[bckt].id,
            "account_name": buckets[bckt].account.name,
            "data_reduction": getattr(buckets[bckt].space, "data_reduction", None),
            "snapshot_space": buckets[bckt].space.snapshots,
            "total_physical_space": buckets[bckt].space.total_physical,
            "unique_space": buckets[bckt].space.unique,
            "virtual_space": buckets[bckt].space.virtual,
            "total_provisioned_space": getattr(
                buckets[bckt].space, "total_provisioned", None
            ),
            "available_provisioned_space": getattr(
                buckets[bckt].space, "available_provisioned", None
            ),
            "available_ratio": getattr(buckets[bckt].space, "available_ratio", None),
            "destroyed_space": getattr(buckets[bckt].space, "destroyed", None),
            "destroyed_virtual_space": getattr(
                buckets[bckt].space, "destroyed_virtual", None
            ),
            "created": buckets[bckt].created,
            "destroyed": buckets[bckt].destroyed,
            "time_remaining": getattr(buckets[bckt], "time_remaining", None),
            "time_remaining_status": getattr(
                buckets[bckt], "time_remaining_status", None
            ),
            "retention_lock": buckets[bckt].retention_lock,
            "quota_limit": buckets[bckt].quota_limit,
            "object_lock_config": {
                "enabled": buckets[bckt].object_lock_config.enabled,
                "freeze_locked_objects": buckets[
                    bckt
                ].object_lock_config.freeze_locked_objects,
                "default_retention": getattr(
                    buckets[bckt].object_lock_config, "default_retention", None
                ),
                "default_retention_mode": getattr(
                    buckets[bckt].object_lock_config,
                    "default_retention_mode",
                    None,
                ),
            },
            "eradication_config": {
                "eradication_delay": getattr(
                    buckets[bckt].eradication_config, "eradication_delay", None
                ),
                "eradication_mode": getattr(
                    buckets[bckt].eradication_config, "eradication_mode", None
                ),
                "manual_eradication": buckets[
                    bckt
                ].eradication_config.manual_eradication,
            },
            "public_status": getattr(buckets[bckt], "public_status", None),
            "public_access_config": {
                "block_new_public_policies": getattr(
                    getattr(buckets[bckt], "public_access_config", None),
                    "block_new_public_policies",
                    None,
                ),
                "block_public_access": getattr(
                    getattr(buckets[bckt], "public_access_config", None),
                    "block_public_access",
                    None,
                ),
            },
            "lifecycle_rules": {},
        }
    for bckt in range(len(buckets)):
        if buckets[bckt].destroyed:
            # skip processing buckets marked as destroyed
            continue
        all_rules = list(blade.get_lifecycle_rules(bucket_ids=[buckets[bckt].id]).items)
        for rule in range(len(all_rules)):
            bucket_name = all_rules[rule].bucket.name
            rule_id = all_rules[rule].rule_id
            if all_rules[rule].keep_previous_version_for:
                keep_previous_version_for = int(
                    all_rules[rule].keep_previous_version_for / 86400000
                )
            else:
                keep_previous_version_for = None
            if all_rules[rule].keep_current_version_for:
                keep_current_version_for = int(
                    all_rules[rule].keep_current_version_for / 86400000
                )
            else:
                keep_current_version_for = None
            if all_rules[rule].abort_incomplete_multipart_uploads_after:
                abort_incomplete_multipart_uploads_after = int(
                    all_rules[rule].abort_incomplete_multipart_uploads_after / 86400000
                )
            else:
                abort_incomplete_multipart_uploads_after = None
            if all_rules[rule].keep_current_version_until:
                keep_current_version_until = datetime.fromtimestamp(
                    all_rules[rule].keep_current_version_until / 1000
                ).strftime("%Y-%m-%d")
            else:
                keep_current_version_until = None
            bucket_info[bucket_name]["lifecycle_rules"][rule_id] = {
                "keep_previous_version_for (days)": keep_previous_version_for,
                "keep_current_version_for (days)": keep_current_version_for,
                "keep_current_version_until": keep_current_version_until,
                "prefix": all_rules[rule].prefix,
                "enabled": all_rules[rule].enabled,
                "abort_incomplete_multipart_uploads_after (days)": abort_incomplete_multipart_uploads_after,
                "cleanup_expired_object_delete_marker": all_rules[
                    rule
                ].cleanup_expired_object_delete_marker,
            }

    return bucket_info


def generate_kerb_dict(blade):
    kerb_info = {}
    keytabs = list(blade.get_keytabs().items)
    for ktab in range(len(keytabs)):
        keytab_name = keytabs[ktab].prefix
        kerb_info[keytab_name] = {}
        for key in range(len(keytabs)):
            if keytabs[key].prefix == keytab_name:
                kerb_info[keytab_name][keytabs[key].suffix] = {
                    "fqdn": keytabs[key].fqdn,
                    "kvno": keytabs[key].kvno,
                    "principal": keytabs[key].principal,
                    "realm": keytabs[key].realm,
                    "encryption_type": keytabs[key].encryption_type,
                    "server": None,
                    "source": None,
                }
                if hasattr(keytabs[key], "server"):
                    kerb_info[keytab_name][keytabs[key].suffix]["server"] = getattr(
                        keytabs[key].server, "name", None
                    )
                if hasattr(keytabs[key], "source"):
                    kerb_info[keytab_name][keytabs[key].suffix]["source"] = getattr(
                        keytabs[key].source, "name", None
                    )
    return kerb_info


def generate_ad_dict(blade):
    ad_info = {}
    active_directory = blade.get_active_directory()
    if active_directory.total_item_count != 0:
        ad_accounts = list(active_directory.items)
        for adir in range(len(ad_accounts)):
            name = ad_accounts[adir].name
            ad_info[name] = {
                "computer": ad_accounts[adir].computer_name,
                "domain": ad_accounts[adir].domain,
                "directory_servers": ad_accounts[adir].directory_servers,
                "kerberos_servers": ad_accounts[adir].kerberos_servers,
                "service_principals": ad_accounts[adir].service_principal_names,
                "join_ou": ad_accounts[adir].join_ou,
                "encryption_types": ad_accounts[adir].encryption_types,
                "global_catalog_servers": getattr(
                    ad_accounts[adir], "global_catalog_servers", None
                ),
                "server": None,
            }
            if hasattr(ad_accounts[adir], "server"):
                ad_info[name]["server"] = getattr(
                    ad_accounts[adir].server, "name", None
                )
    return ad_info


def generate_bucket_access_policies_dict(blade):
    policies_info = {}
    buckets = list(blade.get_buckets().items)
    for bucket in range(len(buckets)):
        res = blade.get_buckets_bucket_access_policies(
            bucket_names=[buckets[bucket].name]
        )
        if res.status_code == 200 and res.total_item_count != 0:
            policies = list(res.items)
            for policy in range(len(policies)):
                policy_name = policies[policy].name
                policies_info[policy_name] = {
                    "description": policies[policy].description,
                    "enabled": policies[policy].enabled,
                    "local": policies[policy].is_local,
                    "rules": [],
                }
                for rule in range(len(policies[policy].rules)):
                    policies_info[policy_name]["rules"].append(
                        {
                            "actions": policies[policy].rules[rule].actions,
                            "resources": policies[policy].rules[rule].resources,
                            "all_principals": policies[policy]
                            .rules[rule]
                            .principals.all,
                            "effect": policies[policy].rules[rule].effect,
                            "name": policies[policy].rules[rule].name,
                        }
                    )
    return policies_info


def generate_bucket_cross_object_policies_dict(blade):
    policies_info = {}
    buckets = list(blade.get_buckets().items)
    for bucket in range(len(buckets)):
        policies = list(
            blade.get_buckets_cross_origin_resource_sharing_policies(
                bucket_names=[buckets[bucket].name]
            ).items
        )
        for policy in range(len(policies)):
            policy_name = policies[policy].name
            policies_info[policy_name] = {
                "allowed_headers": policies[policy].allowed_headers,
                "allowed_methods": policies[policy].allowed_methods,
                "allowed_origins": policies[policy].allowed_origins,
            }
    return policies_info


def generate_object_store_access_policies_dict(blade):
    policies_info = {}
    policies = list(blade.get_object_store_access_policies().items)
    for policy in range(len(policies)):
        policy_name = policies[policy].name
        policies_info[policy_name] = {
            "ARN": policies[policy].arn,
            "description": policies[policy].description,
            "enabled": policies[policy].enabled,
            "local": policies[policy].is_local,
            "rules": [],
        }
        for rule in range(len(policies[policy].rules)):
            policies_info[policy_name]["rules"].append(
                {
                    "actions": policies[policy].rules[rule].actions,
                    "conditions": {
                        "source_ips": policies[policy]
                        .rules[rule]
                        .conditions.source_ips,
                        "s3_delimiters": policies[policy]
                        .rules[rule]
                        .conditions.s3_delimiters,
                        "s3_prefixes": policies[policy]
                        .rules[rule]
                        .conditions.s3_prefixes,
                    },
                    "effect": policies[policy].rules[rule].effect,
                    "name": policies[policy].rules[rule].name,
                }
            )
    return policies_info


def generate_nfs_export_policies_dict(blade):
    policies_info = {}
    policies = list(blade.get_nfs_export_policies().items)
    for policy in range(len(policies)):
        policy_name = policies[policy].name
        policies_info[policy_name] = {
            "local": policies[policy].is_local,
            "enabled": policies[policy].enabled,
            "rules": [],
        }
        for rule in range(len(policies[policy].rules)):
            policies_info[policy_name]["rules"].append(
                {
                    "access": policies[policy].rules[rule].access,
                    "anongid": policies[policy].rules[rule].anongid,
                    "anonuid": policies[policy].rules[rule].anonuid,
                    "atime": policies[policy].rules[rule].atime,
                    "client": policies[policy].rules[rule].client,
                    "fileid_32bit": policies[policy].rules[rule].fileid_32bit,
                    "permission": policies[policy].rules[rule].permission,
                    "secure": policies[policy].rules[rule].secure,
                    "security": policies[policy].rules[rule].security,
                    "index": policies[policy].rules[rule].index,
                }
            )
    return policies_info


def generate_smb_client_policies_dict(blade):
    policies_info = {}
    policies = list(blade.get_smb_client_policies().items)
    for policy in range(len(policies)):
        policy_name = policies[policy].name
        policies_info[policy_name] = {
            "local": policies[policy].is_local,
            "enabled": policies[policy].enabled,
            "version": policies[policy].version,
            "rules": [],
        }
        for rule in range(len(policies[policy].rules)):
            policies_info[policy_name]["rules"].append(
                {
                    "name": policies[policy].rules[rule].name,
                    "change": getattr(policies[policy].rules[rule], "change", None),
                    "full_control": getattr(
                        policies[policy].rules[rule], "full_control", None
                    ),
                    "principal": getattr(
                        policies[policy].rules[rule], "principal", None
                    ),
                    "read": getattr(policies[policy].rules[rule], "read", None),
                    "client": getattr(policies[policy].rules[rule], "client", None),
                    "index": getattr(policies[policy].rules[rule], "index", None),
                    "policy_version": getattr(
                        policies[policy].rules[rule], "policy_version", None
                    ),
                    "encryption": getattr(
                        policies[policy].rules[rule], "encryption", None
                    ),
                    "permission": getattr(
                        policies[policy].rules[rule], "permission", None
                    ),
                }
            )
    return policies_info


def generate_object_store_accounts_dict(blade):
    account_info = {}
    accounts = list(blade.get_object_store_accounts().items)
    for account in range(len(accounts)):
        acc_name = accounts[account].name
        account_info[acc_name] = {
            "object_count": accounts[account].object_count,
            "data_reduction": accounts[account].space.data_reduction,
            "snapshots_space": accounts[account].space.snapshots,
            "total_physical_space": accounts[account].space.total_physical,
            "unique_space": accounts[account].space.unique,
            "virtual_space": accounts[account].space.virtual,
            "total_provisioned_space": getattr(
                accounts[account].space, "total_provisioned", None
            ),
            "available_provisioned_space": getattr(
                accounts[account].space, "available_provisioned", None
            ),
            "available_ratio": getattr(
                accounts[account].space, "available_ratio", None
            ),
            "destroyed_space": getattr(accounts[account].space, "destroyed", None),
            "destroyed_virtual_space": getattr(
                accounts[account].space, "destroyed_virtual", None
            ),
            "quota_limit": getattr(accounts[account], "quota_limit", None),
            "hard_limit_enabled": getattr(
                accounts[account], "hard_limit_enabled", None
            ),
            "total_provisioned": getattr(
                accounts[account].space, "total_provisioned", None
            ),
            "users": {},
            "bucket_defaults": {
                "hard_limit_enabled": getattr(
                    getattr(accounts[account], "bucket_defaults", None),
                    "hard_limit_enabled",
                    None,
                ),
                "quota_limit": getattr(
                    getattr(accounts[account], "bucket_defaults", None),
                    "quota_limit",
                    None,
                ),
            },
            "public_access_config": {
                "block_new_public_policies": getattr(
                    getattr(accounts[account], "public_access_config", None),
                    "block_new_public_policies",
                    None,
                ),
                "block_public_access": getattr(
                    getattr(accounts[account], "public_access_config", None),
                    "block_public_access",
                    None,
                ),
            },
        }
        acc_users = list(
            blade.get_object_store_users(filter='name="' + acc_name + '/*"').items
        )
        for acc_user in range(len(acc_users)):
            user_name = acc_users[acc_user].name.split("/")[1]
            account_info[acc_name]["users"][user_name] = {"keys": [], "policies": []}
            if (
                blade.get_object_store_access_keys(
                    filter='user.name="' + acc_users[acc_user].name + '"'
                ).total_item_count
                != 0
            ):
                access_keys = list(
                    blade.get_object_store_access_keys(
                        filter='user.name="' + acc_users[acc_user].name + '"'
                    ).items
                )
                for key in range(len(access_keys)):
                    account_info[acc_name]["users"][user_name]["keys"].append(
                        {
                            "name": access_keys[key].name,
                            "enabled": bool(access_keys[key].enabled),
                        }
                    )
            if (
                blade.get_object_store_access_policies_object_store_users(
                    member_names=[acc_users[acc_user].name]
                ).total_item_count
                != 0
            ):
                policies = list(
                    blade.get_object_store_access_policies_object_store_users(
                        member_names=[acc_users[acc_user].name]
                    ).items
                )
                for policy in range(len(policies)):
                    account_info[acc_name]["users"][user_name]["policies"].append(
                        policies[policy].policy.name
                    )
    return account_info


def generate_fs_dict(blade):
    fsys = list(blade.get_file_systems().items)
    fs_info = {}
    for fsystem in range(len(fsys)):
        share = fsys[fsystem].name
        fs_info[share] = {
            "fast_remove": fsys[fsystem].fast_remove_directory_enabled,
            "snapshot_enabled": fsys[fsystem].snapshot_directory_enabled,
            "provisioned": fsys[fsystem].provisioned,
            "destroyed": fsys[fsystem].destroyed,
            "nfs_rules": getattr(fsys[fsystem].nfs, "rules", None),
            "nfs_v3": getattr(fsys[fsystem].nfs, "v3_enabled", False),
            "nfs_v4_1": getattr(fsys[fsystem].nfs, "v4_1_enabled", False),
            "user_quotas": {},
            "group_quotas": {},
            "http": fsys[fsystem].http.enabled,
            "smb_mode": getattr(fsys[fsystem].smb, "acl_mode", None),
            "multi_protocol": {
                "safegaurd_acls": fsys[fsystem].multi_protocol.safeguard_acls,
                "access_control_style": fsys[
                    fsystem
                ].multi_protocol.access_control_style,
            },
            "hard_limit": fsys[fsystem].hard_limit_enabled,
            "promotion_status": fsys[fsystem].promotion_status,
            "requested_promotion_state": fsys[fsystem].requested_promotion_state,
            "writable": fsys[fsystem].writable,
            "source": {
                "is_local": fsys[fsystem].source.is_local,
                "name": getattr(fsys[fsystem].source, "name", None),
                "location": getattr(
                    getattr(fsys[fsystem], "location", None), "name", None
                ),
            },
            "default_group_quota": fsys[fsystem].default_group_quota,
            "default_user_quota": fsys[fsystem].default_user_quota,
            "export_policy": getattr(
                getattr(getattr(fsys[fsystem], "nfs", None), "export_policy", None),
                "name",
                None,
            ),
            "smb_client_policy": getattr(
                getattr(getattr(fsys[fsystem], "smb", None), "client_policy", None),
                "name",
                None,
            ),
            "smb_share_policy": getattr(
                getattr(getattr(fsys[fsystem], "smb", None), "share_policy", None),
                "name",
                None,
            ),
            "smb_continuous_availability_enabled": getattr(
                getattr(fsys[fsystem], "smb", None),
                "continuous_availability_enabled",
                False,
            ),
            "multi_protocol_access_control_style": getattr(
                getattr(fsys[fsystem], "multi_protocol", None),
                "access_control_style",
                None,
            ),
            "multi_protocol_safeguard_acls": getattr(
                getattr(fsys[fsystem], "multi_protocol", None), "safeguard_acls", None
            ),
        }
        fs_groups = False
        res = blade.get_quotas_groups(file_system_names=[share])
        if res.total_item_count != 0:
            fs_groups = True
            fs_group_quotas = list(res.items)
        fs_users = False
        res = blade.get_quotas_users(file_system_names=[share])
        if res.total_item_count != 0:
            fs_users = True
            fs_user_quotas = list(res.items)
        if fs_groups:
            for group_quota in range(len(fs_group_quotas)):
                group_name = fs_group_quotas[group_quota].name.rsplit("/")[1]
                fs_info[share]["group_quotas"][group_name] = {
                    "group_id": getattr(fs_group_quotas[group_quota].group, "id", None),
                    "group_name": getattr(
                        fs_group_quotas[group_quota].group, "name", None
                    ),
                    "quota": fs_group_quotas[group_quota].quota,
                    "usage": fs_group_quotas[group_quota].usage,
                }
        if fs_users:
            for user_quota in range(len(fs_user_quotas)):
                user_name = fs_user_quotas[user_quota].name.rsplit("/")[1]
                fs_info[share]["user_quotas"][user_name] = {
                    "user_id": getattr(fs_user_quotas[user_quota].user, "id", None),
                    "user_name": getattr(fs_user_quotas[user_quota].user, "name", None),
                    "quota": fs_user_quotas[user_quota].quota,
                    "usage": fs_user_quotas[user_quota].usage,
                }

    return fs_info


def generate_drives_dict(blade):
    """
    Drives information is only available for the Legend chassis.
    The Legend chassis product_name has // in it so only bother if
    that is the case.
    """
    drives_info = {}
    drives = list(blade.get_drives().items)
    if "//" in list(blade.get_arrays().items)[0].product_type:
        for drive in range(len(drives)):
            name = drives[drive].name
            drives_info[name] = {
                "progress": getattr(drives[drive], "progress", None),
                "raw_capacity": getattr(drives[drive], "raw_capacity", None),
                "status": getattr(drives[drive], "status", None),
                "details": getattr(drives[drive], "details", None),
                "type": getattr(drives[drive], "type", None),
            }
    return drives_info


def generate_servers_dict(blade):
    servers_info = {}
    servers = list(blade.get_servers().items)
    for server in range(len(servers)):
        name = servers[server].name
        servers_info[name] = {
            "created": datetime.fromtimestamp(servers[server].created / 1000).strftime(
                "%Y-%m-%d %H:%M:%S"
            ),
            "dns": [],
            "directory_services": [],
        }
        for d_serv in range(len(servers[server].directory_services)):
            servers_info[name]["directory_services"].append(
                servers[server].directory_services[d_serv].name
            )
        for dns in range(len(servers[server].dns)):
            servers_info[name]["dns"].append(servers[server].dns[dns].name)
    return servers_info


def generate_fleet_dict(blade):
    fleet_info = {}
    fleet = list(blade.get_fleets().items)
    if fleet:
        fleet_name = list(blade.get_fleets().items)[0].name
        fleet_info[fleet_name] = {
            "members": {},
        }
        members = list(blade.get_fleets_members().items)
        for member in range(len(members)):
            name = members[member].member.name
            fleet_info[fleet_name]["members"][name] = {
                "status": members[member].status,
                "status_details": members[member].status_details,
            }
    return fleet_info


def main():
    argument_spec = purefb_argument_spec()
    argument_spec.update(
        dict(gather_subset=dict(default="minimum", type="list", elements="str"))
    )

    module = AnsibleModule(argument_spec, supports_check_mode=True)

    blade = get_system(module)
    api_versions = list(blade.get_versions().items)

    if not module.params["gather_subset"]:
        module.params["gather_subset"] = ["minimum"]
    subset = [test.lower() for test in module.params["gather_subset"]]
    valid_subsets = (
        "all",
        "minimum",
        "config",
        "performance",
        "capacity",
        "network",
        "subnets",
        "lags",
        "filesystems",
        "snapshots",
        "buckets",
        "arrays",
        "replication",
        "policies",
        "accounts",
        "admins",
        "ad",
        "kerberos",
        "drives",
        "servers",
        "fleet",
    )
    subset_test = (test in valid_subsets for test in subset)
    if not all(subset_test):
        module.fail_json(
            msg="value must gather_subset must be one or more of: %s, got: %s"
            % (",".join(valid_subsets), ",".join(subset))
        )

    info = {}

    if "minimum" in subset or "all" in subset:
        info["default"] = generate_default_dict(blade)
    if "performance" in subset or "all" in subset:
        info["performance"] = generate_perf_dict(blade)
    if "config" in subset or "all" in subset:
        info["config"] = generate_config_dict(blade)
    if "capacity" in subset or "all" in subset:
        info["capacity"] = generate_capacity_dict(blade)
    if "lags" in subset or "all" in subset:
        info["lag"] = generate_lag_dict(blade)
    if "network" in subset or "all" in subset:
        info["network"] = generate_network_dict(blade)
    if "subnets" in subset or "all" in subset:
        info["subnet"] = generate_subnet_dict(blade)
    if "filesystems" in subset or "all" in subset:
        info["filesystems"] = generate_fs_dict(blade)
    if "admins" in subset or "all" in subset:
        info["admins"] = generate_admin_dict(blade)
    if "snapshots" in subset or "all" in subset:
        info["snapshots"] = generate_snap_dict(blade)
    if "buckets" in subset or "all" in subset:
        info["buckets"] = generate_bucket_dict(blade)
    if "policies" in subset or "all" in subset:
        info["policies"] = generate_policies_dict(blade)
        info["snapshot_policies"] = generate_policies_dict(blade)
    if "arrays" in subset or "all" in subset:
        info["arrays"] = generate_array_conn_dict(blade)
    if "replication" in subset or "all" in subset:
        info["file_replication"] = generate_file_repl_dict(blade)
        info["bucket_replication"] = generate_bucket_repl_dict(blade)
        info["snap_transfers"] = generate_snap_transfer_dict(blade)
        info["remote_credentials"] = generate_remote_creds_dict(blade)
        info["targets"] = generate_targets_dict(blade)
    if "accounts" in subset or "all" in subset:
        info["accounts"] = generate_object_store_accounts_dict(blade)
    if "ad" in subset or "all" in subset:
        info["active_directory"] = generate_ad_dict(blade)
    if "kerberos" in subset or "all" in subset:
        info["kerberos"] = generate_kerb_dict(blade)
    if "policies" in subset or "all" in subset:
        info["access_policies"] = generate_object_store_access_policies_dict(blade)
        if PUBLIC_API_VERSION in api_versions:
            info["bucket_access_policies"] = generate_bucket_access_policies_dict(blade)
            info["bucket_cross_origin_policies"] = (
                generate_bucket_cross_object_policies_dict(blade)
            )
        info["export_policies"] = generate_nfs_export_policies_dict(blade)
        if SMB_CLIENT_API_VERSION in api_versions:
            info["share_policies"] = generate_smb_client_policies_dict(blade)
        if FLEET_API_VERSION in api_versions:
            info["fleet"] = generate_fleet_dict(blade)
    if "drives" in subset or "all" in subset and DRIVES_API_VERSION in api_versions:
        info["drives"] = generate_drives_dict(blade)
    if "servers" in subset or "all" in subset and SERVERS_API_VERSION in api_versions:
        info["servers"] = generate_servers_dict(blade)
    module.exit_json(changed=False, purefb_info=info)


if __name__ == "__main__":
    main()
