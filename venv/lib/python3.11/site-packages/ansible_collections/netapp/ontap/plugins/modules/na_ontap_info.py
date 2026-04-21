#!/usr/bin/python

# (c) 2018 Piotr Olczak <piotr.olczak@redhat.com>
# (c) 2018-2022, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

'''
na_ontap_info
'''

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_info
author: Piotr Olczak (@dprts) <polczak@redhat.com>
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_zapi
short_description: NetApp information gatherer
description:
    - This module allows you to gather various information about ONTAP configuration
version_added: 2.9.0
requirements:
    - netapp_lib
options:
    state:
        type: str
        description:
            - deprecated as of 21.1.0.
            - this option was ignored and continues to be ignored.
    vserver:
        type: str
        description:
            - If present, 'vserver tunneling' will limit the output to the vserver scope.
            - Note that not all subsets are supported on a vserver, and 'all' will trigger an error.
        version_added: '19.11.0'
    gather_subset:
        type: list
        elements: str
        description:
            - When supplied, this argument will restrict the information collected to a given subset.  Possible values for this argument include
            - "active_directory_account_info"
            - "aggregate_info"
            - "aggr_efficiency_info"
            - "autosupport_check_info"
            - "cifs_options_info"
            - "cifs_server_info"
            - "cifs_share_info"
            - "cifs_vserver_security_info"
            - "cluster_identity_info"
            - "cluster_image_info"
            - "cluster_log_forwarding_info"
            - "cluster_node_info"
            - "cluster_peer_info"
            - "cluster_switch_info"
            - "clock_info"
            - "disk_info"
            - "env_sensors_info"
            - "event_notification_destination_info"
            - "event_notification_info"
            - "export_policy_info"
            - "export_rule_info"
            - "fcp_adapter_info"
            - "fcp_alias_info"
            - "fcp_service_info"
            - "igroup_info"
            - "iscsi_service_info"
            - "job_schedule_cron_info"
            - "kerberos_realm_info"
            - "ldap_client"
            - "ldap_config"
            - "license_info"
            - "lun_info"
            - "lun_map_info"
            - "metrocluster_check_info"
            - "metrocluster_info"
            - "metrocluster_node_info"
            - "net_dev_discovery_info"
            - "net_dns_info"
            - "net_failover_group_info"
            - "net_firewall_info"
            - "net_ifgrp_info"
            - "net_interface_info"
            - "net_interface_service_policy_info"
            - "net_ipspaces_info"
            - "net_port_info"
            - "net_port_broadcast_domain_info"
            - "net_routes_info"
            - "net_vlan_info"
            - "nfs_info"
            - "ntfs_dacl_info"
            - "ntfs_sd_info"
            - "ntp_server_info"
            - "nvme_info"
            - "nvme_interface_info"
            - "nvme_namespace_info"
            - "nvme_subsystem_info"
            - "ontap_system_version"
            - "ontap_version"
            - "ontapi_version"
            - "qos_adaptive_policy_info"
            - "qos_policy_info"
            - "qtree_info"
            - "quota_policy_info"
            - "quota_report_info"
            - "role_info"
            - "security_key_manager_key_info"
            - "security_login_account_info"
            - "security_login_role_config_info"
            - "security_login_role_info"
            - "service_processor_info"
            - "service_processor_network_info"
            - "shelf_info"
            - "sis_info"
            - "sis_policy_info"
            - "snapmirror_info"
            - "snapmirror_destination_info"
            - "snapmirror_policy_info"
            - "snapshot_info"
            - "snapshot_policy_info"
            - "storage_failover_info"
            - "storage_bridge_info"
            - "subsys_health_info"
            - "sysconfig_info"
            - "sys_cluster_alerts"
            - "volume_info"
            - "volume_space_info"
            - "vscan_info"
            - "vscan_status_info"
            - "vscan_scanner_pool_info"
            - "vscan_connection_status_all_info"
            - "vscan_connection_extended_stats_info"
            - "vserver_info"
            - "vserver_login_banner_info"
            - "vserver_motd_info"
            - "vserver_nfs_info"
            - "vserver_peer_info"
            - Can specify a list of values to include a larger subset.
            - Values can also be used with an initial C(!) to specify that a specific subset should not be collected.
            - nvme is supported with ONTAP 9.4 onwards.
            - use "help" to get a list of supported information for your system.
            - with lun_info, serial_hex and naa_id are computed when serial_number is present.
        default: "all"
    max_records:
        type: int
        description:
            - Maximum number of records returned in a single ZAPI call. Valid range is [1..2^32-1].
                This parameter controls internal behavior of this module.
        default: 1024
        version_added: '20.2.0'
    summary:
        description:
            - Boolean flag to control return all attributes of the module info or only the names.
            - If true, only names are returned.
        default: false
        type: bool
        version_added: '20.4.0'
    volume_move_target_aggr_info:
        description:
        - Required options for volume_move_target_aggr_info
        type: dict
        version_added: '20.5.0'
        suboptions:
            volume_name:
                description:
                - Volume name to get target aggr info for
                required: true
                type: str
                version_added: '20.5.0'
            vserver:
                description:
                - vserver the Volume lives on
                required: true
                type: str
                version_added: '20.5.0'
    desired_attributes:
        description:
        - Advanced feature requiring to understand ZAPI internals.
        - Allows to request a specific attribute that is not returned by default, or to limit the returned attributes.
        - A dictionary for the zapi desired-attributes element.
        - An XML tag I(<tag>value</tag>) is a dictionary with tag as the key.
        - Value can be another dictionary, a list of dictionaries, a string, or nothing.
        - eg I(<tag/>) is represented as I(tag:)
        - Only a single subset can be called at a time if this option is set.
        - It is the caller responsibity to make sure key attributes are present in the right position.
        - The module will error out if any key attribute is missing.
        type: dict
        version_added: '20.6.0'
    query:
        description:
        - Advanced feature requiring to understand ZAPI internals.
        - Allows to specify which objects to return.
        - A dictionary for the zapi query element.
        - An XML tag I(<tag>value</tag>) is a dictionary with tag as the key.
        - Value can be another dictionary, a list of dictionaries, a string, or nothing.
        - eg I(<tag/>) is represented as I(tag:)
        - Only a single subset can be called at a time if this option is set.
        type: dict
        version_added: '20.7.0'
    use_native_zapi_tags:
        description:
        - By default, I(-) in the returned dictionary keys are translated to I(_).
        - If set to true, the translation is disabled.
        type: bool
        default: false
        version_added: '20.6.0'
    continue_on_error:
        description:
        - By default, this module fails on the first error.
        - This option allows to provide a list of errors that are not failing the module.
        - Errors in the list are reported in the output, under the related info element, as an "error" entry.
        - Possible values are always, never, missing_vserver_api_error, rpc_error, other_error.
        - missing_vserver_api_error - most likely the API is available at cluster level but not vserver level.
        - rpc_error - some queries are failing because the node cannot reach another node in the cluster.
        - key_error - a query is failing because the returned data does not contain an expected key.
        - for key errors, make sure to report this in Discord.  It may be a change in a new ONTAP version.
        - other_error - anything not in the above list.
        - always will continue on any error, never will fail on any error, they cannot be used with any other keyword.
        type: list
        elements: str
        default: never
'''

EXAMPLES = '''
- name: Get NetApp info as Cluster Admin (Password Authentication)
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "admin"
    password: "admins_password"
  register: ontap_info
- debug:
    msg: "{{ ontap_info.ontap_info }}"

- name: Get NetApp version as Vserver admin
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "vsadmin"
    vserver: trident_svm
    password: "vsadmins_password"

- name: run ontap info module using vserver tunneling and ignoring errors
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "admin"
    password: "admins_password"
    vserver: trident_svm
    summary: true
    continue_on_error:
      - missing_vserver_api_error
      - rpc_error

- name: Limit Info Gathering to Aggregate Information as Cluster Admin
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "admin"
    password: "admins_password"
    gather_subset: "aggregate_info"
  register: ontap_info

- name: Limit Info Gathering to Volume and Lun Information as Cluster Admin
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "admin"
    password: "admins_password"
    gather_subset:
      - volume_info
      - lun_info
  register: ontap_info

- name: Gather all info except for volume and lun information as Cluster Admin
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "admin"
    password: "admins_password"
    gather_subset:
      - "!volume_info"
      - "!lun_info"
  register: ontap_info

- name: Gather Volume move information for a specific volume
  netapp.ontap.na_ontap_info:
    hostname: "na-vsim"
    username: "admin"
    password: "admins_password"
    gather_subset: volume_move_target_aggr_info
    volume_move_target_aggr_info:
      volume_name: carchitest
      vserver: ansible

- name: run ontap info module for aggregate module, requesting specific fields
  netapp.ontap.na_ontap_info:
    # <<: *login
    gather_subset: aggregate_info
    desired_attributes:
      aggr-attributes:
      aggr-inode-attributes:
        files-private-used:
      aggr-raid-attributes:
        aggregate-type:
    use_native_zapi_tags: true
    register: ontap
- debug: var=ontap

- name: run ontap info to get offline volumes with dp in the name
  netapp.ontap.na_ontap_info:
    # <<: *cert_login
    gather_subset: volume_info
    query:
      volume-attributes:
        volume-id-attributes:
          name: '*dp*'
        volume-state-attributes:
          state: offline
    desired_attributes:
      volume-attributes:
        volume-id-attributes:
          name:
        volume-state-attributes:
          state:
  register: ontap
- debug: var=ontap
'''

RETURN = '''
ontap_info:
    description: Returns various information about NetApp cluster configuration
    returned: always
    type: dict
    sample: '{
        "ontap_info": {
            "active_directory_account_info": {...},
            "aggregate_info": {...},
            "autosupport_check_info": {...},
            "cluster_identity_info": {...},
            "cluster_image_info": {...},
            "cluster_node_info": {...},
            "igroup_info": {...},
            "iscsi_service_info": {...},
            "license_info": {...},
            "lun_info": {...},
            "metrocluster_check_info": {...},
            "metrocluster_info": {...},
            "metrocluster_node_info": {...},
            "net_dns_info": {...},
            "net_ifgrp_info": {...},
            "net_interface_info": {...},
            "net_interface_service_policy_info": {...},
            "net_port_info": {...},
            "ontap_system_version": {...},
            "ontap_version": {...},
            "ontapi_version": {...},
            "qos_policy_info": {...},
            "qos_adaptive_policy_info": {...},
            "qtree_info": {...},
            "quota_policy_info": {..},
            "quota_report_info": {...},
            "security_key_manager_key_info": {...},
            "security_login_account_info": {...},
            "snapmirror_info": {...}
            "snapmirror_destination_info": {...}
            "storage_bridge_info": {...}
            "storage_failover_info": {...},
            "volume_info": {...},
            "vserver_login_banner_info": {...},
            "vserver_motd_info": {...},
            "vserver_info": {...},
            "vserver_nfs_info": {...},
            "vscan_status_info": {...},
            "vscan_scanner_pool_info": {...},
            "vscan_connection_status_all_info": {...},
            "vscan_connection_extended_stats_info": {...}
    }'
'''

import codecs
import copy
import traceback
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_bytes, to_native, to_text
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils

IMPORT_ERRORS = []
try:
    import xmltodict
    HAS_XMLTODICT = True
except ImportError as exc:
    HAS_XMLTODICT = False
    IMPORT_ERRORS.append(str(exc))

try:
    import json
    HAS_JSON = True
except ImportError as exc:
    HAS_JSON = False
    IMPORT_ERRORS.append(str(exc))

HAS_NETAPP_LIB = netapp_utils.has_netapp_lib()


class NetAppONTAPGatherInfo:
    '''Class with gather info methods'''

    def __init__(self):
        ''' create module, set up context'''
        argument_spec = netapp_utils.na_ontap_zapi_only_spec()
        argument_spec.update(dict(
            state=dict(type='str'),
            gather_subset=dict(default=['all'], type='list', elements='str'),
            vserver=dict(type='str', required=False),
            max_records=dict(type='int', default=1024, required=False),
            summary=dict(type='bool', default=False, required=False),
            volume_move_target_aggr_info=dict(
                type="dict",
                required=False,
                options=dict(
                    volume_name=dict(type='str', required=True),
                    vserver=dict(type='str', required=True)
                )
            ),
            desired_attributes=dict(type='dict', required=False),
            use_native_zapi_tags=dict(type='bool', required=False, default=False),
            continue_on_error=dict(type='list', required=False, elements='str', default=['never']),
            query=dict(type='dict', required=False),
        ))

        self.module = AnsibleModule(
            argument_spec=argument_spec,
            supports_check_mode=True
        )

        if not HAS_NETAPP_LIB:
            self.module.fail_json(msg=netapp_utils.netapp_lib_is_required())
        if not HAS_XMLTODICT:
            self.module.fail_json(msg="the python xmltodict module is required.  Import error: %s" % str(IMPORT_ERRORS))
        if not HAS_JSON:
            self.module.fail_json(msg="the python json module is required.  Import error: %s" % str(IMPORT_ERRORS))

        self.max_records = str(self.module.params['max_records'])
        volume_move_target_aggr_info = self.module.params.get('volume_move_target_aggr_info', dict())
        if volume_move_target_aggr_info is None:
            volume_move_target_aggr_info = {}
        self.netapp_info = {}
        self.desired_attributes = self.module.params['desired_attributes']
        self.query = self.module.params['query']
        self.translate_keys = not self.module.params['use_native_zapi_tags']
        self.warnings = []  # warnings will be added to the info results, if any
        self.set_error_flags()
        self.module.warn('The module only supports ZAPI; refer to netapp.ontap.na_ontap_rest_info module for RESTful equivalent.')

        # thanks to coreywan (https://github.com/ansible/ansible/pull/47016)
        # for starting this
        # min_version identifies the ontapi version which supports this ZAPI
        # use 0 if it is supported since 9.1
        self.info_subsets = {
            'cluster_identity_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cluster-identity-get',
                    'attributes_list_tag': 'attributes',
                    'attribute': 'cluster-identity-info',
                    'key_fields': 'cluster-name',
                },
                'min_version': '0',
            },
            'cluster_image_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cluster-image-get-iter',
                    'attribute': 'cluster-image-info',
                    'key_fields': 'node-id',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cluster_log_forwarding_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cluster-log-forward-get-iter',
                    'attribute': 'cluster-log-forward-info',
                    'key_fields': ('destination', 'port'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cluster_node_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cluster-node-get-iter',
                    'attribute': 'cluster-node-info',
                    'key_fields': 'node-name',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'security_login_account_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'security-login-get-iter',
                    'attribute': 'security-login-account-info',
                    'key_fields': ('vserver', 'user-name', 'application', 'authentication-method'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'security_login_role_config_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'security-login-role-config-get-iter',
                    'attribute': 'security-login-role-config-info',
                    'key_fields': ('vserver', 'role-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'security_login_role_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'security-login-role-get-iter',
                    'attribute': 'security-login-role-info',
                    'key_fields': ('vserver', 'role-name', 'command-directory-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'active_directory_account_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'active-directory-account-get-iter',
                    'attribute': 'active-directory-account-config',
                    'key_fields': ('vserver', 'account-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'aggregate_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'aggr-get-iter',
                    'attribute': 'aggr-attributes',
                    'key_fields': 'aggregate-name',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'volume_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'volume-get-iter',
                    'attribute': 'volume-attributes',
                    'key_fields': ('name', 'owning-vserver-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'license_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'license-v2-list-info',
                    'attributes_list_tag': None,
                    'attribute': 'licenses',
                },
                'min_version': '0',
            },
            'lun_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'lun-get-iter',
                    'attribute': 'lun-info',
                    'key_fields': ('vserver', 'path'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'metrocluster_check_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'metrocluster-check-get-iter',
                    'attribute': 'metrocluster-check-info',
                    'fail_on_error': False,
                },
                'min_version': '0',
            },
            'metrocluster_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'metrocluster-get',
                    'attribute': 'metrocluster-info',
                    'attributes_list_tag': 'attributes',
                },
                'min_version': '0',
            },
            'metrocluster_node_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'metrocluster-node-get-iter',
                    'attribute': 'metrocluster-node-info',
                    'key_fields': ('cluster-name', 'node-name'),
                },
                'min_version': '0',
            },
            'net_dns_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-dns-get-iter',
                    'attribute': 'net-dns-info',
                    'key_fields': 'vserver-name',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_interface_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-interface-get-iter',
                    'attribute': 'net-interface-info',
                    'key_fields': ('interface-name', 'vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_interface_service_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-interface-service-policy-get-iter',
                    'attribute': 'net-interface-service-policy-info',
                    'key_fields': ('vserver', 'policy'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '150',
            },
            'net_port_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-port-get-iter',
                    'attribute': 'net-port-info',
                    'key_fields': ('node', 'port'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'security_key_manager_key_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'security-key-manager-key-get-iter',
                    'attribute': 'security-key-manager-key-info',
                    'key_fields': ('node', 'key-id'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'storage_failover_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cf-get-iter',
                    'attribute': 'storage-failover-info',
                    'key_fields': 'node',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vserver_motd_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vserver-motd-get-iter',
                    'attribute': 'vserver-motd-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vserver_login_banner_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vserver-login-banner-get-iter',
                    'attribute': 'vserver-login-banner-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vserver_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vserver-get-iter',
                    'attribute': 'vserver-info',
                    'key_fields': 'vserver-name',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vserver_nfs_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'nfs-service-get-iter',
                    'attribute': 'nfs-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_ifgrp_info': {
                'method': self.get_ifgrp_info,
                'kwargs': {},
                'min_version': '0',
            },
            'ontap_system_version': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'system-get-version',
                    'attributes_list_tag': None,
                },
                'min_version': '0',
            },
            'ontap_version': {
                'method': self.ontapi,
                'kwargs': {},
                'min_version': '0',
            },
            'ontapi_version': {
                'method': self.ontapi,
                'kwargs': {},
                'min_version': '0',
            },
            'clock_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'clock-get-clock',
                    'attributes_list_tag': None,
                },
                'min_version': '0'
            },
            'system_node_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'system-node-get-iter',
                    'attribute': 'node-details-info',
                    'key_fields': 'node',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'igroup_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'igroup-get-iter',
                    'attribute': 'initiator-group-info',
                    'key_fields': ('vserver', 'initiator-group-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'iscsi_service_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'iscsi-service-get-iter',
                    'attribute': 'iscsi-service-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'qos_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'qos-policy-group-get-iter',
                    'attribute': 'qos-policy-group-info',
                    'key_fields': 'policy-group',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'qtree_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'qtree-list-iter',
                    'attribute': 'qtree-info',
                    'key_fields': ('vserver', 'volume', 'id'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'quota_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'quota-policy-get-iter',
                    'attribute': 'quota-policy-info',
                    'key_fields': ('vserver', 'policy-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'quota_report_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'quota-report-iter',
                    'attribute': 'quota',
                    'key_fields': ('vserver', 'volume', 'tree', 'quota-type', 'quota-target'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vscan_status_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vscan-status-get-iter',
                    'attribute': 'vscan-status-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vscan_scanner_pool_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vscan-scanner-pool-get-iter',
                    'attribute': 'vscan-scanner-pool-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vscan_connection_status_all_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vscan-connection-status-all-get-iter',
                    'attribute': 'vscan-connection-status-all-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vscan_connection_extended_stats_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vscan-connection-extended-stats-get-iter',
                    'attribute': 'vscan-connection-extended-stats-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'snapshot_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'snapshot-get-iter',
                    'attribute': 'snapshot-info',
                    'key_fields': ('vserver', 'volume', 'name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'storage_bridge_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'storage-bridge-get-iter',
                    'attribute': 'storage-bridge-info',
                    'key_fields': 'name',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            # supported in ONTAP 9.3 and onwards
            'qos_adaptive_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'qos-adaptive-policy-group-get-iter',
                    'attribute': 'qos-adaptive-policy-group-info',
                    'key_fields': 'policy-group',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '130',
            },
            # supported in ONTAP 9.4 and onwards
            'nvme_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'nvme-get-iter',
                    'attribute': 'nvme-target-service-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },
            'nvme_interface_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'nvme-interface-get-iter',
                    'attribute': 'nvme-interface-info',
                    'key_fields': 'vserver',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },
            'nvme_subsystem_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'nvme-subsystem-get-iter',
                    'attribute': 'nvme-subsystem-info',
                    'key_fields': 'subsystem',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },
            'nvme_namespace_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'nvme-namespace-get-iter',
                    'attribute': 'nvme-namespace-info',
                    'key_fields': 'path',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },

            # Alpha Order

            'aggr_efficiency_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'aggr-efficiency-get-iter',
                    'attribute': 'aggr-efficiency-info',
                    # the preferred key is node_name:aggregate_name
                    # but node is not present with MCC
                    'key_fields': (('node', None), 'aggregate'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },
            'autosupport_check_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'autosupport-check-iter',
                    'attribute': 'autosupport-check-info',
                    'key_fields': ('node-name', 'check-type', 'error-detail'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cifs_options_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cifs-options-get-iter',
                    'attribute': 'cifs-options',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cifs_server_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cifs-server-get-iter',
                    'attribute': 'cifs-server-config',
                    # preferred key is <vserver>:<domain>:<cifs-server>
                    # alternate key is <vserver>:<domain-workgroup>:<cifs-server>
                    'key_fields': ('vserver', ('domain', 'domain-workgroup'), 'cifs-server'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cifs_share_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cifs-share-get-iter',
                    'attribute': 'cifs-share',
                    'key_fields': ('share-name', 'path', 'cifs-server'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cifs_vserver_security_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cifs-security-get-iter',
                    'attribute': 'cifs-security',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cluster_peer_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cluster-peer-get-iter',
                    'attribute': 'cluster-peer-info',
                    'key_fields': ('cluster-name', 'remote-cluster-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'cluster_switch_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'cluster-switch-get-iter',
                    'attribute': 'cluster-switch-info',
                    'key_fields': ('device', 'model', 'serial-number'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '160',
            },
            'disk_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'storage-disk-get-iter',
                    'attribute': 'storage-disk-info',
                    'key_fields': ('disk-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'env_sensors_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'environment-sensors-get-iter',
                    'attribute': 'environment-sensors-info',
                    'key_fields': ('node-name', 'sensor-name'),
                    'query': {'max-records': self.max_records},
                    'fail_on_error': False,
                },
                'min_version': '0',
            },
            'event_notification_destination_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'ems-event-notification-destination-get-iter',
                    'attribute': 'event-notification-destination-info',
                    'key_fields': ('name', 'type'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'event_notification_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'ems-event-notification-get-iter',
                    'attribute': 'event-notification',
                    'key_fields': ('id'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'export_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'export-policy-get-iter',
                    'attribute': 'export-policy-info',
                    'key_fields': ('vserver', 'policy-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'export_rule_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'export-rule-get-iter',
                    'attribute': 'export-rule-info',
                    'key_fields': ('vserver-name', 'policy-name', 'rule-index'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'fcp_adapter_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'ucm-adapter-get-iter',
                    'attribute': 'uc-adapter-info',
                    'key_fields': ('adapter-name', 'node-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'fcp_alias_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'fcp-wwpnalias-get-iter',
                    'attribute': 'aliases-info',
                    'key_fields': ('aliases-alias', 'vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'fcp_service_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'fcp-service-get-iter',
                    'attribute': 'fcp-service-info',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'job_schedule_cron_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'job-schedule-cron-get-iter',
                    'attribute': 'job-schedule-cron-info',
                    'key_fields': ('job-schedule-name', ('job-schedule-cluster', None)),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'kerberos_realm_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'kerberos-realm-get-iter',
                    'attribute': 'kerberos-realm',
                    'key_fields': ('vserver-name', 'realm'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'ldap_client': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'ldap-client-get-iter',
                    'attribute': 'ldap-client',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'ldap_config': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'ldap-config-get-iter',
                    'attribute': 'ldap-config',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'lun_map_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'lun-map-get-iter',
                    'attribute': 'lun-map-info',
                    'key_fields': ('initiator-group', 'lun-id', 'node', 'path', 'vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_dev_discovery_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-device-discovery-get-iter',
                    'attribute': 'net-device-discovery-info',
                    'key_fields': ('port'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_failover_group_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-failover-group-get-iter',
                    'attribute': 'net-failover-group-info',
                    'key_fields': ('vserver', 'failover-group'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_firewall_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-firewall-policy-get-iter',
                    'attribute': 'net-firewall-policy-info',
                    'key_fields': ('policy', 'vserver', 'service'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_ipspaces_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-ipspaces-get-iter',
                    'attribute': 'net-ipspaces-info',
                    'key_fields': ('ipspace'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_port_broadcast_domain_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-port-broadcast-domain-get-iter',
                    'attribute': 'net-port-broadcast-domain-info',
                    'key_fields': ('broadcast-domain', 'ipspace'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_routes_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-routes-get-iter',
                    'attribute': 'net-vs-routes-info',
                    'key_fields': ('vserver', 'destination', 'gateway'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'net_vlan_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'net-vlan-get-iter',
                    'attribute': 'vlan-info',
                    'key_fields': ('interface-name', 'node'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'nfs_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'nfs-service-get-iter',
                    'attribute': 'nfs-info',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'ntfs_dacl_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'file-directory-security-ntfs-dacl-get-iter',
                    'attribute': 'file-directory-security-ntfs-dacl',
                    'key_fields': ('vserver', 'ntfs-sd', 'account', 'access-type'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'ntfs_sd_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'file-directory-security-ntfs-get-iter',
                    'attribute': 'file-directory-security-ntfs',
                    'key_fields': ('vserver', 'ntfs-sd'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'ntp_server_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'ntp-server-get-iter',
                    'attribute': 'ntp-server-info',
                    'key_fields': ('server-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'role_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'security-login-role-get-iter',
                    'attribute': 'security-login-role-info',
                    'key_fields': ('vserver', 'role-name', 'access-level', 'command-directory-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'service_processor_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'service-processor-get-iter',
                    'attribute': 'service-processor-info',
                    'key_fields': ('node'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'service_processor_network_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'service-processor-network-get-iter',
                    'attribute': 'service-processor-network-info',
                    # don't use key_fieldss, as we cannot build a key with optional key_fieldss
                    # without a key, we'll get a list of dictionaries
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'shelf_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'storage-shelf-info-get-iter',
                    'attribute': 'storage-shelf-info',
                    'key_fields': ('shelf-id', 'serial-number'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'sis_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'sis-get-iter',
                    'attribute': 'sis-status-info',
                    'key_fields': 'path',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'sis_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'sis-policy-get-iter',
                    'attribute': 'sis-policy-info',
                    'key_fields': ('vserver', 'policy-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'snapmirror_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'snapmirror-get-iter',
                    'attribute': 'snapmirror-info',
                    'key_fields': 'destination-location',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },
            'snapmirror_destination_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'snapmirror-get-destination-iter',
                    'attribute': 'snapmirror-destination-info',
                    'key_fields': 'destination-location',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '140',
            },
            'snapmirror_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'snapmirror-policy-get-iter',
                    'attribute': 'snapmirror-policy-info',
                    'key_fields': ('vserver-name', 'policy-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'snapshot_policy_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'snapshot-policy-get-iter',
                    'attribute': 'snapshot-policy-info',
                    'key_fields': ('vserver-name', 'policy'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'subsys_health_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'diagnosis-subsystem-config-get-iter',
                    'attribute': 'diagnosis-subsystem-config-info',
                    'key_fields': 'subsystem',
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'sys_cluster_alerts': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'diagnosis-alert-get-iter',
                    'attribute': 'diagnosis-alert-info',
                    'key_fields': ('node', 'alerting-resource'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'sysconfig_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'system-get-node-info-iter',
                    'attribute': 'system-info',
                    'key_fields': ('system-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'volume_move_target_aggr_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'volume-move-target-aggr-get-iter',
                    'attribute': 'volume-move-target-aggr-info',
                    'query': {'max-records': self.max_records,
                              'volume-name': volume_move_target_aggr_info.get('volume_name', None),
                              'vserver': volume_move_target_aggr_info.get('vserver', None)},
                    'fail_on_error': False,
                },
                'min_version': '0',
            },
            'volume_space_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'volume-space-get-iter',
                    'attribute': 'space-info',
                    'key_fields': ('vserver', 'volume'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vscan_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vscan-status-get-iter',
                    'attribute': 'vscan-status-info',
                    'key_fields': ('vserver'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
            'vserver_peer_info': {
                'method': self.get_generic_get_iter,
                'kwargs': {
                    'call': 'vserver-peer-get-iter',
                    'attribute': 'vserver-peer-info',
                    'key_fields': ('vserver', 'remote-vserver-name'),
                    'query': {'max-records': self.max_records},
                },
                'min_version': '0',
            },
        }

        # use vserver tunneling if vserver is present (not None)
        self.server = netapp_utils.setup_na_ontap_zapi(module=self.module, vserver=self.module.params['vserver'])

    def ontapi(self):
        '''Method to get ontapi version'''

        api = 'system-get-ontapi-version'
        api_call = netapp_utils.zapi.NaElement(api)
        try:
            results = self.server.invoke_successfully(api_call, enable_tunneling=True)
            ontapi_version = results.get_child_content('minor-version')
            return ontapi_version if ontapi_version is not None else '0'
        except netapp_utils.zapi.NaApiError as error:
            self.module.fail_json(msg="Error calling API %s: %s" %
                                  (api, to_native(error)), exception=traceback.format_exc())

    def call_api(self, call, attributes_list_tag='attributes-list', query=None, fail_on_error=True):
        '''Main method to run an API call'''

        api_call = netapp_utils.zapi.NaElement(call)
        initial_result = None
        result = None

        if query:
            for key, val in query.items():
                # Can val be nested?
                api_call.add_new_child(key, val)

        if self.desired_attributes is not None:
            api_call.translate_struct(self.desired_attributes)
        if self.query is not None:
            api_call.translate_struct(self.query)
        try:
            initial_result = self.server.invoke_successfully(api_call, enable_tunneling=True)
            next_tag = initial_result.get_child_by_name('next-tag')
            result = copy.copy(initial_result)

            while next_tag:
                next_tag_call = netapp_utils.zapi.NaElement(call)
                if query:
                    for key, val in query.items():
                        next_tag_call.add_new_child(key, val)

                next_tag_call.add_new_child("tag", next_tag.get_content(), True)
                next_result = self.server.invoke_successfully(next_tag_call, enable_tunneling=True)

                next_tag = next_result.get_child_by_name('next-tag')
                if attributes_list_tag is None:
                    self.module.fail_json(msg="Error calling API %s: %s" %
                                          (api_call.to_string(), "'next-tag' is not expected for this API"))

                result_attr = result.get_child_by_name(attributes_list_tag)
                new_records = next_result.get_child_by_name(attributes_list_tag)
                if new_records:
                    for record in new_records.get_children():
                        result_attr.add_child_elem(record)

            return result, None

        except netapp_utils.zapi.NaApiError as error:
            if call in ['security-key-manager-key-get-iter']:
                return result, None
            kind, error_message = netapp_utils.classify_zapi_exception(error)
            if kind == 'missing_vserver_api_error':
                # for missing_vserver_api_error, the API is already in error_message
                error_message = "Error invalid API.  %s" % error_message
            else:
                error_message = "Error calling API %s: %s" % (call, error_message)
            if self.error_flags[kind] and fail_on_error:
                self.module.fail_json(msg=error_message, exception=traceback.format_exc())
            return None, error_message

    def get_ifgrp_info(self):
        '''Method to get network port ifgroups info'''

        try:
            net_port_info = self.netapp_info['net_port_info']
        except KeyError:
            net_port_info_calls = self.info_subsets['net_port_info']
            net_port_info = net_port_info_calls['method'](**net_port_info_calls['kwargs'])
        interfaces = net_port_info.keys()

        ifgrps = []
        for ifn in interfaces:
            if net_port_info[ifn]['port_type'] == 'if_group':
                ifgrps.append(ifn)

        net_ifgrp_info = dict()
        for ifgrp in ifgrps:
            query = dict()
            query['node'], query['ifgrp-name'] = ifgrp.split(':')

            tmp = self.get_generic_get_iter('net-port-ifgrp-get', key_fields=('node', 'ifgrp-name'),
                                            attribute='net-ifgrp-info', query=query,
                                            attributes_list_tag='attributes')
            net_ifgrp_info = net_ifgrp_info.copy()
            net_ifgrp_info.update(tmp)
        return net_ifgrp_info

    def get_generic_get_iter(self, call, attribute=None, key_fields=None, query=None, attributes_list_tag='attributes-list', fail_on_error=True):
        '''Method to run a generic get-iter call'''

        generic_call, error = self.call_api(call, attributes_list_tag, query, fail_on_error=fail_on_error)

        if error is not None:
            return {'error': error}

        if generic_call is None:
            return None

        if attributes_list_tag is None:
            attributes_list = generic_call
        else:
            attributes_list = generic_call.get_child_by_name(attributes_list_tag)

        if attributes_list is None:
            return None

        if key_fields is None:
            out = []
        else:
            out = {}

        iteration = 0
        for child in attributes_list.get_children():
            iteration += 1
            dic = xmltodict.parse(child.to_string(), xml_attribs=False)

            if attribute is not None:
                try:
                    dic = dic[attribute]
                except KeyError as exc:
                    error_message = 'Error: attribute %s not found for %s, got: %s' % (str(exc), call, dic)
                    self.module.fail_json(msg=error_message, exception=traceback.format_exc())

            info = json.loads(json.dumps(dic))
            if self.translate_keys:
                info = convert_keys(info)
            if isinstance(key_fields, str):
                try:
                    unique_key = _finditem(dic, key_fields)
                except KeyError as exc:
                    error_message = 'Error: key %s not found for %s, got: %s' % (str(exc), call, repr(info))
                    if self.error_flags['key_error']:
                        self.module.fail_json(msg=error_message, exception=traceback.format_exc())
                    unique_key = 'Error_%d_key_not_found_%s' % (iteration, exc.args[0])
            elif isinstance(key_fields, tuple):
                try:
                    unique_key = ':'.join([_finditem(dic, el) for el in key_fields])
                except KeyError as exc:
                    error_message = 'Error: key %s not found for %s, got: %s' % (str(exc), call, repr(info))
                    if self.error_flags['key_error']:
                        self.module.fail_json(msg=error_message, exception=traceback.format_exc())
                    unique_key = 'Error_%d_key_not_found_%s' % (iteration, exc.args[0])
            else:
                unique_key = None
            if unique_key is not None:
                out = out.copy()
                out.update({unique_key: info})
            else:
                out.append(info)

        if attributes_list_tag is None and key_fields is None:
            if len(out) == 1:
                # flatten the list as only 1 element is expected
                out = out[0]
            elif len(out) > 1:
                # aggregate a list of dictionaries into a single dict
                # make sure we only have dicts and no key duplication
                dic = dict()
                key_count = 0
                for item in out:
                    if not isinstance(item, dict):
                        # abort if we don't see a dict - not sure this can happen with ZAPI
                        key_count = -1
                        break
                    dic.update(item)
                    key_count += len(item)
                if key_count == len(dic):
                    # no duplicates!
                    out = dic

        return out

    def augment_subset(self, subset, info):
        if subset == 'lun_info' and info:
            for lun_info in info.values():
                # the keys may have been converted, or not
                serial = lun_info.get('serial_number') or lun_info.get('serial-number')
                if serial:
                    hexlify = codecs.getencoder('hex')
                    # dictionaries are mutable
                    lun_info['serial_hex'] = to_text(hexlify(to_bytes(lun_info['serial_number']))[0])
                    lun_info['naa_id'] = 'naa.600a0980' + lun_info['serial_hex']
        return info

    def get_all(self, gather_subset):
        '''Method to get all subsets'''

        self.netapp_info['ontapi_version'] = self.ontapi()
        self.netapp_info['ontap_version'] = self.netapp_info['ontapi_version']

        run_subset = self.get_subset(gather_subset, self.netapp_info['ontapi_version'])
        if 'ontap_version' in gather_subset:
            if netapp_utils.has_feature(self.module, 'deprecation_warning'):
                self.netapp_info['deprecation_warning'] = 'ontap_version is deprecated, please use ontapi_version'
        if 'help' in gather_subset:
            self.netapp_info['help'] = sorted(run_subset)
        else:
            if self.desired_attributes is not None:
                if len(run_subset) > 1:
                    self.module.fail_json(msg="desired_attributes option is only supported with a single subset")
                self.sanitize_desired_attributes()
            if self.query is not None:
                if len(run_subset) > 1:
                    self.module.fail_json(msg="query option is only supported with a single subset")
                self.sanitize_query()
            for subset in run_subset:
                call = self.info_subsets[subset]
                self.netapp_info[subset] = call['method'](**call['kwargs'])
                self.augment_subset(subset, self.netapp_info[subset])

        if self.warnings:
            self.netapp_info['module_warnings'] = self.warnings

        return self.netapp_info

    def get_subset(self, gather_subset, version):
        '''Method to get a single subset'''

        runable_subsets = set()
        exclude_subsets = set()
        usable_subsets = [key for key in self.info_subsets if version >= self.info_subsets[key]['min_version']]
        if 'help' in gather_subset:
            return usable_subsets
        for subset in gather_subset:
            if subset == 'all':
                runable_subsets.update(usable_subsets)
                return runable_subsets
            if subset.startswith('!'):
                subset = subset[1:]
                if subset == 'all':
                    return set()
                exclude = True
            else:
                exclude = False

            if subset not in usable_subsets:
                if subset not in self.info_subsets.keys():
                    self.module.fail_json(msg='Bad subset: %s' % subset)
                self.module.fail_json(msg='Remote system at version %s does not support %s' %
                                      (version, subset))

            if exclude:
                exclude_subsets.add(subset)
            else:
                runable_subsets.add(subset)

        if not runable_subsets:
            runable_subsets.update(usable_subsets)

        runable_subsets.difference_update(exclude_subsets)

        return runable_subsets

    def get_summary(self, ontap_info):
        for info in ontap_info:
            if '_info' in info and ontap_info[info] is not None and isinstance(ontap_info[info], dict):
                # don't summarize errors
                if 'error' not in ontap_info[info]:
                    ontap_info[info] = ontap_info[info].keys()
        return ontap_info

    def sanitize_desired_attributes(self):
        ''' add top 'desired-attributes' if absent
            check for _ as more likely ZAPI does not take them
        '''
        da_key = 'desired-attributes'
        if da_key not in self.desired_attributes:
            desired_attributes = dict()
            desired_attributes[da_key] = self.desired_attributes
            self.desired_attributes = desired_attributes
        self.check_for___in_keys(self.desired_attributes)

    def sanitize_query(self):
        ''' add top 'query' if absent
            check for _ as more likely ZAPI does not take them
        '''
        key = 'query'
        if key not in self.query:
            query = dict()
            query[key] = self.query
            self.query = query
        self.check_for___in_keys(self.query)

    def check_for___in_keys(self, d_param):
        '''Method to warn on underscore in a ZAPI tag'''
        if isinstance(d_param, dict):
            for key, val in d_param.items():
                self.check_for___in_keys(val)
                if '_' in key:
                    self.warnings.append("Underscore in ZAPI tag: %s, do you mean '-'?" % key)
        elif isinstance(d_param, list):
            for val in d_param:
                self.check_for___in_keys(val)

    def set_error_flags(self):
        error_flags = self.module.params['continue_on_error']
        generic_flags = ('always', 'never')
        if len(error_flags) > 1:
            for key in generic_flags:
                if key in error_flags:
                    self.module.fail_json(msg="%s needs to be the only keyword in 'continue_on_error' option." % key)
        specific_flags = ('rpc_error', 'missing_vserver_api_error', 'key_error', 'other_error')
        for key in error_flags:
            if key not in generic_flags and key not in specific_flags:
                self.module.fail_json(msg="%s is not a valid keyword in 'continue_on_error' option." % key)
        self.error_flags = dict()
        for flag in specific_flags:
            self.error_flags[flag] = True
            for key in error_flags:
                if key == 'always' or key == flag:
                    self.error_flags[flag] = False

    def apply(self):
        gather_subset = self.module.params['gather_subset']
        if gather_subset is None:
            gather_subset = ['all']
        gf_all = self.get_all(gather_subset)
        if self.module.params['summary']:
            gf_all = self.get_summary(gf_all)
        results = {'changed': False, 'ontap_info': gf_all}
        if self.module.params['state'] is not None:
            results['state'] = self.module.params['state']
            results['warnings'] = "option 'state' is deprecated."
            self.module.warn("option 'state' is deprecated.")
        self.module.exit_json(**results)


# https://stackoverflow.com/questions/14962485/finding-a-key-recursively-in-a-dictionary
def __finditem(obj, key):

    if key is None:
        # allows for a key not to be present
        return "key_not_present"
    if key in obj:
        if obj[key] is None:
            return "None"
        return obj[key]
    for dummy, val in obj.items():
        if isinstance(val, dict):
            item = __finditem(val, key)
            if item is not None:
                return item
    return None


def _finditem(obj, keys):
    ''' if keys is a string, use it as a key
        if keys is a tuple, stop on the first valid key
        if no valid key is found, raise a KeyError '''

    value = None
    if isinstance(keys, str):
        value = __finditem(obj, keys)
    elif isinstance(keys, tuple):
        for key in keys:
            value = __finditem(obj, key)
            if value is not None:
                break
    if value is not None:
        return value
    raise KeyError(str(keys))


def convert_keys(d_param):
    '''Method to convert hyphen to underscore'''

    if isinstance(d_param, dict):
        out = {}
        for key, val in d_param.items():
            val = convert_keys(val)
            out[key.replace('-', '_')] = val
        return out
    elif isinstance(d_param, list):
        return [convert_keys(val) for val in d_param]
    return d_param


def main():
    '''Execute action'''
    gf_obj = NetAppONTAPGatherInfo()
    gf_obj.apply()


if __name__ == '__main__':
    main()
