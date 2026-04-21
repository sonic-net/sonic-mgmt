#!/usr/bin/python

# (c) 2020-2025, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" NetApp ONTAP Info using REST APIs """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = '''
module: na_ontap_rest_info
author: NetApp Ansible Team (@carchi8py) <ng-ansible-team@netapp.com>
extends_documentation_fragment:
    - netapp.ontap.netapp.na_ontap_rest
short_description: NetApp ONTAP information gatherer using REST APIs
description:
    - This module allows you to gather various information about ONTAP configuration using REST APIs
version_added: 20.5.0
notes:
  - I(security_login_role_config_info) there is no REST equivalent.
  - I(security_login_role_info) there is no REST equivalent.
  - I(security_key_manager_key_info) there is no REST equivalent.
  - I(vserver_motd_info) there is no REST equivalent.
  - I(vserver_login_banner_info) there is no REST equivalent.
  - I(vscan_connection_extended_stats_info) there is no REST equivalent.
  - I(env_sensors_info) there is no REST equivalent.
  - I(fcp_adapter_info) there is no REST equivalent.
  - I(net_dev_discovery_info) there is no REST equivalent.
  - I(net_failover_group_info)  there is no REST equivalent.
  - I(net_firewall_info) there is no REST equivalent.
  - I(ntfs_dacl_info) there is no REST equivalent.
  - I(ntfs_sd_info) there is no REST equivalent.
  - I(role_info) there is not REST equivalent.
  - I(subsys_health_info) there is not REST equivalent.
  - I(volume_move_target_aggr_info) there is not REST equivalent.

options:
  state:
    type: str
    description:
      - deprecated as of 21.1.0.
      - this option was ignored and continues to be ignored.
  gather_subset:
    type: list
    elements: str
    description:
      - When supplied, this argument will restrict the information collected to a given subset.
      - Either the REST API or the ZAPI info name can be given. Possible values for this argument include
      - application/applications or application_info
      - application/consistency-groups
      - application/consistency-groups/metrics B(Requires the owning_resource to be set)
      - application/consistency-groups/snapshots B(Requires the owning_resource to be set)
      - application/templates or application_template_info
      - cloud/targets or cloud_targets_info
      - cluster
      - cluster/chassis or cluster_chassis_info
      - cluster/counter/tables
      - cluster/firmware/history
      - cluster/jobs or cluster_jobs_info
      - cluster/licensing/capacity-pools
      - cluster/licensing/license-managers
      - cluster/licensing/licenses or license_info
      - cluster/mediators
      - cluster/metrics or cluster_metrics_info
      - cluster/metrocluster or metrocluster_info
      - cluster/metrocluster/diagnostics or cluster_metrocluster_diagnostics or metrocluster_check_info
      - cluster/metrocluster/dr-groups
      - cluster/metrocluster/interconnects
      - cluster/metrocluster/nodes or metrocluster-node-get-iter
      - cluster/metrocluster/operations
      - cluster/metrocluster/svms
      - cluster/nodes or cluster_node_info or sysconfig_info
      - cluster/ntp/keys
      - cluster/ntp/servers or ntp_server_info
      - cluster/peers or cluster_peer_info
      - cluster/schedules or cluster_schedules or job_schedule_cron_info
      - cluster/sensors
      - cluster/software or ontap_system_version or  cluster_image_info
      - cluster/software/download or cluster_software_download
      - cluster/software/history or cluster_software_history
      - cluster/software/packages or cluster_software_packages
      - cluster/web
      - name-services/cache/group-membership/settings
      - name-services/cache/host/settings
      - name-services/cache/netgroup/settings
      - name-services/cache/setting
      - name-services/cache/unix-group/settings
      - name-services/dns or svm_dns_config_info or net_dns_info
      - name-services/ldap or svm_ldap_config_info or ldap_client or ldap_config
      - name-services/ldap-schemas
      - name-services/local-hosts
      - name-services/name-mappings or svm_name_mapping_config_info
      - name-services/nis or svm_nis_config_info
      - name-services/unix-groups
      - name-services/unix-users
      - network/ethernet/broadcast-domains or broadcast_domains_info or net_port_broadcast_domain_info
      - network/ethernet/ports or network_ports_info or  net_port_info
      - network/ethernet/switch/ports
      - network/ethernet/switches or cluster_switch_info
      - network/fc/fabrics
      - network/fc/interfaces
      - network/fc/logins or san_fc_logins_info
      - network/fc/ports
      - network/fc/wwpn-aliases or san_fc_wppn-aliases or fcp_alias_info
      - network/http-proxy
      - network/ip/bgp/peer-groups
      - network/ip/interfaces or ip_interfaces_info or net_interface_info
      - network/ip/routes or ip_routes_info or net_routes_info
      - network/ip/service-policies or ip_service_policies or net_interface_service_policy_info
      - network/ip/subnets
      - network/ipspaces or network_ipspaces_info or net_ipspaces_info
      - private/support/alerts or sys_cluster_alerts
      - private/cli/vserver/security/file-directory or file_directory_security
      - protocols/active-directory
      - protocols/audit
      - protocols/cifs/connections
      - protocols/cifs/domains
      - protocols/cifs/group-policies
      - protocols/cifs/home-directory/search-paths or cifs_home_directory_info
      - protocols/cifs/local-groups
      - protocols/cifs/local-users
      - protocols/cifs/netbios
      - protocols/cifs/services or cifs_services_info or cifs_options_info
      - protocols/cifs/session/files
      - protocols/cifs/sessions
      - protocols/cifs/shadow-copies
      - protocols/cifs/shadowcopy-sets
      - protocols/cifs/shares or cifs_share_info
      - protocols/cifs/users-and-groups/privileges
      - protocols/cifs/unix-symlink-mapping
      - protocols/fpolicy
      - protocols/locks
      - protocols/ndmp
      - protocols/ndmp/nodes
      - protocols/ndmp/sessions
      - protocols/ndmp/svms
      - protocols/nfs/connected-clients
      - protocols/nfs/connected-client-maps
      - protocols/nfs/connected-client-settings
      - protocols/nfs/export-policies or export_policy_info
      - protocols/nfs/export-policies/rules B(Requires the owning_resource to be set)
      - protocols/nfs/kerberos/interfaces
      - protocols/nfs/kerberos/realms or kerberos_realm_info
      - protocols/nfs/services or vserver_nfs_info or nfs_info
      - protocols/nvme/interfaces or nvme_interface_info
      - protocols/nvme/services or nvme_info
      - protocols/nvme/subsystems or nvme_subsystem_info
      - protocols/nvme/subsystem-controllers
      - protocols/nvme/subsystem-maps
      - protocols/s3/buckets
      - protocols/s3/services
      - protocols/san/fcp/services or san_fcp_services or fcp_service_info
      - protocols/san/igroups or nitiator_groups_info or igroup_info
      - protocols/san/iscsi/credentials or san_iscsi_credentials
      - protocols/san/iscsi/services or san_iscsi_services or iscsi_service_info
      - protocols/san/iscsi/sessions
      - protocols/san/lun-maps or san_lun_maps or lun_map_info
      - protocols/san/portsets
      - protocols/san/vvol-bindings
      - protocols/vscan or vscan_status_info or vscan_info
      - protocols/vscan/on-access-policies B(Requires the owning_resource to be set)
      - protocols/vscan/on-demand-policies B(Requires the owning_resource to be set)
      - protocols/vscan/scanner-pools B(Requires the owning_resource to be set)
      - protocols/vscan/server-status or vscan_connection_status_all_info
      - security
      - security/accounts or security_login_info or security_login_account_info
      - security/anti-ransomware/suspects
      - security/audit
      - security/audit/destinations or cluster_log_forwarding_info
      - security/audit/messages
      - security/authentication/cluster/ad-proxy
      - security/authentication/cluster/ldap
      - security/authentication/cluster/nis
      - security/authentication/cluster/saml-sp
      - security/authentication/publickeys
      - security/aws-kms
      - security/azure-key-vaults
      - security/certificates
      - security/gcp-kms
      - security/ipsec
      - security/ipsec/ca-certificates
      - security/ipsec/policies
      - security/ipsec/security-associations
      - security/key-manager-configs
      - security/key-managers
      - security/key-stores
      - security/login/messages
      - security/multi-admin-verify
      - security/multi-admin-verify/approval-groups
      - security/multi-admin-verify/requests
      - security/multi-admin-verify/rules
      - security/roles or security_login_rest_role_info
      - security/ssh
      - security/ssh/svms
      - snapmirror/policies or snapmirror_policy_info
      - snapmirror/relationships or snapmirror_info
      - storage/aggregates or aggregate_info
      - storage/bridges or storage_bridge_info
      - storage/cluster
      - storage/disks or disk_info
      - storage/file/clone/split-loads
      - storage/file/clone/split-status
      - storage/file/clone/tokens
      - storage/file/moves
      - storage/flexcache/flexcaches or storage_flexcaches_info
      - storage/flexcache/origins or storage_flexcaches_origin_info
      - storage/luns or storage_luns_info or lun_info (if serial_number is present, serial_hex and naa_id are computed)
      - storage/namespaces or storage_NVMe_namespaces or nvme_namespace_info
      - storage/pools
      - storage/ports or storage_ports_info
      - storage/qos/policies or storage_qos_policies or qos_policy_info or qos_adaptive_policy_info
      - storage/qos/workloads
      - storage/qtrees or storage_qtrees_config or qtree_info
      - storage/quota/reports or storage_quota_reports or quota_report_info
      - storage/quota/rules or storage_quota_policy_rules
      - storage/shelves or storage_shelves_config or shelf_info
      - storage/snaplock/audit-logs
      - storage/snaplock/compliance-clocks
      - storage/snaplock/event-retention/operations
      - storage/snaplock/event-retention/policies
      - storage/snaplock/file-fingerprints
      - storage/snaplock/litigations
      - storage/snapshot-policies or storage_snapshot_policies or snapshot_policy_info
      - storage/switches
      - storage/tape-devices
      - storage/volumes or volume_info
      - storage/volumes/snapshots B(Requires the owning_resource to be set)
      - storage/volume-efficiency-policies or sis_policy_info
      - support/autosupport or autosupport_config_info
      - support/autosupport/check or autosupport_check_info
      - support/autosupport/messages or autosupport_messages_history
      - support/auto-update
      - support/auto-update/configurations
      - support/auto-update/updates
      - support/configuration-backup
      - support/configuration-backup/backups
      - support/coredump/coredumps
      - support/ems or support_ems_config
      - support/ems/destinations or event_notification_info or event_notification_destination_info
      - support/ems/events or support_ems_events
      - support/ems/filters or support_ems_filters
      - support/ems/messages
      - support/snmp
      - support/snmp/traphosts
      - support/snmp/users
      - svm/migrations
      - svm/peers or svm_peers_info or vserver_peer_info
      - svm/peer-permissions or svm_peer-permissions_info
      - svm/svms or vserver_info
      - B(The following do not have direct Rest API equivalent)
      - aggr_efficiency_info
      - cifs_vserver_security_info
      - clock_info
      - cluster_identity_info
      - net_vlan_info
      - sis_info
      - snapmirror_destination_info
      - system_node_info
      - volume_space_info
      - Can specify a list of values to include a larger subset.
      - REST APIs are supported with ONTAP 9.6 onwards.
    default: "demo"
  max_records:
    type: int
    description:
      - Maximum number of records returned in a single call.
    default: 1024
  fields:
    type: list
    elements: str
    description:
      - Request specific fields from subset.
      - Recommended - '<list of fields>' to return specified fields, only one subset will be allowed.
      - Discouraged - '*' to return all the fields, one or more subsets are allowed. This option can be used for discovery, but is discouraged in production.
      - Stongly discouraged - '**' to return all the fields, one or more subsets are allowed.
        This option can put an extra load on the system and should not be used in production.
      - Limited - '' to return default fields, generally the properties that uniquely identify the record (keys).
        Other data is not returned by default and need to be explicitly called for using the field name or *.
      - If the option is not present, return default fields for that API (see '' above).
    version_added: '20.6.0'
  parameters:
    description:
      - Allows for any rest option to be passed in
    type: dict
    version_added: '20.7.0'
  use_python_keys:
    description:
      - If true, I(/) in the returned dictionary keys are translated to I(_).
      - It makes it possible to use a . notation when processing the output.
      - For instance I(ontap_info["svm/svms"]) can be accessed as I(ontap_info.svm_svms).
    type: bool
    default: false
    version_added: '21.9.0'
  owning_resource:
    description:
      - Some resources cannot be accessed directly.  You need to select them based on the owner or parent.  For instance, volume for a snapshot.
      - The following subsets require an owning resource, and the following suboptions when uuid is not present.
      - <application/consistency-groups/metrics> B(cg_name) is the consistency group name, B(svm_name) is the owning vserver name for the consistency group.
      - <application/consistency-groups/snapshots> B(cg_name) is the consistency group name, B(svm_name) is the owning vserver name for the consistency group.
      - <storage/volumes/snapshots>  B(volume_name) is the volume name, B(svm_name) is the owning vserver name for the volume.
      - <protocols/nfs/export-policies/rules> B(policy_name) is the name of the policy, B(svm_name) is the owning vserver name for the policy,
        B(rule_index) is the rule index.
      - <protocols/vscan/on-access-policies> B(svm_name) is the owning vserver name for the vscan.
      - <protocols/vscan/on-demand-policies> B(svm_name) is the owning vserver name for the vscan.
      - <protocols/vscan/scanner-pools> B(svm_name) is the owning vserver name for the vscan.
    type: dict
    version_added: '21.19.0'
  ignore_api_errors:
    description:
      - List of substrings.
      - If a substring is contained in an error message when fetching a subset, the module does not fail and the error is reported in the subset.
    type: list
    elements: str
    version_added: '21.23.0'
  hal_linking:
    description:
      - if false, HAL-encoded links are disabled in the REST calls.
    default: true
    type: bool
'''

EXAMPLES = '''
- name: Run ONTAP gather facts for vserver info
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    validate_certs: false
    gather_subset:
      - svm/svms

- name: Run ONTAP gather facts for aggregate info and volume info
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    validate_certs: false
    gather_subset:
      - storage/aggregates
      - storage/volumes

- name: Run ONTAP gather facts for aggregate info and volume info with fields section
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    fields:
      - '*'
    validate_certs: false
    gather_subset:
      - storage/aggregates
      - storage/volumes

- name: Run ONTAP gather facts for aggregate info with specified fields
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    fields:
      - 'uuid'
      - 'name'
      - 'node'
    validate_certs: false
    gather_subset:
      - storage/aggregates
    parameters:
      recommend:
        true

- name: Get Snapshot info (owning_resource example)
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    fields:
      - '*'
    validate_certs: false
    gather_subset:
      - storage/volumes/snapshots
    owning_resource:
      volume_name: volume_name
      svm_name: svm_name

- name: Run ONTAP gather facts for volume info with query on name and state
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    validate_certs: false
    gather_subset:
      - storage/volumes
    parameters:
      name: ansible*
      state: online

- name: Run ONTAP gather fact to get DACLs
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    validate_certs: false
    gather_subset:
      - file_directory_security
    parameters:
      vserver: svm1
      path: /vol1/qtree1
    use_python_keys: true

- name: Get ip network interface info
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    validate_certs: false
    gather_subset:
      - ip_interfaces_info
    parameters:
      location.failover: home_node_only
      location.node.name: ontap_cluster
      service_policy.name: default-data-files

- name: Get aggregate info
  netapp.ontap.na_ontap_rest_info:
    hostname: "{{ netapp_hostname }}"
    username: "{{ netapp_username }}"
    password: "{{ netapp_password }}"
    validate_certs: false
    gather_subset:
      - aggregate_info
    parameters:
      node.name: ontap_cluster
      block_storage.primary.raid_type: raid_dp

# assuming module_defaults is used to set hostname, username, ...
- name: Run demo subset using custom vsadmin role
  netapp.ontap.na_ontap_rest_info:
    gather_subset:
      - demo
    force_ontap_version: 9.8
    ignore_api_errors:
      - 'not authorized for that command'

# reports: {"cluster/nodes": {"error": {"code": "6", "message": "not authorized for that command"}}
'''

import codecs
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils._text import to_text, to_bytes
import ansible_collections.netapp.ontap.plugins.module_utils.netapp as netapp_utils
from ansible_collections.netapp.ontap.plugins.module_utils.netapp_module import NetAppModule
from ansible_collections.netapp.ontap.plugins.module_utils.netapp import OntapRestAPI
from ansible_collections.netapp.ontap.plugins.module_utils import rest_owning_resource, rest_vserver


class NetAppONTAPGatherInfo(object):
    '''Class with gather info methods'''

    def __init__(self):
        """
        Parse arguments, setup state variables,
        check parameters and ensure request module is installed
        """
        self.argument_spec = netapp_utils.na_ontap_rest_only_spec()
        self.argument_spec.update(dict(
            state=dict(type='str', required=False),
            gather_subset=dict(default=['demo'], type='list', elements='str', required=False),
            max_records=dict(type='int', default=1024, required=False),
            fields=dict(type='list', elements='str', required=False),
            parameters=dict(type='dict', required=False),
            use_python_keys=dict(type='bool', default=False),
            owning_resource=dict(type='dict', required=False),
            ignore_api_errors=dict(type='list', elements='str', required=False),
            hal_linking=dict(required=False, type='bool', default=True),
        ))

        self.module = AnsibleModule(
            argument_spec=self.argument_spec,
            supports_check_mode=True
        )

        # set up variables
        self.na_helper = NetAppModule()
        self.parameters = self.na_helper.set_parameters(self.module.params)
        self.fields = ''

        self.rest_api = OntapRestAPI(self.module)
        self.rest_api.fail_if_not_rest_minimum_version('na_ontap_rest_info', 9, 6, 0)

    def get_subset_info(self, gather_subset_info, default_fields=None):
        """
            Gather ONTAP information for the given subset using REST APIs
            Input for REST APIs call : (api, data)
            return gathered_ontap_info
        """

        api = gather_subset_info['api_call']
        if gather_subset_info.pop('post', False):
            self.run_post(gather_subset_info)
        if default_fields:
            fields = default_fields + ',' + self.fields
        elif 'fields' in gather_subset_info:
            fields = gather_subset_info['fields']
        else:
            fields = self.fields

        data = {'max_records': self.parameters['max_records'], 'fields': fields}

        #  Delete the fields record from data if it is a private/cli API call.
        #  The private_cli_fields method handles the fields for API calls using the private/cli endpoint.
        if '/private/cli' in api:
            del data['fields']

        # allow for passing in any additional rest api fields
        if self.parameters.get('parameters'):
            for each in self.parameters['parameters']:
                data[each] = self.parameters['parameters'][each]

        accept_header = 'application/hal+json' if self.parameters.get('hal_linking') else 'application/json'
        headers = self.rest_api.build_headers(accept=accept_header)
        gathered_ontap_info, error = self.rest_api.get(api, data, headers=headers)

        if error and "entry doesn't exist" in error.get('message', ''):
            # If the API returns no records, return an empty set of records.
            return {'records': [], 'num_records': 0}

        if not error:
            return gathered_ontap_info

        if isinstance(error, dict):
            # If the API doesn't exist (using an older system), we don't want to fail the task.
            if int(error.get('code', 0)) == 3 or (
                    # if Aggr recommender can't make a recommendation, it will fail with the following error code, don't fail the task.
                    int(error.get('code', 0)) == 19726344 and "No recommendation can be made for this cluster" in error.get('message')):
                return error.get('message')

            # Do not fail on error
            for error_pattern in self.parameters.get('ignore_api_errors', []):
                if error_pattern in error.get('message'):
                    return {'error': error}
            # Fail the module if error occurs from REST APIs call
            if int(error.get('code', 0)) == 6:
                error = "Error: %s user is not authorized to make %s api call" % (self.parameters.get('username'), api)
        self.module.fail_json(msg=error)

    @staticmethod
    def strip_dacls(response):
        # Use 'DACL - ACE' as a marker for the start of the list of DACLS in the descriptor.
        if 'acls' not in response['records'][0]:
            return None
        if 'DACL - ACEs' not in response['records'][0]['acls']:
            return None
        index = response['records'][0]['acls'].index('DACL - ACEs')
        dacls = response['records'][0]['acls'][(index + 1):]

        dacl_list = []
        if dacls:
            for dacl in dacls:
                # The '-' marker is the start of the DACL, the '-0x' marker is the end of the DACL.
                start_hyphen = dacl.index('-') + 1
                first_hyphen_removed = dacl[start_hyphen:]
                end_hyphen = first_hyphen_removed.index('-0x')
                dacl_dict = {'access_type': dacl[:start_hyphen - 1].strip()}
                dacl_dict['user_or_group'] = first_hyphen_removed[:end_hyphen]
                dacl_list.append(dacl_dict)
        return dacl_list

    def run_post(self, gather_subset_info):
        api = gather_subset_info['api_call']
        post_return, error = self.rest_api.post(api, None)
        if error:
            return None
        dummy, error = self.rest_api.wait_on_job(post_return['job'], increment=5)
        if error:
            # TODO: Handle errors that are not errors
            self.module.fail_json(msg="%s" % error)

    def get_next_records(self, api):
        """
            Gather next set of ONTAP information for the specified api
            Input for REST APIs call : (api, data)
            return gather_subset_info
        """

        data = {}
        gather_subset_info, error = self.rest_api.get(api, data)

        if error:
            self.module.fail_json(msg=error)

        return gather_subset_info

    def private_cli_fields(self, api):
        '''
        The private cli endpoint does not allow '*' to be an entered.
        If fields='*' or fields are not included within the playbook, the API call will be populated to return all possible fields.
        If fields is entered into the playbook the fields entered will be used when calling the API.
        '''
        if 'fields' not in self.parameters or '*' in self.parameters['fields'] or '**' in self.parameters['fields']:
            if api == 'support/autosupport/check':
                fields = 'node,corrective-action,status,error-detail,check-type,check-category'
            elif api == 'private/cli/vserver/security/file-directory':
                fields = 'acls'
            else:
                self.module.fail_json(msg='Internal error, no field for %s' % api)
        else:
            fields = ','.join(self.parameters['fields'])
        return fields

    def convert_subsets(self):
        """
        Convert an info to the REST API
        """
        info_to_rest_mapping = {
            "aggregate_info": "storage/aggregates",
            "aggr_efficiency_info": ['storage/aggregates', 'space.efficiency,name,node'],
            "application_info": "application/applications",
            "application_template_info": "application/templates",
            "autosupport_check_info": "support/autosupport/check",
            "autosupport_config_info": "support/autosupport",
            "autosupport_messages_history": "support/autosupport/messages",
            "broadcast_domains_info": "network/ethernet/broadcast-domains",
            "cifs_home_directory_info": "protocols/cifs/home-directory/search-paths",
            "cifs_options_info": "protocols/cifs/services",
            "cifs_services_info": "protocols/cifs/services",
            "cifs_share_info": "protocols/cifs/shares",
            "cifs_vserver_security_info": ["protocols/cifs/services", "security.encrypt_dc_connection,"
                                                                      "security.kdc_encryption,security.smb_signing,"
                                                                      "security.smb_encryption,"
                                                                      "security.lm_compatibility_level,svm.name"],
            "clock_info": ["cluster/nodes", "date"],
            "cloud_targets_info": "cloud/targets",
            "cluster_chassis_info": "cluster/chassis",
            "cluster_identity_info": ["cluster", "contact,location,name,uuid"],
            "cluster_image_info": "cluster/software",
            "cluster_jobs_info": "cluster/jobs",
            "cluster_log_forwarding_info": "security/audit/destinations",
            "cluster_metrocluster_diagnostics": "cluster/metrocluster/diagnostics",
            "cluster_metrics_info": "cluster/metrics",
            "cluster_node_info": "cluster/nodes",
            "cluster_peer_info": "cluster/peers",
            "cluster_schedules": "cluster/schedules",
            "cluster_software_download": "cluster/software/download",
            "cluster_software_history": "cluster/software/history",
            "cluster_software_packages": "cluster/software/packages",
            "cluster_switch_info": "network/ethernet/switches",
            "disk_info": "storage/disks",
            "event_notification_info": "support/ems/destinations",
            "event_notification_destination_info": "support/ems/destinations",
            "export_policy_info": "protocols/nfs/export-policies",
            "fcp_alias_info": "network/fc/wwpn-aliases",
            "fcp_service_info": "protocols/san/fcp/services",
            "file_directory_security": "private/cli/vserver/security/file-directory",
            "igroup_info": "protocols/san/igroups",
            "initiator_groups_info": "protocols/san/igroups",
            "ip_interfaces_info": "network/ip/interfaces",
            "ip_routes_info": "network/ip/routes",
            "ip_service_policies": "network/ip/service-policies",
            "iscsi_service_info": "protocols/san/iscsi/services",
            "job_schedule_cron_info": "cluster/schedules",
            "kerberos_realm_info": "protocols/nfs/kerberos/realms",
            "ldap_client": "name-services/ldap",
            "ldap_config": "name-services/ldap",
            "license_info": "cluster/licensing/licenses",
            "lun_info": "storage/luns",
            "lun_map_info": "protocols/san/lun-maps",
            "net_dns_info": "name-services/dns",
            "net_interface_info": "network/ip/interfaces",
            "net_interface_service_policy_info": "network/ip/service-policies",
            "net_port_broadcast_domain_info": "network/ethernet/broadcast-domains",
            "net_port_info": "network/ethernet/ports",
            "net_routes_info": "network/ip/routes",
            "net_ipspaces_info": "network/ipspaces",
            "net_vlan_info": ["network/ethernet/ports", "name,node.name,vlan.base_port,vlan.tag"],
            "network_ipspaces_info": "network/ipspaces",
            "network_ports_info": "network/ethernet/ports",
            "nfs_info": "protocols/nfs/services",
            "ntp_server_info": "cluster/ntp/servers",
            "nvme_info": "protocols/nvme/services",
            "nvme_interface_info": "protocols/nvme/interfaces",
            "nvme_namespace_info": "storage/namespaces",
            "nvme_subsystem_info": "protocols/nvme/subsystems",
            "metrocluster_info": "cluster/metrocluster",
            "metrocluster_node_info": "cluster/metrocluster/nodes",
            "metrocluster_check_info": "cluster/metrocluster/diagnostics",
            "ontap_system_version": "cluster/software",
            "quota_report_info": "storage/quota/reports",
            "qos_policy_info": "storage/qos/policies",
            "qos_adaptive_policy_info": "storage/qos/policies",
            "qtree_info": "storage/qtrees",
            "san_fc_logins_info": "network/fc/logins",
            "san_fc_wppn-aliases": "network/fc/wwpn-aliases",
            "san_fcp_services": "protocols/san/fcp/services",
            "san_iscsi_credentials": "protocols/san/iscsi/credentials",
            "san_iscsi_services": "protocols/san/iscsi/services",
            "san_lun_maps": "protocols/san/lun-maps",
            "security_login_account_info": "security/accounts",
            "security_login_info": "security/accounts",
            "security_login_rest_role_info": "security/roles",
            "shelf_info": "storage/shelves",
            "sis_info": ["storage/volumes", "efficiency.compression,efficiency.cross_volume_dedupe,"
                                            "efficiency.cross_volume_dedupe,efficiency.compaction,"
                                            "efficiency.compression,efficiency.dedupe,efficiency.policy.name,"
                                            "efficiency.schedule,svm.name"],
            "sis_policy_info": "storage/volume-efficiency-policies",
            "snapmirror_destination_info": ["snapmirror/relationships", "destination.path,destination.svm.name,"
                                                                        "destination.svm.uuid,policy.type,uuid,state,"
                                                                        "source.path,source.svm.name,source.svm.uuid,"
                                                                        "transfer.bytes_transferred"],
            "snapmirror_info": "snapmirror/relationships",
            "snapmirror_policy_info": "snapmirror/policies",
            "snapshot_policy_info": "storage/snapshot-policies",
            "storage_bridge_info": "storage/bridges",
            "storage_flexcaches_info": "storage/flexcache/flexcaches",
            "storage_flexcaches_origin_info": "storage/flexcache/origins",
            "storage_luns_info": "storage/luns",
            "storage_NVMe_namespaces": "storage/namespaces",
            "storage_ports_info": "storage/ports",
            "storage_qos_policies": "storage/qos/policies",
            "storage_qtrees_config": "storage/qtrees",
            "storage_quota_reports": "storage/quota/reports",
            "storage_quota_policy_rules": "storage/quota/rules",
            "storage_shelves_config": "storage/shelves",
            "storage_snapshot_policies": "storage/snapshot-policies",
            "support_ems_config": "support/ems",
            "support_ems_events": "support/ems/events",
            "support_ems_filters": "support/ems/filters",
            "svm_dns_config_info": "name-services/dns",
            "svm_ldap_config_info": "name-services/ldap",
            "svm_name_mapping_config_info": "name-services/name-mappings",
            "svm_nis_config_info": "name-services/nis",
            "svm_peers_info": "svm/peers",
            "svm_peer-permissions_info": "svm/peer-permissions",
            "sysconfig_info": "cluster/nodes",
            "system_node_info": ["cluster/nodes", "controller.cpu.firmware_release,controller.failed_fan.count,"
                                                  "controller.failed_fan.message,"
                                                  "controller.failed_power_supply.count,"
                                                  "controller.failed_power_supply.message,"
                                                  "controller.over_temperature,is_all_flash_optimized,"
                                                  "is_all_flash_select_optimized,is_capacity_optimized,state,name,"
                                                  "location,model,nvram.id,owner,serial_number,storage_configuration,"
                                                  "system_id,uptime,uuid,vendor_serial_number,nvram.battery_state,"
                                                  "version,vm.provider_type"],
            "sys_cluster_alerts": "private/support/alerts",
            "vserver_info": "svm/svms",
            "vserver_peer_info": "svm/peers",
            "vserver_nfs_info": "protocols/nfs/services",
            "volume_info": "storage/volumes",
            "volume_space_info": ["storage/volumes", 'space.logical_space.available,space.logical_space.used,'
                                                     'space.logical_space.used_percent,space.snapshot.reserve_size,'
                                                     'space.snapshot.reserve_percent,space.used,name,svm.name'],
            "vscan_connection_status_all_info": "protocols/vscan/server-status",
            "vscan_info": "protocols/vscan",
            "vscan_status_info": "protocols/vscan"
        }
        # Add rest API names as there info version, also make sure we don't add a duplicate
        subsets = []
        for subset in self.parameters['gather_subset']:
            if subset in info_to_rest_mapping:
                if info_to_rest_mapping[subset] not in subsets:
                    subsets.append(info_to_rest_mapping[subset])
            elif subset not in subsets:
                subsets.append(subset)
        return subsets

    def add_naa_id(self, info):
        ''' https://kb.netapp.com/Advice_and_Troubleshooting/Data_Storage_Systems/FlexPod_with_Infrastructure_Automation/
            How_to_match__LUNs_NAA_number_to_its_serial_number
        '''
        if info and 'records' in info:
            for lun in info['records']:
                if 'serial_number' in lun:
                    hexlify = codecs.getencoder('hex')
                    lun['serial_hex'] = to_text(hexlify(to_bytes(lun['serial_number']))[0])
                    lun['naa_id'] = 'naa.600a0980' + lun['serial_hex']

    def augment_subset_info(self, subset, subset_info):
        if subset == 'private/cli/vserver/security/file-directory':
            # creates a new list of dicts
            subset_info = self.strip_dacls(subset_info)
        if subset == 'storage/luns':
            # mutates the existing dicts
            self.add_naa_id(subset_info)
        return subset_info

    def get_ontap_subset_info_all(self, subset, default_fields, get_ontap_subset_info):
        """ Iteratively get all records for a subset """
        try:
            # Verify whether the supported subset passed
            specified_subset = get_ontap_subset_info[subset]
        except KeyError:
            self.module.fail_json(msg="Specified subset %s is not found, supported subsets are %s" %
                                  (subset, list(get_ontap_subset_info.keys())))
        if 'api_call' not in specified_subset:
            specified_subset['api_call'] = subset
        subset_info = self.get_subset_info(specified_subset, default_fields)

        if subset_info is not None and isinstance(subset_info, dict) and '_links' in subset_info:
            while subset_info['_links'].get('next'):
                # Get all the set of records if next link found in subset_info for the specified subset
                next_api = subset_info['_links']['next']['href']
                gathered_subset_info = self.get_next_records(next_api.replace('/api', ''))

                # Update the subset info for the specified subset
                subset_info['_links'] = gathered_subset_info['_links']
                subset_info['records'].extend(gathered_subset_info['records'])

            # metrocluster doesn't have a records field, so we need to skip this
            if subset_info.get('records') is not None:
                # Getting total number of records
                subset_info['num_records'] = len(subset_info['records'])

        return self.augment_subset_info(subset, subset_info)

    def apply(self):
        """
        Perform pre-checks, call functions and exit
        """

        # Defining gather_subset and appropriate api_call
        get_ontap_subset_info = {
            'application/applications': {},
            'application/consistency-groups': {'version': (9, 10, 1)},
            'application/templates': {},
            'cloud/targets': {},
            'cluster': {},
            'cluster/chassis': {},
            'cluster/counter/tables': {'version': (9, 11, 1)},
            'cluster/firmware/history': {'version': (9, 8)},
            'cluster/jobs': {},
            'cluster/licensing/capacity-pools': {'version': (9, 8)},
            'cluster/licensing/license-managers': {'version': (9, 8)},
            'cluster/licensing/licenses': {},
            'cluster/mediators': {'version': (9, 8)},
            'cluster/metrics': {},
            'cluster/metrocluster': {'version': (9, 8)},
            'cluster/metrocluster/diagnostics': {
                'version': (9, 8),
                'post': True
            },
            'cluster/metrocluster/dr-groups': {'version': (9, 8)},
            'cluster/metrocluster/interconnects': {'version': (9, 8)},
            'cluster/metrocluster/nodes': {'version': (9, 8)},
            'cluster/metrocluster/operations': {'version': (9, 8)},
            'cluster/metrocluster/svms': {'version': (9, 11, 1)},
            'cluster/nodes': {},
            'cluster/ntp/keys': {'version': (9, 7)},
            'cluster/ntp/servers': {'version': (9, 7)},
            'cluster/peers': {},
            'cluster/schedules': {},
            'cluster/sensors': {'version': (9, 11, 1)},
            'cluster/software': {},
            'cluster/software/download': {'version': (9, 7)},
            'cluster/software/history': {},
            'cluster/software/packages': {},
            'cluster/web': {'version': (9, 10, 1)},
            'name-services/cache/group-membership/settings': {'version': (9, 11, 1)},
            'name-services/cache/host/settings': {'version': (9, 11, 1)},
            'name-services/cache/netgroup/settings': {'version': (9, 11, 1)},
            'name-services/cache/setting': {'version': (9, 11, 1)},
            'name-services/cache/unix-group/settings': {'version': (9, 11, 1)},
            'name-services/dns': {},
            'name-services/ldap': {},
            'name-services/ldap-schemas': {'version': (9, 11, 1)},
            'name-services/local-hosts': {'version': (9, 10, 1)},
            'name-services/name-mappings': {},
            'name-services/nis': {},
            'name-services/unix-groups': {'version': (9, 9)},
            'name-services/unix-users': {'version': (9, 9)},
            'network/ethernet/broadcast-domains': {},
            'network/ethernet/ports': {},
            'network/ethernet/switch/ports': {'version': (9, 8)},
            'network/ethernet/switches': {'version': (9, 8)},
            'network/fc/fabrics': {'version': (9, 11, 1)},
            'network/fc/interfaces': {},
            'network/fc/logins': {},
            'network/fc/ports': {},
            'network/fc/wwpn-aliases': {},
            'network/http-proxy': {'version': (9, 7)},
            'network/ip/bgp/peer-groups': {'version': (9, 7)},
            'network/ip/interfaces': {},
            'network/ip/routes': {},
            'network/ip/service-policies': {},
            'network/ip/subnets': {'version': (9, 11, 1)},
            'network/ipspaces': {},
            'private/support/alerts': {},
            'protocols/active-directory': {'version': (9, 12, 1)},
            'protocols/audit': {},
            'protocols/cifs/connections': {'version': (9, 11, 1)},
            'protocols/cifs/domains': {'version': (9, 10, 1)},
            'protocols/cifs/group-policies': {'version': (9, 12, 1)},
            'protocols/cifs/home-directory/search-paths': {},
            'protocols/cifs/local-groups': {'version': (9, 9)},
            'protocols/cifs/local-users': {'version': (9, 9)},
            'protocols/cifs/netbios': {'version': (9, 11, 1)},
            'protocols/cifs/services': {},
            'protocols/cifs/session/files': {'version': (9, 11, 1)},
            'protocols/cifs/sessions': {'version': (9, 8)},
            'protocols/cifs/shadow-copies': {'version': (9, 11, 1)},
            'protocols/cifs/shadowcopy-sets': {'version': (9, 11, 1)},
            'protocols/cifs/shares': {},
            'protocols/cifs/unix-symlink-mapping': {},
            'protocols/cifs/users-and-groups/privileges': {'version': (9, 9)},
            'protocols/fpolicy': {},
            'protocols/locks': {'version': (9, 10, 1)},
            'protocols/ndmp': {'version': (9, 7)},
            'protocols/ndmp/nodes': {'version': (9, 7)},
            'protocols/ndmp/sessions': {'version': (9, 7)},
            'protocols/ndmp/svms': {'version': (9, 7)},
            'protocols/nfs/connected-clients': {'version': (9, 7)},
            'protocols/nfs/connected-client-maps': {'version': (9, 11, 1)},
            'protocols/nfs/connected-client-settings': {'version': (9, 12, 1)},
            'protocols/nfs/export-policies': {},
            'protocols/nfs/kerberos/interfaces': {},
            'protocols/nfs/kerberos/realms': {},
            'protocols/nfs/services': {},
            'protocols/nvme/interfaces': {},
            'protocols/nvme/services': {},
            'protocols/nvme/subsystem-controllers': {},
            'protocols/nvme/subsystem-maps': {},
            'protocols/nvme/subsystems': {},
            'protocols/s3/buckets': {'version': (9, 7)},
            'protocols/s3/services': {'version': (9, 7)},
            'protocols/san/fcp/services': {},
            'protocols/san/igroups': {},
            'protocols/san/iscsi/credentials': {},
            'protocols/san/iscsi/services': {},
            'protocols/san/iscsi/sessions': {},
            'protocols/san/lun-maps': {},
            'protocols/san/portsets': {'version': (9, 9)},
            'protocols/san/vvol-bindings': {'version': (9, 10, 1)},
            'protocols/vscan/server-status': {},
            'protocols/vscan': {},
            'security': {'version': (9, 7)},
            'security/accounts': {},
            'security/anti-ransomware/suspects': {'version': (9, 10, 1)},
            'security/audit': {},
            'security/audit/destinations': {},
            'security/audit/messages': {},
            'security/authentication/cluster/ad-proxy': {'version': (9, 7)},
            'security/authentication/cluster/ldap': {},
            'security/authentication/cluster/nis': {},
            'security/authentication/cluster/saml-sp': {},
            'security/authentication/publickeys': {'version': (9, 7)},
            'security/aws-kms': {'version': (9, 12, 1)},
            'security/azure-key-vaults': {'version': (9, 8)},
            'security/certificates': {},
            'security/gcp-kms': {'version': (9, 9)},
            'security/ipsec': {'version': (9, 8)},
            'security/ipsec/ca-certificates': {'version': (9, 10, 1)},
            'security/ipsec/policies': {'version': (9, 8)},
            'security/ipsec/security-associations': {'version': (9, 8)},
            'security/key-manager-configs': {'version': (9, 10, 1)},
            'security/key-managers': {},
            'security/key-stores': {'version': (9, 10, 1)},
            'security/login/messages': {},
            'security/multi-admin-verify': {'version': (9, 11, 1)},
            'security/multi-admin-verify/approval-groups': {'version': (9, 11, 1)},
            'security/multi-admin-verify/requests': {'version': (9, 11, 1)},
            'security/multi-admin-verify/rules': {'version': (9, 11, 1)},
            'security/roles': {},
            'security/ssh': {'version': (9, 7)},
            'security/ssh/svms': {'version': (9, 10, 1)},
            'snapmirror/policies': {},
            'snapmirror/relationships': {},
            'storage/aggregates': {},
            'storage/bridges': {'version': (9, 9)},
            'storage/cluster': {},
            'storage/disks': {},
            'storage/file/clone/split-loads': {'version': (9, 10, 1)},
            'storage/file/clone/split-status': {'version': (9, 10, 1)},
            'storage/file/clone/tokens': {'version': (9, 10, 1)},
            'storage/file/moves': {'version': (9, 11, 1)},
            'storage/flexcache/flexcaches': {},
            'storage/flexcache/origins': {},
            'storage/luns': {},
            'storage/namespaces': {},
            'storage/pools': {'version': (9, 11, 1)},
            'storage/ports': {},
            'storage/qos/policies': {},
            'storage/qos/workloads': {'version': (9, 10, 1)},
            'storage/qtrees': {},
            'storage/quota/reports': {},
            'storage/quota/rules': {},
            'storage/shelves': {},
            'storage/snaplock/audit-logs': {'version': (9, 7)},
            'storage/snaplock/compliance-clocks': {'version': (9, 7)},
            'storage/snaplock/event-retention/operations': {'version': (9, 7)},
            'storage/snaplock/event-retention/policies': {'version': (9, 7)},
            'storage/snaplock/file-fingerprints': {'version': (9, 7)},
            'storage/snaplock/litigations': {'version': (9, 7)},
            'storage/snapshot-policies': {},
            'storage/switches': {'version': (9, 9)},
            'storage/tape-devices': {'version': (9, 9)},
            'storage/volumes': {},
            'storage/volume-efficiency-policies': {'version': (9, 8)},
            'support/autosupport': {},
            'support/autosupport/check': {
                'api_call': '/private/cli/system/node/autosupport/check/details',
                'fields': self.private_cli_fields('support/autosupport/check'),
            },
            'support/autosupport/messages': {},
            'support/auto-update': {'version': (9, 10, 1)},
            'support/auto-update/configurations': {'version': (9, 10, 1)},
            'support/auto-update/updates': {'version': (9, 10, 1)},
            'support/configuration-backup': {},
            'support/configuration-backup/backups': {'version': (9, 7)},
            'support/coredump/coredumps': {'version': (9, 10, 1)},
            'support/ems': {},
            'support/ems/destinations': {},
            'support/ems/events': {},
            'support/ems/filters': {},
            'support/ems/messages': {},
            'support/snmp': {'version': (9, 7)},
            'support/snmp/traphosts': {'version': (9, 7)},
            'support/snmp/users': {'version': (9, 7)},
            'svm/migrations': {'version': (9, 10, 1)},
            'svm/peers': {},
            'svm/peer-permissions': {},
            'svm/svms': {}
        }
        if 'gather_subset' in self.parameters and (
                'private/cli/vserver/security/file-directory' in self.parameters['gather_subset']
                or 'file_directory_security' in self.parameters['gather_subset']
        ):
            get_ontap_subset_info['private/cli/vserver/security/file-directory'] = {
                'api_call': 'private/cli/vserver/security/file-directory',
                'fields': self.private_cli_fields('private/cli/vserver/security/file-directory')
            }
        if 'all' in self.parameters['gather_subset']:
            # If all in subset list, get the information of all subsets
            self.parameters['gather_subset'] = sorted(get_ontap_subset_info.keys())
        if 'demo' in self.parameters['gather_subset']:
            self.parameters['gather_subset'] = ['cluster/software', 'svm/svms', 'cluster/nodes']
        get_ontap_subset_info = self.add_uuid_subsets(get_ontap_subset_info)

        length_of_subsets = len(self.parameters['gather_subset'])
        unsupported_subsets = self.subset_version_warning(get_ontap_subset_info)

        if self.parameters.get('fields'):
            if '**' in self.parameters.get('fields'):
                self.module.warn('Using ** can put an extra load on the system and should not be used in production')
            # If multiple fields specified to return, convert list to string
            self.fields = ','.join(self.parameters.get('fields'))

            if self.fields not in ('*', '**') and length_of_subsets > 1:
                # Restrict gather subsets to one subset if fields section is list_of_fields
                self.module.fail_json(msg="Error: fields: %s, only one subset will be allowed." % self.parameters.get('fields'))
        converted_subsets = self.convert_subsets()

        result_message = {}
        for subset in converted_subsets:
            subset, default_fields = subset if isinstance(subset, list) else (subset, None)
            result_message[subset] = self.get_ontap_subset_info_all(subset, default_fields, get_ontap_subset_info)
        for subset in unsupported_subsets:
            result_message[subset] = '%s requires ONTAP %s' % (subset, get_ontap_subset_info[subset]['version'])

        results = {'changed': False}
        if self.parameters.get('state') is not None:
            results['state'] = self.parameters['state']
            results['warnings'] = "option 'state' is deprecated."
        if self.parameters['use_python_keys']:
            new_dict = dict((key.replace('/', '_'), value) for (key, value) in result_message.items())
            new_dict = dict((key.replace('-', '_'), value) for (key, value) in new_dict.items())
            result_message = new_dict
        self.module.exit_json(ontap_info=result_message, **results)

    def subset_version_warning(self, get_ontap_subset_info):
        # If a user requests a subset that their version of ONTAP does not support give them a warning (but don't fail)
        unsupported_subset = []
        warn_message = ''
        user_version = self.rest_api.get_ontap_version()
        for subset in self.parameters['gather_subset']:
            if subset in get_ontap_subset_info and 'version' in get_ontap_subset_info[subset] and get_ontap_subset_info[subset]['version'] > user_version:
                warn_message += '%s requires %s, ' % (subset, get_ontap_subset_info[subset]['version'])
                # remove subset so info dosn't fail for a bad subset
                unsupported_subset.append(subset)
                self.parameters['gather_subset'].remove(subset)
        if warn_message != '':
            self.module.warn('The following subset have been removed from your query as they are not supported on your version of ONTAP %s' % warn_message)
        return unsupported_subset

    def add_uuid_subsets(self, get_ontap_subset_info):
        params = self.parameters.get('owning_resource')
        owning_resource_supported_subsets = ['application/consistency-groups/metrics', 'application/consistency-groups/snapshots',
                                             'storage/volumes/snapshots', 'protocols/nfs/export-policies/rules',
                                             'protocols/vscan/on-access-policies', 'protocols/vscan/on-demand-policies',
                                             'protocols/vscan/scanner-pools']
        if 'gather_subset' in self.parameters:
            if 'application/consistency-groups/metrics' in self.parameters['gather_subset']:
                self.check_error_values('application/consistency-groups/metrics', params, ['cg_name', 'svm_name'])
                cg_uuid = rest_owning_resource.get_consistency_group_uuid(self.rest_api, self.parameters['owning_resource']['cg_name'],
                                                                          self.parameters['owning_resource']['svm_name'], self.module)
                if cg_uuid:
                    get_ontap_subset_info['application/consistency-groups/metrics'] = {'api_call': 'application/consistency-groups/%s/metrics' % cg_uuid}
            if 'application/consistency-groups/snapshots' in self.parameters['gather_subset']:
                self.check_error_values('application/consistency-groups/snapshots', params, ['cg_name', 'svm_name'])
                cg_uuid = rest_owning_resource.get_consistency_group_uuid(self.rest_api, self.parameters['owning_resource']['cg_name'],
                                                                          self.parameters['owning_resource']['svm_name'], self.module)
                if cg_uuid:
                    get_ontap_subset_info['application/consistency-groups/snapshots'] = {'api_call': 'application/consistency-groups/%s/snapshots' % cg_uuid}
            if 'storage/volumes/snapshots' in self.parameters['gather_subset']:
                self.check_error_values('storage/volumes/snapshots', params, ['volume_name', 'svm_name'])
                volume_uuid = rest_owning_resource.get_volume_uuid(self.rest_api, self.parameters['owning_resource']['volume_name'],
                                                                   self.parameters['owning_resource']['svm_name'], self.module)
                if volume_uuid:
                    get_ontap_subset_info['storage/volumes/snapshots'] = {'api_call': 'storage/volumes/%s/snapshots' % volume_uuid}
            if 'protocols/nfs/export-policies/rules' in self.parameters['gather_subset']:
                self.check_error_values('protocols/nfs/export-policies/rules', params, ['policy_name', 'svm_name', 'rule_index'])
                policy_id = rest_owning_resource.get_export_policy_id(self.rest_api, self.parameters['owning_resource']['policy_name'],
                                                                      self.parameters['owning_resource']['svm_name'], self.module)
                if policy_id:
                    get_ontap_subset_info['protocols/nfs/export-policies/rules'] = {
                        'api_call': 'protocols/nfs/export-policies/%s/rules/%s' % (policy_id, self.parameters['owning_resource']['rule_index']),
                    }
            if 'protocols/vscan/on-access-policies' in self.parameters['gather_subset']:
                self.add_vserver_owning_resource('protocols/vscan/on-access-policies', params, 'protocols/vscan/%s/on-access-policies', get_ontap_subset_info)
            if 'protocols/vscan/on-demand-policies' in self.parameters['gather_subset']:
                self.add_vserver_owning_resource('protocols/vscan/on-demand-policies', params, 'protocols/vscan/%s/on-demand-policies', get_ontap_subset_info)
            if 'protocols/vscan/scanner-pools' in self.parameters['gather_subset']:
                self.add_vserver_owning_resource('protocols/vscan/scanner-pools', params, 'protocols/vscan/%s/scanner-pools', get_ontap_subset_info)
            owning_resource_warning = any(subset not in owning_resource_supported_subsets for subset in self.parameters['gather_subset'])
            if owning_resource_warning and params is not None:
                self.module.warn("Kindly refer to Ansible documentation to check the subsets that support option 'owning_resource'.")
        return get_ontap_subset_info

    def add_vserver_owning_resource(self, subset, params, api, get_ontap_subset_info):
        self.check_error_values(subset, params, ['svm_name'])
        svm_uuid, dummy = rest_vserver.get_vserver_uuid(self.rest_api, self.parameters['owning_resource']['svm_name'], self.module, True)
        if svm_uuid:
            get_ontap_subset_info[subset] = {'api_call': api % svm_uuid}

    def check_error_values(self, api, params, items):
        error = not params or sorted(list(params.keys())) != sorted(items)
        if error:
            self.module.fail_json(msg="Error: %s are required for %s" % (', '.join(items), api))


def main():
    """
    Main function
    """
    obj = NetAppONTAPGatherInfo()
    obj.apply()


if __name__ == '__main__':
    main()
