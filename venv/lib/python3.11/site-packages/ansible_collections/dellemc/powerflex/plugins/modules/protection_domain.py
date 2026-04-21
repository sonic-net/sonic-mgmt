#!/usr/bin/python

# Copyright: (c) 2022, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing Protection Domain on Dell Technologies (Dell) PowerFlex"""
from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: protection_domain
version_added: '1.2.0'
short_description: Manage Protection Domain on Dell PowerFlex
description:
- Managing Protection Domain on PowerFlex storage system includes creating,
  modifying attributes, deleting and getting details of Protection Domain.
author:
- Bhavneet Sharma (@sharmb5) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  protection_domain_name:
    description:
    - The name of the protection domain.
    - Mandatory for create operation.
    - It is unique across the PowerFlex array.
    - Mutually exclusive with I(protection_domain_id).
    type: str
  protection_domain_id:
    description:
    - The ID of the protection domain.
    - Except for create operation, all other operations can be performed
      using protection_domain_id.
    - Mutually exclusive with I(protection_domain_name).
    type: str
  protection_domain_new_name:
    description:
    - Used to rename the protection domain.
    type: str
  is_active:
    description:
    - Used to activate or deactivate the protection domain.
    type: bool
  network_limits:
    description:
    - Network bandwidth limit used by all SDS in protection domain.
    type: dict
    suboptions:
      rebuild_limit:
        description:
        - Limit the network bandwidth for rebuild.
        type: int
      rebalance_limit:
        description:
        - Limit the network bandwidth for rebalance.
        type: int
      vtree_migration_limit:
        description:
        - Limit the network bandwidth for vtree migration.
        type: int
      overall_limit:
        description:
        - Limit the overall network bandwidth.
        type: int
      bandwidth_unit:
        description:
        - Unit for network bandwidth limits.
        type: str
        choices: ['KBps', 'MBps', 'GBps']
        default: 'KBps'
  rf_cache_limits:
    description:
    - Used to set the RFcache parameters of the protection domain.
    type: dict
    suboptions:
      is_enabled:
        description:
        - Used to enable or disable RFcache in the protection domain.
        type: bool
      page_size:
        description:
        - Used to set the cache page size in KB.
        type: int
      max_io_limit:
        description:
        - Used to set cache maximum I/O limit in KB.
        type: int
      pass_through_mode:
        description:
        - Used to set the cache mode.
        choices: ['None', 'Read', 'Write', 'ReadAndWrite', 'WriteMiss']
        type: str
  state:
    description:
    - State of the protection domain.
    required: true
    type: str
    choices: ['present', 'absent']
notes:
  - The protection domain can only be deleted if all its related objects have
    been dissociated from the protection domain.
  - If the protection domain set to inactive, then no operation can be
    performed on protection domain.
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Create protection domain
  dellemc.powerflex.protection_domain:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    protection_domain_name: "domain1"
    state: "present"

- name: Create protection domain with all parameters
  dellemc.powerflex.protection_domain:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    protection_domain_name: "domain1"
    is_active: true
    network_limits:
      rebuild_limit: 10
      rebalance_limit: 17
      vtree_migration_limit: 14
      overall_limit: 20
      bandwidth_unit: "MBps"
    rf_cache_limits:
      is_enabled: true
      page_size: 16
      max_io_limit: 128
      pass_through_mode: "Read"
    state: "present"

- name: Get protection domain details using name
  dellemc.powerflex.protection_domain:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    protection_domain_name: "domain1"
    state: "present"

- name: Get protection domain details using ID
  dellemc.powerflex.protection_domain:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    protection_domain_id: "5718253c00000004"
    state: "present"

- name: Modify protection domain attributes
  dellemc.powerflex.protection_domain:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    protection_domain_name: "domain1"
    protection_domain_new_name: "domain1_new"
    network_limits:
      rebuild_limit: 14
      rebalance_limit: 20
      overall_limit: 25
      bandwidth_unit: "MBps"
    rf_cache_limits:
      page_size: 64
      pass_through_mode: "WriteMiss"
    state: "present"

- name: Delete protection domain using name
  dellemc.powerflex.protection_domain:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    protection_domain_name: "domain1_new"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
protection_domain_details:
    description: Details of the protection domain.
    returned: When protection domain exists
    type: dict
    contains:
        fglDefaultMetadataCacheSize:
            description: FGL metadata cache size.
            type: int
        fglDefaultNumConcurrentWrites:
            description: FGL concurrent writes.
            type: str
        fglMetadataCacheEnabled:
            description: Whether FGL cache enabled.
            type: bool
        id:
            description: Protection domain ID.
            type: str
        links:
            description: Protection domain links.
            type: list
            contains:
                href:
                    description: Protection domain instance URL.
                    type: str
                rel:
                    description: Protection domain's relationship with
                                 different entities.
                    type: str
        mdmSdsNetworkDisconnectionsCounterParameters:
            description: MDM's SDS counter parameter.
            type: dict
            contains:
                longWindow:
                    description: Long window for Counter Parameters.
                    type: int
                mediumWindow:
                    description: Medium window for Counter Parameters.
                    type: int
                shortWindow:
                    description: Short window for Counter Parameters.
                    type: int
        name:
            description: Name of the protection domain.
            type: str
        overallIoNetworkThrottlingEnabled:
            description: Whether overall network throttling enabled.
            type: bool
        overallIoNetworkThrottlingInKbps:
            description: Overall network throttling in KBps.
            type: int
        protectedMaintenanceModeNetworkThrottlingEnabled:
            description: Whether protected maintenance mode network throttling
                         enabled.
            type: bool
        protectedMaintenanceModeNetworkThrottlingInKbps:
            description: Protected maintenance mode network throttling in
                         KBps.
            type: int
        protectionDomainState:
            description: State of protection domain.
            type: int
        rebalanceNetworkThrottlingEnabled:
            description: Whether rebalance network throttling enabled.
            type: int
        rebalanceNetworkThrottlingInKbps:
            description: Rebalance network throttling in KBps.
            type: int
        rebuildNetworkThrottlingEnabled:
            description: Whether rebuild network throttling enabled.
            type: int
        rebuildNetworkThrottlingInKbps:
            description: Rebuild network throttling in KBps.
            type: int
        rfcacheAccpId:
            description: Id of RF cache acceleration pool.
            type: str
        rfcacheEnabled:
            description: Whether RF cache is enabled or not.
            type: bool
        rfcacheMaxIoSizeKb:
            description: RF cache maximum I/O size in KB.
            type: int
        rfcacheOpertionalMode:
            description: RF cache operational mode.
            type: str
        rfcachePageSizeKb:
            description: RF cache page size in KB.
            type: bool
        sdrSdsConnectivityInfo:
            description: Connectivity info of SDR and SDS.
            type: dict
            contains:
                clientServerConnStatus:
                    description: Connectivity status of client and server.
                    type: str
                disconnectedClientId:
                    description: Disconnected client ID.
                    type: str
                disconnectedClientName:
                    description: Disconnected client name.
                    type: str
                disconnectedServerId:
                    description: Disconnected server ID.
                    type: str
                disconnectedServerIp:
                    description: Disconnected server IP.
                    type: str
                disconnectedServerName:
                    description: Disconnected server name.
                    type: str
        sdsSdsNetworkDisconnectionsCounterParameters:
            description: Counter parameter for SDS-SDS network.
            type: dict
            contains:
                longWindow:
                    description: Long window for Counter Parameters.
                    type: int
                mediumWindow:
                    description: Medium window for Counter Parameters.
                    type: int
                shortWindow:
                    description: Short window for Counter Parameters.
                    type: int
        storagePool:
            description: List of storage pools.
            type: list
        systemId:
            description: ID of system.
            type: str
        vtreeMigrationNetworkThrottlingEnabled:
            description: Whether V-Tree migration network throttling enabled.
            type: bool
        vtreeMigrationNetworkThrottlingInKbps:
            description: V-Tree migration network throttling in KBps.
            type: int
    sample: {
        "fglDefaultMetadataCacheSize": 0,
        "fglDefaultNumConcurrentWrites": 1000,
        "fglMetadataCacheEnabled": false,
        "id": "7bd6457000000000",
        "links": [
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000",
                "rel": "self"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/Statistics",
                "rel": "/api/ProtectionDomain/relationship/Statistics"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/Sdr",
                "rel": "/api/ProtectionDomain/relationship/Sdr"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/AccelerationPool",
                "rel": "/api/ProtectionDomain/relationship/AccelerationPool"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/StoragePool",
                "rel": "/api/ProtectionDomain/relationship/StoragePool"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/Sds",
                "rel": "/api/ProtectionDomain/relationship/Sds"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/ReplicationConsistencyGroup",
                "rel": "/api/ProtectionDomain/relationship/
                        ReplicationConsistencyGroup"
            },
            {
                "href": "/api/instances/ProtectionDomain::7bd6457000000000/
                        relationships/FaultSet",
                "rel": "/api/ProtectionDomain/relationship/FaultSet"
            },
            {
                "href": "/api/instances/System::0989ce79058f150f",
                "rel": "/api/parent/relationship/systemId"
            }
        ],
        "mdmSdsNetworkDisconnectionsCounterParameters": {
            "longWindow": {
                "threshold": 700,
                "windowSizeInSec": 86400
            },
            "mediumWindow": {
                "threshold": 500,
                "windowSizeInSec": 3600
            },
            "shortWindow": {
                "threshold": 300,
                "windowSizeInSec": 60
            }
        },
        "name": "domain1",
        "overallIoNetworkThrottlingEnabled": false,
        "overallIoNetworkThrottlingInKbps": null,
        "protectedMaintenanceModeNetworkThrottlingEnabled": false,
        "protectedMaintenanceModeNetworkThrottlingInKbps": null,
        "protectionDomainState": "Active",
        "rebalanceNetworkThrottlingEnabled": false,
        "rebalanceNetworkThrottlingInKbps": null,
        "rebuildNetworkThrottlingEnabled": false,
        "rebuildNetworkThrottlingInKbps": null,
        "rfcacheAccpId": null,
        "rfcacheEnabled": true,
        "rfcacheMaxIoSizeKb": 128,
        "rfcacheOpertionalMode": "WriteMiss",
        "rfcachePageSizeKb": 64,
        "sdrSdsConnectivityInfo": {
            "clientServerConnStatus": "CLIENT_SERVER_CONN_STATUS_ALL
                                      _CONNECTED",
            "disconnectedClientId": null,
            "disconnectedClientName": null,
            "disconnectedServerId": null,
            "disconnectedServerIp": null,
            "disconnectedServerName": null
        },
        "sdsConfigurationFailureCounterParameters": {
            "longWindow": {
                "threshold": 700,
                "windowSizeInSec": 86400
            },
            "mediumWindow": {
                "threshold": 500,
                "windowSizeInSec": 3600
            },
            "shortWindow": {
                "threshold": 300,
                "windowSizeInSec": 60
            }
        },
        "sdsDecoupledCounterParameters": {
            "longWindow": {
                "threshold": 700,
                "windowSizeInSec": 86400
            },
            "mediumWindow": {
                "threshold": 500,
                "windowSizeInSec": 3600
            },
            "shortWindow": {
                "threshold": 300,
                "windowSizeInSec": 60
            }
        },
        "sdsReceiveBufferAllocationFailuresCounterParameters": {
            "longWindow": {
                "threshold": 2000000,
                "windowSizeInSec": 86400
            },
            "mediumWindow": {
                "threshold": 200000,
                "windowSizeInSec": 3600
            },
            "shortWindow": {
                "threshold": 20000,
                "windowSizeInSec": 60
            }
        },
        "sdsSdsNetworkDisconnectionsCounterParameters": {
            "longWindow": {
                "threshold": 700,
                "windowSizeInSec": 86400
            },
            "mediumWindow": {
                "threshold": 500,
                "windowSizeInSec": 3600
            },
            "shortWindow": {
                "threshold": 300,
                "windowSizeInSec": 60
            }
        },
        "storagePool": [
            {
                "id": "8d1cba1700000000",
                "name": "pool1"
            }
        ],
        "systemId": "0989ce79058f150f",
        "vtreeMigrationNetworkThrottlingEnabled": false,
        "vtreeMigrationNetworkThrottlingInKbps": null
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell \
    import utils

LOG = utils.get_logger('protection_domain')


class PowerFlexProtectionDomain(object):
    """Class with protection domain operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_protection_domain_parameters())

        mut_ex_args = [['protection_domain_name', 'protection_domain_id']]

        required_one_of_args = [['protection_domain_name',
                                 'protection_domain_id']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mut_ex_args,
            required_one_of=required_one_of_args)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def validate_input_params(self):
        """Validate the input parameters"""

        name_params = ['protection_domain_name', 'protection_domain_new_name',
                       'protection_domain_id']
        msg = "Please provide the valid {0}"

        for n_item in name_params:
            if self.module.params[n_item] is not None and (len(
                    self.module.params[n_item].strip()) or self.
                    module.params[n_item].count(" ") > 0) == 0:
                err_msg = msg.format(n_item)
                self.module.fail_json(msg=err_msg)

        if self.module.params['network_limits'] is not None:
            if self.module.params['network_limits']['overall_limit'] is not None and \
                    self.module.params['network_limits']['overall_limit'] < 0:
                error_msg = "Overall limit cannot be negative. " \
                            "Provide a valid value "
                LOG.info(error_msg)
                self.module.fail_json(msg=error_msg)

    def is_id_or_new_name_in_create(self):
        """Checking if protection domain id or new names present in create """

        if self.module.params['protection_domain_new_name'] or \
                self.module.params['protection_domain_id']:
            error_msg = "protection_domain_new_name/protection_domain_id " \
                        "are not supported during creation of protection " \
                        "domain. Please try with protection_domain_name."
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_storage_pool(self, protection_domain_id):
        """
        Get Storage pools details
        :param protection_domain_id: Name of the protection domain
        :type protection_domain_id: str
        :return: list containing storage pools which are present in
                 protection domain
        """

        try:
            sps_list = []
            resp = self.powerflex_conn.protection_domain. \
                get_storage_pools(protection_domain_id=protection_domain_id)
            for items in resp:
                sp_name_id = dict()
                sp_name_id['id'] = items['id']
                sp_name_id['name'] = items['name']
                sps_list.append(sp_name_id)
            return sps_list

        except Exception as e:
            errmsg = "Failed to get the storage pools present in protection" \
                     " domain %s with error %s" % (protection_domain_id, str(e))
            LOG.error(errmsg)
            self.module.fail_json(msg=errmsg)

    def get_protection_domain(self, protection_domain_name=None,
                              protection_domain_id=None):
        """
        Get protection domain details
        :param protection_domain_name: Name of the protection domain
        :param protection_domain_id: ID of the protection domain
        :return: Protection domain details if exists
        :rtype: dict
        """

        name_or_id = protection_domain_id if protection_domain_id \
            else protection_domain_name

        try:
            if protection_domain_id:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={'id': protection_domain_id})

            else:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={'name': protection_domain_name})

            if len(pd_details) == 0:
                error_msg = "Unable to find the protection domain with " \
                            "'%s'." % name_or_id
                LOG.info(error_msg)
                return None

            # Append storage pool list present in protection domain
            pd_details[0]['storagePool'] = self.get_storage_pool(pd_details
                                                                 [0]['id'])
            return pd_details[0]

        except Exception as e:
            error_msg = "Failed to get the protection domain '%s' with " \
                        "error '%s'" % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def create_protection_domain(self, protection_domain_name):
        """
        Create Protection Domain
        :param protection_domain_name: Name of the protection domain
        :type protection_domain_name: str
        :return: Boolean indicating if create operation is successful
        """
        # Creation of Protection domain
        try:
            LOG.info("Creating protection domain with name: %s ",
                     protection_domain_name)
            self.powerflex_conn.protection_domain.\
                create(name=protection_domain_name)
            return True

        except Exception as e:
            error_msg = "Create protection domain '%s' operation failed" \
                        " with error '%s'" % (protection_domain_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_create_operation(self, state, pd_details,
                                 protection_domain_name):
        """performing creation of protection domain details"""

        if state == 'present' and not pd_details:
            self.is_id_or_new_name_in_create()
            create_change = self.\
                create_protection_domain(protection_domain_name)
            if create_change:
                pd_details = self. \
                    get_protection_domain(protection_domain_name)
                msg = "Protection domain created successfully, fetched" \
                      " protection domain details {0}". \
                    format(str(pd_details))
                LOG.info(msg)
                return create_change, pd_details

        return False, pd_details

    def is_modify_required(self, pd_details, network_limits, rf_cache_limits,
                           protection_domain_new_name, is_active):
        """Check if modification required"""

        if (self.module.params['state'] == 'present') and pd_details and \
                (network_limits is not None or rf_cache_limits is not None
                 or protection_domain_new_name is not None or is_active is
                 not None):
            return True

    def modify_nw_limits(self, protection_domain_id, nw_modify_dict,
                         create_flag=False):
        """
        Modify Protection domain attributes
        :param protection_domain_id: ID of the protection domain
        :type protection_domain_id: str
        :param nw_modify_dict: Dictionary containing the attributes of
                               protection domain which are to be updated
        :type nw_modify_dict: dict
        :param create_flag: Flag to indicate whether modify operation is
                            followed by create operation or not
        :type create_flag: bool
        :return: Boolean indicating if the operation is successful
        """
        try:
            msg = "Dict containing network modify params {0}".\
                format(str(nw_modify_dict))
            LOG.info(msg)
            if 'rebuild_limit' in nw_modify_dict or 'rebalance_limit' in \
                    nw_modify_dict or 'vtree_migration_limit' in \
                    nw_modify_dict or 'overall_limit' in nw_modify_dict:
                self.powerflex_conn.protection_domain.network_limits(
                    protection_domain_id=protection_domain_id,
                    rebuild_limit=nw_modify_dict['rebuild_limit'],
                    rebalance_limit=nw_modify_dict['rebalance_limit'],
                    vtree_migration_limit=nw_modify_dict['vtree_migration_limit'],
                    overall_limit=nw_modify_dict['overall_limit'])
                msg = "The Network limits are updated to {0}, {1}, {2}, " \
                      "{3} successfully.". \
                    format(nw_modify_dict['rebuild_limit'],
                           nw_modify_dict['rebalance_limit'],
                           nw_modify_dict['vtree_migration_limit'],
                           nw_modify_dict['overall_limit'])
                LOG.info(msg)
            return True

        except Exception as e:
            if create_flag:
                err_msg = "Create protection domain is successful," \
                          " but failed to update the network limits" \
                          " {0} with error {1}".format(protection_domain_id,
                                                       str(e))
            else:
                err_msg = "Failed to update the network limits of " \
                          "protection domain {0} with error {1}".\
                    format(protection_domain_id, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def modify_rf_limits(self, protection_domain_id, rf_modify_dict,
                         create_flag):
        """
        Modify Protection domain attributes
        :param protection_domain_id: ID of the protection domain
        :type protection_domain_id: str
        :param rf_modify_dict: Dict containing the attributes of rf cache
                               which are to be updated
        :type rf_modify_dict: dict
        :param create_flag: Flag to indicate whether modify operation is
                            followed by create operation or not
        :type create_flag: bool
        :return: Boolean indicating if the operation is successful
        """
        try:
            msg = "Dict containing network modify params {0}". \
                format(str(rf_modify_dict))
            LOG.info(msg)

            if 'is_enabled' in rf_modify_dict and \
                    rf_modify_dict['is_enabled'] is not None:
                self.powerflex_conn.protection_domain.set_rfcache_enabled(
                    protection_domain_id, rf_modify_dict['is_enabled'])
                msg = "The RFcache is enabled to '%s' successfully." \
                      % rf_modify_dict['is_enabled']
                LOG.info(msg)

            if 'page_size' in rf_modify_dict or 'max_io_limit' in \
                    rf_modify_dict or 'pass_through_mode' in rf_modify_dict:
                self.powerflex_conn.protection_domain.rfcache_parameters(
                    protection_domain_id=protection_domain_id,
                    page_size=rf_modify_dict['page_size'],
                    max_io_limit=rf_modify_dict['max_io_limit'],
                    pass_through_mode=rf_modify_dict['pass_through_mode'])
                msg = "The RFcache parameters are updated to {0}, {1},{2}.'" \
                    .format(rf_modify_dict['page_size'],
                            rf_modify_dict['max_io_limit'],
                            rf_modify_dict['pass_through_mode'])
                LOG.info(msg)
            return True

        except Exception as e:
            if create_flag:
                err_msg = "Create protection domain is successful," \
                          " but failed to update the rf cache limits" \
                          " {0} with error {1}".format(protection_domain_id,
                                                       str(e))
            else:
                err_msg = "Failed to update the rf cache limits of " \
                          "protection domain {0} with error {1}". \
                    format(protection_domain_id, str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def modify_pd_attributes(self, protection_domain_id, modify_dict,
                             create_flag=False):
        """
        Modify Protection domain attributes
        :param protection_domain_id: ID of the protection domain
        :type protection_domain_id: str
        :param modify_dict: Dictionary containing the attributes of
                            protection domain which are to be updated
        :type modify_dict: dict
        :param create_flag: Flag to indicate whether modify operation is
                            followed by create operation or not
        :type create_flag: bool
        :return: Boolean indicating if the operation is successful
        """
        try:
            msg = "Dictionary containing attributes which need to be" \
                  " updated are '%s'." % (str(modify_dict))
            LOG.info(msg)

            if 'protection_domain_new_name' in modify_dict:
                self.powerflex_conn.protection_domain. \
                    rename(protection_domain_id,
                           modify_dict['protection_domain_new_name'])
                msg = "The name of the protection domain is updated to " \
                      "'%s' successfully." % \
                      modify_dict['protection_domain_new_name']
                LOG.info(msg)

            if 'is_active' in modify_dict and modify_dict['is_active']:
                self.powerflex_conn.protection_domain. \
                    activate(protection_domain_id, modify_dict['is_active'])
                msg = "The protection domain is activated successfully, by " \
                      "setting as is_active: '%s' " % \
                      modify_dict['is_active']
                LOG.info(msg)

            if 'is_active' in modify_dict and not modify_dict['is_active']:
                self.powerflex_conn.protection_domain. \
                    inactivate(protection_domain_id, modify_dict['is_active'])
                msg = "The protection domain is inactivated successfully, " \
                      "by setting as is_active: '%s' " % \
                      modify_dict['is_active']
                LOG.info(msg)
            return True

        except Exception as e:
            if create_flag:
                err_msg = "Create protection domain is successful," \
                          " but failed to update the protection domain" \
                          " {0} with error {1}".format(protection_domain_id,
                                                       str(e))
            else:
                err_msg = "Failed to update the protection domain {0}" \
                          " with error {1}".format(protection_domain_id,
                                                   str(e))
            LOG.error(err_msg)
            self.module.fail_json(msg=err_msg)

    def delete_protection_domain(self, protection_domain_id):
        """
        Delete Protection Domain
        :param protection_domain_id: ID of the protection domain
        :type protection_domain_id: str
        :return: Boolean indicating if delete operation is successful
        """
        try:
            self.powerflex_conn.protection_domain.delete(protection_domain_id)
            LOG.info("Protection domain deleted successfully.")
            return True
        except Exception as e:
            error_msg = "Delete protection domain '%s' operation failed" \
                        " with error '%s'" % (protection_domain_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on protection domain based on parameters
        passed in the playbook
        """
        protection_domain_name = self.module.params['protection_domain_name']
        protection_domain_id = self.module.params['protection_domain_id']
        protection_domain_new_name = self.module.params[
            'protection_domain_new_name']
        is_active = self.module.params['is_active']
        network_limits = self.convert_limits_in_kbps(
            self.module.params['network_limits'])
        rf_cache_limits = self.module.params['rf_cache_limits']
        state = self.module.params['state']

        # result is a dictionary to contain end state and protection domain
        # details
        changed = False
        result = dict(
            changed=False,
            protection_domain_details=None
        )

        # Checking invalid value for id, name and rename
        self.validate_input_params()

        # get Protection Domain details
        pd_details = self.get_protection_domain(protection_domain_name,
                                                protection_domain_id)

        if pd_details:
            protection_domain_id = pd_details['id']
            msg = "Fetched the protection domain details with id '%s', name" \
                  " '%s'" % (protection_domain_id, protection_domain_name)
            LOG.info(msg)

        # create operation
        create_changed = False
        create_changed, pd_details = self.\
            perform_create_operation(state, pd_details,
                                     protection_domain_name)

        # checking if basic protection domain parameters are modified or not
        modify_dict = {}
        nw_modify_dict = {}
        rf_modify_dict = {}

        if self.is_modify_required(pd_details, network_limits,
                                   rf_cache_limits,
                                   protection_domain_new_name, is_active):
            modify_dict = to_modify(pd_details, protection_domain_new_name,
                                    is_active)
            nw_modify_dict = to_nw_limit_modify(pd_details, network_limits)
            rf_modify_dict = to_rf_limit_modify(pd_details, rf_cache_limits)
            msg = "Parameters to be modified are as follows: %s %s, %s" \
                  % (str(modify_dict), str(nw_modify_dict),
                     str(rf_modify_dict))
            LOG.info(msg)

        # modify operation
        modify_changed = False
        is_nw_limit = all(value is None for value in nw_modify_dict.values())
        is_rf_limit = all(value is None for value in rf_modify_dict.values())

        if not is_nw_limit and state == 'present':
            modify_changed = self.modify_nw_limits(pd_details['id'],
                                                   nw_modify_dict,
                                                   create_changed)
        if not is_rf_limit and state == 'present':
            modify_changed = self.modify_rf_limits(pd_details['id'],
                                                   rf_modify_dict,
                                                   create_changed)
        if modify_dict and state == 'present':
            modify_changed = self. \
                modify_pd_attributes(pd_details['id'], modify_dict,
                                     create_changed)
        if modify_changed:
            pd_details = self.get_protection_domain(
                protection_domain_id=pd_details['id'])
            msg = "Protection domain details after modification:" \
                  " '%s'" % str(pd_details)
            LOG.info(msg)

        # delete operation
        delete_changed = False
        if state == 'absent' and pd_details:
            delete_changed = self.\
                delete_protection_domain(pd_details['id'])

        if create_changed or modify_changed or delete_changed:
            changed = True

        # Returning the updated Protection domain details
        if state == 'present':
            pd_details = self.get_protection_domain(
                protection_domain_id=pd_details['id'])
            result['protection_domain_details'] = pd_details
        result['changed'] = changed
        self.module.exit_json(**result)

    def convert_limits_in_kbps(self, network_limits):
        """
        Convert the limits into KBps

        :param network_limits: dict containing all Network bandwidth limits
        :rtype: converted network limits
        """
        limit_params = ['rebuild_limit', 'rebalance_limit',
                        'vtree_migration_limit', 'overall_limit']
        modified_limits = dict()
        modified_limits['rebuild_limit'] = None
        modified_limits['rebalance_limit'] = None
        modified_limits['vtree_migration_limit'] = None
        modified_limits['overall_limit'] = None
        if network_limits is None:
            return None
        for limits in network_limits:
            if network_limits[limits] is not None and limits in limit_params:
                if network_limits['bandwidth_unit'] == "GBps":
                    modified_limits[limits] = \
                        network_limits[limits] * 1024 * 1024
                elif network_limits['bandwidth_unit'] == "MBps":
                    modified_limits[limits] = network_limits[limits] * 1024
                else:
                    modified_limits[limits] = network_limits[limits]

        return modified_limits


def to_modify(pd_details, protection_domain_new_name, is_active):
    """
    Check if modification required for rename and is_active for protection
    domain
    :param pd_details: Details of the protection domain
    :type pd_details: dict
    :param protection_domain_new_name: To rename protection domain
    :type protection_domain_new_name: str
    :param is_active: Whether to activate protection domain
    :type is_active: bool
    :return: Dictionary containing the attributes of protection domain
             which are to be updated
    :rtype: dict
    """

    modify_dict = dict()
    if protection_domain_new_name is not None and \
            protection_domain_new_name != pd_details['name']:
        modify_dict['protection_domain_new_name'] = \
            protection_domain_new_name

    if is_active is not None and \
            ((pd_details['protectionDomainState'] == 'Active' and
              not is_active) or
             (pd_details['protectionDomainState'] == 'Inactive' and
              is_active)):
        modify_dict['is_active'] = is_active

    return modify_dict


def to_nw_limit_modify(pd_details, network_limits):
    """
    Check if modification required network bandwidth limit for protection
    domain
    :param pd_details: Details of the protection domain
    :type pd_details: dict
    :param network_limits: dict of Network bandwidth limit
    :type network_limits: dict
    :return: Dictionary containing the attributes of protection domain
             which are to be updated
    :rtype: dict
    """

    modify_dict = {}
    if network_limits is not None:
        modify_dict['rebuild_limit'] = None
        modify_dict['rebalance_limit'] = None
        modify_dict['vtree_migration_limit'] = None
        modify_dict['overall_limit'] = None

        if network_limits['rebuild_limit'] is not None and \
                pd_details['rebuildNetworkThrottlingInKbps'] != network_limits['rebuild_limit']:
            modify_dict['rebuild_limit'] = network_limits['rebuild_limit']

        if network_limits['rebalance_limit'] is not None and \
                pd_details['rebalanceNetworkThrottlingInKbps'] \
                != network_limits['rebalance_limit']:
            modify_dict['rebalance_limit'] = network_limits['rebalance_limit']

        if network_limits['vtree_migration_limit'] is not None and \
                pd_details['vtreeMigrationNetworkThrottlingInKbps'] != \
                network_limits['vtree_migration_limit']:
            modify_dict['vtree_migration_limit'] = network_limits['vtree_migration_limit']

        if network_limits['overall_limit'] is not None and \
                pd_details['overallIoNetworkThrottlingInKbps'] != \
                network_limits['overall_limit']:
            modify_dict['overall_limit'] = network_limits['overall_limit']

    return modify_dict


def to_rf_limit_modify(pd_details, rf_cache_limits):
    """
    Check if modification required for RF cache for protection domain
    :param pd_details: Details of the protection domain
    :type pd_details: dict
    :param rf_cache_limits: dict for RF cache
    :type rf_cache_limits: dict
    :return: Dictionary containing the attributes of protection domain
             which are to be updated
    :rtype: dict
    """
    modify_dict = {}
    if rf_cache_limits is not None:
        modify_dict['is_enabled'] = None
        modify_dict['page_size'] = None
        modify_dict['max_io_limit'] = None
        modify_dict['pass_through_mode'] = None

        if rf_cache_limits['is_enabled'] is not None and pd_details['rfcacheEnabled'] != \
                rf_cache_limits['is_enabled']:
            modify_dict['is_enabled'] = rf_cache_limits['is_enabled']

        if rf_cache_limits['page_size'] is not None and pd_details['rfcachePageSizeKb'] != \
                rf_cache_limits['page_size']:
            modify_dict['page_size'] = rf_cache_limits['page_size']

        if rf_cache_limits['max_io_limit'] is not None and pd_details['rfcacheMaxIoSizeKb'] != \
                rf_cache_limits['max_io_limit']:
            modify_dict['max_io_limit'] = rf_cache_limits['max_io_limit']

        if rf_cache_limits['pass_through_mode'] is not None and \
                pd_details['rfcacheOpertionalMode'] != rf_cache_limits['pass_through_mode']:
            modify_dict['pass_through_mode'] = rf_cache_limits['pass_through_mode']

    return modify_dict


def get_powerflex_protection_domain_parameters():
    """This method provides parameters required for the protection domain
    module on PowerFlex"""
    return dict(
        protection_domain_name=dict(),
        protection_domain_new_name=dict(),
        protection_domain_id=dict(),
        is_active=dict(type='bool'),
        network_limits=dict(
            type='dict', options=dict(
                rebuild_limit=dict(type='int'),
                rebalance_limit=dict(type='int'),
                vtree_migration_limit=dict(type='int'),
                overall_limit=dict(type='int'),
                bandwidth_unit=dict(choices=['KBps', 'MBps', 'GBps'],
                                    default='KBps')
            )
        ),
        rf_cache_limits=dict(
            type='dict', options=dict(
                is_enabled=dict(type='bool'),
                page_size=dict(type='int'),
                max_io_limit=dict(type='int'),
                pass_through_mode=dict(choices=['None', 'Read', 'Write',
                                                'ReadAndWrite', 'WriteMiss'])
            )
        ),
        state=dict(required=True, type='str', choices=['present', 'absent'])
    )


def main():
    """ Create PowerFlex protection domain object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexProtectionDomain()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
