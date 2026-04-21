#!/usr/bin/python

# Copyright: (c) 2021, Dell Technologies
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Ansible module for managing device on Dell Technologies (Dell) PowerFlex"""

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = r'''
module: device
version_added: '1.1.0'
short_description: Manage device on Dell PowerFlex
description:
- Managing device on PowerFlex storage system includes
  adding new device, getting details of device, and removing a device.
author:
- Rajshree Khare (@khareRajshree) <ansible.team@dell.com>
extends_documentation_fragment:
  - dellemc.powerflex.powerflex
options:
  current_pathname:
    description:
    - Full path of the device to be added.
    - Required while adding a device.
    type: str
  device_name:
    description:
    - Device name.
    - Mutually exclusive with I(device_id).
    type: str
  device_id:
    description:
    - Device ID.
    - Mutually exclusive with I(device_name).
    type: str
  sds_name:
    description:
    - The name of the SDS.
    - Required while adding a device.
    - Mutually exclusive with I(sds_id).
    type: str
  sds_id:
    description:
    - The ID of the SDS.
    - Required while adding a device.
    - Mutually exclusive with I(sds_name).
    type: str
  storage_pool_name:
    description:
    - Storage Pool name.
    - Used while adding a storage device.
    - Mutually exclusive with I(storage_pool_id), I(acceleration_pool_id) and
      I(acceleration_pool_name).
    type: str
  storage_pool_id:
    description:
    - Storage Pool ID.
    - Used while adding a storage device.
    - Media type supported are C(SSD) and C(HDD).
    - Mutually exclusive with I(storage_pool_name), I(acceleration_pool_id) and
      I(acceleration_pool_name).
    type: str
  acceleration_pool_name:
    description:
    - Acceleration Pool Name.
    - Used while adding an acceleration device.
    - Media type supported are C(SSD) and C(NVDIMM).
    - Mutually exclusive with I(storage_pool_id), I(storage_pool_name) and
      I(acceleration_pool_name).
    type: str
  acceleration_pool_id:
    description:
    - Acceleration Pool ID.
    - Used while adding an acceleration device.
    - Media type supported are C(SSD) and C(NVDIMM).
    - Mutually exclusive with I(acceleration_pool_name), I(storage_pool_name) and
      I(storage_pool_id).
    type: str
  protection_domain_name:
    description:
    - Protection domain name.
    - Used while identifying a storage pool along with I(storage_pool_name).
    - Mutually exclusive with I(protection_domain_id).
    type: str
  protection_domain_id:
    description:
    - Protection domain ID.
    - Used while identifying a storage pool along with I(storage_pool_name).
    - Mutually exclusive with I(protection_domain_name).
    type: str
  external_acceleration_type:
    description:
    - Device external acceleration types.
    - Used while adding a device.
    type: str
    choices: ['Invalid', 'None', 'Read', 'Write', 'ReadAndWrite']
  media_type:
    description:
    - Device media types.
    - Required while adding a device.
    type: str
    choices: ['HDD', 'SSD', 'NVDIMM']
  state:
    description:
    - State of the device.
    choices: ['present', 'absent']
    required: true
    type: str
  force:
    description:
    - Using the Force flag to add a device.
    - Use this flag, to overwrite existing data on the device.
    - Use this flag with caution, because all data on the device will be
      destroyed.
    type: bool
    default: false
notes:
  - The value for device_id is generated only after successful addition of the
    device.
  - To uniquely identify a device, either I(device_id) can be passed or one of
    I(current_pathname) or I(device_name) must be passed with I(sds_id) or I(sds_name).
  - It is recommended to install Rfcache driver for SSD device on SDS in
    order to add it to an acceleration pool.
  - The I(check_mode) is not supported.
'''

EXAMPLES = r'''
- name: Add a device
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    current_pathname: "/dev/sdb"
    sds_name: "node1"
    media_type: "HDD"
    device_name: "device2"
    storage_pool_name: "pool1"
    protection_domain_name: "domain1"
    external_acceleration_type: "ReadAndWrite"
    state: "present"
- name: Add a device with force flag
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    current_pathname: "/dev/sdb"
    sds_name: "node1"
    media_type: "HDD"
    device_name: "device2"
    storage_pool_name: "pool1"
    protection_domain_name: "domain1"
    external_acceleration_type: "ReadAndWrite"
    force: true
    state: "present"
- name: Get device details using device_id
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    device_id: "d7fe088900000000"
    state: "present"
- name: Get device details using (current_pathname, sds_name)
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    current_pathname: "/dev/sdb"
    sds_name: "node0"
    state: "present"
- name: Get device details using (current_pathname, sds_id)
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    current_pathname: "/dev/sdb"
    sds_id: "5717d71800000000"
    state: "present"
- name: Remove a device using device_id
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    device_id: "76eb7e2f00010000"
    state: "absent"
- name: Remove a device using (current_pathname, sds_id)
  dellemc.powerflex.device:
    hostname: "{{hostname}}"
    username: "{{username}}"
    password: "{{password}}"
    validate_certs: "{{validate_certs}}"
    port: "{{port}}"
    current_pathname: "/dev/sdb"
    sds_name: "node1"
    state: "absent"
'''

RETURN = r'''
changed:
    description: Whether or not the resource has changed.
    returned: always
    type: bool
    sample: 'false'
device_details:
    description: Details of the device.
    returned: When device exists
    type: dict
    contains:
        accelerationPoolId:
            description: Acceleration pool ID.
            type: str
        accelerationPoolName:
            description: Acceleration pool name.
            type: str
        accelerationProps:
            description: Indicates acceleration props.
            type: str
        aggregatedState:
            description: Indicates aggregated state.
            type: str
        ataSecurityActive:
            description: Indicates ATA security active state.
            type: bool
        autoDetectMediaType:
            description: Indicates auto detection of media type.
            type: str
        cacheLookAheadActive:
            description: Indicates cache look ahead active state.
            type: bool
        capacity:
            description: Device capacity.
            type: int
        capacityLimitInKb:
            description: Device capacity limit in KB.
            type: int
        deviceCurrentPathName:
            description: Device current path name.
            type: str
        deviceOriginalPathName:
            description: Device original path name.
            type: str
        deviceState:
            description: Indicates device state.
            type: str
        deviceType:
            description: Indicates device type.
            type: str
        errorState:
            description: Indicates error state.
            type: str
        externalAccelerationType:
            description: Indicates external acceleration type.
            type: str
        fglNvdimmMetadataAmortizationX100:
            description: Indicates FGL NVDIMM meta data amortization value.
            type: int
        fglNvdimmWriteCacheSize:
            description: Indicates FGL NVDIMM write cache size.
            type: int
        firmwareVersion:
            description: Indicates firmware version.
            type: str
        id:
            description: Device ID.
            type: str
        ledSetting:
            description: Indicates LED setting.
            type: str
        links:
            description: Device links.
            type: list
            contains:
                href:
                    description: Device instance URL.
                    type: str
                rel:
                    description: Relationship of device with different
                                 entities.
                    type: str
        logicalSectorSizeInBytes:
            description: Logical sector size in bytes.
            type: int
        longSuccessfulIos:
            description: Indicates long successful IOs.
            type: list
        maxCapacityInKb:
            description: Maximum device capacity limit in KB.
            type: int
        mediaFailing:
            description: Indicates media failing.
            type: bool
        mediaType:
            description: Indicates media type.
            type: str
        modelName:
            description: Indicates model name.
            type: str
        name:
            description: Device name.
            type: str
        persistentChecksumState:
            description: Indicates persistent checksum state.
            type: str
        physicalSectorSizeInBytes:
            description: Physical sector size in bytes.
            type: int
        protectionDomainId:
            description: Protection domain ID.
            type: str
        protectionDomainName:
            description: Protection domain name.
            type: str
        raidControllerSerialNumber:
            description: RAID controller serial number.
            type: str
        rfcacheErrorDeviceDoesNotExist:
            description: Indicates RF cache error device does not exist.
            type: bool
        rfcacheProps:
            description: RF cache props.
            type: str
        sdsId:
            description: SDS ID.
            type: str
        sdsName:
            description: SDS name.
            type: str
        serialNumber:
            description: Indicates Serial number.
            type: str
        spSdsId:
            description: Indicates SPs SDS ID.
            type: str
        ssdEndOfLifeState:
            description: Indicates SSD end of life state.
            type: str
        storagePoolId:
            description: Storage Pool ID.
            type: str
        storagePoolName:
            description: Storage Pool name.
            type: str
        storageProps:
            description: Storage props.
            type: list
        temperatureState:
            description: Indicates temperature state.
            type: str
        vendorName:
            description: Indicates vendor name.
            type: str
        writeCacheActive:
            description: Indicates write cache active.
            type: bool
    sample: {
        "accelerationPoolId": null,
        "accelerationProps": null,
        "aggregatedState": "NeverFailed",
        "ataSecurityActive": false,
        "autoDetectMediaType": "SSD",
        "cacheLookAheadActive": false,
        "capacity": 0,
        "capacityLimitInKb": 365772800,
        "deviceCurrentPathName": "/dev/sdb",
        "deviceOriginalPathName": "/dev/sdb",
        "deviceState": "Normal",
        "deviceType": "Unknown",
        "errorState": "None",
        "externalAccelerationType": "None",
        "fglNvdimmMetadataAmortizationX100": 150,
        "fglNvdimmWriteCacheSize": 16,
        "firmwareVersion": null,
        "id": "b6efa59900000000",
        "ledSetting": "Off",
        "links": [
            {
                "href": "/api/instances/Device::b6efa59900000000",
                "rel": "self"
            },
            {
                "href": "/api/instances/Device::b6efa59900000000/relationships
                        /Statistics",
                "rel": "/api/Device/relationship/Statistics"
            },
            {
                "href": "/api/instances/Sds::8f3bb0ce00000000",
                "rel": "/api/parent/relationship/sdsId"
            },
            {
                "href": "/api/instances/StoragePool::e0d8f6c900000000",
                "rel": "/api/parent/relationship/storagePoolId"
            },
            {
                "href": "/api/instances/SpSds::fedf6f2000000000",
                "rel": "/api/parent/relationship/spSdsId"
            }
        ],
        "logicalSectorSizeInBytes": 0,
        "longSuccessfulIos": {
            "longWindow": null,
            "mediumWindow": null,
            "shortWindow": null
        },
        "maxCapacityInKb": 365772800,
        "mediaFailing": false,
        "mediaType": "HDD",
        "modelName": null,
        "name": "device230",
        "persistentChecksumState": "Protected",
        "physicalSectorSizeInBytes": 0,
        "protectionDomainId": "9300c1f900000000",
        "protectionDomainName": "domain1",
        "raidControllerSerialNumber": null,
        "rfcacheErrorDeviceDoesNotExist": false,
        "rfcacheProps": null,
        "sdsId": "8f3bb0ce00000000",
        "sdsName": "node1",
        "serialNumber": null,
        "slotNumber": null,
        "spSdsId": "fedf6f2000000000",
        "ssdEndOfLifeState": "NeverFailed",
        "storagePoolId": "e0d8f6c900000000",
        "storagePoolName": "pool1",
        "storageProps": {
            "destFglAccDeviceId": null,
            "destFglNvdimmSizeMb": 0,
            "fglAccDeviceId": null,
            "fglNvdimmSizeMb": 0
        },
        "temperatureState": "NeverFailed",
        "vendorName": null,
        "writeCacheActive": false
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.powerflex.plugins.module_utils.storage.dell\
    import utils

LOG = utils.get_logger('device')


class PowerFlexDevice(object):
    """Class with device operations"""

    def __init__(self):
        """ Define all parameters required by this module"""
        self.module_params = utils.get_powerflex_gateway_host_parameters()
        self.module_params.update(get_powerflex_device_parameters())

        mut_ex_args = [['sds_name', 'sds_id'],
                       ['device_name', 'device_id'],
                       ['protection_domain_name',
                        'protection_domain_id'],
                       ['storage_pool_name', 'storage_pool_id'],
                       ['acceleration_pool_name', 'acceleration_pool_id'],
                       ['acceleration_pool_id', 'storage_pool_id'],
                       ['acceleration_pool_name', 'storage_pool_name'],
                       ['device_id', 'sds_name'],
                       ['device_id', 'sds_id'],
                       ['device_id', 'current_pathname']]

        # initialize the Ansible module
        self.module = AnsibleModule(
            argument_spec=self.module_params,
            supports_check_mode=False,
            mutually_exclusive=mut_ex_args)

        utils.ensure_required_libs(self.module)

        try:
            self.powerflex_conn = utils.get_powerflex_gateway_host_connection(
                self.module.params)
            LOG.info("Got the PowerFlex system connection object instance")
        except Exception as e:
            LOG.error(str(e))
            self.module.fail_json(msg=str(e))

    def get_device_details(self, current_pathname=None, sds_id=None,
                           device_name=None, device_id=None):
        """Get device details
            :param current_pathname: Device path name
            :type current_pathname: str
            :param sds_id: ID of the SDS
            :type sds_id: str
            :param device_name: Name of the device
            :type device_name: str
            :param device_id: ID of the device
            :type device_id: str
            :return: Details of device if it exist
            :rtype: dict
        """

        try:
            if current_pathname and sds_id:
                device_details = self.powerflex_conn.device.get(
                    filter_fields={'deviceCurrentPathName': current_pathname,
                                   'sdsId': sds_id})
            elif device_name and sds_id:
                device_details = self.powerflex_conn.device.get(
                    filter_fields={'name': device_name,
                                   'sdsId': sds_id})
            else:
                device_details = self.powerflex_conn.device.get(
                    filter_fields={'id': device_id})

            if len(device_details) == 0:
                msg = "Device not found"
                LOG.info(msg)
                return None

            return device_details[0]

        except Exception as e:
            error_msg = "Failed to get the device with error '%s'" % str(e)
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_sds(self, sds_name=None, sds_id=None):
        """Get SDS details
            :param sds_name: Name of the SDS
            :param sds_id: ID of the SDS
            :return: SDS details
            :rtype: dict
        """
        name_or_id = sds_id if sds_id else sds_name
        try:
            sds_details = None
            if sds_id:
                sds_details = self.powerflex_conn.sds.get(
                    filter_fields={'id': sds_id})

            if sds_name:
                sds_details = self.powerflex_conn.sds.get(
                    filter_fields={'name': sds_name})

            if not sds_details:
                error_msg = "Unable to find the SDS with '%s'. Please " \
                            "enter a valid SDS name/id." % name_or_id
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            return sds_details[0]

        except Exception as e:
            error_msg = "Failed to get the SDS '%s' with error '%s'" \
                        % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_protection_domain(self, protection_domain_name=None,
                              protection_domain_id=None):
        """Get protection domain details
            :param protection_domain_name: Name of the protection domain
            :param protection_domain_id: ID of the protection domain
            :return: Protection domain details
            :rtype: dict
        """
        name_or_id = protection_domain_id if protection_domain_id \
            else protection_domain_name
        try:
            pd_details = None
            if protection_domain_id:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={'id': protection_domain_id})

            if protection_domain_name:
                pd_details = self.powerflex_conn.protection_domain.get(
                    filter_fields={'name': protection_domain_name})

            if not pd_details:
                error_msg = "Unable to find the protection domain with " \
                            "'%s'. Please enter a valid protection domain " \
                            "name/id." % name_or_id
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            return pd_details[0]

        except Exception as e:
            error_msg = "Failed to get the protection domain '%s' with " \
                        "error '%s'" % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_storage_pool(self, storage_pool_name=None,
                         storage_pool_id=None,
                         protection_domain_id=None):
        """Get storage pool details
            :param storage_pool_name: Name of the storage pool
            :param storage_pool_id: ID of the storage pool
            :param protection_domain_id: ID of the protection domain
            :return: Storage pool details
            :rtype: dict
        """
        name_or_id = storage_pool_id if storage_pool_id else storage_pool_name
        try:
            storage_pool_details = None
            if storage_pool_id:
                storage_pool_details = self.powerflex_conn.storage_pool.get(
                    filter_fields={'id': storage_pool_id})

            if storage_pool_name:
                storage_pool_details = self.powerflex_conn.storage_pool.get(
                    filter_fields={'name': storage_pool_name,
                                   'protectionDomainId': protection_domain_id}
                )

            if not storage_pool_details:
                error_msg = "Unable to find the storage pool with " \
                            "'%s'. Please enter a valid storage pool " \
                            "name/id." % name_or_id
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            return storage_pool_details[0]

        except Exception as e:
            error_msg = "Failed to get the storage_pool '%s' with " \
                        "error '%s'" % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_acceleration_pool(self, acceleration_pool_name=None,
                              acceleration_pool_id=None,
                              protection_domain_id=None):
        """Get acceleration pool details
            :param acceleration_pool_name: Name of the acceleration pool
            :param acceleration_pool_id: ID of the acceleration pool
            :param protection_domain_id: ID of the protection domain
            :return: Acceleration pool details
            :rtype: dict
        """
        name_or_id = acceleration_pool_id \
            if acceleration_pool_id else acceleration_pool_name
        try:
            acceleration_pool_details = None
            if acceleration_pool_id:
                acceleration_pool_details = self.powerflex_conn.\
                    acceleration_pool.get(filter_fields={
                        'id': acceleration_pool_id})

            if acceleration_pool_name:
                acceleration_pool_details = self.powerflex_conn.\
                    acceleration_pool.get(filter_fields={
                        'name': acceleration_pool_name,
                        'protectionDomainId': protection_domain_id})

            if not acceleration_pool_details:
                error_msg = "Unable to find the acceleration pool with " \
                            "'%s'. Please enter a valid acceleration pool " \
                            "name/id." % name_or_id
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            return acceleration_pool_details[0]

        except Exception as e:
            error_msg = "Failed to get the acceleration pool '%s' with " \
                        "error '%s'" % (name_or_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def add_device(self, device_name, current_pathname, sds_id,
                   storage_pool_id, media_type, acceleration_pool_id,
                   external_acceleration_type):
        """Add device
            :param device_name: Device name
            :type device_name: str
            :param current_pathname: Current pathname of device
            :type current_pathname: str
            :param sds_id: SDS ID
            :type sds_id: str
            :param storage_pool_id: Storage Pool ID
            :type storage_pool_id: str
            :param media_type: Media type of device
            :type media_type: str
            :param acceleration_pool_id: Acceleration pool ID
            :type acceleration_pool_id: str
            :param external_acceleration_type: External acceleration type
            :type external_acceleration_type: str
            return: Boolean indicating if add device operation is successful
        """
        try:
            if device_name is None or len(device_name.strip()) == 0:
                error_msg = "Please provide valid device_name value for " \
                            "adding a device."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            if current_pathname is None or len(current_pathname.strip()) == 0:
                error_msg = "Current pathname of device is a mandatory " \
                            "parameter for adding a device. Please enter a " \
                            "valid value."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            if sds_id is None or len(sds_id.strip()) == 0:
                error_msg = "Please provide valid sds_id value " \
                            "for adding a device."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            if storage_pool_id is None and acceleration_pool_id is None:
                error_msg = "Please provide either storage pool name/ID " \
                            "or acceleration pool name/ID for adding a " \
                            "device."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)

            add_params = ("current_pathname: %s, "
                          "sds_id: %s, "
                          "acceleration_pool_id: %s,"
                          "external_acceleration_type: %s,"
                          "media_type: %s,"
                          "device_name: %s,"
                          "storage_pool_id: %s,"
                          % (current_pathname, sds_id,
                             acceleration_pool_id,
                             external_acceleration_type,
                             media_type,
                             device_name,
                             storage_pool_id))
            LOG.info("Adding device with params: %s", add_params)

            self.powerflex_conn.device.create(
                current_pathname=current_pathname,
                sds_id=sds_id, acceleration_pool_id=acceleration_pool_id,
                external_acceleration_type=external_acceleration_type,
                media_type=media_type, name=device_name,
                storage_pool_id=storage_pool_id,
                force=self.module.params['force'])
            return True
        except Exception as e:
            error_msg = "Adding device %s operation failed with " \
                        "error '%s'" % (device_name, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def remove_device(self, device_id):
        """Remove device
            :param device_id: Device ID
            :type device_id: str
            return: Boolean indicating if remove device operation is
                    successful
        """
        try:
            LOG.info("Device to be removed: %s", device_id)
            self.powerflex_conn.device.delete(device_id=device_id)
            return True
        except Exception as e:
            error_msg = "Remove device '%s' operation failed with " \
                        "error '%s'" % (device_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_input_parameters(self, device_name=None, device_id=None,
                                  current_pathname=None, sds_name=None,
                                  sds_id=None):
        """Validate the input parameters"""

        # Unique ways to identify a device:
        # (current_pathname , sds_id)
        # (current_pathname , sds_name)
        # (device_name , sds_name)
        # (device_name , sds_id)
        # device_id.

        self.validate_current_pathname(current_pathname, sds_name, sds_id)

        self.validate_device_name(device_name, sds_name, sds_id)

        self.validate_sds_name(device_name, current_pathname, sds_name)

        self.validate_sds_id(device_name, current_pathname, sds_id)

        if device_id is not None and len(device_id.strip()) == 0:
            error_msg = "Please provide valid device_id value to identify " \
                        "a device."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

        if current_pathname is None and device_name is None \
                and device_id is None:
            error_msg = "Please specify a valid parameter combination to " \
                        "identify a device."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_sds_id(self, device_name, current_pathname, sds_id):
        if sds_id:
            if (current_pathname is None
                or len(current_pathname.strip()) == 0) \
                    and (device_name is None
                         or len(device_name.strip()) == 0):
                error_msg = "current_pathname or device_name is mandatory " \
                            "along with sds_id. Please enter a valid value."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        elif sds_id is not None and len(sds_id.strip()) == 0:
            error_msg = "Please enter a valid value for sds_id."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_sds_name(self, device_name, current_pathname, sds_name):
        if sds_name:
            if (current_pathname is None
                or len(current_pathname.strip()) == 0) \
                    and (device_name is None
                         or len(device_name.strip()) == 0):
                error_msg = "current_pathname or device_name is mandatory " \
                            "along with sds_name. Please enter a valid value."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        elif sds_name is not None and len(sds_name.strip()) == 0:
            error_msg = "Please enter a valid value for sds_name."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_device_name(self, device_name, sds_name, sds_id):
        if device_name:
            if (sds_name is None or len(sds_name.strip()) == 0) \
                    and (sds_id is None or len(sds_id.strip()) == 0):
                error_msg = "sds_name or sds_id is mandatory along with " \
                            "device_name. Please enter a valid value."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        elif device_name is not None and len(device_name.strip()) == 0:
            error_msg = "Please enter a valid value for device_name."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_current_pathname(self, current_pathname, sds_name, sds_id):
        if current_pathname:
            if (sds_name is None or len(sds_name.strip()) == 0) \
                    and (sds_id is None or len(sds_id.strip()) == 0):
                error_msg = "sds_name or sds_id is mandatory along with " \
                            "current_pathname. Please enter a valid value."
                LOG.error(error_msg)
                self.module.fail_json(msg=error_msg)
        elif current_pathname is not None \
                and len(current_pathname.strip()) == 0:
            error_msg = "Please enter a valid value for current_pathname."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def validate_add_parameters(self, device_id=None,
                                external_acceleration_type=None,
                                storage_pool_id=None,
                                storage_pool_name=None,
                                acceleration_pool_id=None,
                                acceleration_pool_name=None):
        """Validate the add device parameters"""

        if device_id:
            error_msg = "Addition of device is allowed using " \
                        "device_name only, device_id given."
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)
        if external_acceleration_type and storage_pool_id is None \
                and storage_pool_name is None \
                and acceleration_pool_id is None \
                and acceleration_pool_name is None:
            error_msg = "Storage Pool ID/name or Acceleration Pool " \
                        "ID/name is mandatory along with " \
                        "external_acceleration_type."
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)

    def perform_module_operation(self):
        """
        Perform different actions on device based on parameters passed in
        the playbook
        """
        current_pathname = self.module.params['current_pathname']
        device_name = self.module.params['device_name']
        device_id = self.module.params['device_id']
        sds_name = self.module.params['sds_name']
        sds_id = self.module.params['sds_id']
        storage_pool_name = self.module.params['storage_pool_name']
        storage_pool_id = self.module.params['storage_pool_id']
        acceleration_pool_id = self.module.params['acceleration_pool_id']
        acceleration_pool_name = self.module.params['acceleration_pool_name']
        protection_domain_name = self.module.params['protection_domain_name']
        protection_domain_id = self.module.params['protection_domain_id']
        external_acceleration_type = self.module.params[
            'external_acceleration_type']
        media_type = self.module.params['media_type']
        state = self.module.params['state']

        # result is a dictionary to contain end state and device details
        result = dict(
            changed=False,
            device_details={}
        )

        # validate input parameters
        self.validate_input_parameters(device_name, device_id,
                                       current_pathname, sds_name, sds_id)

        # get SDS ID from name
        if sds_name:
            sds_id = self.get_sds_id(sds_name)

        # get device details
        device_details = self.get_device_details(current_pathname,
                                                 sds_id, device_name,
                                                 device_id)
        # Get device id
        if device_details:
            device_id = device_details['id']
        msg = "Fetched the device details %s" % (str(device_details))
        LOG.info(msg)

        # add operation
        add_changed = False
        if state == 'present':
            if device_details:
                # modify operation
                modify_dict = to_modify(device_details, media_type,
                                        external_acceleration_type)
                self.can_modify(modify_dict)
            else:
                # get Protection Domain ID from name
                # it is needed to uniquely identify a storage pool or acceleration
                # pool using name
                device_id, add_changed = self.create_device(
                    current_pathname, device_name, device_id, sds_id,
                    storage_pool_id, storage_pool_name, acceleration_pool_id,
                    acceleration_pool_name, protection_domain_id,
                    protection_domain_name, external_acceleration_type,
                    media_type)

            device_details = self.show_output(device_id)
            result['device_details'] = device_details

        # remove operation
        remove_changed = False
        if state == 'absent' and device_details:
            remove_changed = self.remove_device(device_id)

        # Returning the updated device details
        result['changed'] = add_changed or remove_changed
        self.module.exit_json(**result)

    def create_device(self, current_pathname, device_name, device_id, sds_id,
                      storage_pool_id, storage_pool_name, acceleration_pool_id,
                      acceleration_pool_name, protection_domain_id,
                      protection_domain_name, external_acceleration_type,
                      media_type):
        if protection_domain_name \
                and (storage_pool_name or acceleration_pool_name):
            protection_domain_id = self.get_protection_domain_id(
                protection_domain_name)

            # get storage pool ID from name
        if storage_pool_name:
            storage_pool_id = self.get_storage_pool_id(
                storage_pool_name, protection_domain_id)

            # get acceleration pool ID from name
        if acceleration_pool_name:
            acceleration_pool_id = self.get_acceleration_pool_id(
                acceleration_pool_name, protection_domain_id)

            # validate input parameters
        self.validate_add_parameters(device_id,
                                     external_acceleration_type,
                                     storage_pool_id,
                                     storage_pool_name,
                                     acceleration_pool_id,
                                     acceleration_pool_name)
        add_changed = self.add_device(device_name, current_pathname,
                                      sds_id, storage_pool_id, media_type,
                                      acceleration_pool_id,
                                      external_acceleration_type)
        if add_changed:
            device_details = self.get_device_details(
                device_name=device_name, sds_id=sds_id)
            device_id = device_details['id']
            msg = "Device created successfully, fetched device details " \
                "%s" % (str(device_details))
            LOG.info(msg)
        return device_id, add_changed

    def can_modify(self, modify_dict):
        if modify_dict:
            error_msg = "Modification of device attributes is " \
                "currently not supported by Ansible modules."
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)

    def get_acceleration_pool_id(self, acceleration_pool_name, protection_domain_id):
        if protection_domain_id:
            acceleration_pool_details = self.get_acceleration_pool(
                acceleration_pool_name=acceleration_pool_name,
                protection_domain_id=protection_domain_id)
            if acceleration_pool_details:
                acceleration_pool_id = acceleration_pool_details['id']
            msg = "Fetched the acceleration pool details with id " \
                "'%s', name '%s'" % (acceleration_pool_id,
                                     acceleration_pool_name)
            LOG.info(msg)
        else:
            error_msg = "Protection domain name/id is required to " \
                "uniquely identify a acceleration pool, " \
                "only acceleration_pool_name is given."
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)
        return acceleration_pool_id

    def get_storage_pool_id(self, storage_pool_name, protection_domain_id):
        if protection_domain_id:
            storage_pool_details = self.get_storage_pool(
                storage_pool_name=storage_pool_name,
                protection_domain_id=protection_domain_id)
            if storage_pool_details:
                storage_pool_id = storage_pool_details['id']
            msg = "Fetched the storage pool details with id '%s', " \
                "name '%s'" % (storage_pool_id, storage_pool_name)
            LOG.info(msg)
        else:
            error_msg = "Protection domain name/id is required to " \
                "uniquely identify a storage pool, only " \
                "storage_pool_name is given."
            LOG.info(error_msg)
            self.module.fail_json(msg=error_msg)
        return storage_pool_id

    def get_protection_domain_id(self, protection_domain_name):
        pd_details = self.get_protection_domain(
            protection_domain_name)
        if pd_details:
            protection_domain_id = pd_details['id']
        msg = "Fetched the protection domain details with id " \
            "'%s', name '%s'" % (protection_domain_id,
                                 protection_domain_name)
        LOG.info(msg)
        return protection_domain_id

    def get_sds_id(self, sds_name):
        sds_details = self.get_sds(sds_name)
        if sds_details:
            sds_id = sds_details['id']
        msg = "Fetched the SDS details with id '%s', name '%s'" \
            % (sds_id, sds_name)
        LOG.info(msg)
        return sds_id

    def show_output(self, device_id):
        """Show device details
            :param device_id: ID of the device
            :type device_id: str
            :return: Details of device
            :rtype: dict
        """

        try:
            device_details = self.powerflex_conn.device.get(
                filter_fields={'id': device_id})

            if len(device_details) == 0:
                msg = "Device with identifier '%s' not found" % device_id
                LOG.error(msg)
                return None

            # Append SDS name
            if 'sdsId' in device_details[0] and device_details[0]['sdsId']:
                sds_details = self.get_sds(sds_id=device_details[0]['sdsId'])
                device_details[0]['sdsName'] = sds_details['name']

            # Append storage pool name and its protection domain name and ID
            if 'storagePoolId' in device_details[0] \
                    and device_details[0]['storagePoolId']:
                sp_details = self.get_storage_pool(
                    storage_pool_id=device_details[0]['storagePoolId'])
                device_details[0]['storagePoolName'] = sp_details['name']
                pd_id = sp_details['protectionDomainId']
                device_details[0]['protectionDomainId'] = pd_id
                pd_details = self.get_protection_domain(
                    protection_domain_id=pd_id)
                device_details[0]['protectionDomainName'] = pd_details['name']

            # Append acceleration pool name and its protection domain name
            # and ID
            if 'accelerationPoolId' in device_details[0] \
                    and device_details[0]['accelerationPoolId']:
                ap_details = self.get_acceleration_pool(
                    acceleration_pool_id=device_details[0][
                        'accelerationPoolId'])
                device_details[0]['accelerationPoolName'] = ap_details['name']
                pd_id = ap_details['protectionDomainId']
                device_details[0]['protectionDomainId'] = pd_id
                pd_details = self.get_protection_domain(
                    protection_domain_id=pd_id)
                device_details[0]['protectionDomainName'] = pd_details['name']

            return device_details[0]

        except Exception as e:
            error_msg = "Failed to get the device '%s' with error '%s'"\
                        % (device_id, str(e))
            LOG.error(error_msg)
            self.module.fail_json(msg=error_msg)


def to_modify(device_details, media_type, external_acceleration_type):
    """Identify device attributes to be modified"""

    modify_dict = {}

    if media_type is not None and \
            device_details['mediaType'] != media_type:
        modify_dict['mediaType'] = media_type

    if external_acceleration_type is not None and \
            device_details['externalAccelerationType'] \
            != external_acceleration_type:
        modify_dict['externalAccelerationType'] \
            = external_acceleration_type

    if len(modify_dict) != 0:
        LOG.info("Attributes to be modified: %s", modify_dict)
    return modify_dict


def get_powerflex_device_parameters():
    """This method provide parameter required for the device module on
    PowerFlex"""
    return dict(
        current_pathname=dict(), device_name=dict(), device_id=dict(),
        sds_name=dict(), sds_id=dict(), storage_pool_name=dict(),
        storage_pool_id=dict(), acceleration_pool_id=dict(),
        acceleration_pool_name=dict(), protection_domain_name=dict(),
        protection_domain_id=dict(), external_acceleration_type=dict(
            choices=['Invalid', 'None', 'Read', 'Write', 'ReadAndWrite']),
        media_type=dict(choices=['HDD', 'SSD', 'NVDIMM']),
        state=dict(required=True, type='str', choices=['present', 'absent']),
        force=dict(type='bool', default=False)
    )


def main():
    """ Create PowerFlex device object and perform actions on it
        based on user input from playbook"""
    obj = PowerFlexDevice()
    obj.perform_module_operation()


if __name__ == '__main__':
    main()
