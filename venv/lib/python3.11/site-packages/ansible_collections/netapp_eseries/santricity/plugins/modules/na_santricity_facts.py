#!/usr/bin/python

# (c) 2024, NetApp, Inc
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
module: na_santricity_facts
short_description: NetApp E-Series retrieve facts about NetApp E-Series storage arrays
description:
    - The na_santricity_facts module returns a collection of facts regarding NetApp E-Series storage arrays.
author:
    - Kevin Hulquest (@hulquest)
    - Nathan Swartz (@swartzn)
    - Vu Tran (@VuTran007)
extends_documentation_fragment:
    - netapp_eseries.santricity.santricity.santricity_doc
'''

EXAMPLES = """
---
- name: Get array facts
  na_santricity_facts:
    ssid: "1"
    api_url: "https://192.168.1.100:8443/devmgr/v2"
    api_username: "admin"
    api_password: "adminpass"
    validate_certs: true
"""

RETURN = """
    msg:
        description: Success message
        returned: on success
        type: str
        sample:
            - Gathered facts for storage array. Array ID [1].
            - Gathered facts for web services proxy.
    storage_array_facts:
        description: provides details about the array, controllers, management interfaces, hostside interfaces,
                     driveside interfaces, disks, storage pools, volumes, snapshots, and features.
        returned: on successful inquiry from from embedded web services rest api
        type: complex
        contains:
            netapp_controllers:
                description: storage array controller list that contains basic controller identification and status
                type: list
                sample:
                    - [{"name": "A", "serial": "021632007299", "status": "optimal"},
                       {"name": "B", "serial": "021632007300", "status": "failed"}]
            netapp_disks:
                description: drive list that contains identification, type, and status information for each drive
                type: list
                sample:
                    - [{"available": false,
                        "firmware_version": "MS02",
                        "id": "01000000500003960C8B67880000000000000000",
                        "media_type": "ssd",
                        "product_id": "PX02SMU080      ",
                        "serial_number": "15R0A08LT2BA",
                        "status": "optimal",
                        "tray_ref": "0E00000000000000000000000000000000000000",
                        "usable_bytes": "799629205504" }]
            netapp_driveside_interfaces:
                description: drive side interface list that contains identification, type, and speed for each interface
                type: list
                sample:
                    - [{ "controller": "A", "interface_speed": "12g", "interface_type": "sas" }]
                    - [{ "controller": "B", "interface_speed": "10g", "interface_type": "iscsi" }]
            netapp_enabled_features:
                description: specifies the enabled features on the storage array.
                returned: on success
                type: list
                sample:
                    - [ "flashReadCache", "performanceTier", "protectionInformation", "secureVolume" ]
            netapp_host_groups:
                description: specifies the host groups on the storage arrays.
                returned: on success
                type: list
                sample:
                    - [{ "id": "85000000600A098000A4B28D003610705C40B964", "name": "group1" }]
            netapp_hosts:
                description: specifies the hosts on the storage arrays.
                returned: on success
                type: list
                sample:
                    - [{ "id": "8203800000000000000000000000000000000000",
                         "name": "host1",
                         "group_id": "85000000600A098000A4B28D003610705C40B964",
                         "host_type_index": 28,
                         "ports": [{ "type": "fc", "address": "1000FF7CFFFFFF01", "label": "FC_1" },
                                   { "type": "fc", "address": "1000FF7CFFFFFF00", "label": "FC_2" }]}]
            netapp_host_types:
                description: lists the available host types on the storage array.
                returned: on success
                type: list
                sample:
                    - [{ "index": 0, "type": "FactoryDefault" },
                       { "index": 1, "type": "W2KNETNCL"},
                       { "index": 2, "type": "SOL" },
                       { "index": 5, "type": "AVT_4M" },
                       { "index": 6, "type": "LNX" },
                       { "index": 7, "type": "LnxALUA" },
                       { "index": 8, "type": "W2KNETCL" },
                       { "index": 9, "type": "AIX MPIO" },
                       { "index": 10, "type": "VmwTPGSALUA" },
                       { "index": 15, "type": "HPXTPGS" },
                       { "index": 17, "type": "SolTPGSALUA" },
                       { "index": 18, "type": "SVC" },
                       { "index": 22, "type": "MacTPGSALUA" },
                       { "index": 23, "type": "WinTPGSALUA" },
                       { "index": 24, "type": "LnxTPGSALUA" },
                       { "index": 25, "type": "LnxTPGSALUA_PM" },
                       { "index": 26, "type": "ONTAP_ALUA" },
                       { "index": 27, "type": "LnxTPGSALUA_SF" },
                       { "index": 28, "type": "LnxDHALUA" },
                       { "index": 29, "type": "ATTOClusterAllOS" }]
            netapp_hostside_interfaces:
                description: host side interface list that contains identification, configuration, type, speed, and
                             status information for each interface
                type: list
                sample:
                    - [{"iscsi":
                        [{ "controller": "A",
                            "current_interface_speed": "10g",
                            "ipv4_address": "10.10.10.1",
                            "ipv4_enabled": true,
                            "ipv4_gateway": "10.10.10.1",
                            "ipv4_subnet_mask": "255.255.255.0",
                            "ipv6_enabled": false,
                            "iqn": "iqn.1996-03.com.netapp:2806.600a098000a81b6d0000000059d60c76",
                            "link_status": "up",
                            "mtu": 9000,
                            "supported_interface_speeds": [ "10g" ] }]}]
            netapp_management_interfaces:
                description: management interface list that contains identification, configuration, and status for
                             each interface
                type: list
                sample:
                    - [{"alias": "ict-2800-A",
                        "channel": 1,
                        "controller": "A",
                        "dns_config_method": "dhcp",
                        "dns_servers": [],
                        "ipv4_address": "10.1.1.1",
                        "ipv4_address_config_method": "static",
                        "ipv4_enabled": true,
                        "ipv4_gateway": "10.113.1.1",
                        "ipv4_subnet_mask": "255.255.255.0",
                        "ipv6_enabled": false,
                        "link_status": "up",
                        "mac_address": "00A098A81B5D",
                        "name": "wan0",
                        "ntp_config_method": "disabled",
                        "ntp_servers": [],
                        "remote_ssh_access": false }]
            netapp_storage_array:
                description: provides storage array identification, firmware version, and available capabilities
                type: dict
                sample:
                    - {"chassis_serial": "021540006043",
                       "firmware": "08.40.00.01",
                       "name": "ict-2800-11_40",
                       "wwn": "600A098000A81B5D0000000059D60C76",
                       "cacheBlockSizes": [4096,
                                           8192,
                                           16384,
                                           32768],
                       "supportedSegSizes": [8192,
                                             16384,
                                             32768,
                                             65536,
                                             131072,
                                             262144,
                                             524288]}
            netapp_storage_pools:
                description: storage pool list that contains identification and capacity information for each pool
                type: list
                sample:
                    - [{"available_capacity": "3490353782784",
                        "id": "04000000600A098000A81B5D000002B45A953A61",
                        "name": "Raid6",
                        "total_capacity": "5399466745856",
                        "used_capacity": "1909112963072" }]
            netapp_volumes:
                description: storage volume list that contains identification and capacity information for each volume
                type: list
                sample:
                    - [{"capacity": "5368709120",
                        "id": "02000000600A098000AAC0C3000002C45A952BAA",
                        "is_thin_provisioned": false,
                        "name": "5G",
                        "parent_storage_pool_id": "04000000600A098000A81B5D000002B45A953A61" }]
            netapp_workload_tags:
                description: workload tag list
                type: list
                sample:
                    - [{"id": "87e19568-43fb-4d8d-99ea-2811daaa2b38",
                        "name": "ftp_server",
                        "workloadAttributes": [{"key": "use",
                                                "value": "general"}]}]
            netapp_volumes_by_initiators:
                description: list of available volumes keyed by the mapped initiators.
                type: dict
                sample:
                   - {"beegfs_host": [{"id": "02000000600A098000A4B9D1000015FD5C8F7F9E",
                                      "meta_data": {"filetype": "ext4", "public": true},
                                      "name": "some_volume",
                                      "workload_name": "beegfs_metadata",
                                      "workload_metadata": {"filetype": "ext4", "public": true},
                                      "volume_metadata": '{"format_type": "ext4",
                                                           "format_options": "-i 2048 -I 512 -J size=400 -Odir_index,filetype",
                                                           "mount_options": "noatime,nodiratime,nobarrier,_netdev",
                                                           "mount_directory": "/data/beegfs/"}',
                                      "host_types": ["nvmeof"],
                                      "eui": "0000139A3885FA4500A0980000EAA272V",
                                      "wwn": "600A098000A4B9D1000015FD5C8F7F9E"}]}
            snapshot_images:
                description: snapshot image list that contains identification, capacity, and status information for each
                             snapshot image
                type: list
                sample:
                    - [{"active_cow": true,
                        "creation_method": "user",
                        "id": "34000000600A098000A81B5D00630A965B0535AC",
                        "pit_capacity": "5368709120",
                        "reposity_cap_utilization": "0",
                        "rollback_source": false,
                        "status": "optimal" }]
    proxy_facts:
        description: proxy storage system list
        returned: on successful inquiry from from web services proxy's rest api
        type: complex
        contains:
            ssid:
                description: storage system id
                type: str
                sample: "ec8ed9d2-eba3-4cac-88fb-0954f327f1d4"
            name:
                description: storage system name
                type: str
                sample: "EF570-NVMe"
            wwn:
                description: storage system unique identifier
                type: str
                sample: "AC1100051E1E1E1E1E1E1E1E1E1E1E1E"
            model:
                description: NetApp E-Series model number
                type: str
                sample: "5700"
            controller:
                description: controller list that contains identification, ip addresses, and certificate information for
                             each controller
                type: list
                sample: [{"certificateStatus": "selfSigned",
                          "controllerId": "070000000000000000000001",
                          "ipAddresses": ["172.17.0.5", "3.3.3.3"]}]
            drive_types:
                description: all available storage system drive types
                type: list
                sample: ["sas", "fibre"]
            unconfigured_space:
                description: unconfigured storage system space in bytes
                type: str
                sample: "982259020595200"
            array_status:
                description: storage system status
                type: str
                sample: "optimal"
            password_status:
                description: storage system password status
                type: str
                sample: "invalid"
            certificate_status:
                description: storage system ssl certificate status
                type: str
                sample: "untrusted"
            firmware_version:
                description: storage system install firmware version
                type: str
                sample: "08.50.42.99"
            chassis_serial:
                description: storage system chassis serial number
                type: str
                sample: "SX0810032"
            asup_enabled:
                description: storage system auto-support status
                type: bool
                sample: True
"""

from datetime import datetime
import re
from ansible_collections.netapp_eseries.santricity.plugins.module_utils.santricity import NetAppESeriesModule
try:
    from ansible.module_utils.ansible_release import __version__ as ansible_version
except ImportError:
    ansible_version = 'unknown'


class Facts(NetAppESeriesModule):
    def __init__(self):
        web_services_version = "02.00.0000.0000"
        super(Facts, self).__init__(ansible_options={},
                                    web_services_version=web_services_version,
                                    supports_check_mode=True)

    def get_controllers(self):
        """Retrieve a mapping of controller references to their labels."""
        controllers = list()
        try:
            rc, controllers = self.request('storage-systems/%s/graph/xpath-filter?query=/controller/id' % self.ssid)
        except Exception as err:
            self.module.fail_json(
                msg="Failed to retrieve controller list! Array Id [%s]. Error [%s]."
                    % (self.ssid, str(err)))

        controllers.sort()

        controllers_dict = {}
        i = ord('A')
        for controller in controllers:
            label = chr(i)
            controllers_dict[controller] = label
            i += 1

        return controllers_dict

    def get_array_facts(self):
        """Extract particular facts from the storage array graph"""
        facts = dict(facts_from_proxy=(not self.is_embedded()), ssid=self.ssid)
        controller_reference_label = self.get_controllers()
        array_facts = None
        hardware_inventory_facts = None

        # Get the storage array graph
        try:
            rc, array_facts = self.request("storage-systems/%s/graph" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to obtain facts from storage array with id [%s]. Error [%s]" % (self.ssid, str(error)))

        # Get the storage array hardware inventory
        try:
            rc, hardware_inventory_facts = self.request("storage-systems/%s/hardware-inventory" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to obtain hardware inventory from storage array with id [%s]. Error [%s]" % (self.ssid, str(error)))

        # Get storage system specific key-value pairs
        key_value_url = "key-values"
        key_values = []
        if not self.is_embedded() and self.ssid.lower() not in ["0", "proxy"]:
            key_value_url = "storage-systems/%s/forward/devmgr/v2/key-values" % self.ssid
        try:
            rc, key_values = self.request(key_value_url)
        except Exception as error:
            self.module.fail_json(msg="Failed to obtain embedded key-value database. Array [%s]. Error [%s]" % (self.ssid, str(error)))

        facts['netapp_storage_array'] = dict(
            name=array_facts['sa']['saData']['storageArrayLabel'],
            chassis_serial=array_facts['sa']['saData']['chassisSerialNumber'],
            firmware=array_facts['sa']['saData']['fwVersion'],
            wwn=array_facts['sa']['saData']['saId']['worldWideName'],
            segment_sizes=array_facts['sa']['featureParameters']['supportedSegSizes'],
            cache_block_sizes=array_facts['sa']['featureParameters']['cacheBlockSizes'])

        facts['netapp_controllers'] = [
            dict(
                name=controller_reference_label[controller['controllerRef']],
                serial=controller['serialNumber'].strip(),
                status=controller['status'],
            ) for controller in array_facts['controller']]

        facts['netapp_hosts'] = [
            dict(
                group_id=host['clusterRef'],
                hosts_reference=host['hostRef'],
                id=host['id'],
                name=host['name'],
                host_type_index=host['hostTypeIndex'],
                ports=host['hostSidePorts']
            ) for host in array_facts['storagePoolBundle']['host']]

        facts['netapp_host_groups'] = [
            dict(
                id=group['id'],
                name=group['name'],
                hosts=[host['name'] for host in facts['netapp_hosts'] if host['group_id'] == group['id']]
            ) for group in array_facts['storagePoolBundle']['cluster']]
        facts['netapp_host_groups'].append(dict(
            id='0000000000000000000000000000000000000000',
            name='default_hostgroup',
            hosts=[host["name"] for host in facts['netapp_hosts'] if host['group_id'] == '0000000000000000000000000000000000000000']))

        facts['netapp_host_types'] = [
            dict(
                type=host_type['hostType'],
                index=host_type['index']
            ) for host_type in array_facts['sa']['hostSpecificVals']
            if 'hostType' in host_type.keys() and host_type['hostType']
            # This conditional ignores zero-length strings which indicates that the associated host-specific NVSRAM region has been cleared.
        ]

        facts['snapshot_images'] = [
            dict(
                id=snapshot['id'],
                status=snapshot['status'],
                pit_capacity=snapshot['pitCapacity'],
                creation_method=snapshot['creationMethod'],
                reposity_cap_utilization=snapshot['repositoryCapacityUtilization'],
                active_cow=snapshot['activeCOW'],
                rollback_source=snapshot['isRollbackSource']
            ) for snapshot in array_facts['highLevelVolBundle']['pit']]

        facts['netapp_disks'] = [
            dict(
                id=disk['id'],
                available=disk['available'],
                media_type=disk['driveMediaType'],
                status=disk['status'],
                usable_bytes=disk['usableCapacity'],
                tray_ref=disk['physicalLocation']['trayRef'],
                product_id=disk['productID'],
                firmware_version=disk['firmwareVersion'],
                serial_number=disk['serialNumber'].lstrip()
            ) for disk in array_facts['drive']]

        facts['netapp_management_interfaces'] = [
            dict(controller=controller_reference_label[controller['controllerRef']],
                 name=iface['ethernet']['interfaceName'],
                 alias=iface['ethernet']['alias'],
                 channel=iface['ethernet']['channel'],
                 mac_address=iface['ethernet']['macAddr'],
                 remote_ssh_access=iface['ethernet']['rloginEnabled'],
                 link_status=iface['ethernet']['linkStatus'],
                 ipv4_enabled=iface['ethernet']['ipv4Enabled'],
                 ipv4_address_config_method=iface['ethernet']['ipv4AddressConfigMethod'].lower().replace("config", ""),
                 ipv4_address=iface['ethernet']['ipv4Address'],
                 ipv4_subnet_mask=iface['ethernet']['ipv4SubnetMask'],
                 ipv4_gateway=iface['ethernet']['ipv4GatewayAddress'],
                 ipv6_enabled=iface['ethernet']['ipv6Enabled'],
                 dns_config_method=iface['ethernet']['dnsProperties']['acquisitionProperties']['dnsAcquisitionType'],
                 dns_servers=(iface['ethernet']['dnsProperties']['acquisitionProperties']['dnsServers']
                              if iface['ethernet']['dnsProperties']['acquisitionProperties']['dnsServers'] else []),
                 ntp_config_method=iface['ethernet']['ntpProperties']['acquisitionProperties']['ntpAcquisitionType'],
                 ntp_servers=(iface['ethernet']['ntpProperties']['acquisitionProperties']['ntpServers']
                              if iface['ethernet']['ntpProperties']['acquisitionProperties']['ntpServers'] else [])
                 ) for controller in array_facts['controller'] for iface in controller['netInterfaces']]

        facts['netapp_hostside_interfaces'] = [
            dict(
                fc=[dict(controller=controller_reference_label[controller['controllerRef']],
                         channel=iface['fibre']['channel'],
                         link_status=iface['fibre']['linkStatus'],
                         current_interface_speed=strip_interface_speed(iface['fibre']['currentInterfaceSpeed']),
                         maximum_interface_speed=strip_interface_speed(iface['fibre']['maximumInterfaceSpeed']))
                    for controller in array_facts['controller']
                    for iface in controller['hostInterfaces']
                    if iface['interfaceType'] == 'fc'],
                ib=[dict(controller=controller_reference_label[controller['controllerRef']],
                         channel=iface['ib']['channel'],
                         link_status=iface['ib']['linkState'],
                         mtu=iface['ib']['maximumTransmissionUnit'],
                         current_interface_speed=strip_interface_speed(iface['ib']['currentSpeed']),
                         maximum_interface_speed=strip_interface_speed(iface['ib']['supportedSpeed']))
                    for controller in array_facts['controller']
                    for iface in controller['hostInterfaces']
                    if iface['interfaceType'] == 'ib'],
                iscsi=[dict(controller=controller_reference_label[controller['controllerRef']],
                            iqn=iface['iscsi']['iqn'],
                            link_status=iface['iscsi']['interfaceData']['ethernetData']['linkStatus'],
                            ipv4_enabled=iface['iscsi']['ipv4Enabled'],
                            ipv4_address=iface['iscsi']['ipv4Data']['ipv4AddressData']['ipv4Address'],
                            ipv4_subnet_mask=iface['iscsi']['ipv4Data']['ipv4AddressData']['ipv4SubnetMask'],
                            ipv4_gateway=iface['iscsi']['ipv4Data']['ipv4AddressData']['ipv4GatewayAddress'],
                            ipv6_enabled=iface['iscsi']['ipv6Enabled'],
                            mtu=iface['iscsi']['interfaceData']['ethernetData']['maximumFramePayloadSize'],
                            current_interface_speed=strip_interface_speed(iface['iscsi']['interfaceData']
                                                                          ['ethernetData']['currentInterfaceSpeed']),
                            supported_interface_speeds=strip_interface_speed(iface['iscsi']['interfaceData']
                                                                             ['ethernetData']
                                                                             ['supportedInterfaceSpeeds']))
                       for controller in array_facts['controller']
                       for iface in controller['hostInterfaces']
                       if iface['interfaceType'] == 'iscsi' and iface['iscsi']['interfaceData']['type'] == 'ethernet'],
                sas=[dict(controller=controller_reference_label[controller['controllerRef']],
                          channel=iface['sas']['channel'],
                          current_interface_speed=strip_interface_speed(iface['sas']['currentInterfaceSpeed']),
                          maximum_interface_speed=strip_interface_speed(iface['sas']['maximumInterfaceSpeed']),
                          link_status=iface['sas']['iocPort']['state'])
                     for controller in array_facts['controller']
                     for iface in controller['hostInterfaces']
                     if iface['interfaceType'] == 'sas'])]

        facts['netapp_driveside_interfaces'] = [
            dict(
                controller=controller_reference_label[controller['controllerRef']],
                interface_type=interface['interfaceType'],
                interface_speed=strip_interface_speed(
                    interface[interface['interfaceType']]['maximumInterfaceSpeed']
                    if (interface['interfaceType'] == 'sata' or
                        interface['interfaceType'] == 'sas' or
                        interface['interfaceType'] == 'fibre')
                    else (
                        interface[interface['interfaceType']]['currentSpeed']
                        if interface['interfaceType'] == 'ib'
                        else (
                            interface[interface['interfaceType']]['interfaceData']['maximumInterfaceSpeed']
                            if interface['interfaceType'] == 'iscsi' else 'unknown'
                        ))),
            )
            for controller in array_facts['controller']
            for interface in controller['driveInterfaces']]

        facts['netapp_storage_pools'] = [
            dict(
                id=storage_pool['id'],
                name=storage_pool['name'],
                available_capacity=storage_pool['freeSpace'],
                total_capacity=storage_pool['totalRaidedSpace'],
                used_capacity=storage_pool['usedSpace']
            ) for storage_pool in array_facts['volumeGroup']]

        all_volumes = list(array_facts['volume'] + array_facts['highLevelVolBundle']['thinVolume'])

        facts['netapp_volumes'] = [
            dict(
                id=v['id'],
                name=v['name'],
                parent_storage_pool_id=v['volumeGroupRef'],
                capacity=v['capacity'],
                is_thin_provisioned=v['thinProvisioned'],
                workload=v['metadata'],

            ) for v in all_volumes]

        # Add access volume information to volumes when enabled.
        if array_facts['sa']['accessVolume']['enabled']:
            facts['netapp_volumes'].append(dict(
                id=array_facts['sa']['accessVolume']['id'],
                name="access_volume",
                parent_storage_pool_id="",
                capacity=array_facts['sa']['accessVolume']['capacity'],
                is_thin_provisioned=False,
                workload=""))

        facts['netapp_snapshot_consistency_groups'] = []
        for group in array_facts["highLevelVolBundle"]["pitConsistencyGroup"]:
            reserve_capacity_full_policy = "purge" if group["repFullPolicy"] == "purgepit" else "reject"
            group_info = {"id": group["id"],
                          "name": group["name"],
                          "reserve_capacity_full_policy": reserve_capacity_full_policy,
                          "rollback_priority": group["rollbackPriority"],
                          "base_volumes": [],
                          "pit_images": [],
                          "pit_views": {}}

            # Determine all consistency group base volumes.
            volumes_by_id = {}
            for pit_group in array_facts["highLevelVolBundle"]["pitGroup"]:
                if pit_group["consistencyGroupRef"] == group["id"]:
                    for volume in array_facts["volume"]:
                        if volume["id"] == pit_group["baseVolume"]:
                            volumes_by_id.update({volume["id"]: volume["name"]})
                            group_info["base_volumes"].append({"id": volume["id"],
                                                               "name": volume["name"],
                                                               "reserve_capacity_volume_id": pit_group["repositoryVolume"]})
                            break

            # Determine all consistency group pit snapshot images.
            group_pit_key_values = {}
            for entry in key_values:
                if re.search("ansible\\|%s\\|" % group["name"], entry["key"]):
                    pit_name = entry["key"].replace("ansible|%s|" % group["name"], "")
                    pit_values = entry["value"].split("|")
                    if len(pit_values) == 3:
                        timestamp, image_id, description = pit_values
                        group_pit_key_values.update({timestamp: {"name": pit_name, "description": description}})

            pit_by_id = {}
            for pit in array_facts["highLevelVolBundle"]["pit"]:
                if pit["consistencyGroupId"] == group["id"]:

                    if pit["pitTimestamp"] in group_pit_key_values.keys():
                        pit_image = {"name": group_pit_key_values[pit["pitTimestamp"]]["name"],
                                     "description": group_pit_key_values[pit["pitTimestamp"]]["description"],
                                     "timestamp": datetime.fromtimestamp(int(pit["pitTimestamp"])).strftime("%Y-%m-%d %H:%M:%S")}
                    else:
                        pit_image = {"name": "", "description": "",
                                     "timestamp": datetime.fromtimestamp(int(pit["pitTimestamp"])).strftime("%Y-%m-%d %H:%M:%S")}
                    group_info["pit_images"].append(pit_image)
                    pit_by_id.update({pit["id"]: pit_image})

            # Determine all consistency group pit views.
            for view in array_facts["highLevelVolBundle"]["pitView"]:
                if view["consistencyGroupId"] == group["id"]:
                    view_timestamp = datetime.fromtimestamp(int(view["viewTime"])).strftime("%Y-%m-%d %H:%M:%S")
                    reserve_capacity_pct = int(round(float(view["repositoryCapacity"]) / float(view["baseVolumeCapacity"]) * 100))
                    if view_timestamp in group_info["pit_views"].keys():
                        group_info["pit_views"][view_timestamp]["volumes"].append({"name": view["name"],
                                                                                   "base_volume": volumes_by_id[view["baseVol"]],
                                                                                   "writable": view["accessMode"] == "readWrite",
                                                                                   "reserve_capacity_pct": reserve_capacity_pct,
                                                                                   "status": view["status"]})
                    else:
                        group_info["pit_views"].update({view_timestamp: {"name": pit_by_id[view["basePIT"]]["name"],
                                                                         "description": pit_by_id[view["basePIT"]]["description"],
                                                                         "volumes": [{"name": view["name"],
                                                                                      "base_volume": volumes_by_id[view["baseVol"]],
                                                                                      "writable": view["accessMode"] == "readWrite",
                                                                                      "reserve_capacity_pct": reserve_capacity_pct,
                                                                                      "status": view["status"]}]}})

            facts['netapp_snapshot_consistency_groups'].append(group_info)

        lun_mappings = dict()
        for host in facts['netapp_hosts']:
            lun_mappings.update({host["name"]: []})
        for host in facts['netapp_host_groups']:
            lun_mappings.update({host["name"]: []})

        facts['netapp_default_hostgroup_access_volume_lun'] = None
        for lun in [a['lun'] for a in array_facts['storagePoolBundle']['lunMapping']
                    if a['type'] == 'all' and a['mapRef'] == '0000000000000000000000000000000000000000']:
            facts['netapp_default_hostgroup_access_volume_lun'] = lun

        # Get all host mappings
        host_mappings = dict()
        for host_mapping in [h for h in array_facts['storagePoolBundle']['lunMapping'] if h['type'] == 'host']:
            for host_name in [h['name'] for h in facts['netapp_hosts'] if h['id'] == host_mapping['mapRef']]:
                for volume in [v['name'] for v in facts['netapp_volumes'] if v['id'] == host_mapping['volumeRef']]:
                    if host_name in host_mappings.keys():
                        host_mappings[host_name].append((volume, host_mapping['lun']))
                    else:
                        host_mappings[host_name] = [(volume, host_mapping['lun'])]

        # Get all host group mappings
        group_mappings = dict()
        for group_mapping in [h for h in array_facts['storagePoolBundle']['lunMapping'] if h['type'] == 'cluster']:
            for group_name, group_hosts in [(g['name'], g['hosts']) for g in facts['netapp_host_groups'] if g['id'] == group_mapping['mapRef']]:
                for volume in [v['name'] for v in facts['netapp_volumes'] if v['id'] == group_mapping['volumeRef']]:
                    if group_name in group_mappings.keys():
                        group_mappings[group_name].append((volume, group_mapping['lun']))
                    else:
                        group_mappings[group_name] = [(volume, group_mapping['lun'])]

                    for host_name in [h for h in group_hosts if h in host_mappings.keys()]:
                        if host_name in host_mappings.keys():
                            host_mappings[host_name].append((volume, group_mapping['lun']))
                        else:
                            host_mappings[host_name] = [(volume, group_mapping['lun'])]

        facts['netapp_luns_by_target'] = lun_mappings
        if host_mappings:
            facts['netapp_luns_by_target'].update(host_mappings)
        if group_mappings:
            facts['netapp_luns_by_target'].update(group_mappings)

        # Add all host mappings to respective groups mappings
        for host_group in facts['netapp_host_groups']:
            group_name = host_group['name']
            for host in host_group['hosts']:
                facts['netapp_luns_by_target'][group_name].extend(facts['netapp_luns_by_target'][host])

        # Remove duplicate entries
        for obj in facts['netapp_luns_by_target'].keys():
            tmp = dict(facts['netapp_luns_by_target'][obj])
            facts['netapp_luns_by_target'][obj] = [(k, tmp[k]) for k in tmp.keys()]

        workload_tags = None
        try:
            rc, workload_tags = self.request("storage-systems/%s/workloads" % self.ssid)
        except Exception as error:
            self.module.fail_json(msg="Failed to retrieve workload tags. Array [%s]." % self.ssid)

        facts['netapp_workload_tags'] = [
            dict(
                id=workload_tag['id'],
                name=workload_tag['name'],
                attributes=workload_tag['workloadAttributes']
            ) for workload_tag in workload_tags]

        targets = array_facts["storagePoolBundle"]["target"]

        facts['netapp_hostside_io_interfaces'] = []
        if "ioInterface" in array_facts:
            for interface in array_facts["ioInterface"]:

                # Select only the host side channels
                if interface["channelType"] == "hostside":
                    interface_type = interface["ioInterfaceTypeData"]["interfaceType"]
                    if interface_type == "fibre":
                        interface_type = "fc"
                    elif interface_type == "nvmeCouplingDriver":
                        interface_type = "couplingDriverNvme"

                    interface_data = interface["ioInterfaceTypeData"][interface_type]
                    command_protocol_properties = interface["commandProtocolPropertiesList"]["commandProtocolProperties"]

                    # Build generic information for each interface entry
                    interface_info = {"protocol": "unknown",
                                      "interface_reference": interface_data["interfaceRef"],
                                      "controller_reference": interface["controllerRef"],
                                      "channel_port_reference": interface_data["channelPortRef"] if "channelPortRef" in interface_data else "",
                                      "controller": controller_reference_label[interface["controllerRef"]],
                                      "channel": interface_data["channel"],
                                      "part": "unknown",
                                      "link_status": "unknown",
                                      "speed": {"current": "unknown", "maximum": "unknown", "supported": []},
                                      "mtu": None,
                                      "guid": None,
                                      "lid": None,
                                      "nqn": None,
                                      "iqn": None,
                                      "wwnn": None,
                                      "wwpn": None,
                                      "ipv4": None,  # enabled, config_method, address, subnet, gateway
                                      "ipv6": None}  # for expansion if needed

                    # Determine storage target identifiers
                    controller_iqn = "unknown"
                    controller_nqn = "unknown"
                    for target in targets:
                        if target["nodeName"]["ioInterfaceType"] == "nvmeof":
                            controller_nqn = target["nodeName"]["nvmeNodeName"]
                        if target["nodeName"]["ioInterfaceType"] == "iscsi":
                            controller_iqn = target["nodeName"]["iscsiNodeName"]

                    # iSCSI IO interface
                    if interface_type == "iscsi":
                        interface_info.update({"ipv4": {"enabled": interface_data["ipv4Enabled"],
                                                        "config_method": interface_data["ipv4Data"]["ipv4AddressConfigMethod"],
                                                        "address": interface_data["ipv4Data"]["ipv4AddressData"]["ipv4Address"],
                                                        "subnet": interface_data["ipv4Data"]["ipv4AddressData"]["ipv4SubnetMask"],
                                                        "gateway": interface_data["ipv4Data"]["ipv4AddressData"]["ipv4GatewayAddress"]}})

                        # InfiniBand (iSER) protocol
                        if interface_data["interfaceData"]["type"] == "infiniband" and interface_data["interfaceData"]["infinibandData"]["isIser"]:
                            interface_info.update({"protocol": "ib_iser",
                                                   "iqn": controller_iqn})

                            # Get more details from hardware-inventory
                            for ib_port in hardware_inventory_facts["ibPorts"]:
                                if ib_port["channelPortRef"] == interface_info["channel_port_reference"]:
                                    interface_info.update({"link_status": ib_port["linkState"],
                                                           "guid": ib_port["globalIdentifier"],
                                                           "lid": ib_port["localIdentifier"],
                                                           "speed": {"current": strip_interface_speed(ib_port["currentSpeed"]),
                                                                     "maximum": strip_interface_speed(ib_port["supportedSpeed"])[-1],
                                                                     "supported": strip_interface_speed(ib_port["supportedSpeed"])}})

                        # iSCSI protocol
                        elif interface_data["interfaceData"]["type"] == "ethernet":
                            ethernet_data = interface_data["interfaceData"]["ethernetData"]
                            interface_info.update({"protocol": "iscsi",
                                                   "iqn": controller_iqn})
                            interface_info.update({"part": "%s,%s" % (ethernet_data["partData"]["vendorName"], ethernet_data["partData"]["partNumber"]),
                                                   "link_status": ethernet_data["linkStatus"],
                                                   "mtu": ethernet_data["maximumFramePayloadSize"],
                                                   "speed": {"current": strip_interface_speed(ethernet_data["currentInterfaceSpeed"]),
                                                             "maximum": strip_interface_speed(ethernet_data["maximumInterfaceSpeed"]),
                                                             "supported": strip_interface_speed(ethernet_data["supportedInterfaceSpeeds"])}})

                    # Fibre Channel IO interface
                    elif interface_type == "fc":
                        interface_info.update({"wwnn": interface_data["nodeName"],
                                               "wwpn": interface_data["addressId"],
                                               "part": interface_data["part"],
                                               "link_status": interface_data["linkStatus"],
                                               "speed": {"current": strip_interface_speed(interface_data["currentInterfaceSpeed"]),
                                                         "maximum": strip_interface_speed(interface_data["maximumInterfaceSpeed"]),
                                                         "supported": "unknown"}})

                        # NVMe over fibre channel protocol
                        if (command_protocol_properties and command_protocol_properties[0]["commandProtocol"] == "nvme" and
                                command_protocol_properties[0]["nvmeProperties"]["commandSet"] == "nvmeof" and
                                command_protocol_properties[0]["nvmeProperties"]["nvmeofProperties"]["fcProperties"]):
                            interface_info.update({"protocol": "nvme_fc",
                                                   "nqn": controller_nqn})

                        # Fibre channel protocol
                        else:
                            interface_info.update({"protocol": "fc"})

                    # SAS IO interface
                    elif interface_type == "sas":
                        interface_info.update({"protocol": "sas",
                                               "wwpn": interface_data["addressId"],
                                               "part": interface_data["part"],
                                               "speed": {"current": strip_interface_speed(interface_data["currentInterfaceSpeed"]),
                                                         "maximum": strip_interface_speed(interface_data["maximumInterfaceSpeed"]),
                                                         "supported": "unknown"}})

                    # Infiniband IO interface
                    elif interface_type == "ib":
                        interface_info.update({"link_status": interface_data["linkState"],
                                               "speed": {"current": strip_interface_speed(interface_data["currentSpeed"]),
                                                         "maximum": strip_interface_speed(interface_data["supportedSpeed"])[-1],
                                                         "supported": strip_interface_speed(interface_data["supportedSpeed"])},
                                               "mtu": interface_data["maximumTransmissionUnit"],
                                               "guid": interface_data["globalIdentifier"],
                                               "lid": interface_data["localIdentifier"]})

                        # Determine protocol (NVMe over Infiniband, InfiniBand iSER, InfiniBand SRP)
                        if interface_data["isNVMeSupported"]:
                            interface_info.update({"protocol": "nvme_ib",
                                                   "nqn": controller_nqn})
                        elif interface_data["isISERSupported"]:
                            interface_info.update({"protocol": "ib_iser",
                                                   "iqn": controller_iqn})
                        elif interface_data["isSRPSupported"]:
                            interface_info.update({"protocol": "ib_srp"})

                        # Determine command protocol information
                        if command_protocol_properties:
                            for command_protocol_property in command_protocol_properties:
                                if command_protocol_property["commandProtocol"] == "nvme":
                                    if command_protocol_property["nvmeProperties"]["commandSet"] == "nvmeof":
                                        ip_address_data = command_protocol_property["nvmeProperties"]["nvmeofProperties"]["ibProperties"]["ipAddressData"]
                                        if ip_address_data["addressType"] == "ipv4":
                                            interface_info.update({"ipv4": {"enabled": True,
                                                                            "config_method": "configStatic",
                                                                            "address": ip_address_data["ipv4Data"]["ipv4Address"],
                                                                            "subnet": ip_address_data["ipv4Data"]["ipv4SubnetMask"],
                                                                            "gateway": ip_address_data["ipv4Data"]["ipv4GatewayAddress"]}})

                                elif command_protocol_property["commandProtocol"] == "scsi":
                                    if command_protocol_property["scsiProperties"]["scsiProtocolType"] == "iser":
                                        ipv4_data = command_protocol_property["scsiProperties"]["iserProperties"]["ipv4Data"]
                                        interface_info.update({"ipv4": {"enabled": True,
                                                                        "config_method": ipv4_data["ipv4AddressConfigMethod"],
                                                                        "address": ipv4_data["ipv4AddressData"]["ipv4Address"],
                                                                        "subnet": ipv4_data["ipv4AddressData"]["ipv4SubnetMask"],
                                                                        "gateway": ipv4_data["ipv4AddressData"]["ipv4GatewayAddress"]}})

                    # Ethernet IO interface
                    elif interface_type == "ethernet":
                        ethernet_data = interface_data["interfaceData"]["ethernetData"]
                        interface_info.update({"part": "%s,%s" % (ethernet_data["partData"]["vendorName"], ethernet_data["partData"]["partNumber"]),
                                               "link_status": ethernet_data["linkStatus"],
                                               "mtu": ethernet_data["maximumFramePayloadSize"],
                                               "speed": {"current": strip_interface_speed(ethernet_data["currentInterfaceSpeed"]),
                                                         "maximum": strip_interface_speed(ethernet_data["maximumInterfaceSpeed"]),
                                                         "supported": strip_interface_speed(ethernet_data["supportedInterfaceSpeeds"])}})

                        # Determine command protocol information
                        if command_protocol_properties:
                            for command_protocol_property in command_protocol_properties:
                                if command_protocol_property["commandProtocol"] == "nvme":
                                    if command_protocol_property["nvmeProperties"]["commandSet"] == "nvmeof":

                                        nvmeof_properties = command_protocol_property["nvmeProperties"]["nvmeofProperties"]
                                        if nvmeof_properties["provider"] == "providerRocev2":
                                            ipv4_data = nvmeof_properties["roceV2Properties"]["ipv4Data"]
                                            interface_info.update({"protocol": "nvme_roce",
                                                                   "nqn": controller_nqn})
                                            interface_info.update({"ipv4": {"enabled": nvmeof_properties["roceV2Properties"]["ipv4Enabled"],
                                                                            "config_method": ipv4_data["ipv4AddressConfigMethod"],
                                                                            "address": ipv4_data["ipv4AddressData"]["ipv4Address"],
                                                                            "subnet": ipv4_data["ipv4AddressData"]["ipv4SubnetMask"],
                                                                            "gateway": ipv4_data["ipv4AddressData"]["ipv4GatewayAddress"]}})

                    facts['netapp_hostside_io_interfaces'].append(interface_info)

        # Gather information from controller->hostInterfaces if available (This is a deprecated data structure. Prefer information from ioInterface.
        for controller in array_facts['controller']:
            if "hostInterfaces" in controller.keys():
                for interface in controller['hostInterfaces']:

                    # Ignore any issue with this data structure since its a deprecated data structure.
                    try:
                        interface_type = interface["interfaceType"]
                        interface_data = interface["fibre" if interface_type == "fc" else interface_type]

                        # Build generic information for each interface entry
                        interface_info = {"protocol": "unknown",
                                          "interface_reference": interface_data["interfaceRef"],
                                          "controller_reference": controller["controllerRef"],
                                          "channel_port_reference": interface_data["channelPortRef"] if "channelPortRef" in interface_data else "",
                                          "controller": controller_reference_label[controller["controllerRef"]],
                                          "channel": interface_data["channel"],
                                          "part": "unknown",
                                          "link_status": "unknown",
                                          "speed": {"current": "unknown", "maximum": "unknown", "supported": []},
                                          "mtu": None,
                                          "guid": None,
                                          "lid": None,
                                          "nqn": None,
                                          "iqn": None,
                                          "wwnn": None,
                                          "wwpn": None,
                                          "ipv4": None,  # enabled, config_method, address, subnet, gateway
                                          "ipv6": None}  # for expansion if needed

                        # Add target information
                        for target in targets:
                            if target["nodeName"]["ioInterfaceType"] == "nvmeof":
                                interface_info.update({"nqn": target["nodeName"]["nvmeNodeName"]})
                            if target["nodeName"]["ioInterfaceType"] == "iscsi":
                                interface_info.update({"iqn": target["nodeName"]["iscsiNodeName"]})

                        # iSCSI IO interface
                        if interface_type == "iscsi":
                            interface_info.update({"ipv4": {"enabled": interface_data["ipv4Enabled"],
                                                            "config_method": interface_data["ipv4Data"]["ipv4AddressConfigMethod"],
                                                            "address": interface_data["ipv4Data"]["ipv4AddressData"]["ipv4Address"],
                                                            "subnet": interface_data["ipv4Data"]["ipv4AddressData"]["ipv4SubnetMask"],
                                                            "gateway": interface_data["ipv4Data"]["ipv4AddressData"]["ipv4GatewayAddress"]}})
                            # InfiniBand (iSER) protocol
                            if interface_data["interfaceData"]["type"] == "infiniband" and interface_data["interfaceData"]["infinibandData"]["isIser"]:
                                interface_info.update({"protocol": "ib_iser"})

                                # Get more details from hardware-inventory
                                for ib_port in hardware_inventory_facts["ibPorts"]:
                                    if ib_port["channelPortRef"] == interface_info["channel_port_reference"]:
                                        interface_info.update({"link_status": ib_port["linkState"],
                                                               "guid": ib_port["globalIdentifier"],
                                                               "lid": ib_port["localIdentifier"],
                                                               "speed": {"current": strip_interface_speed(ib_port["currentSpeed"]),
                                                                         "maximum": strip_interface_speed(ib_port["supportedSpeed"])[-1],
                                                                         "supported": strip_interface_speed(ib_port["supportedSpeed"])}})
                            # iSCSI protocol
                            elif interface_data["interfaceData"]["type"] == "ethernet":
                                ethernet_data = interface_data["interfaceData"]["ethernetData"]
                                interface_info.update({"protocol": "iscsi"})
                                interface_info.update({"part": "%s,%s" % (ethernet_data["partData"]["vendorName"], ethernet_data["partData"]["partNumber"]),
                                                       "link_status": ethernet_data["linkStatus"],
                                                       "mtu": ethernet_data["maximumFramePayloadSize"],
                                                       "speed": {"current": strip_interface_speed(ethernet_data["currentInterfaceSpeed"]),
                                                                 "maximum": strip_interface_speed(ethernet_data["maximumInterfaceSpeed"]),
                                                                 "supported": strip_interface_speed(ethernet_data["supportedInterfaceSpeeds"])}})
                        # Fibre Channel IO interface
                        elif interface_type == "fc":
                            interface_info.update({"protocol": "fc",
                                                   "wwnn": interface_data["nodeName"],
                                                   "wwpn": interface_data["addressId"],
                                                   "link_status": interface_data["linkStatus"],
                                                   "speed": {"current": strip_interface_speed(interface_data["currentInterfaceSpeed"]),
                                                             "maximum": strip_interface_speed(interface_data["maximumInterfaceSpeed"]),
                                                             "supported": "unknown"}})
                        # SAS IO interface
                        elif interface_type == "sas":
                            interface_info.update({"protocol": "sas",
                                                   "wwpn": interface_data["iocPort"]["portTypeData"]["portIdentifier"],
                                                   "part": interface_data["part"],
                                                   "speed": {"current": strip_interface_speed(interface_data["currentInterfaceSpeed"]),
                                                             "maximum": strip_interface_speed(interface_data["maximumInterfaceSpeed"]),
                                                             "supported": "unknown"}})
                        # Infiniband IO interface
                        elif interface_type == "ib":
                            interface_info.update({"link_status": interface_data["linkState"],
                                                   "speed": {"current": strip_interface_speed(interface_data["currentSpeed"]),
                                                             "maximum": strip_interface_speed(interface_data["supportedSpeed"])[-1],
                                                             "supported": strip_interface_speed(interface_data["supportedSpeed"])},
                                                   "mtu": interface_data["maximumTransmissionUnit"],
                                                   "guid": interface_data["globalIdentifier"],
                                                   "lid": interface_data["localIdentifier"]})

                            # Determine protocol (NVMe over Infiniband, InfiniBand iSER, InfiniBand SRP)
                            if interface_data["isNVMeSupported"]:
                                interface_info.update({"protocol": "nvme_ib"})
                            elif interface_data["isISERSupported"]:
                                interface_info.update({"protocol": "ib_iser"})
                            elif interface_data["isSRPSupported"]:
                                interface_info.update({"protocol": "ib_srp"})

                        # Ethernet IO interface
                        elif interface_type == "ethernet":
                            ethernet_data = interface_data["interfaceData"]["ethernetData"]
                            interface_info.update({"part": "%s,%s" % (ethernet_data["partData"]["vendorName"], ethernet_data["partData"]["partNumber"]),
                                                   "link_status": ethernet_data["linkStatus"],
                                                   "mtu": ethernet_data["maximumFramePayloadSize"],
                                                   "speed": {"current": strip_interface_speed(ethernet_data["currentInterfaceSpeed"]),
                                                             "maximum": strip_interface_speed(ethernet_data["maximumInterfaceSpeed"]),
                                                             "supported": strip_interface_speed(ethernet_data["supportedInterfaceSpeeds"])}})

                        # Only add interface if not already added (i.e. was part of ioInterface structure)
                        for existing_hostside_io_interfaces in facts['netapp_hostside_io_interfaces']:
                            if existing_hostside_io_interfaces["interface_reference"] == interface_info["interface_reference"]:
                                break
                        else:
                            facts['netapp_hostside_io_interfaces'].append(interface_info)
                    except Exception as error:
                        pass

        # Create a dictionary of volume lists keyed by host names
        facts['netapp_volumes_by_initiators'] = dict()
        for mapping in array_facts['storagePoolBundle']['lunMapping']:
            for host in facts['netapp_hosts']:
                if mapping['mapRef'] == host['hosts_reference'] or mapping['mapRef'] == host['group_id']:
                    if host['name'] not in facts['netapp_volumes_by_initiators'].keys():
                        facts['netapp_volumes_by_initiators'].update({host['name']: []})

                    # Determine host io interface protocols
                    host_types = [port['type'] for port in host['ports']]
                    hostside_io_interface_protocols = []
                    host_port_protocols = []
                    host_port_information = {}
                    for interface in facts['netapp_hostside_io_interfaces']:
                        hostside_io_interface_protocols.append(interface["protocol"])
                        for host_type in host_types:
                            if host_type == "iscsi" and interface["protocol"] in ["iscsi", "ib_iser"]:
                                host_port_protocols.append(interface["protocol"])
                                if interface["protocol"] in host_port_information:
                                    # Skip duplicate entries into host_port_information
                                    for host_port_info in host_port_information[interface["protocol"]]:
                                        if interface["interface_reference"] == host_port_info["interface_reference"]:
                                            break
                                    else:
                                        host_port_information[interface["protocol"]].append(interface)
                                else:
                                    host_port_information.update({interface["protocol"]: [interface]})

                            elif host_type == "fc" and interface["protocol"] in ["fc"]:
                                host_port_protocols.append(interface["protocol"])
                                if interface["protocol"] in host_port_information:
                                    # Skip duplicate entries into host_port_information
                                    for host_port_info in host_port_information[interface["protocol"]]:
                                        if interface["interface_reference"] == host_port_info["interface_reference"]:
                                            break
                                    else:
                                        host_port_information[interface["protocol"]].append(interface)
                                else:
                                    host_port_information.update({interface["protocol"]: [interface]})

                            elif host_type == "sas" and interface["protocol"] in ["sas"]:
                                host_port_protocols.append(interface["protocol"])
                                if interface["protocol"] in host_port_information:
                                    # Skip duplicate entries into host_port_information
                                    for host_port_info in host_port_information[interface["protocol"]]:
                                        if interface["interface_reference"] == host_port_info["interface_reference"]:
                                            break
                                    else:
                                        host_port_information[interface["protocol"]].append(interface)
                                else:
                                    host_port_information.update({interface["protocol"]: [interface]})

                            elif host_type == "ib" and interface["protocol"] in ["ib_iser", "ib_srp"]:
                                host_port_protocols.append(interface["protocol"])
                                if interface["protocol"] in host_port_information:
                                    # Skip duplicate entries into host_port_information
                                    for host_port_info in host_port_information[interface["protocol"]]:
                                        if interface["interface_reference"] == host_port_info["interface_reference"]:
                                            break
                                    else:
                                        host_port_information[interface["protocol"]].append(interface)
                                else:
                                    host_port_information.update({interface["protocol"]: [interface]})

                            elif host_type == "nvmeof" and interface["protocol"] in ["nvme_ib", "nvme_fc", "nvme_roce"]:
                                host_port_protocols.append(interface["protocol"])
                                if interface["protocol"] in host_port_information:
                                    # Skip duplicate entries into host_port_information
                                    for host_port_info in host_port_information[interface["protocol"]]:
                                        if interface["interface_reference"] == host_port_info["interface_reference"]:
                                            break
                                    else:
                                        host_port_information[interface["protocol"]].append(interface)
                                else:
                                    host_port_information.update({interface["protocol"]: [interface]})

                    for volume in all_volumes:
                        storage_pool = [pool["name"] for pool in facts['netapp_storage_pools'] if pool["id"] == volume["volumeGroupRef"]][0]

                        if mapping['id'] in [volume_mapping['id'] for volume_mapping in volume['listOfMappings']]:

                            # Determine workload name if there is one
                            workload_name = ""
                            metadata = dict()
                            for volume_tag in volume['metadata']:
                                if volume_tag['key'] == 'workloadId':
                                    for workload_tag in facts['netapp_workload_tags']:
                                        if volume_tag['value'] == workload_tag['id']:
                                            workload_name = workload_tag['name']
                                            metadata = dict((entry['key'], entry['value'])
                                                            for entry in workload_tag['attributes']
                                                            if entry['key'] != 'profileId')

                            # Get volume specific metadata tags
                            volume_metadata_raw = dict()
                            volume_metadata = dict()
                            for entry in volume['metadata']:
                                volume_metadata_raw.update({entry["key"]: entry["value"]})

                            for sorted_key in sorted(volume_metadata_raw.keys()):
                                if re.match(".*~[0-9]$", sorted_key):
                                    key = re.sub("~[0-9]$", "", sorted_key)
                                    if key in volume_metadata:
                                        volume_metadata[key] = volume_metadata[key] + volume_metadata_raw[sorted_key]
                                    else:
                                        volume_metadata.update({key: volume_metadata_raw[sorted_key]})
                                else:
                                    volume_metadata.update({sorted_key: volume_metadata_raw[sorted_key]})

                            # Determine drive count
                            stripe_count = 0
                            vg_drive_num = sum(1 for d in array_facts['drive'] if d['currentVolumeGroupRef'] == volume['volumeGroupRef'] and not d['hotSpare'])

                            if volume['raidLevel'] == "raidDiskPool":
                                stripe_count = 8
                            if volume['raidLevel'] == "raid0":
                                stripe_count = vg_drive_num
                            if volume['raidLevel'] == "raid1":
                                stripe_count = int(vg_drive_num / 2)
                            if volume['raidLevel'] in ["raid3", "raid5"]:
                                stripe_count = vg_drive_num - 1
                            if volume['raidLevel'] == "raid6":
                                stripe_count = vg_drive_num - 2

                            volume_info = {"type": volume['objectType'],
                                           "name": volume['name'],
                                           "storage_pool": storage_pool,
                                           "host_types": set(host_types),
                                           "host_port_information": host_port_information,
                                           "host_port_protocols": set(host_port_protocols),
                                           "hostside_io_interface_protocols": set(hostside_io_interface_protocols),
                                           "id": volume['id'],
                                           "wwn": volume['wwn'],
                                           "eui": volume['extendedUniqueIdentifier'],
                                           "workload_name": workload_name,
                                           "workload_metadata": metadata,
                                           "meta_data": metadata,
                                           "volume_metadata": volume_metadata,
                                           "raid_level": volume['raidLevel'],
                                           "segment_size_kb": int(volume['segmentSize'] / 1024),
                                           "stripe_count": stripe_count}
                            facts['netapp_volumes_by_initiators'][host['name']].append(volume_info)

                            # Use the base volume to populate related details for snapshot volumes.
                            for pit_view_volume in array_facts["highLevelVolBundle"]["pitView"]:
                                if volume["id"] == pit_view_volume["baseVol"]:
                                    pit_view_volume_info = volume_info.copy()
                                    pit_view_volume_info.update({"type": pit_view_volume["objectType"],
                                                                 "name": pit_view_volume['name'],
                                                                 "id": pit_view_volume['id'],
                                                                 "wwn": pit_view_volume['wwn'],
                                                                 "eui": pit_view_volume['extendedUniqueIdentifier']})
                                    facts['netapp_volumes_by_initiators'][host['name']].append(pit_view_volume_info)

        features = list(feature for feature in array_facts['sa']['capabilities'])
        features.extend([feature['capability'] for feature in array_facts['sa']['premiumFeatures']
                         if feature['isEnabled']])
        features = list(set(features))  # ensure unique
        features.sort()
        facts['netapp_enabled_features'] = features

        return facts

    def get_facts(self):
        """Get the embedded or web services proxy information."""
        facts = self.get_array_facts()

        facts_from_proxy = not self.is_embedded()
        facts.update({"facts_from_proxy": facts_from_proxy})

        self.module.exit_json(msg="Gathered facts for storage array. Array ID: [%s]." % self.ssid,
                              storage_array_facts=facts)


def strip_interface_speed(speed):
    """Converts symbol interface speeds to a more common notation. Example: 'speed10gig' -> '10g'"""
    if isinstance(speed, list):
        result = [re.match(r"speed[0-9]{1,3}[gm]", sp) for sp in speed]
        result = [sp.group().replace("speed", "") if result else "unknown" for sp in result if sp]
        result = ["auto" if re.match(r"auto", sp) else sp for sp in result]
    else:
        result = re.match(r"speed[0-9]{1,3}[gm]", speed)
        result = result.group().replace("speed", "") if result else "unknown"
        result = "auto" if re.match(r"auto", result.lower()) else result
    return result


def main():
    facts = Facts()
    facts.get_facts()


if __name__ == "__main__":
    main()
