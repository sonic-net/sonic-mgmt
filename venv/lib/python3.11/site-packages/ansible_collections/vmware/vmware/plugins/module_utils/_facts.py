# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

# Note: This utility is considered private, and can only be referenced from inside the vmware.vmware collection.
#       It may be made public at a later date

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import json
import os

PYVMOMI_IMP_ERR = None
try:
    from pyVmomi import vim, vmodl, VmomiJSONEncoder
except ImportError:
    pass

from ansible.module_utils.common.text.converters import to_text
from collections.abc import Mapping
from ansible_collections.vmware.vmware.plugins.module_utils._folder_paths import get_folder_path_of_vsphere_object


class VmFacts():
    def __init__(self, vm):
        self.vm = vm

    def hw_all_facts(self):
        '''
        Returns a combined set of all 'hw_' facts
        '''
        return {
            **self.hw_general_facts(),
            **self.hw_folder_facts(),
            **self.hw_files_facts(),
            **self.hw_datastore_facts(),
            **self.hw_runtime_facts(),
            **self.hw_network_device_facts()
        }

    def all_facts(self, content):
        return {
            **self.hw_all_facts(),
            **self.identifier_facts(),
            **self.custom_attribute_facts(content),
            **self.advanced_settings_facts(),
            **self.guest_facts(),
            **self.ip_facts(),
            **self.snapshot_facts(),
            **self.vnc_facts(),
            **self.tpm_facts()
        }

    def identifier_facts(self):
        return {
            'instance_uuid': self.vm.config.instanceUuid,
            'moid': self.vm._moId,
            'vimref': "vim.VirtualMachine:%s" % self.vm._moId
        }

    def custom_attribute_facts(self, content):
        custom_value_facts = {}
        custom_fields_manager = content.customFieldsManager

        for custom_value_obj in self.vm.summary.customValue:
            if custom_fields_manager is None or not custom_fields_manager.field:
                custom_value_facts[custom_value_obj.key] = custom_value_obj.value
                continue

            for field in custom_fields_manager.field:
                if field.key == custom_value_obj.key:
                    custom_value_facts[field.name] = custom_value_obj.value
                    break

        return {
            'customvalues': custom_value_facts,
            'annotation': self.vm.config.annotation
        }

    def advanced_settings_facts(self):
        output = {}
        for advanced_setting in self.vm.config.extraConfig:
            output[advanced_setting.key] = advanced_setting.value

        return {'advanced_settings': output}

    def guest_facts(self):
        return {
            'guest_tools_status': get_vm_prop_or_none(self.vm, ('guest', 'toolsRunningStatus')),
            'guest_tools_version': get_vm_prop_or_none(self.vm, ('guest', 'toolsVersion')),
            'guest_question': json.loads(json.dumps(self.vm.summary.runtime.question, cls=VmomiJSONEncoder.VmomiJSONEncoder,
                                                    sort_keys=True, strip_dynamic=True)),
            'guest_consolidation_needed': self.vm.summary.runtime.consolidationNeeded,
        }

    def ip_facts(self):
        facts = {
            'ipv6': None,
            'ipv4': None
        }

        if self.vm.guest.ipAddress:
            if ':' in self.vm.guest.ipAddress:
                facts['ipv6'] = self.vm.guest.ipAddress
            else:
                facts['ipv4'] = self.vm.guest.ipAddress

        return facts

    def snapshot_facts(self):
        snapshots = []
        current_snapshot = None
        snapshot_facts = list_snapshots(self.vm)
        if 'snapshots' in snapshot_facts:
            snapshots = snapshot_facts['snapshots']
            current_snapshot = snapshot_facts['current_snapshot']

        return {
            'snapshots': snapshots,
            'current_snapshot': current_snapshot
        }

    def vnc_facts(self):
        facts = {}
        for opts in self.vm.config.extraConfig:
            for optkeyname in ['enabled', 'ip', 'port', 'password']:
                if opts.key.lower() == "remotedisplay.vnc." + optkeyname:
                    facts[optkeyname] = opts.value

        return {'vnc': facts}

    def tpm_facts(self):
        facts = {
            'tpm_present': None,
            'provider_id': None
        }

        if hasattr(self.vm.summary.config, 'tpmPresent'):
            facts['tpm_present'] = self.vm.summary.config.tpmPresent

        if self.vm.config.keyId:
            facts['provider_id'] = self.vm.config.keyId.providerId.id

        return {'tpm_info': facts}

    def hw_general_facts(self):
        '''
        Returns overview and summary 'hw_' facts
        '''
        return {
            'module_hw': True,
            'hw_name': self.vm.config.name,
            'hw_power_status': self.vm.summary.runtime.powerState,
            'hw_guest_full_name': self.vm.summary.guest.guestFullName,
            'hw_guest_id': self.vm.summary.guest.guestId,
            'hw_product_uuid': self.vm.config.uuid,
            'hw_processor_count': self.vm.config.hardware.numCPU,
            'hw_cores_per_socket': self.vm.config.hardware.numCoresPerSocket,
            'hw_memtotal_mb': self.vm.config.hardware.memoryMB,
            'hw_is_template': self.vm.config.template,
            'hw_version': self.vm.config.version,
        }

    def hw_folder_facts(self):
        try:
            hw_folder = get_folder_path_of_vsphere_object(self.vm)
        except Exception:
            hw_folder = None

        return {'hw_folder': hw_folder}

    def hw_files_facts(self):
        hw_files = []
        try:
            files = self.vm.config.files
            layout = self.vm.layout
            if files:
                hw_files = [files.vmPathName]
                for item in layout.snapshot:
                    for snap in item.snapshotFile:
                        if 'vmsn' in snap:
                            hw_files.append(snap)
                for item in layout.configFile:
                    hw_files.append(os.path.join(os.path.dirname(files.vmPathName), item))
                for item in self.vm.layout.logFile:
                    hw_files.append(os.path.join(files.logDirectory, item))
                for item in self.vm.layout.disk:
                    for disk in item.diskFile:
                        hw_files.append(disk)
        except Exception:
            pass

        return {'hw_files': hw_files}

    def hw_datastore_facts(self):
        output = []
        for ds in self.vm.datastore:
            output.append(ds.info.name)

        return {'hw_datastores': output}

    def hw_runtime_facts(self):
        output = {
            'hw_esxi_host': None,
            'hw_guest_ha_state': None
        }

        # facts that may or may not exist
        if self.vm.summary.runtime.host:
            try:
                host = self.vm.summary.runtime.host
                output['hw_esxi_host'] = host.summary.config.name
                if host.parent and isinstance(host.parent, vim.ClusterComputeResource):
                    output['hw_cluster'] = host.parent.name

            except vim.fault.NoPermission:
                # User does not have read permission for the host system,
                # proceed without this value. This value does not contribute or hamper
                # provisioning or power management operations.
                pass

        if self.vm.summary.runtime.dasVmProtection:
            output['hw_guest_ha_state'] = self.vm.summary.runtime.dasVmProtection.dasProtected

        return output

    def hw_network_device_facts(self):
        facts = {}
        hw_interfaces_facts = []
        ethernet_idx = 0

        vmnet = get_vm_prop_or_none(self.vm, ('guest', 'net'))
        net_dict = {}
        if vmnet:
            for device in vmnet:
                if device.deviceConfigId > 0:
                    net_dict[device.macAddress] = list(device.ipAddress)

        for hardware_device in self.vm.config.hardware.device:
            if not hasattr(hardware_device, 'macAddress'):
                continue

            if hardware_device.macAddress:
                mac_addr = hardware_device.macAddress
                mac_addr_dash = mac_addr.replace(':', '-')
            else:
                mac_addr = mac_addr_dash = None

            if (
                hasattr(hardware_device, "backing")
                and hasattr(hardware_device.backing, "port")
                and hasattr(hardware_device.backing.port, "portKey")
                and hasattr(hardware_device.backing.port, "portgroupKey")
            ):
                port_group_key = hardware_device.backing.port.portgroupKey
                port_key = hardware_device.backing.port.portKey
            else:
                port_group_key = None
                port_key = None

            facts['hw_eth' + str(ethernet_idx)] = {
                'addresstype': hardware_device.addressType,
                'label': hardware_device.deviceInfo.label,
                'macaddress': mac_addr,
                'ipaddresses': net_dict.get(hardware_device.macAddress, None),
                'macaddress_dash': mac_addr_dash,
                'summary': hardware_device.deviceInfo.summary,
                'portgroup_portkey': port_key,
                'portgroup_key': port_group_key,
            }
            hw_interfaces_facts.append('eth' + str(ethernet_idx))
            ethernet_idx += 1

        return {
            'hw_interfaces': hw_interfaces_facts,
            **facts
        }


class ClusterFacts():
    DPM_DEFAULT_RATE = 3
    DRS_DEFAULT_RATE = 3

    def __init__(self, cluster):
        self.cluster = cluster

    @staticmethod
    def reverse_drs_or_dpm_rate(input_rate):
        return 6 - int(input_rate)

    def all_facts(self):
        return {
            **self.host_facts(),
            **self.ha_facts(),
            **self.identifier_facts(),
            **self.drs_facts(),
            **self.vsan_facts(),
            **self.resource_usage_facts(),
            **self.dpm_facts()
        }

    def identifier_facts(self):
        return {
            "moid": self.cluster._moId,
            "datacenter": self.cluster.parent.parent.name
        }

    def host_facts(self):
        hosts = []
        for host in self.cluster.host:
            hosts.append({
                'name': host.name,
                'folder': get_folder_path_of_vsphere_object(host),
            })
        return {"hosts": hosts}

    def ha_facts(self):
        fact_keys = [
            "ha_enabled", "ha_failover_level", "ha_vm_monitoring", "ha_admission_control_enabled",
            "ha_restart_priority", "ha_vm_tools_monitoring", "ha_vm_min_up_time", "ha_vm_max_failures",
            "ha_vm_max_failure_window", "ha_vm_failure_interval"
        ]
        ha_facts = dict.fromkeys(fact_keys, None)
        das_config = self.cluster.configurationEx.dasConfig
        if not das_config:
            ha_facts['ha_enabled'] = False
            return ha_facts

        ha_facts["ha_enabled"] = das_config.enabled
        ha_facts["ha_vm_monitoring"] = das_config.vmMonitoring
        ha_facts["ha_host_monitoring"] = das_config.hostMonitoring
        ha_facts["ha_admission_control_enabled"] = das_config.admissionControlEnabled

        if getattr(das_config, "admissionControlPolicy"):
            ha_facts['ha_failover_level'] = das_config.admissionControlPolicy.failoverLevel
        if getattr(das_config, "defaultVmSettings"):
            ha_facts['ha_restart_priority'] = das_config.defaultVmSettings.restartPriority
            ha_facts['ha_vm_tools_monitoring'] = das_config.defaultVmSettings.vmToolsMonitoringSettings.vmMonitoring
            ha_facts['ha_vm_min_up_time'] = das_config.defaultVmSettings.vmToolsMonitoringSettings.minUpTime
            ha_facts['ha_vm_max_failures'] = das_config.defaultVmSettings.vmToolsMonitoringSettings.maxFailures
            ha_facts['ha_vm_max_failure_window'] = das_config.defaultVmSettings.vmToolsMonitoringSettings.maxFailureWindow
            ha_facts['ha_vm_failure_interval'] = das_config.defaultVmSettings.vmToolsMonitoringSettings.failureInterval

        return ha_facts

    def dpm_facts(self):
        fact_keys = ["dpm_enabled", "dpm_default_dpm_behavior", "dpm_host_power_action_rate"]
        output_facts = dict.fromkeys(fact_keys, None)
        dpm_config = self.cluster.configurationEx.dpmConfigInfo
        if not dpm_config:
            output_facts["dpm_enabled"] = False
            return output_facts

        output_facts["dpm_enabled"] = dpm_config.enabled
        output_facts["dpm_default_dpm_behavior"] = getattr(dpm_config, "defaultDpmBehavior", None)
        # dpm host power rate is reversed by the vsphere API. so a 1 in the API is really a 5 in the UI
        try:
            output_facts["dpm_host_power_action_rate"] = ClusterFacts.reverse_drs_or_dpm_rate(dpm_config.hostPowerActionRate)
        except (TypeError, AttributeError):
            output_facts["dpm_host_power_action_rate"] = ClusterFacts.DPM_DEFAULT_RATE

        return output_facts

    def drs_facts(self):
        fact_keys = ["drs_enabled", "drs_enable_vm_behavior_overrides", "drs_default_vm_behavior", "drs_vmotion_rate"]
        output_facts = dict.fromkeys(fact_keys, None)
        drs_config = self.cluster.configurationEx.drsConfig
        if not drs_config:
            output_facts["drs_enabled"] = False
            return output_facts

        output_facts["drs_enabled"] = drs_config.enabled
        output_facts["drs_enable_vm_behavior_overrides"] = getattr(drs_config, "enableVmBehaviorOverrides", None)

        # docs call one option 'automatic' but the API calls it 'automated'. So we adjust here to match docs
        _drs_default_vm_behavior = getattr(drs_config, "defaultVmBehavior", None)
        output_facts["drs_default_vm_behavior"] = 'automatic' if _drs_default_vm_behavior == 'automated' else _drs_default_vm_behavior

        # drs vmotion rate is reversed by the vsphere API. so a 1 in the API is really a 5 in the UI
        try:
            output_facts["drs_vmotion_rate"] = ClusterFacts.reverse_drs_or_dpm_rate(drs_config.vmotionRate)
        except (TypeError, AttributeError):
            output_facts["drs_vmotion_rate"] = ClusterFacts.DRS_DEFAULT_RATE

        return output_facts

    def vsan_facts(self):
        vsan_config = getattr(self.cluster.configurationEx, 'vsanConfigInfo', None)
        vsan_facts = {
            "vsan_enabled": False,
            "vsan_auto_claim_storage": None
        }
        if vsan_config:
            vsan_facts['vsan_enabled'] = vsan_config.enabled
            vsan_facts['vsan_auto_claim_storage'] = vsan_config.defaultConfig.autoClaimStorage
        return vsan_facts

    def resource_usage_facts(self):
        try:
            resource_summary = vmware_obj_to_json(self.cluster.GetResourceUsage())
        except vmodl.fault.MethodNotFound:
            return {'resource_summary': {}}

        if '_vimtype' in resource_summary:
            del resource_summary['_vimtype']
        return {'resource_summary': resource_summary}


def get_vm_prop_or_none(vm, attributes):
    """Safely get a property or return None"""
    result = vm
    for attribute in attributes:
        try:
            result = getattr(result, attribute)
        except (AttributeError, IndexError):
            return None
    return result


def deserialize_snapshot_obj(obj):
    return {'id': obj.id,
            'name': obj.name,
            'description': obj.description,
            'creation_time': obj.createTime,
            'state': obj.state,
            'quiesced': obj.quiesced}


def list_snapshots_recursively(snapshots):
    snapshot_data = []
    for snapshot in snapshots:
        snapshot_data.append(deserialize_snapshot_obj(snapshot))
        snapshot_data = snapshot_data + list_snapshots_recursively(snapshot.childSnapshotList)
    return snapshot_data


def get_current_snap_obj(snapshots, snapob):
    snap_obj = []
    for snapshot in snapshots:
        if snapshot.snapshot == snapob:
            snap_obj.append(snapshot)
        snap_obj = snap_obj + get_current_snap_obj(snapshot.childSnapshotList, snapob)
    return snap_obj


def list_snapshots(vm):
    result = {}
    snapshot = get_vm_prop_or_none(vm, ('snapshot',))
    if not snapshot:
        return result
    if vm.snapshot is None:
        return result

    result['snapshots'] = list_snapshots_recursively(vm.snapshot.rootSnapshotList)
    current_snapref = vm.snapshot.currentSnapshot
    current_snap_obj = get_current_snap_obj(vm.snapshot.rootSnapshotList, current_snapref)
    if current_snap_obj:
        result['current_snapshot'] = deserialize_snapshot_obj(current_snap_obj[0])
    else:
        result['current_snapshot'] = dict()
    return result


def serialize_spec(clonespec):
    """Serialize a clonespec or a relocation spec"""
    data = {}
    attrs = dir(clonespec)
    attrs = [x for x in attrs if not x.startswith('_')]
    for x in attrs:
        xo = getattr(clonespec, x)
        if callable(xo):
            continue
        xt = type(xo)
        if xo is None:
            data[x] = None
        elif isinstance(xo, vim.vm.ConfigSpec):
            data[x] = serialize_spec(xo)
        elif isinstance(xo, vim.vm.RelocateSpec):
            data[x] = serialize_spec(xo)
        elif isinstance(xo, vim.vm.device.VirtualDisk):
            data[x] = serialize_spec(xo)
        elif isinstance(xo, vim.vm.device.VirtualDeviceSpec.FileOperation):
            data[x] = to_text(xo)
        elif isinstance(xo, vim.Description):
            data[x] = {
                'dynamicProperty': serialize_spec(xo.dynamicProperty),
                'dynamicType': serialize_spec(xo.dynamicType),
                'label': serialize_spec(xo.label),
                'summary': serialize_spec(xo.summary),
            }
        elif hasattr(xo, 'name'):
            data[x] = to_text(xo) + ':' + to_text(xo.name)
        elif isinstance(xo, vim.vm.ProfileSpec):
            pass
        elif issubclass(xt, list):
            data[x] = []
            for xe in xo:
                data[x].append(serialize_spec(xe))
        elif issubclass(xt, (str, int, float, bool)):
            if issubclass(xt, int):
                data[x] = int(xo)
            else:
                data[x] = to_text(xo)
        elif issubclass(xt, bool):
            data[x] = xo
        elif issubclass(xt, dict):
            data[to_text(x)] = {}
            for k, v in xo.items():
                k = to_text(k)
                data[x][k] = serialize_spec(v)
        else:
            data[x] = str(xt)

    return data


#
# Conversion to JSON
#
def deepmerge_dicts(d, u):
    """
    Deep merges u into d.

    Credit:
        https://bit.ly/2EDOs1B (stackoverflow question 3232943)
    License:
        cc-by-sa 3.0 (https://creativecommons.org/licenses/by-sa/3.0/)

    Args:
        - d (dict): dict to merge into
        - u (dict): dict to merge into d

    Returns:
        dict, with u merged into d
    """
    for k, v in u.items():
        if isinstance(v, Mapping):
            d[k] = deepmerge_dicts(d.get(k, {}), v)
        else:
            d[k] = v
    return d


def extract_object_attributes_to_dict(obj, convert_to_strings=True):
    """
    Takes the attribute key/values from a object and puts them in a dict. Nested attributes
    and their hierarchy is preserved. Optionally all values are converted to strings
    Args:
      obj: the object your want to export to a dict
      convert_to_strings: If true, all values will be converted to strings instead of other primitives
    """
    output_dict = {}

    for attr_key, attr_val in vars(obj).items():
        if not attr_key.startswith('_'):
            if hasattr(attr_val, '__dict__') and not isinstance(attr_val, str):
                output_dict[attr_key] = extract_object_attributes_to_dict(attr_val)
            else:
                output_dict[attr_key] = str(attr_val) if convert_to_strings else attr_val

    return output_dict


def extract_dotted_property_to_dict(data, remainder):
    """
    This is used to break down dotted properties for extraction.

    Args:
        - data (dict): result of _jsonify on a property
        - remainder: the remainder of the dotted property to select

    Return:
        dict
    """
    result = dict()
    if '.' not in remainder:
        result[remainder] = data[remainder]
        return result
    key, remainder = remainder.split('.', 1)
    if isinstance(data, list):
        temp_ds = []
        for i in range(len(data)):
            temp_ds.append(extract_dotted_property_to_dict(data[i][key], remainder))
        result[key] = temp_ds
    else:
        result[key] = extract_dotted_property_to_dict(data[key], remainder)
    return result


def _jsonify_vmware_object(obj):
    """
    Convert an object from pyVmomi into JSON.

    Args:
        - obj (object): vim object

    Return:
        dict
    """
    return json.loads(json.dumps(obj, cls=VmomiJSONEncoder.VmomiJSONEncoder,
                                 sort_keys=True, strip_dynamic=True))


def vmware_obj_to_json(obj, properties=None):
    """
    Convert a vSphere (pyVmomi) Object into JSON.  This is a deep
    transformation.  The list of properties is optional - if not
    provided then all properties are deeply converted.  The resulting
    JSON is sorted to improve human readability.

    Args:
        - obj (object): vim object
        - properties (list, optional): list of properties following
            the property collector specification, for example:
            ["config.hardware.memoryMB", "name", "overallStatus"]
            default is a complete object dump, which can be large

    Return:
        dict
    """
    result = dict()
    if properties:
        for prop in properties:
            try:
                if '.' in prop:
                    key, remainder = prop.split('.', 1)
                    tmp = dict()
                    tmp[key] = extract_dotted_property_to_dict(_jsonify_vmware_object(getattr(obj, key)), remainder)
                    deepmerge_dicts(result, tmp)
                else:
                    result[prop] = _jsonify_vmware_object(getattr(obj, prop))
                    # To match gather_vm_facts output
                    prop_name = prop
                    if prop.lower() == '_moid':
                        prop_name = 'moid'
                    elif prop.lower() == '_vimref':
                        prop_name = 'vimref'
                    result[prop_name] = result[prop]
            except (AttributeError, KeyError):
                raise AttributeError("Property '%s' not found." % prop)
    else:
        result = _jsonify_vmware_object(obj)
    return result


def flatten_dict(dictionary, separator=".", parent_key=""):
    """
    Changes nested dictionary keys to be their dot notation versions, so the dictionary
    only has one level of depth.
    For example {"foo":{"bar":1}} would become {"foo.bar":1}
    Args:
        dictionary: dict, The original dictionary
        separator: str, A character to use to separate keys once they are flattened
        parent_key: str, Used as part of the recursion inside this method.
    Returns:
        dict
    """
    new_dict_items = []
    for k, v in dictionary.items():
        new_key = parent_key + separator + k if parent_key else k
        if v and isinstance(v, dict):
            new_dict_items.extend(
                flatten_dict(dictionary=v, separator=separator, parent_key=new_key)
                .items()
            )
        else:
            new_dict_items.append((new_key, v))
    return dict(new_dict_items)
