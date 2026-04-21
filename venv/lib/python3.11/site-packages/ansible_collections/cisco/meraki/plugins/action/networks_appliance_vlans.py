#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type
from ansible.plugins.action import ActionBase
try:
    from ansible_collections.ansible.utils.plugins.module_utils.common.argspec_validate import (
        AnsibleArgSpecValidator,
    )
except ImportError:
    ANSIBLE_UTILS_IS_INSTALLED = False
else:
    ANSIBLE_UTILS_IS_INSTALLED = True
from ansible.errors import AnsibleActionFail
from ansible_collections.cisco.meraki.plugins.plugin_utils.meraki import (
    MERAKI,
    meraki_argument_spec,
    meraki_compare_equality2,
    get_dict_result,
)
from ansible_collections.cisco.meraki.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = meraki_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    applianceIp=dict(type="str"),
    cidr=dict(type="str"),
    dhcpBootOptionsEnabled=dict(type="bool"),
    dhcpHandling=dict(type="str"),
    dhcpLeaseTime=dict(type="str"),
    dhcpOptions=dict(type="list"),
    groupPolicyId=dict(type="str"),
    id=dict(type="str"),
    ipv6=dict(type="dict"),
    mandatoryDhcp=dict(type="dict"),
    mask=dict(type="int"),
    name=dict(type="str"),
    subnet=dict(type="str"),
    templateVlanType=dict(type="str"),
    networkId=dict(type="str"),
    vlanId=dict(type="str"),
    dhcpBootFilename=dict(type="str"),
    dhcpBootNextServer=dict(type="str"),
    dhcpRelayServerIps=dict(type="list"),
    dnsNameservers=dict(type="str"),
    fixedIpAssignments=dict(type="dict"),
    reservedIpRanges=dict(type="list"),
    vpnNatSubnet=dict(type="str"),
))

required_if = [
    ("state", "present", ["name", "networkId", "vlanId"], True),
    ("state", "absent", ["name", "networkId", "vlanId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksApplianceVlans(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            applianceIp=params.get("applianceIp"),
            cidr=params.get("cidr"),
            dhcpBootOptionsEnabled=params.get("dhcpBootOptionsEnabled"),
            dhcpHandling=params.get("dhcpHandling"),
            dhcpLeaseTime=params.get("dhcpLeaseTime"),
            dhcpOptions=params.get("dhcpOptions"),
            groupPolicyId=params.get("groupPolicyId"),
            id=params.get("id"),
            ipv6=params.get("ipv6"),
            mandatoryDhcp=params.get("mandatoryDhcp"),
            mask=params.get("mask"),
            name=params.get("name"),
            subnet=params.get("subnet"),
            templateVlanType=params.get("templateVlanType"),
            networkId=params.get("networkId"),
            vlanId=params.get("vlanId"),
            dhcpBootFilename=params.get("dhcpBootFilename"),
            dhcpBootNextServer=params.get("dhcpBootNextServer"),
            dhcpRelayServerIps=params.get("dhcpRelayServerIps"),
            dnsNameservers=params.get("dnsNameservers"),
            fixedIpAssignments=params.get("fixedIpAssignments"),
            reservedIpRanges=params.get("reservedIpRanges"),
            vpnNatSubnet=params.get("vpnNatSubnet"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def get_params_by_id(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('vlanId') is not None or self.new_object.get('vlan_id') is not None or \
                self.new_object.get('id') is not None:
            new_object_params['vlanId'] = self.new_object.get('id') or \
                self.new_object.get('id')
        return new_object_params

    def create_params(self):
        new_object_params = {}
        if self.new_object.get('applianceIp') is not None or self.new_object.get('appliance_ip') is not None:
            new_object_params['applianceIp'] = self.new_object.get('applianceIp') or \
                self.new_object.get('appliance_ip')
        if self.new_object.get('cidr') is not None or self.new_object.get('cidr') is not None:
            new_object_params['cidr'] = self.new_object.get('cidr') or \
                self.new_object.get('cidr')
        if self.new_object.get('dhcpBootOptionsEnabled') is not None or self.new_object.get('dhcp_boot_options_enabled') is not None:
            new_object_params['dhcpBootOptionsEnabled'] = self.new_object.get(
                'dhcpBootOptionsEnabled')
        if self.new_object.get('dhcpHandling') is not None or self.new_object.get('dhcp_handling') is not None:
            new_object_params['dhcpHandling'] = self.new_object.get('dhcpHandling') or \
                self.new_object.get('dhcp_handling')
        if self.new_object.get('dhcpLeaseTime') is not None or self.new_object.get('dhcp_lease_time') is not None:
            new_object_params['dhcpLeaseTime'] = self.new_object.get('dhcpLeaseTime') or \
                self.new_object.get('dhcp_lease_time')
        if self.new_object.get('dhcpOptions') is not None or self.new_object.get('dhcp_options') is not None:
            new_object_params['dhcpOptions'] = self.new_object.get('dhcpOptions') or \
                self.new_object.get('dhcp_options')
        if self.new_object.get('groupPolicyId') is not None or self.new_object.get('group_policy_id') is not None:
            new_object_params['groupPolicyId'] = self.new_object.get('groupPolicyId') or \
                self.new_object.get('group_policy_id')
        if self.new_object.get('id') is not None or self.new_object.get('id') is not None:
            new_object_params['id'] = self.new_object.get('id') or \
                self.new_object.get('id')
        if self.new_object.get('ipv6') is not None or self.new_object.get('ipv6') is not None:
            new_object_params['ipv6'] = self.new_object.get('ipv6') or \
                self.new_object.get('ipv6')
        if self.new_object.get('mandatoryDhcp') is not None or self.new_object.get('mandatory_dhcp') is not None:
            new_object_params['mandatoryDhcp'] = self.new_object.get('mandatoryDhcp') or \
                self.new_object.get('mandatory_dhcp')
        if self.new_object.get('mask') is not None or self.new_object.get('mask') is not None:
            new_object_params['mask'] = self.new_object.get('mask') or \
                self.new_object.get('mask')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('subnet') is not None or self.new_object.get('subnet') is not None:
            new_object_params['subnet'] = self.new_object.get('subnet') or \
                self.new_object.get('subnet')
        if self.new_object.get('templateVlanType') is not None or self.new_object.get('template_vlan_type') is not None:
            new_object_params['templateVlanType'] = self.new_object.get('templateVlanType') or \
                self.new_object.get('template_vlan_type')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('vlanId') is not None or self.new_object.get('vlan_id') is not None or \
                self.new_object.get('id') is not None:
            new_object_params['vlanId'] = self.new_object.get('id') or \
                self.new_object.get('id')
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('applianceIp') is not None or self.new_object.get('appliance_ip') is not None:
            new_object_params['applianceIp'] = self.new_object.get('applianceIp') or \
                self.new_object.get('appliance_ip')
        if self.new_object.get('cidr') is not None or self.new_object.get('cidr') is not None:
            new_object_params['cidr'] = self.new_object.get('cidr') or \
                self.new_object.get('cidr')
        if self.new_object.get('dhcpBootFilename') is not None or self.new_object.get('dhcp_boot_filename') is not None:
            new_object_params['dhcpBootFilename'] = self.new_object.get('dhcpBootFilename') or \
                self.new_object.get('dhcp_boot_filename')
        if self.new_object.get('dhcpBootNextServer') is not None or self.new_object.get('dhcp_boot_next_server') is not None:
            new_object_params['dhcpBootNextServer'] = self.new_object.get('dhcpBootNextServer') or \
                self.new_object.get('dhcp_boot_next_server')
        if self.new_object.get('dhcpBootOptionsEnabled') is not None or self.new_object.get('dhcp_boot_options_enabled') is not None:
            new_object_params['dhcpBootOptionsEnabled'] = self.new_object.get(
                'dhcpBootOptionsEnabled')
        if self.new_object.get('dhcpHandling') is not None or self.new_object.get('dhcp_handling') is not None:
            new_object_params['dhcpHandling'] = self.new_object.get('dhcpHandling') or \
                self.new_object.get('dhcp_handling')
        if self.new_object.get('dhcpLeaseTime') is not None or self.new_object.get('dhcp_lease_time') is not None:
            new_object_params['dhcpLeaseTime'] = self.new_object.get('dhcpLeaseTime') or \
                self.new_object.get('dhcp_lease_time')
        if self.new_object.get('dhcpOptions') is not None or self.new_object.get('dhcp_options') is not None:
            new_object_params['dhcpOptions'] = self.new_object.get('dhcpOptions') or \
                self.new_object.get('dhcp_options')
        if self.new_object.get('dhcpRelayServerIps') is not None or self.new_object.get('dhcp_relay_server_ips') is not None:
            new_object_params['dhcpRelayServerIps'] = self.new_object.get('dhcpRelayServerIps') or \
                self.new_object.get('dhcp_relay_server_ips')
        if self.new_object.get('dnsNameservers') is not None or self.new_object.get('dns_nameservers') is not None:
            new_object_params['dnsNameservers'] = self.new_object.get('dnsNameservers') or \
                self.new_object.get('dns_nameservers')
        if self.new_object.get('fixedIpAssignments') is not None or self.new_object.get('fixed_ip_assignments') is not None:
            new_object_params['fixedIpAssignments'] = self.new_object.get('fixedIpAssignments') or \
                self.new_object.get('fixed_ip_assignments')
        if self.new_object.get('groupPolicyId') is not None or self.new_object.get('group_policy_id') is not None:
            new_object_params['groupPolicyId'] = self.new_object.get('groupPolicyId') or \
                self.new_object.get('group_policy_id')
        if self.new_object.get('ipv6') is not None or self.new_object.get('ipv6') is not None:
            new_object_params['ipv6'] = self.new_object.get('ipv6') or \
                self.new_object.get('ipv6')
        if self.new_object.get('mandatoryDhcp') is not None or self.new_object.get('mandatory_dhcp') is not None:
            new_object_params['mandatoryDhcp'] = self.new_object.get('mandatoryDhcp') or \
                self.new_object.get('mandatory_dhcp')
        if self.new_object.get('mask') is not None or self.new_object.get('mask') is not None:
            new_object_params['mask'] = self.new_object.get('mask') or \
                self.new_object.get('mask')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('reservedIpRanges') is not None or self.new_object.get('reserved_ip_ranges') is not None:
            new_object_params['reservedIpRanges'] = self.new_object.get('reservedIpRanges') or \
                self.new_object.get('reserved_ip_ranges')
        if self.new_object.get('subnet') is not None or self.new_object.get('subnet') is not None:
            new_object_params['subnet'] = self.new_object.get('subnet') or \
                self.new_object.get('subnet')
        if self.new_object.get('templateVlanType') is not None or self.new_object.get('template_vlan_type') is not None:
            new_object_params['templateVlanType'] = self.new_object.get('templateVlanType') or \
                self.new_object.get('template_vlan_type')
        if self.new_object.get('vpnNatSubnet') is not None or self.new_object.get('vpn_nat_subnet') is not None:
            new_object_params['vpnNatSubnet'] = self.new_object.get('vpnNatSubnet') or \
                self.new_object.get('vpn_nat_subnet')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('vlanId') is not None or self.new_object.get('vlan_id') is not None or \
                self.new_object.get('id') is not None:
            new_object_params['vlanId'] = self.new_object.get('id') or \
                self.new_object.get('id')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.meraki.exec_meraki(
                family="appliance",
                function="getNetworkApplianceVlans",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            result = get_dict_result(items, 'name', name)
            if result is None:
                result = items
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.meraki.exec_meraki(
                family="appliance",
                function="getNetworkApplianceVlan",
                params=self.get_params_by_id()
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            result = get_dict_result(items, 'vlanId', id)
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def exists(self):
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("id")
        o_id = o_id or self.new_object.get(
            "vlan_id") or self.new_object.get("vlanId")
        name = None
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("vlanId")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(vlanId=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("applianceIp", "applianceIp"),
            ("cidr", "cidr"),
            ("dhcpBootOptionsEnabled", "dhcpBootOptionsEnabled"),
            ("dhcpHandling", "dhcpHandling"),
            ("dhcpLeaseTime", "dhcpLeaseTime"),
            ("dhcpOptions", "dhcpOptions"),
            ("groupPolicyId", "groupPolicyId"),
            ("id", "id"),
            ("ipv6", "ipv6"),
            ("mandatoryDhcp", "mandatoryDhcp"),
            ("mask", "mask"),
            ("name", "name"),
            ("subnet", "subnet"),
            ("templateVlanType", "templateVlanType"),
            ("networkId", "networkId"),
            ("vlanId", "vlanId"),
            ("dhcpBootFilename", "dhcpBootFilename"),
            ("dhcpBootNextServer", "dhcpBootNextServer"),
            ("dhcpRelayServerIps", "dhcpRelayServerIps"),
            ("dnsNameservers", "dnsNameservers"),
            ("fixedIpAssignments", "fixedIpAssignments"),
            ("reservedIpRanges", "reservedIpRanges"),
            ("vpnNatSubnet", "vpnNatSubnet"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (DNAC) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def create(self):
        result = self.meraki.exec_meraki(
            family="appliance",
            function="createNetworkApplianceVlan",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("vlanId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("vlanId")
            if id_:
                self.new_object.update(dict(vlanId=id_))
        result = self.meraki.exec_meraki(
            family="appliance",
            function="updateNetworkApplianceVlan",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("vlanId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("vlanId")
            if id_:
                self.new_object.update(dict(vlanId=id_))
        result = self.meraki.exec_meraki(
            family="appliance",
            function="deleteNetworkApplianceVlan",
            params=self.delete_by_id_params(),
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = False
        self._result = None

    # Checks the supplied parameters against the argument spec for this module
    def _check_argspec(self):
        aav = AnsibleArgSpecValidator(
            data=self._task.args,
            schema=dict(argument_spec=argument_spec),
            schema_format="argspec",
            schema_conditionals=dict(
                required_if=required_if,
                required_one_of=required_one_of,
                mutually_exclusive=mutually_exclusive,
                required_together=required_together,
            ),
            name=self._task.action,
        )
        valid, errors, self._task.args = aav.validate()
        if not valid:
            raise AnsibleActionFail(errors)

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        meraki = MERAKI(self._task.args)
        obj = NetworksApplianceVlans(self._task.args, meraki)

        state = self._task.args.get("state")

        response = None

        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = obj.update()
                    meraki.object_updated()
                else:
                    response = prev_obj
                    meraki.object_already_present()
            else:
                response = obj.create()
                meraki.object_created()

        elif state == "absent":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                response = obj.delete()
                meraki.object_deleted()
            else:
                meraki.object_already_absent()

        self._result.update(dict(meraki_response=response))
        self._result.update(meraki.exit_json())
        return self._result
