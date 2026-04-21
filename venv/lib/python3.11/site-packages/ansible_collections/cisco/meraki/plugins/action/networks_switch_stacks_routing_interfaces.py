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
    defaultGateway=dict(type="str"),
    interfaceIp=dict(type="str"),
    ipv6=dict(type="dict"),
    multicastRouting=dict(type="str"),
    name=dict(type="str"),
    ospfSettings=dict(type="dict"),
    subnet=dict(type="str"),
    vlanId=dict(type="int"),
    networkId=dict(type="str"),
    switchStackId=dict(type="str"),
    interfaceId=dict(type="str"),
))

required_if = [
    ("state", "present", ["interfaceId", "name",
     "networkId", "switchStackId"], True),
    ("state", "absent", ["interfaceId", "name",
     "networkId", "switchStackId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksSwitchStacksRoutingInterfaces(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            defaultGateway=params.get("defaultGateway"),
            interfaceIp=params.get("interfaceIp"),
            ipv6=params.get("ipv6"),
            multicastRouting=params.get("multicastRouting"),
            name=params.get("name"),
            ospfSettings=params.get("ospfSettings"),
            subnet=params.get("subnet"),
            vlanId=params.get("vlanId"),
            networkId=params.get("networkId"),
            switchStackId=params.get("switchStackId"),
            interfaceId=params.get("interfaceId"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('protocol') is not None or self.new_object.get('protocol') is not None:
            new_object_params['protocol'] = self.new_object.get('protocol')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('switchStackId') is not None or self.new_object.get('switch_stack_id') is not None:
            new_object_params['switchStackId'] = self.new_object.get('switchStackId') or \
                self.new_object.get('switch_stack_id')
        return new_object_params

    def get_params_by_id(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('switchStackId') is not None or self.new_object.get('switch_stack_id') is not None:
            new_object_params['switchStackId'] = self.new_object.get('switchStackId') or \
                self.new_object.get('switch_stack_id')
        if self.new_object.get('interfaceId') is not None or self.new_object.get('interface_id') is not None:
            new_object_params['interfaceId'] = self.new_object.get('interfaceId') or \
                self.new_object.get('interface_id')
        return new_object_params

    def create_params(self):
        new_object_params = {}
        if self.new_object.get('defaultGateway') is not None or self.new_object.get('default_gateway') is not None:
            new_object_params['defaultGateway'] = self.new_object.get('defaultGateway') or \
                self.new_object.get('default_gateway')
        if self.new_object.get('interfaceIp') is not None or self.new_object.get('interface_ip') is not None:
            new_object_params['interfaceIp'] = self.new_object.get('interfaceIp') or \
                self.new_object.get('interface_ip')
        if self.new_object.get('ipv6') is not None or self.new_object.get('ipv6') is not None:
            new_object_params['ipv6'] = self.new_object.get('ipv6') or \
                self.new_object.get('ipv6')
        if self.new_object.get('multicastRouting') is not None or self.new_object.get('multicast_routing') is not None:
            new_object_params['multicastRouting'] = self.new_object.get('multicastRouting') or \
                self.new_object.get('multicast_routing')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('ospfSettings') is not None or self.new_object.get('ospf_settings') is not None:
            new_object_params['ospfSettings'] = self.new_object.get('ospfSettings') or \
                self.new_object.get('ospf_settings')
        if self.new_object.get('subnet') is not None or self.new_object.get('subnet') is not None:
            new_object_params['subnet'] = self.new_object.get('subnet') or \
                self.new_object.get('subnet')
        if self.new_object.get('vlanId') is not None or self.new_object.get('vlan_id') is not None:
            new_object_params['vlanId'] = self.new_object.get('vlanId') or \
                self.new_object.get('vlan_id')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('switchStackId') is not None or self.new_object.get('switch_stack_id') is not None:
            new_object_params['switchStackId'] = self.new_object.get('switchStackId') or \
                self.new_object.get('switch_stack_id')
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('switchStackId') is not None or self.new_object.get('switch_stack_id') is not None:
            new_object_params['switchStackId'] = self.new_object.get('switchStackId') or \
                self.new_object.get('switch_stack_id')
        if self.new_object.get('interfaceId') is not None or self.new_object.get('interface_id') is not None:
            new_object_params['interfaceId'] = self.new_object.get('interfaceId') or \
                self.new_object.get('interface_id')
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('defaultGateway') is not None or self.new_object.get('default_gateway') is not None:
            new_object_params['defaultGateway'] = self.new_object.get('defaultGateway') or \
                self.new_object.get('default_gateway')
        if self.new_object.get('interfaceIp') is not None or self.new_object.get('interface_ip') is not None:
            new_object_params['interfaceIp'] = self.new_object.get('interfaceIp') or \
                self.new_object.get('interface_ip')
        if self.new_object.get('ipv6') is not None or self.new_object.get('ipv6') is not None:
            new_object_params['ipv6'] = self.new_object.get('ipv6') or \
                self.new_object.get('ipv6')
        if self.new_object.get('multicastRouting') is not None or self.new_object.get('multicast_routing') is not None:
            new_object_params['multicastRouting'] = self.new_object.get('multicastRouting') or \
                self.new_object.get('multicast_routing')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('ospfSettings') is not None or self.new_object.get('ospf_settings') is not None:
            new_object_params['ospfSettings'] = self.new_object.get('ospfSettings') or \
                self.new_object.get('ospf_settings')
        if self.new_object.get('subnet') is not None or self.new_object.get('subnet') is not None:
            new_object_params['subnet'] = self.new_object.get('subnet') or \
                self.new_object.get('subnet')
        if self.new_object.get('vlanId') is not None or self.new_object.get('vlan_id') is not None:
            new_object_params['vlanId'] = self.new_object.get('vlanId') or \
                self.new_object.get('vlan_id')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('switchStackId') is not None or self.new_object.get('switch_stack_id') is not None:
            new_object_params['switchStackId'] = self.new_object.get('switchStackId') or \
                self.new_object.get('switch_stack_id')
        if self.new_object.get('interfaceId') is not None or self.new_object.get('interface_id') is not None:
            new_object_params['interfaceId'] = self.new_object.get('interfaceId') or \
                self.new_object.get('interface_id')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.meraki.exec_meraki(
                family="switch",
                function="getNetworkSwitchStackRoutingInterfaces",
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
                family="switch",
                function="getNetworkSwitchStackRoutingInterface",
                params=self.get_params_by_id()
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            result = get_dict_result(items, 'interfaceId', id)
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
            "interface_id") or self.new_object.get("interfaceId")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("interfaceId")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(interfaceId=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("defaultGateway", "defaultGateway"),
            ("interfaceIp", "interfaceIp"),
            ("ipv6", "ipv6"),
            ("multicastRouting", "multicastRouting"),
            ("name", "name"),
            ("ospfSettings", "ospfSettings"),
            ("subnet", "subnet"),
            ("vlanId", "vlanId"),
            ("networkId", "networkId"),
            ("switchStackId", "switchStackId"),
            ("interfaceId", "interfaceId"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (DNAC) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def create(self):
        result = self.meraki.exec_meraki(
            family="switch",
            function="createNetworkSwitchStackRoutingInterface",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("interfaceId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("interfaceId")
            if id_:
                self.new_object.update(dict(interfaceId=id_))
        result = self.meraki.exec_meraki(
            family="switch",
            function="updateNetworkSwitchStackRoutingInterface",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("interfaceId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("interfaceId")
            if id_:
                self.new_object.update(dict(interfaceId=id_))
        result = self.meraki.exec_meraki(
            family="switch",
            function="deleteNetworkSwitchStackRoutingInterface",
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
        obj = NetworksSwitchStacksRoutingInterfaces(self._task.args, meraki)

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
