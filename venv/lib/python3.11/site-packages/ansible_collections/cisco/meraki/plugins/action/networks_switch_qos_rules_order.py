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


# Get common arguments specification
argument_spec = meraki_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    state=dict(type="str", default="present", choices=["present", "absent"]),
    dscp=dict(type="int"),
    dstPort=dict(type="int"),
    dstPortRange=dict(type="str"),
    protocol=dict(type="str"),
    srcPort=dict(type="int"),
    srcPortRange=dict(type="str"),
    vlan=dict(type="int"),
    networkId=dict(type="str"),
    qosRuleId=dict(type="str"),
))

required_if = [
    ("state", "present", ["networkId", "qosRuleId"], True),
    ("state", "absent", ["networkId", "qosRuleId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksSwitchQosRulesOrder(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            dscp=params.get("dscp"),
            dstPort=params.get("dstPort"),
            dstPortRange=params.get("dstPortRange"),
            protocol=params.get("protocol"),
            srcPort=params.get("srcPort"),
            srcPortRange=params.get("srcPortRange"),
            vlan=params.get("vlan"),
            networkId=params.get("networkId"),
            qosRuleId=params.get("qosRuleId"),
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
        if self.new_object.get('qosRuleId') is not None or self.new_object.get('qos_rule_id') is not None:
            new_object_params['qosRuleId'] = self.new_object.get('qosRuleId') or \
                self.new_object.get('qos_rule_id')
        return new_object_params

    def create_params(self):
        new_object_params = {}
        if self.new_object.get('dscp') is not None or self.new_object.get('dscp') is not None:
            new_object_params['dscp'] = self.new_object.get('dscp') or \
                self.new_object.get('dscp')
        if self.new_object.get('dstPort') is not None or self.new_object.get('dst_port') is not None:
            new_object_params['dstPort'] = self.new_object.get('dstPort') or \
                self.new_object.get('dst_port')
        if self.new_object.get('dstPortRange') is not None or self.new_object.get('dst_port_range') is not None:
            new_object_params['dstPortRange'] = self.new_object.get('dstPortRange') or \
                self.new_object.get('dst_port_range')
        if self.new_object.get('protocol') is not None or self.new_object.get('protocol') is not None:
            new_object_params['protocol'] = self.new_object.get('protocol') or \
                self.new_object.get('protocol')
        if self.new_object.get('srcPort') is not None or self.new_object.get('src_port') is not None:
            new_object_params['srcPort'] = self.new_object.get('srcPort') or \
                self.new_object.get('src_port')
        if self.new_object.get('srcPortRange') is not None or self.new_object.get('src_port_range') is not None:
            new_object_params['srcPortRange'] = self.new_object.get('srcPortRange') or \
                self.new_object.get('src_port_range')
        if self.new_object.get('vlan') is not None or self.new_object.get('vlan') is not None:
            new_object_params['vlan'] = self.new_object.get('vlan') or \
                self.new_object.get('vlan')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('qosRuleId') is not None or self.new_object.get('qos_rule_id') is not None:
            new_object_params['qosRuleId'] = self.new_object.get('qosRuleId') or \
                self.new_object.get('qos_rule_id')
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('dscp') is not None or self.new_object.get('dscp') is not None:
            new_object_params['dscp'] = self.new_object.get('dscp') or \
                self.new_object.get('dscp')
        if self.new_object.get('dstPort') is not None or self.new_object.get('dst_port') is not None:
            new_object_params['dstPort'] = self.new_object.get('dstPort') or \
                self.new_object.get('dst_port')
        if self.new_object.get('dstPortRange') is not None or self.new_object.get('dst_port_range') is not None:
            new_object_params['dstPortRange'] = self.new_object.get('dstPortRange') or \
                self.new_object.get('dst_port_range')
        if self.new_object.get('protocol') is not None or self.new_object.get('protocol') is not None:
            new_object_params['protocol'] = self.new_object.get('protocol') or \
                self.new_object.get('protocol')
        if self.new_object.get('srcPort') is not None or self.new_object.get('src_port') is not None:
            new_object_params['srcPort'] = self.new_object.get('srcPort') or \
                self.new_object.get('src_port')
        if self.new_object.get('srcPortRange') is not None or self.new_object.get('src_port_range') is not None:
            new_object_params['srcPortRange'] = self.new_object.get('srcPortRange') or \
                self.new_object.get('src_port_range')
        if self.new_object.get('vlan') is not None or self.new_object.get('vlan') is not None:
            new_object_params['vlan'] = self.new_object.get('vlan') or \
                self.new_object.get('vlan')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('qosRuleId') is not None or self.new_object.get('qos_rule_id') is not None:
            new_object_params['qosRuleId'] = self.new_object.get('qosRuleId') or \
                self.new_object.get('qos_rule_id')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.meraki.exec_meraki(
                family="switch",
                function="getNetworkSwitchQosRules",
                params=self.get_all_params(name=name),
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            for item in items:
                if (item.get("vlan") == self.new_object.get("vlan") and
                        item.get("protocol") == self.new_object.get("protocol") and
                        item.get("srcPort") == self.new_object.get("srcPort") and
                        item.get("dstPort") == self.new_object.get("dstPort") and
                        item.get("srcPortRange") == self.new_object.get("srcPortRange") and
                        item.get("dstPortRange") == self.new_object.get("dstPortRange")):
                    result = item
                    break
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.meraki.exec_meraki(
                family="switch",
                function="getNetworkSwitchQosRule",
                params=self.get_params_by_id()
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            if id is not None:
                print("Is NOT NONE")
                result = get_dict_result(items, 'qosRuleId', id)
            else:
                # Validate if this
                print("Is NONE")
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def exists(self):
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("qosRuleId") or self.new_object.get("id")
        o_id = o_id or self.new_object.get(
            "qos_rule_id") or self.new_object.get("qosRuleId")
        name = self.new_object.get("name") or self.new_object.get("id")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
        else:
            print("Is NONE")
            prev_obj = self.get_object_by_name(name)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object
        current_obj["networkId"] = requested_obj.get("networkId") or None
        obj_params = [
            ("dscp", "dscp"),
            ("dstPort", "dstPort"),
            ("dstPortRange", "dstPortRange"),
            ("protocol", "protocol"),
            ("srcPort", "srcPort"),
            ("srcPortRange", "srcPortRange"),
            ("vlan", "vlan"),
            ("networkId", "networkId"),
            ("qosRuleId", "qosRuleId"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (DNAC) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def create(self):
        print("creating object.....")
        params = self.create_params()
        if params.get("vlan") is None:
            params["vlan"] = None
        print(params)
        result = self.meraki.exec_meraki(
            family="switch",
            function="createNetworkSwitchQosRule",
            params=params,
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("qosRuleId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("qosRuleId")
            if id_:
                self.new_object.update(dict(qosRuleId=id_))
        result = self.meraki.exec_meraki(
            family="switch",
            function="updateNetworkSwitchQosRule",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("qosRuleId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("qosRuleId")
            if id_:
                self.new_object.update(dict(qosRuleId=id_))
        result = self.meraki.exec_meraki(
            family="switch",
            function="deleteNetworkSwitchQosRule",
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
        obj = NetworksSwitchQosRulesOrder(self._task.args, meraki)

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
