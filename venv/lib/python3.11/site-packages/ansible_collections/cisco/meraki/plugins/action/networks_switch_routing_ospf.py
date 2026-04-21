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
    state=dict(type="str", default="present", choices=["present"]),
    areas=dict(type="list"),
    deadTimerInSeconds=dict(type="int"),
    enabled=dict(type="bool"),
    helloTimerInSeconds=dict(type="int"),
    md5AuthenticationEnabled=dict(type="bool"),
    md5AuthenticationKey=dict(type="dict"),
    v3=dict(type="dict"),
    networkId=dict(type="str"),
))

required_if = [
    ("state", "present", ["networkId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksSwitchRoutingOspf(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            areas=params.get("areas"),
            deadTimerInSeconds=params.get("deadTimerInSeconds"),
            enabled=params.get("enabled"),
            helloTimerInSeconds=params.get("helloTimerInSeconds"),
            md5AuthenticationEnabled=params.get("md5AuthenticationEnabled"),
            md5AuthenticationKey=params.get("md5AuthenticationKey"),
            v3=params.get("v3"),
            network_id=params.get("networkId"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        if self.new_object.get('areas') is not None or self.new_object.get('areas') is not None:
            new_object_params['areas'] = self.new_object.get('areas') or \
                self.new_object.get('areas')
        if self.new_object.get('deadTimerInSeconds') is not None or self.new_object.get('dead_timer_in_seconds') is not None:
            new_object_params['deadTimerInSeconds'] = self.new_object.get('deadTimerInSeconds') or \
                self.new_object.get('dead_timer_in_seconds')
        if self.new_object.get('enabled') is not None or self.new_object.get('enabled') is not None:
            new_object_params['enabled'] = self.new_object.get('enabled')
        if self.new_object.get('helloTimerInSeconds') is not None or self.new_object.get('hello_timer_in_seconds') is not None:
            new_object_params['helloTimerInSeconds'] = self.new_object.get('helloTimerInSeconds') or \
                self.new_object.get('hello_timer_in_seconds')
        if self.new_object.get('md5AuthenticationEnabled') is not None or self.new_object.get('md5_authentication_enabled') is not None:
            new_object_params['md5AuthenticationEnabled'] = self.new_object.get(
                'md5AuthenticationEnabled')
        if self.new_object.get('md5AuthenticationKey') is not None or self.new_object.get('md5_authentication_key') is not None:
            new_object_params['md5AuthenticationKey'] = self.new_object.get('md5AuthenticationKey') or \
                self.new_object.get('md5_authentication_key')
        if self.new_object.get('v3') is not None or self.new_object.get('v3') is not None:
            new_object_params['v3'] = self.new_object.get('v3') or \
                self.new_object.get('v3')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.meraki.exec_meraki(
                family="switch",
                function="getNetworkSwitchRoutingOspf",
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
        # NOTE: Does not have a get by id method or it is in another action
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get(
            "networkId") or self.new_object.get("network_id")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_name(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("areas", "areas"),
            ("deadTimerInSeconds", "deadTimerInSeconds"),
            ("enabled", "enabled"),
            ("helloTimerInSeconds", "helloTimerInSeconds"),
            ("md5AuthenticationEnabled", "md5AuthenticationEnabled"),
            ("md5AuthenticationKey", "md5AuthenticationKey"),
            ("v3", "v3"),
            ("networkId", "networkId"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        name = self.new_object.get("name")
        result = None
        result = self.meraki.exec_meraki(
            family="switch",
            function="updateNetworkSwitchRoutingOspf",
            params=self.update_all_params(),
            op_modifies=True,
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
        obj = NetworksSwitchRoutingOspf(self._task.args, meraki)

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
                meraki.fail_json(
                    "Object does not exists, plugin only has update")

        self._result.update(dict(meraki_response=response))
        self._result.update(meraki.exit_json())
        return self._result
