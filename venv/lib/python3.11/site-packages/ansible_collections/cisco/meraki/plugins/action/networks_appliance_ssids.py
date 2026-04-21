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
    authMode=dict(type="str"),
    defaultVlanId=dict(type="int"),
    dhcpEnforcedDeauthentication=dict(type="dict"),
    dot11w=dict(type="dict"),
    enabled=dict(type="bool"),
    encryptionMode=dict(type="str"),
    name=dict(type="str"),
    psk=dict(type="str"),
    radiusServers=dict(type="list"),
    visible=dict(type="bool"),
    wpaEncryptionMode=dict(type="str"),
    networkId=dict(type="str"),
    number=dict(type="str"),
))

required_if = [
    ("state", "present", ["name", "networkId", "number"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksApplianceSsids(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            authMode=params.get("authMode"),
            defaultVlanId=params.get("defaultVlanId"),
            dhcpEnforcedDeauthentication=params.get(
                "dhcpEnforcedDeauthentication"),
            dot11w=params.get("dot11w"),
            enabled=params.get("enabled"),
            encryptionMode=params.get("encryptionMode"),
            name=params.get("name"),
            psk=params.get("psk"),
            radiusServers=params.get("radiusServers"),
            visible=params.get("visible"),
            wpaEncryptionMode=params.get("wpaEncryptionMode"),
            network_id=params.get("networkId"),
            number=params.get("number"),
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
        if self.new_object.get('number') is not None or self.new_object.get('number') is not None:
            new_object_params['number'] = self.new_object.get('number')
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('authMode') is not None or self.new_object.get('auth_mode') is not None:
            new_object_params['authMode'] = self.new_object.get('authMode') or \
                self.new_object.get('auth_mode')
        if self.new_object.get('defaultVlanId') is not None or self.new_object.get('default_vlan_id') is not None:
            new_object_params['defaultVlanId'] = self.new_object.get('defaultVlanId') or \
                self.new_object.get('default_vlan_id')
        if self.new_object.get('dhcpEnforcedDeauthentication') is not None or self.new_object.get('dhcp_enforced_deauthentication') is not None:
            new_object_params['dhcpEnforcedDeauthentication'] = self.new_object.get('dhcpEnforcedDeauthentication') or \
                self.new_object.get('dhcp_enforced_deauthentication')
        if self.new_object.get('dot11w') is not None or self.new_object.get('dot11w') is not None:
            new_object_params['dot11w'] = self.new_object.get('dot11w') or \
                self.new_object.get('dot11w')
        if self.new_object.get('enabled') is not None or self.new_object.get('enabled') is not None:
            new_object_params['enabled'] = self.new_object.get('enabled')
        if self.new_object.get('encryptionMode') is not None or self.new_object.get('encryption_mode') is not None:
            new_object_params['encryptionMode'] = self.new_object.get('encryptionMode') or \
                self.new_object.get('encryption_mode')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('psk') is not None or self.new_object.get('psk') is not None:
            new_object_params['psk'] = self.new_object.get('psk') or \
                self.new_object.get('psk')
        if self.new_object.get('radiusServers') is not None or self.new_object.get('radius_servers') is not None:
            new_object_params['radiusServers'] = self.new_object.get('radiusServers') or \
                self.new_object.get('radius_servers')
        if self.new_object.get('visible') is not None or self.new_object.get('visible') is not None:
            new_object_params['visible'] = self.new_object.get('visible')
        if self.new_object.get('wpaEncryptionMode') is not None or self.new_object.get('wpa_encryption_mode') is not None:
            new_object_params['wpaEncryptionMode'] = self.new_object.get('wpaEncryptionMode') or \
                self.new_object.get('wpa_encryption_mode')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('number') is not None or self.new_object.get('number') is not None:
            new_object_params['number'] = self.new_object.get('number') or \
                self.new_object.get('number')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.meraki.exec_meraki(
                family="appliance",
                function="getNetworkApplianceSsids",
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
                function="getNetworkApplianceSsid",
                params=self.get_params_by_id()
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            result = items
        except Exception as e:
            print("Error: ", e)
            result = None
        return result

    def exists(self):
        prev_obj = None
        id_exists = False
        name_exists = False
        o_id = self.new_object.get(
            "networkId") or self.new_object.get("network_id")
        o_id = o_id or self.new_object.get(
            "number") or self.new_object.get("number")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("number")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(number=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("authMode", "authMode"),
            ("defaultVlanId", "defaultVlanId"),
            ("dhcpEnforcedDeauthentication", "dhcpEnforcedDeauthentication"),
            ("dot11w", "dot11w"),
            ("enabled", "enabled"),
            ("encryptionMode", "encryptionMode"),
            ("name", "name"),
            ("psk", "psk"),
            ("radiusServers", "radiusServers"),
            ("visible", "visible"),
            ("wpaEncryptionMode", "wpaEncryptionMode"),
            ("networkId", "networkId"),
            ("number", "number"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("number")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("number")
            if id_:
                self.new_object.update(dict(number=id_))
        result = self.meraki.exec_meraki(
            family="appliance",
            function="updateNetworkApplianceSsid",
            params=self.update_by_id_params(),
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
        obj = NetworksApplianceSsids(self._task.args, meraki)

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
