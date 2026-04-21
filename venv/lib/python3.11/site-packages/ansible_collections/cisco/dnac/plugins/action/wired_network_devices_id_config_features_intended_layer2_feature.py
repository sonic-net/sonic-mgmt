#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

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
from ansible_collections.cisco.dnac.plugins.plugin_utils.dnac import (
    DNACSDK,
    dnac_argument_spec,
    dnac_compare_equality,
    get_dict_result,
)
from ansible_collections.cisco.dnac.plugins.plugin_utils.exceptions import (
    InconsistentParameters,
)

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        state=dict(type="str", default="present", choices=["present", "absent"]),
        cdpGlobalConfig=dict(type="dict"),
        cdpInterfaceConfig=dict(type="dict"),
        dhcpSnoopingInterfaceConfig=dict(type="dict"),
        dhcpSnoopingGlobalConfig=dict(type="dict"),
        dot1xInterfaceConfig=dict(type="dict"),
        dot1xGlobalConfig=dict(type="dict"),
        lldpGlobalConfig=dict(type="dict"),
        lldpInterfaceConfig=dict(type="dict"),
        mabInterfaceConfig=dict(type="dict"),
        mldSnoopingGlobalConfig=dict(type="dict"),
        igmpSnoopingGlobalConfig=dict(type="dict"),
        stpGlobalConfig=dict(type="dict"),
        stpInterfaceConfig=dict(type="dict"),
        trunkInterfaceConfig=dict(type="dict"),
        vtpGlobalConfig=dict(type="dict"),
        vtpInterfaceConfig=dict(type="dict"),
        vlanConfig=dict(type="dict"),
        portChannelConfig=dict(type="dict"),
        switchportInterfaceConfig=dict(type="dict"),
        id=dict(type="str"),
        feature=dict(type="str"),
    )
)

required_if = [
    ("state", "present", ["feature", "id"], True),
    ("state", "absent", ["feature", "id"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class WiredNetworkDevicesIdConfigFeaturesIntendedLayer2Feature(object):
    def __init__(self, params, dnac):
        self.dnac = dnac
        self.new_object = dict(
            cdpGlobalConfig=params.get("cdpGlobalConfig"),
            cdpInterfaceConfig=params.get("cdpInterfaceConfig"),
            dhcpSnoopingInterfaceConfig=params.get("dhcpSnoopingInterfaceConfig"),
            dhcpSnoopingGlobalConfig=params.get("dhcpSnoopingGlobalConfig"),
            dot1xInterfaceConfig=params.get("dot1xInterfaceConfig"),
            dot1xGlobalConfig=params.get("dot1xGlobalConfig"),
            lldpGlobalConfig=params.get("lldpGlobalConfig"),
            lldpInterfaceConfig=params.get("lldpInterfaceConfig"),
            mabInterfaceConfig=params.get("mabInterfaceConfig"),
            mldSnoopingGlobalConfig=params.get("mldSnoopingGlobalConfig"),
            igmpSnoopingGlobalConfig=params.get("igmpSnoopingGlobalConfig"),
            stpGlobalConfig=params.get("stpGlobalConfig"),
            stpInterfaceConfig=params.get("stpInterfaceConfig"),
            trunkInterfaceConfig=params.get("trunkInterfaceConfig"),
            vtpGlobalConfig=params.get("vtpGlobalConfig"),
            vtpInterfaceConfig=params.get("vtpInterfaceConfig"),
            vlanConfig=params.get("vlanConfig"),
            portChannelConfig=params.get("portChannelConfig"),
            switchportInterfaceConfig=params.get("switchportInterfaceConfig"),
            id=params.get("id"),
            feature=params.get("feature"),
        )

    def create_params(self):
        new_object_params = {}
        new_object_params["cdpGlobalConfig"] = self.new_object.get("cdpGlobalConfig")
        new_object_params["cdpInterfaceConfig"] = self.new_object.get(
            "cdpInterfaceConfig"
        )
        new_object_params["dhcpSnoopingInterfaceConfig"] = self.new_object.get(
            "dhcpSnoopingInterfaceConfig"
        )
        new_object_params["dhcpSnoopingGlobalConfig"] = self.new_object.get(
            "dhcpSnoopingGlobalConfig"
        )
        new_object_params["dot1xInterfaceConfig"] = self.new_object.get(
            "dot1xInterfaceConfig"
        )
        new_object_params["dot1xGlobalConfig"] = self.new_object.get(
            "dot1xGlobalConfig"
        )
        new_object_params["lldpGlobalConfig"] = self.new_object.get("lldpGlobalConfig")
        new_object_params["lldpInterfaceConfig"] = self.new_object.get(
            "lldpInterfaceConfig"
        )
        new_object_params["mabInterfaceConfig"] = self.new_object.get(
            "mabInterfaceConfig"
        )
        new_object_params["mldSnoopingGlobalConfig"] = self.new_object.get(
            "mldSnoopingGlobalConfig"
        )
        new_object_params["igmpSnoopingGlobalConfig"] = self.new_object.get(
            "igmpSnoopingGlobalConfig"
        )
        new_object_params["stpGlobalConfig"] = self.new_object.get("stpGlobalConfig")
        new_object_params["stpInterfaceConfig"] = self.new_object.get(
            "stpInterfaceConfig"
        )
        new_object_params["trunkInterfaceConfig"] = self.new_object.get(
            "trunkInterfaceConfig"
        )
        new_object_params["vtpGlobalConfig"] = self.new_object.get("vtpGlobalConfig")
        new_object_params["vtpInterfaceConfig"] = self.new_object.get(
            "vtpInterfaceConfig"
        )
        new_object_params["vlanConfig"] = self.new_object.get("vlanConfig")
        new_object_params["portChannelConfig"] = self.new_object.get(
            "portChannelConfig"
        )
        new_object_params["switchportInterfaceConfig"] = self.new_object.get(
            "switchportInterfaceConfig"
        )
        new_object_params["id"] = self.new_object.get("id")
        new_object_params["feature"] = self.new_object.get("feature")
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        new_object_params["id"] = self.new_object.get("id")
        new_object_params["feature"] = self.new_object.get("feature")
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        new_object_params["cdpGlobalConfig"] = self.new_object.get("cdpGlobalConfig")
        new_object_params["cdpInterfaceConfig"] = self.new_object.get(
            "cdpInterfaceConfig"
        )
        new_object_params["dhcpSnoopingInterfaceConfig"] = self.new_object.get(
            "dhcpSnoopingInterfaceConfig"
        )
        new_object_params["dhcpSnoopingGlobalConfig"] = self.new_object.get(
            "dhcpSnoopingGlobalConfig"
        )
        new_object_params["dot1xInterfaceConfig"] = self.new_object.get(
            "dot1xInterfaceConfig"
        )
        new_object_params["dot1xGlobalConfig"] = self.new_object.get(
            "dot1xGlobalConfig"
        )
        new_object_params["lldpGlobalConfig"] = self.new_object.get("lldpGlobalConfig")
        new_object_params["lldpInterfaceConfig"] = self.new_object.get(
            "lldpInterfaceConfig"
        )
        new_object_params["mabInterfaceConfig"] = self.new_object.get(
            "mabInterfaceConfig"
        )
        new_object_params["mldSnoopingGlobalConfig"] = self.new_object.get(
            "mldSnoopingGlobalConfig"
        )
        new_object_params["igmpSnoopingGlobalConfig"] = self.new_object.get(
            "igmpSnoopingGlobalConfig"
        )
        new_object_params["stpGlobalConfig"] = self.new_object.get("stpGlobalConfig")
        new_object_params["stpInterfaceConfig"] = self.new_object.get(
            "stpInterfaceConfig"
        )
        new_object_params["trunkInterfaceConfig"] = self.new_object.get(
            "trunkInterfaceConfig"
        )
        new_object_params["vtpGlobalConfig"] = self.new_object.get("vtpGlobalConfig")
        new_object_params["vtpInterfaceConfig"] = self.new_object.get(
            "vtpInterfaceConfig"
        )
        new_object_params["vlanConfig"] = self.new_object.get("vlanConfig")
        new_object_params["portChannelConfig"] = self.new_object.get(
            "portChannelConfig"
        )
        new_object_params["switchportInterfaceConfig"] = self.new_object.get(
            "switchportInterfaceConfig"
        )
        new_object_params["id"] = self.new_object.get("id")
        new_object_params["feature"] = self.new_object.get("feature")
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        # NOTE: Does not have get all
        return result

    def get_object_by_id(self, id):
        result = None
        try:
            items = self.dnac.exec(
                family="wired",
                function="get_configurations_for_an_intended_layer2_feature_on_a_wired_device",
                params={"feature": id},
            )
            if isinstance(items, dict):
                if "response" in items:
                    items = items.get("response")
            result = get_dict_result(items, "feature", id)
        except Exception:
            result = None
        return result

    def exists(self):
        id_exists = False
        name_exists = False
        prev_obj = None
        o_id = self.new_object.get("id")
        o_id = o_id or self.new_object.get("feature")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("feature")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object"
                )
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(feature=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("cdpGlobalConfig", "cdpGlobalConfig"),
            ("cdpInterfaceConfig", "cdpInterfaceConfig"),
            ("dhcpSnoopingInterfaceConfig", "dhcpSnoopingInterfaceConfig"),
            ("dhcpSnoopingGlobalConfig", "dhcpSnoopingGlobalConfig"),
            ("dot1xInterfaceConfig", "dot1xInterfaceConfig"),
            ("dot1xGlobalConfig", "dot1xGlobalConfig"),
            ("lldpGlobalConfig", "lldpGlobalConfig"),
            ("lldpInterfaceConfig", "lldpInterfaceConfig"),
            ("mabInterfaceConfig", "mabInterfaceConfig"),
            ("mldSnoopingGlobalConfig", "mldSnoopingGlobalConfig"),
            ("igmpSnoopingGlobalConfig", "igmpSnoopingGlobalConfig"),
            ("stpGlobalConfig", "stpGlobalConfig"),
            ("stpInterfaceConfig", "stpInterfaceConfig"),
            ("trunkInterfaceConfig", "trunkInterfaceConfig"),
            ("vtpGlobalConfig", "vtpGlobalConfig"),
            ("vtpInterfaceConfig", "vtpInterfaceConfig"),
            ("vlanConfig", "vlanConfig"),
            ("portChannelConfig", "portChannelConfig"),
            ("switchportInterfaceConfig", "switchportInterfaceConfig"),
            ("id", "id"),
            ("feature", "feature"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (DNAC) params
        # If any does not have eq params, it requires update
        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param) in obj_params
        )

    def create(self):
        result = self.dnac.exec(
            family="wired",
            function="create_configurations_for_an_intended_layer2_feature_on_a_wired_device",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("feature")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("feature")
            if id_:
                self.new_object.update(dict(feature=id_))
        result = self.dnac.exec(
            family="wired",
            function="update_configurations_for_an_intended_layer2_feature_on_a_wired_device",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("feature")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("feature")
            if id_:
                self.new_object.update(dict(feature=id_))
        result = self.dnac.exec(
            family="wired",
            function="delete_configurations_for_an_intended_layer2_feature_on_a_wired_device",
            params=self.delete_by_id_params(),
        )
        return result


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'"
            )
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

        dnac = DNACSDK(self._task.args)
        obj = WiredNetworkDevicesIdConfigFeaturesIntendedLayer2Feature(
            self._task.args, dnac
        )

        state = self._task.args.get("state")

        response = None

        if state == "present":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                if obj.requires_update(prev_obj):
                    response = obj.update()
                    dnac.object_updated()
                else:
                    response = prev_obj
                    dnac.object_already_present()
            else:
                response = obj.create()
                dnac.object_created()

        elif state == "absent":
            (obj_exists, prev_obj) = obj.exists()
            if obj_exists:
                response = obj.delete()
                dnac.object_deleted()
            else:
                dnac.object_already_absent()

        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
