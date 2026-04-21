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
    address=dict(type="str"),
    floorPlanId=dict(type="str"),
    lat=dict(type="float"),
    lng=dict(type="float"),
    moveMapMarker=dict(type="bool"),
    name=dict(type="str"),
    notes=dict(type="str"),
    switchProfileId=dict(type="str"),
    tags=dict(type="list"),
    serial=dict(type="str"),
    organizationId=dict(type="str"),
))

required_if = [
    ("state", "present", ["name", "organizationId", "serial"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class Devices(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            address=params.get("address"),
            floorPlanId=params.get("floorPlanId"),
            lat=params.get("lat"),
            lng=params.get("lng"),
            moveMapMarker=params.get("moveMapMarker"),
            name=params.get("name"),
            notes=params.get("notes"),
            switchProfileId=params.get("switchProfileId"),
            tags=params.get("tags"),
            serial=params.get("serial"),
            organization_id=params.get("organizationId"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('perPage') is not None or self.new_object.get('per_page') is not None:
            new_object_params['perPage'] = self.new_object.get('perPage') or \
                self.new_object.get('per_page')
        new_object_params['total_pages'] = -1
        if self.new_object.get('startingAfter') is not None or self.new_object.get('starting_after') is not None:
            new_object_params['startingAfter'] = self.new_object.get('startingAfter') or \
                self.new_object.get('starting_after')
        if self.new_object.get('endingBefore') is not None or self.new_object.get('ending_before') is not None:
            new_object_params['endingBefore'] = self.new_object.get('endingBefore') or \
                self.new_object.get('ending_before')
        if self.new_object.get('configurationUpdatedAfter') is not None or self.new_object.get('configuration_updated_after') is not None:
            new_object_params['configurationUpdatedAfter'] = self.new_object.get('configurationUpdatedAfter') or \
                self.new_object.get('configuration_updated_after')
        if self.new_object.get('networkIds') is not None or self.new_object.get('network_ids') is not None:
            new_object_params['networkIds'] = self.new_object.get('networkIds') or \
                self.new_object.get('network_ids')
        if self.new_object.get('productTypes') is not None or self.new_object.get('product_types') is not None:
            new_object_params['productTypes'] = self.new_object.get('productTypes') or \
                self.new_object.get('product_types')
        if self.new_object.get('tags') is not None or self.new_object.get('tags') is not None:
            new_object_params['tags'] = self.new_object.get('tags')
        if self.new_object.get('tagsFilterType') is not None or self.new_object.get('tags_filter_type') is not None:
            new_object_params['tagsFilterType'] = self.new_object.get('tagsFilterType') or \
                self.new_object.get('tags_filter_type')
        new_object_params['name'] = name or self.new_object.get('name')
        if self.new_object.get('mac') is not None or self.new_object.get('mac') is not None:
            new_object_params['mac'] = self.new_object.get('mac')
        if self.new_object.get('serial') is not None or self.new_object.get('serial') is not None:
            new_object_params['serial'] = self.new_object.get('serial')
        if self.new_object.get('model') is not None or self.new_object.get('model') is not None:
            new_object_params['model'] = self.new_object.get('model')
        if self.new_object.get('macs') is not None or self.new_object.get('macs') is not None:
            new_object_params['macs'] = self.new_object.get('macs')
        if self.new_object.get('serials') is not None or self.new_object.get('serials') is not None:
            new_object_params['serials'] = self.new_object.get('serials')
        if self.new_object.get('sensorMetrics') is not None or self.new_object.get('sensor_metrics') is not None:
            new_object_params['sensorMetrics'] = self.new_object.get('sensorMetrics') or \
                self.new_object.get('sensor_metrics')
        if self.new_object.get('sensorAlertProfileIds') is not None or self.new_object.get('sensor_alert_profile_ids') is not None:
            new_object_params['sensorAlertProfileIds'] = self.new_object.get('sensorAlertProfileIds') or \
                self.new_object.get('sensor_alert_profile_ids')
        if self.new_object.get('models') is not None or self.new_object.get('models') is not None:
            new_object_params['models'] = self.new_object.get('models')
        if self.new_object.get('organizationId') is not None or self.new_object.get('organization_id') is not None:
            new_object_params['organizationId'] = self.new_object.get('organizationId') or \
                self.new_object.get('organization_id')
        return new_object_params

    def get_params_by_id(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('serial') is not None or self.new_object.get('serial') is not None:
            new_object_params['serial'] = self.new_object.get('serial')
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('address') is not None or self.new_object.get('address') is not None:
            new_object_params['address'] = self.new_object.get('address') or \
                self.new_object.get('address')
        if self.new_object.get('floorPlanId') is not None or self.new_object.get('floor_plan_id') is not None:
            new_object_params['floorPlanId'] = self.new_object.get('floorPlanId') or \
                self.new_object.get('floor_plan_id')
        if self.new_object.get('lat') is not None or self.new_object.get('lat') is not None:
            new_object_params['lat'] = self.new_object.get('lat') or \
                self.new_object.get('lat')
        if self.new_object.get('lng') is not None or self.new_object.get('lng') is not None:
            new_object_params['lng'] = self.new_object.get('lng') or \
                self.new_object.get('lng')
        if self.new_object.get('moveMapMarker') is not None or self.new_object.get('move_map_marker') is not None:
            new_object_params['moveMapMarker'] = self.new_object.get(
                'moveMapMarker')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('notes') is not None or self.new_object.get('notes') is not None:
            new_object_params['notes'] = self.new_object.get('notes') or \
                self.new_object.get('notes')
        if self.new_object.get('switchProfileId') is not None or self.new_object.get('switch_profile_id') is not None:
            new_object_params['switchProfileId'] = self.new_object.get('switchProfileId') or \
                self.new_object.get('switch_profile_id')
        if self.new_object.get('tags') is not None or self.new_object.get('tags') is not None:
            new_object_params['tags'] = self.new_object.get('tags') or \
                self.new_object.get('tags')
        if self.new_object.get('serial') is not None or self.new_object.get('serial') is not None:
            new_object_params['serial'] = self.new_object.get('serial') or \
                self.new_object.get('serial')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method, using get all
        try:
            items = self.meraki.exec_meraki(
                family="organizations",
                function="getOrganizationDevices",
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
                family="devices",
                function="getDevice",
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
        o_id = self.new_object.get("id")
        o_id = o_id or self.new_object.get(
            "serial") or self.new_object.get("serial")
        name = self.new_object.get("name")
        orgID = self.new_object.get("organizationId") or self.new_object.get(
            "organization_id")
        print(name)
        print(orgID)
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name and orgID:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("serial")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(serial=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("address", "address"),
            ("floorPlanId", "floorPlanId"),
            ("lat", "lat"),
            ("lng", "lng"),
            ("moveMapMarker", "moveMapMarker"),
            ("name", "name"),
            ("notes", "notes"),
            ("switchProfileId", "switchProfileId"),
            ("tags", "tags"),
            ("serial", "serial"),
            ("organizationId", "organizationId"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (ISE) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("serial")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("serial")
            if id_:
                self.new_object.update(dict(serial=id_))
        result = self.meraki.exec_meraki(
            family="devices",
            function="updateDevice",
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
        obj = Devices(self._task.args, meraki)

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
