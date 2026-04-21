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
    apBandSettings=dict(type="dict"),
    bandSelectionType=dict(type="str"),
    clientBalancingEnabled=dict(type="bool"),
    fiveGhzSettings=dict(type="dict"),
    flexRadios=dict(type="dict"),
    minBitrateType=dict(type="str"),
    name=dict(type="str"),
    perSsidSettings=dict(type="dict"),
    sixGhzSettings=dict(type="dict"),
    transmission=dict(type="dict"),
    twoFourGhzSettings=dict(type="dict"),
    networkId=dict(type="str"),
    rfProfileId=dict(type="str"),
    isIndoorDefault=dict(type="bool"),
    isOutdoorDefault=dict(type="bool"),
))

required_if = [
    ("state", "present", ["name", "networkId", "rfProfileId"], True),
    ("state", "absent", ["name", "networkId", "rfProfileId"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksWirelessRfProfiles(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            apBandSettings=params.get("apBandSettings"),
            bandSelectionType=params.get("bandSelectionType"),
            clientBalancingEnabled=params.get("clientBalancingEnabled"),
            fiveGhzSettings=params.get("fiveGhzSettings"),
            flexRadios=params.get("flexRadios"),
            minBitrateType=params.get("minBitrateType"),
            name=params.get("name"),
            perSsidSettings=params.get("perSsidSettings"),
            sixGhzSettings=params.get("sixGhzSettings"),
            transmission=params.get("transmission"),
            twoFourGhzSettings=params.get("twoFourGhzSettings"),
            networkId=params.get("networkId"),
            rfProfileId=params.get("rfProfileId"),
            isIndoorDefault=params.get("isIndoorDefault"),
            isOutdoorDefault=params.get("isOutdoorDefault"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('includeTemplateProfiles') is not None or self.new_object.get('include_template_profiles') is not None:
            new_object_params['includeTemplateProfiles'] = self.new_object.get('includeTemplateProfiles') or \
                self.new_object.get('include_template_profiles')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def get_params_by_id(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('rfProfileId') is not None or self.new_object.get('rf_profile_id') is not None:
            new_object_params['rfProfileId'] = self.new_object.get('rfProfileId') or \
                self.new_object.get('rf_profile_id')
        return new_object_params

    def create_params(self):
        new_object_params = {}
        if self.new_object.get('apBandSettings') is not None or self.new_object.get('ap_band_settings') is not None:
            new_object_params['apBandSettings'] = self.new_object.get('apBandSettings') or \
                self.new_object.get('ap_band_settings')
        if self.new_object.get('bandSelectionType') is not None or self.new_object.get('band_selection_type') is not None:
            new_object_params['bandSelectionType'] = self.new_object.get('bandSelectionType') or \
                self.new_object.get('band_selection_type')
        if self.new_object.get('clientBalancingEnabled') is not None or self.new_object.get('client_balancing_enabled') is not None:
            new_object_params['clientBalancingEnabled'] = self.new_object.get(
                'clientBalancingEnabled')
        if self.new_object.get('fiveGhzSettings') is not None or self.new_object.get('five_ghz_settings') is not None:
            new_object_params['fiveGhzSettings'] = self.new_object.get('fiveGhzSettings') or \
                self.new_object.get('five_ghz_settings')
        if self.new_object.get('flexRadios') is not None or self.new_object.get('flex_radios') is not None:
            new_object_params['flexRadios'] = self.new_object.get('flexRadios') or \
                self.new_object.get('flex_radios')
        if self.new_object.get('minBitrateType') is not None or self.new_object.get('min_bitrate_type') is not None:
            new_object_params['minBitrateType'] = self.new_object.get('minBitrateType') or \
                self.new_object.get('min_bitrate_type')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('perSsidSettings') is not None or self.new_object.get('per_ssid_settings') is not None:
            new_object_params['perSsidSettings'] = self.new_object.get('perSsidSettings') or \
                self.new_object.get('per_ssid_settings')
        if self.new_object.get('sixGhzSettings') is not None or self.new_object.get('six_ghz_settings') is not None:
            new_object_params['sixGhzSettings'] = self.new_object.get('sixGhzSettings') or \
                self.new_object.get('six_ghz_settings')
        if self.new_object.get('transmission') is not None or self.new_object.get('transmission') is not None:
            new_object_params['transmission'] = self.new_object.get('transmission') or \
                self.new_object.get('transmission')
        if self.new_object.get('twoFourGhzSettings') is not None or self.new_object.get('two_four_ghz_settings') is not None:
            new_object_params['twoFourGhzSettings'] = self.new_object.get('twoFourGhzSettings') or \
                self.new_object.get('two_four_ghz_settings')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        return new_object_params

    def delete_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('rfProfileId') is not None or self.new_object.get('rf_profile_id') is not None:
            new_object_params['rfProfileId'] = self.new_object.get('rfProfileId') or \
                self.new_object.get('rf_profile_id')
        return new_object_params

    def update_by_id_params(self):
        new_object_params = {}
        if self.new_object.get('apBandSettings') is not None or self.new_object.get('ap_band_settings') is not None:
            new_object_params['apBandSettings'] = self.new_object.get('apBandSettings') or \
                self.new_object.get('ap_band_settings')
        if self.new_object.get('bandSelectionType') is not None or self.new_object.get('band_selection_type') is not None:
            new_object_params['bandSelectionType'] = self.new_object.get('bandSelectionType') or \
                self.new_object.get('band_selection_type')
        if self.new_object.get('clientBalancingEnabled') is not None or self.new_object.get('client_balancing_enabled') is not None:
            new_object_params['clientBalancingEnabled'] = self.new_object.get(
                'clientBalancingEnabled')
        if self.new_object.get('fiveGhzSettings') is not None or self.new_object.get('five_ghz_settings') is not None:
            new_object_params['fiveGhzSettings'] = self.new_object.get('fiveGhzSettings') or \
                self.new_object.get('five_ghz_settings')
        if self.new_object.get('flexRadios') is not None or self.new_object.get('flex_radios') is not None:
            new_object_params['flexRadios'] = self.new_object.get('flexRadios') or \
                self.new_object.get('flex_radios')
        if self.new_object.get('isIndoorDefault') is not None or self.new_object.get('is_indoor_default') is not None:
            new_object_params['isIndoorDefault'] = self.new_object.get(
                'isIndoorDefault')
        if self.new_object.get('isOutdoorDefault') is not None or self.new_object.get('is_outdoor_default') is not None:
            new_object_params['isOutdoorDefault'] = self.new_object.get(
                'isOutdoorDefault')
        if self.new_object.get('minBitrateType') is not None or self.new_object.get('min_bitrate_type') is not None:
            new_object_params['minBitrateType'] = self.new_object.get('minBitrateType') or \
                self.new_object.get('min_bitrate_type')
        if self.new_object.get('name') is not None or self.new_object.get('name') is not None:
            new_object_params['name'] = self.new_object.get('name') or \
                self.new_object.get('name')
        if self.new_object.get('perSsidSettings') is not None or self.new_object.get('per_ssid_settings') is not None:
            new_object_params['perSsidSettings'] = self.new_object.get('perSsidSettings') or \
                self.new_object.get('per_ssid_settings')
        if self.new_object.get('sixGhzSettings') is not None or self.new_object.get('six_ghz_settings') is not None:
            new_object_params['sixGhzSettings'] = self.new_object.get('sixGhzSettings') or \
                self.new_object.get('six_ghz_settings')
        if self.new_object.get('transmission') is not None or self.new_object.get('transmission') is not None:
            new_object_params['transmission'] = self.new_object.get('transmission') or \
                self.new_object.get('transmission')
        if self.new_object.get('twoFourGhzSettings') is not None or self.new_object.get('two_four_ghz_settings') is not None:
            new_object_params['twoFourGhzSettings'] = self.new_object.get('twoFourGhzSettings') or \
                self.new_object.get('two_four_ghz_settings')
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('rfProfileId') is not None or self.new_object.get('rf_profile_id') is not None:
            new_object_params['rfProfileId'] = self.new_object.get('rfProfileId') or \
                self.new_object.get('rf_profile_id')
        return new_object_params

    def get_object_by_name(self, name):
        result = None
        # NOTE: Does not have a get by name method or it is in another action
        try:
            items = self.meraki.exec_meraki(
                family="wireless",
                function="getNetworkWirelessRfProfiles",
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
                family="wireless",
                function="getNetworkWirelessRfProfile",
                params=self.get_params_by_id()
            )
            if isinstance(items, dict):
                if 'response' in items:
                    items = items.get('response')
            result = get_dict_result(items, 'rfProfileId', id)
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
            "rf_profile_id") or self.new_object.get("rfProfileId")
        name = self.new_object.get("name")
        if o_id:
            prev_obj = self.get_object_by_id(o_id)
            id_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if not id_exists and name:
            prev_obj = self.get_object_by_name(name)
            name_exists = prev_obj is not None and isinstance(prev_obj, dict)
        if name_exists:
            _id = prev_obj.get("id")
            _id = _id or prev_obj.get("rfProfileId")
            if id_exists and name_exists and o_id != _id:
                raise InconsistentParameters(
                    "The 'id' and 'name' params don't refer to the same object")
            if _id:
                self.new_object.update(dict(id=_id))
                self.new_object.update(dict(rfProfileId=_id))
            if _id:
                prev_obj = self.get_object_by_id(_id)
        it_exists = prev_obj is not None and isinstance(prev_obj, dict)
        return (it_exists, prev_obj)

    def requires_update(self, current_obj):
        requested_obj = self.new_object

        obj_params = [
            ("apBandSettings", "apBandSettings"),
            ("bandSelectionType", "bandSelectionType"),
            ("clientBalancingEnabled", "clientBalancingEnabled"),
            ("fiveGhzSettings", "fiveGhzSettings"),
            ("flexRadios", "flexRadios"),
            ("minBitrateType", "minBitrateType"),
            ("name", "name"),
            ("perSsidSettings", "perSsidSettings"),
            ("sixGhzSettings", "sixGhzSettings"),
            ("transmission", "transmission"),
            ("twoFourGhzSettings", "twoFourGhzSettings"),
            ("networkId", "networkId"),
            ("rfProfileId", "rfProfileId"),
            ("isIndoorDefault", "isIndoorDefault"),
            ("isOutdoorDefault", "isOutdoorDefault"),
        ]
        # Method 1. Params present in request (Ansible) obj are the same as the current (DNAC) params
        # If any does not have eq params, it requires update
        return any(not meraki_compare_equality2(current_obj.get(meraki_param),
                                                requested_obj.get(ansible_param))
                   for (meraki_param, ansible_param) in obj_params)

    def create(self):
        result = self.meraki.exec_meraki(
            family="wireless",
            function="createNetworkWirelessRfProfile",
            params=self.create_params(),
            op_modifies=True,
        )
        return result

    def update(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("rfProfileId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("rfProfileId")
            if id_:
                self.new_object.update(dict(rfProfileId=id_))
        result = self.meraki.exec_meraki(
            family="wireless",
            function="updateNetworkWirelessRfProfile",
            params=self.update_by_id_params(),
            op_modifies=True,
        )
        return result

    def delete(self):
        id = self.new_object.get("id")
        id = id or self.new_object.get("rfProfileId")
        name = self.new_object.get("name")
        result = None
        if not id:
            prev_obj_name = self.get_object_by_name(name)
            id_ = None
            if prev_obj_name:
                id_ = prev_obj_name.get("id")
                id_ = id_ or prev_obj_name.get("rfProfileId")
            if id_:
                self.new_object.update(dict(rfProfileId=id_))
        result = self.meraki.exec_meraki(
            family="wireless",
            function="deleteNetworkWirelessRfProfile",
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
        obj = NetworksWirelessRfProfiles(self._task.args, meraki)

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
