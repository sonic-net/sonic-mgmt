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
    allowSimultaneousLogins=dict(type="bool"),
    billing=dict(type="dict"),
    blockAllTrafficBeforeSignOn=dict(type="bool"),
    controllerDisconnectionBehavior=dict(type="str"),
    guestSponsorship=dict(type="dict"),
    redirectUrl=dict(type="str"),
    selfRegistration=dict(type="dict"),
    sentryEnrollment=dict(type="dict"),
    splashImage=dict(type="dict"),
    splashLogo=dict(type="dict"),
    splashPrepaidFront=dict(type="dict"),
    splashTimeout=dict(type="int"),
    splashUrl=dict(type="str"),
    themeId=dict(type="str"),
    useRedirectUrl=dict(type="bool"),
    useSplashUrl=dict(type="bool"),
    welcomeMessage=dict(type="str"),
    networkId=dict(type="str"),
    number=dict(type="str"),
))

required_if = [
    ("state", "present", ["networkId", "number"], True),
]
required_one_of = []
mutually_exclusive = []
required_together = []


class NetworksWirelessSsidsSplashSettings(object):
    def __init__(self, params, meraki):
        self.meraki = meraki
        self.new_object = dict(
            allowSimultaneousLogins=params.get("allowSimultaneousLogins"),
            billing=params.get("billing"),
            blockAllTrafficBeforeSignOn=params.get(
                "blockAllTrafficBeforeSignOn"),
            controllerDisconnectionBehavior=params.get(
                "controllerDisconnectionBehavior"),
            guestSponsorship=params.get("guestSponsorship"),
            redirectUrl=params.get("redirectUrl"),
            selfRegistration=params.get("selfRegistration"),
            sentryEnrollment=params.get("sentryEnrollment"),
            splashImage=params.get("splashImage"),
            splashLogo=params.get("splashLogo"),
            splashPrepaidFront=params.get("splashPrepaidFront"),
            splashTimeout=params.get("splashTimeout"),
            splashUrl=params.get("splashUrl"),
            themeId=params.get("themeId"),
            useRedirectUrl=params.get("useRedirectUrl"),
            useSplashUrl=params.get("useSplashUrl"),
            welcomeMessage=params.get("welcomeMessage"),
            network_id=params.get("networkId"),
            number=params.get("number"),
        )

    def get_all_params(self, name=None, id=None):
        new_object_params = {}
        if self.new_object.get('networkId') is not None or self.new_object.get('network_id') is not None:
            new_object_params['networkId'] = self.new_object.get('networkId') or \
                self.new_object.get('network_id')
        if self.new_object.get('number') is not None or self.new_object.get('number') is not None:
            new_object_params['number'] = self.new_object.get('number')
        return new_object_params

    def update_all_params(self):
        new_object_params = {}
        if self.new_object.get('allowSimultaneousLogins') is not None or self.new_object.get('allow_simultaneous_logins') is not None:
            new_object_params['allowSimultaneousLogins'] = self.new_object.get(
                'allowSimultaneousLogins')
        if self.new_object.get('billing') is not None or self.new_object.get('billing') is not None:
            new_object_params['billing'] = self.new_object.get('billing') or \
                self.new_object.get('billing')
        if self.new_object.get('blockAllTrafficBeforeSignOn') is not None or self.new_object.get('block_all_traffic_before_sign_on') is not None:
            new_object_params['blockAllTrafficBeforeSignOn'] = self.new_object.get(
                'blockAllTrafficBeforeSignOn')
        if self.new_object.get('controllerDisconnectionBehavior') is not None or self.new_object.get('controller_disconnection_behavior') is not None:
            new_object_params['controllerDisconnectionBehavior'] = self.new_object.get('controllerDisconnectionBehavior') or \
                self.new_object.get('controller_disconnection_behavior')
        if self.new_object.get('guestSponsorship') is not None or self.new_object.get('guest_sponsorship') is not None:
            new_object_params['guestSponsorship'] = self.new_object.get('guestSponsorship') or \
                self.new_object.get('guest_sponsorship')
        if self.new_object.get('redirectUrl') is not None or self.new_object.get('redirect_url') is not None:
            new_object_params['redirectUrl'] = self.new_object.get('redirectUrl') or \
                self.new_object.get('redirect_url')
        if self.new_object.get('selfRegistration') is not None or self.new_object.get('self_registration') is not None:
            new_object_params['selfRegistration'] = self.new_object.get('selfRegistration') or \
                self.new_object.get('self_registration')
        if self.new_object.get('sentryEnrollment') is not None or self.new_object.get('sentry_enrollment') is not None:
            new_object_params['sentryEnrollment'] = self.new_object.get('sentryEnrollment') or \
                self.new_object.get('sentry_enrollment')
        if self.new_object.get('splashImage') is not None or self.new_object.get('splash_image') is not None:
            new_object_params['splashImage'] = self.new_object.get('splashImage') or \
                self.new_object.get('splash_image')
        if self.new_object.get('splashLogo') is not None or self.new_object.get('splash_logo') is not None:
            new_object_params['splashLogo'] = self.new_object.get('splashLogo') or \
                self.new_object.get('splash_logo')
        if self.new_object.get('splashPrepaidFront') is not None or self.new_object.get('splash_prepaid_front') is not None:
            new_object_params['splashPrepaidFront'] = self.new_object.get('splashPrepaidFront') or \
                self.new_object.get('splash_prepaid_front')
        if self.new_object.get('splashTimeout') is not None or self.new_object.get('splash_timeout') is not None:
            new_object_params['splashTimeout'] = self.new_object.get('splashTimeout') or \
                self.new_object.get('splash_timeout')
        if self.new_object.get('splashUrl') is not None or self.new_object.get('splash_url') is not None:
            new_object_params['splashUrl'] = self.new_object.get('splashUrl') or \
                self.new_object.get('splash_url')
        if self.new_object.get('themeId') is not None or self.new_object.get('theme_id') is not None:
            new_object_params['themeId'] = self.new_object.get('themeId') or \
                self.new_object.get('theme_id')
        if self.new_object.get('useRedirectUrl') is not None or self.new_object.get('use_redirect_url') is not None:
            new_object_params['useRedirectUrl'] = self.new_object.get(
                'useRedirectUrl')
        if self.new_object.get('useSplashUrl') is not None or self.new_object.get('use_splash_url') is not None:
            new_object_params['useSplashUrl'] = self.new_object.get(
                'useSplashUrl')
        if self.new_object.get('welcomeMessage') is not None or self.new_object.get('welcome_message') is not None:
            new_object_params['welcomeMessage'] = self.new_object.get('welcomeMessage') or \
                self.new_object.get('welcome_message')
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
                family="wireless",
                function="getNetworkWirelessSsidSplashSettings",
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
            ("allowSimultaneousLogins", "allowSimultaneousLogins"),
            ("billing", "billing"),
            ("blockAllTrafficBeforeSignOn", "blockAllTrafficBeforeSignOn"),
            ("controllerDisconnectionBehavior", "controllerDisconnectionBehavior"),
            ("guestSponsorship", "guestSponsorship"),
            ("redirectUrl", "redirectUrl"),
            ("selfRegistration", "selfRegistration"),
            ("sentryEnrollment", "sentryEnrollment"),
            ("splashImage", "splashImage"),
            ("splashLogo", "splashLogo"),
            ("splashPrepaidFront", "splashPrepaidFront"),
            ("splashTimeout", "splashTimeout"),
            ("splashUrl", "splashUrl"),
            ("themeId", "themeId"),
            ("useRedirectUrl", "useRedirectUrl"),
            ("useSplashUrl", "useSplashUrl"),
            ("welcomeMessage", "welcomeMessage"),
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
        name = self.new_object.get("name")
        result = None
        result = self.meraki.exec_meraki(
            family="wireless",
            function="updateNetworkWirelessSsidSplashSettings",
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
        obj = NetworksWirelessSsidsSplashSettings(self._task.args, meraki)

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
