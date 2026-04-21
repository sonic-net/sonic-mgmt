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
)

# Get common arguements specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        apList=dict(type="list"),
        configureAdminStatus=dict(type="bool"),
        adminStatus=dict(type="bool"),
        configureApMode=dict(type="bool"),
        apMode=dict(type="int"),
        configureFailoverPriority=dict(type="bool"),
        failoverPriority=dict(type="int"),
        configureLedStatus=dict(type="bool"),
        ledStatus=dict(type="bool"),
        configureLedBrightnessLevel=dict(type="bool"),
        ledBrightnessLevel=dict(type="int"),
        configureLocation=dict(type="bool"),
        location=dict(type="str"),
        configureHAController=dict(type="bool"),
        primaryControllerName=dict(type="str"),
        primaryIpAddress=dict(type="dict"),
        secondaryControllerName=dict(type="str"),
        secondaryIpAddress=dict(type="dict"),
        tertiaryControllerName=dict(type="str"),
        tertiaryIpAddress=dict(type="dict"),
        radioConfigurations=dict(type="list"),
        isAssignedSiteAsLocation=dict(type="bool"),
    )
)

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


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

    def get_object(self, params):
        new_object = dict(
            apList=params.get("apList"),
            configureAdminStatus=params.get("configureAdminStatus"),
            adminStatus=params.get("adminStatus"),
            configureApMode=params.get("configureApMode"),
            apMode=params.get("apMode"),
            configureFailoverPriority=params.get("configureFailoverPriority"),
            failoverPriority=params.get("failoverPriority"),
            configureLedStatus=params.get("configureLedStatus"),
            ledStatus=params.get("ledStatus"),
            configureLedBrightnessLevel=params.get("configureLedBrightnessLevel"),
            ledBrightnessLevel=params.get("ledBrightnessLevel"),
            configureLocation=params.get("configureLocation"),
            location=params.get("location"),
            configureHAController=params.get("configureHAController"),
            primaryControllerName=params.get("primaryControllerName"),
            primaryIpAddress=params.get("primaryIpAddress"),
            secondaryControllerName=params.get("secondaryControllerName"),
            secondaryIpAddress=params.get("secondaryIpAddress"),
            tertiaryControllerName=params.get("tertiaryControllerName"),
            tertiaryIpAddress=params.get("tertiaryIpAddress"),
            radioConfigurations=params.get("radioConfigurations"),
            isAssignedSiteAsLocation=params.get("isAssignedSiteAsLocation"),
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        dnac = DNACSDK(params=self._task.args)

        response = dnac.exec(
            family="wireless",
            function="configure_access_points",
            op_modifies=True,
            params=self.get_object(self._task.args),
        )
        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
