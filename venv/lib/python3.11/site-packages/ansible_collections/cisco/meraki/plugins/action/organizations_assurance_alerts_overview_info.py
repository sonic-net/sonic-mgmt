#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

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
)

# Get common arguments specification
argument_spec = meraki_argument_spec()
# Add arguments specific for this module
argument_spec.update(dict(
    organizationId=dict(type="str"),
    networkId=dict(type="str"),
    severity=dict(type="str"),
    types=dict(type="list"),
    tsStart=dict(type="str"),
    tsEnd=dict(type="str"),
    category=dict(type="str"),
    serials=dict(type="list"),
    deviceTypes=dict(type="list"),
    deviceTags=dict(type="list"),
    active=dict(type="bool"),
    dismissed=dict(type="bool"),
    resolved=dict(type="bool"),
    suppressAlertsForOfflineNodes=dict(type="bool"),
))

required_if = []
required_one_of = []
mutually_exclusive = []
required_together = []


class ActionModule(ActionBase):
    def __init__(self, *args, **kwargs):
        if not ANSIBLE_UTILS_IS_INSTALLED:
            raise AnsibleActionFail(
                "ansible.utils is not installed. Execute 'ansible-galaxy collection install ansible.utils'")
        super(ActionModule, self).__init__(*args, **kwargs)
        self._supports_async = False
        self._supports_check_mode = True
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

    def get_all(self, params):
        new_object = {}
        if params.get("organizationId") is not None:
            new_object["organizationId"] = params.get(
                "organizationId")
        if params.get("networkId") is not None:
            new_object["networkId"] = params.get(
                "networkId")
        if params.get("severity") is not None:
            new_object["severity"] = params.get(
                "severity")
        if params.get("types") is not None:
            new_object["types"] = params.get(
                "types")
        if params.get("tsStart") is not None:
            new_object["tsStart"] = params.get(
                "tsStart")
        if params.get("tsEnd") is not None:
            new_object["tsEnd"] = params.get(
                "tsEnd")
        if params.get("category") is not None:
            new_object["category"] = params.get(
                "category")
        if params.get("serials") is not None:
            new_object["serials"] = params.get(
                "serials")
        if params.get("deviceTypes") is not None:
            new_object["deviceTypes"] = params.get(
                "deviceTypes")
        if params.get("deviceTags") is not None:
            new_object["deviceTags"] = params.get(
                "deviceTags")
        if params.get("active") is not None:
            new_object["active"] = params.get(
                "active")
        if params.get("dismissed") is not None:
            new_object["dismissed"] = params.get(
                "dismissed")
        if params.get("resolved") is not None:
            new_object["resolved"] = params.get(
                "resolved")
        if params.get("suppressAlertsForOfflineNodes") is not None:
            new_object["suppressAlertsForOfflineNodes"] = params.get(
                "suppressAlertsForOfflineNodes")

        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        self._result.update(dict(meraki_response={}))

        meraki = MERAKI(params=self._task.args)

        response = meraki.exec_meraki(
            family="organizations",
            function='getOrganizationAssuranceAlertsOverview',
            params=self.get_all(self._task.args),
        )
        self._result.update(dict(meraki_response=response))
        self._result.update(meraki.exit_json())
        return self._result
