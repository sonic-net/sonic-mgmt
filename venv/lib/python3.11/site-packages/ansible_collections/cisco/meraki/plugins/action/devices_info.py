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
    serial=dict(type="str"),
    organizationId=dict(type="str"),
    perPage=dict(type="int"),
    total_pages=dict(type="int"),
    direction=dict(type="str"),
    startingAfter=dict(type="str"),
    endingBefore=dict(type="str"),
    configurationUpdatedAfter=dict(type="str"),
    networkIds=dict(type="list"),
    productTypes=dict(type="list"),
    tags=dict(type="list"),
    tagsFilterType=dict(type="str"),
    name=dict(type="str"),
    mac=dict(type="str"),
    model=dict(type="str"),
    macs=dict(type="list"),
    serials=dict(type="list"),
    sensorMetrics=dict(type="list"),
    sensorAlertProfileIds=dict(type="list"),
    models=dict(type="list"),
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

    def get_object(self, params):
        new_object = {}
        if params.get("serial") is not None:
            new_object["serial"] = params.get(
                "serial")
        return new_object

    def get_all(self, params):
        new_object = {}
        if params.get("organizationId") is not None:
            new_object["organizationId"] = params.get(
                "organizationId")
        if params.get("perPage") is not None:
            new_object["perPage"] = params.get(
                "perPage")
        new_object['total_pages'] = params.get(
            "total_pages") or 1
        new_object['direction'] = params.get(
            "direction") or "next"
        if params.get("startingAfter") is not None:
            new_object["startingAfter"] = params.get(
                "startingAfter")
        if params.get("endingBefore") is not None:
            new_object["endingBefore"] = params.get(
                "endingBefore")
        if params.get("configurationUpdatedAfter") is not None:
            new_object["configurationUpdatedAfter"] = params.get(
                "configurationUpdatedAfter")
        if params.get("networkIds") is not None:
            new_object["networkIds"] = params.get(
                "networkIds")
        if params.get("productTypes") is not None:
            new_object["productTypes"] = params.get(
                "productTypes")
        if params.get("tags") is not None:
            new_object["tags"] = params.get(
                "tags")
        if params.get("tagsFilterType") is not None:
            new_object["tagsFilterType"] = params.get(
                "tagsFilterType")
        if params.get("name") is not None:
            new_object["name"] = params.get(
                "name")
        if params.get("mac") is not None:
            new_object["mac"] = params.get(
                "mac")
        if params.get("serial") is not None:
            new_object["serial"] = params.get(
                "serial")
        if params.get("model") is not None:
            new_object["model"] = params.get(
                "model")
        if params.get("macs") is not None:
            new_object["macs"] = params.get(
                "macs")
        if params.get("serials") is not None:
            new_object["serials"] = params.get(
                "serials")
        if params.get("sensorMetrics") is not None:
            new_object["sensorMetrics"] = params.get(
                "sensorMetrics")
        if params.get("sensorAlertProfileIds") is not None:
            new_object["sensorAlertProfileIds"] = params.get(
                "sensorAlertProfileIds")
        if params.get("models") is not None:
            new_object["models"] = params.get(
                "models")

        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        self._result.update(dict(meraki_response={}))

        meraki = MERAKI(params=self._task.args)

        id = self._task.args.get("serial")
        if id:
            response = meraki.exec_meraki(
                family="devices",
                function='getDevice',
                params=self.get_object(self._task.args),
            )
            self._result.update(dict(meraki_response=response))
            self._result.update(meraki.exit_json())
            return self._result
        if not id:
            response = meraki.exec_meraki(
                family="organizations",
                function='getOrganizationDevices',
                params=self.get_all(self._task.args),
            )
            self._result.update(dict(meraki_response=response))
            self._result.update(meraki.exit_json())
            return self._result
