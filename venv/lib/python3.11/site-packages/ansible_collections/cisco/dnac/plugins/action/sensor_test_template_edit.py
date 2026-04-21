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
        templateName=dict(type="str"),
        name=dict(type="str"),
        _id=dict(type="str"),
        version=dict(type="int"),
        modelVersion=dict(type="int"),
        startTime=dict(type="int"),
        lastModifiedTime=dict(type="int"),
        numAssociatedSensor=dict(type="int"),
        location=dict(type="str"),
        siteHierarchy=dict(type="str"),
        status=dict(type="str"),
        connection=dict(type="str"),
        actionInProgress=dict(type="str"),
        frequency=dict(type="dict"),
        rssiThreshold=dict(type="int"),
        numNeighborAPThreshold=dict(type="int"),
        scheduleInDays=dict(type="int"),
        wlans=dict(type="list"),
        ssids=dict(type="list"),
        profiles=dict(type="list"),
        testScheduleMode=dict(type="str"),
        showWlcUpgradeBanner=dict(type="bool"),
        radioAsSensorRemoved=dict(type="bool"),
        encryptionMode=dict(type="str"),
        runNow=dict(type="str"),
        locationInfoList=dict(type="list"),
        sensors=dict(type="list"),
        apCoverage=dict(type="list"),
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
            templateName=params.get("templateName"),
            name=params.get("name"),
            _id=params.get("_id"),
            version=params.get("version"),
            modelVersion=params.get("modelVersion"),
            startTime=params.get("startTime"),
            lastModifiedTime=params.get("lastModifiedTime"),
            numAssociatedSensor=params.get("numAssociatedSensor"),
            location=params.get("location"),
            siteHierarchy=params.get("siteHierarchy"),
            status=params.get("status"),
            connection=params.get("connection"),
            actionInProgress=params.get("actionInProgress"),
            frequency=params.get("frequency"),
            rssiThreshold=params.get("rssiThreshold"),
            numNeighborAPThreshold=params.get("numNeighborAPThreshold"),
            scheduleInDays=params.get("scheduleInDays"),
            wlans=params.get("wlans"),
            ssids=params.get("ssids"),
            profiles=params.get("profiles"),
            testScheduleMode=params.get("testScheduleMode"),
            showWlcUpgradeBanner=params.get("showWlcUpgradeBanner"),
            radioAsSensorRemoved=params.get("radioAsSensorRemoved"),
            encryptionMode=params.get("encryptionMode"),
            runNow=params.get("runNow"),
            locationInfoList=params.get("locationInfoList"),
            sensors=params.get("sensors"),
            apCoverage=params.get("apCoverage"),
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        dnac = DNACSDK(params=self._task.args)

        response = dnac.exec(
            family="sensors",
            function="edit_sensor_test_template",
            op_modifies=True,
            params=self.get_object(self._task.args),
        )
        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
