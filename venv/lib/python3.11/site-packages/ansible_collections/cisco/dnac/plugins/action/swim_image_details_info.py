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

# Get common arguments specification
argument_spec = dnac_argument_spec()
# Add arguments specific for this module
argument_spec.update(
    dict(
        imageUuid=dict(type="str"),
        name=dict(type="str"),
        family=dict(type="str"),
        applicationType=dict(type="str"),
        imageIntegrityStatus=dict(type="str"),
        version=dict(type="str"),
        imageSeries=dict(type="str"),
        imageName=dict(type="str"),
        isTaggedGolden=dict(type="bool"),
        isCCORecommended=dict(type="bool"),
        isCCOLatest=dict(type="bool"),
        createdTime=dict(type="int"),
        imageSizeGreaterThan=dict(type="int"),
        imageSizeLesserThan=dict(type="int"),
        sortBy=dict(type="str"),
        sortOrder=dict(type="str"),
        limit=dict(type="int"),
        offset=dict(type="int"),
        headers=dict(type="dict"),
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
        new_object = dict(
            image_uuid=params.get("imageUuid"),
            name=params.get("name"),
            family=params.get("family"),
            application_type=params.get("applicationType"),
            image_integrity_status=params.get("imageIntegrityStatus"),
            version=params.get("version"),
            image_series=params.get("imageSeries"),
            image_name=params.get("imageName"),
            is_tagged_golden=params.get("isTaggedGolden"),
            is_cco_recommended=params.get("isCCORecommended"),
            is_cco_latest=params.get("isCCOLatest"),
            created_time=params.get("createdTime"),
            image_size_greater_than=params.get("imageSizeGreaterThan"),
            image_size_lesser_than=params.get("imageSizeLesserThan"),
            sort_by=params.get("sortBy"),
            sort_order=params.get("sortOrder"),
            limit=params.get("limit"),
            offset=params.get("offset"),
            headers=params.get("headers"),
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        self._result.update(dict(dnac_response={}))

        dnac = DNACSDK(params=self._task.args)

        response = dnac.exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            params=self.get_object(self._task.args),
        )
        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
