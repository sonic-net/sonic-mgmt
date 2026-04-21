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
        hostname=dict(type="list"),
        managementIpAddress=dict(type="list"),
        macAddress=dict(type="list"),
        locationName=dict(type="list"),
        serialNumber=dict(type="list"),
        location=dict(type="list"),
        family=dict(type="list"),
        type=dict(type="list"),
        series=dict(type="list"),
        collectionStatus=dict(type="list"),
        collectionInterval=dict(type="list"),
        notSyncedForMinutes=dict(type="list"),
        errorCode=dict(type="list"),
        errorDescription=dict(type="list"),
        softwareVersion=dict(type="list"),
        softwareType=dict(type="list"),
        platformId=dict(type="list"),
        role=dict(type="list"),
        reachabilityStatus=dict(type="list"),
        upTime=dict(type="list"),
        associatedWlcIp=dict(type="list"),
        license_name=dict(type="list"),
        license_type=dict(type="list"),
        license_status=dict(type="list"),
        module_name=dict(type="list"),
        module_equpimenttype=dict(type="list"),
        module_servicestate=dict(type="list"),
        module_vendorequipmenttype=dict(type="list"),
        module_partnumber=dict(type="list"),
        module_operationstatecode=dict(type="list"),
        id=dict(type="str"),
        deviceSupportLevel=dict(type="str"),
        offset=dict(type="int"),
        limit=dict(type="int"),
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
            hostname=params.get("hostname"),
            management_ip_address=params.get("managementIpAddress"),
            mac_address=params.get("macAddress"),
            location_name=params.get("locationName"),
            serial_number=params.get("serialNumber"),
            location=params.get("location"),
            family=params.get("family"),
            type=params.get("type"),
            series=params.get("series"),
            collection_status=params.get("collectionStatus"),
            collection_interval=params.get("collectionInterval"),
            not_synced_for_minutes=params.get("notSyncedForMinutes"),
            error_code=params.get("errorCode"),
            error_description=params.get("errorDescription"),
            software_version=params.get("softwareVersion"),
            software_type=params.get("softwareType"),
            platform_id=params.get("platformId"),
            role=params.get("role"),
            reachability_status=params.get("reachabilityStatus"),
            up_time=params.get("upTime"),
            associated_wlc_ip=params.get("associatedWlcIp"),
            license_name=params.get("license_name"),
            license_type=params.get("license_type"),
            license_status=params.get("license_status"),
            module_name=params.get("module_name"),
            module_equpimenttype=params.get("module_equpimenttype"),
            module_servicestate=params.get("module_servicestate"),
            module_vendorequipmenttype=params.get("module_vendorequipmenttype"),
            module_partnumber=params.get("module_partnumber"),
            module_operationstatecode=params.get("module_operationstatecode"),
            id=params.get("id"),
            device_support_level=params.get("deviceSupportLevel"),
            offset=params.get("offset"),
            limit=params.get("limit"),
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

        id = self._task.args.get("id")
        if id:
            response = dnac.exec(
                family="devices",
                function="get_device_by_id",
                params=self.get_object(self._task.args),
            )
            self._result.update(dict(dnac_response=response))
            self._result.update(dnac.exit_json())
            return self._result
        if not id:
            response = dnac.exec(
                family="devices",
                function="get_device_list",
                params=self.get_object(self._task.args),
            )
            self._result.update(dict(dnac_response=response))
            self._result.update(dnac.exit_json())
            return self._result
