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
        name=dict(type="str"),
        ipv6AddressSpace=dict(type="bool"),
        ipv4DhcpServers=dict(type="list"),
        ipv4DnsServers=dict(type="list"),
        ipv6GlobalPool=dict(type="str"),
        ipv6Prefix=dict(type="bool"),
        ipv6PrefixLength=dict(type="int"),
        ipv6Subnet=dict(type="str"),
        ipv6TotalHost=dict(type="int"),
        ipv6GateWay=dict(type="str"),
        ipv6DhcpServers=dict(type="list"),
        ipv6DnsServers=dict(type="list"),
        slaacSupport=dict(type="bool"),
        ipv4GateWay=dict(type="str"),
        siteId=dict(type="str"),
        id=dict(type="str"),
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
            name=params.get("name"),
            ipv6AddressSpace=params.get("ipv6AddressSpace"),
            ipv4DhcpServers=params.get("ipv4DhcpServers"),
            ipv4DnsServers=params.get("ipv4DnsServers"),
            ipv6GlobalPool=params.get("ipv6GlobalPool"),
            ipv6Prefix=params.get("ipv6Prefix"),
            ipv6PrefixLength=params.get("ipv6PrefixLength"),
            ipv6Subnet=params.get("ipv6Subnet"),
            ipv6TotalHost=params.get("ipv6TotalHost"),
            ipv6GateWay=params.get("ipv6GateWay"),
            ipv6DhcpServers=params.get("ipv6DhcpServers"),
            ipv6DnsServers=params.get("ipv6DnsServers"),
            slaacSupport=params.get("slaacSupport"),
            ipv4GateWay=params.get("ipv4GateWay"),
            site_id=params.get("siteId"),
            id=params.get("id"),
        )
        return new_object

    def run(self, tmp=None, task_vars=None):
        self._task.diff = False
        self._result = super(ActionModule, self).run(tmp, task_vars)
        self._result["changed"] = False
        self._check_argspec()

        dnac = DNACSDK(params=self._task.args)

        response = dnac.exec(
            family="network_settings",
            function="update_reserve_ip_subpool",
            op_modifies=True,
            params=self.get_object(self._task.args),
        )
        self._result.update(dict(dnac_response=response))
        self._result.update(dnac.exit_json())
        return self._result
