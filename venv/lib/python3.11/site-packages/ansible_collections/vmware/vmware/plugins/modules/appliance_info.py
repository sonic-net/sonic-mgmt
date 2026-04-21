#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: appliance_info
short_description: Gather appliance information
description:
- This module gather VCenter appliance information.
author:
- Ansible Cloud Team (@ansible-collections)
requirements:
- vSphere Automation SDK
options:
  properties:
    choices:
        - summary
        - access
        - networking
        - firewall
        - time
        - services
        - update
        - syslog
        - all
    description:
      - Specify the properties to retrieve.
      - If not specified, all properties are retrieved.
    type: list
    elements: str
    default: all
attributes:
  check_mode:
    description: The check_mode support.
    support: full
extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options

'''

EXAMPLES = r'''
- name: Gather all appliance info
  vmware.vmware.appliance_info:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
'''

RETURN = r'''
appliance:
    description:
        - Information about appliance.
    returned: On success
    type: dict
    sample: {
        "appliance": {
            "access": {
                "consolecli": false,
                "dcui": false,
                "shell": {
                    "enabled": "False",
                    "timeout": "0"
                },
                "ssh": true
            },
            "firewall": {
                "inbound": [
                    {
                        "address": "1.2.3.6",
                        "interface_name": "*",
                        "policy": "ACCEPT",
                        "prefix": "32"
                    },
                    {
                        "address": "1.2.4.5",
                        "interface_name": "nic0",
                        "policy": "IGNORE",
                        "prefix": "24"
                    }
                ]
            },
            "networking": {
                "network": {
                    "dns_servers": [],
                    "hostname": [
                        "vcenter.local"
                    ],
                    "nics": {
                        "nic0": {
                            "ipv4": "{configurable : True, mode : STATIC, address : 10.185.246.4, prefix : 26, default_gateway : 10.185.246.1}",
                            "ipv6": "None",
                            "mac": "00:50:56:cd:e7:2e",
                            "name": "nic0",
                            "status": "up"
                        }
                    }
                },
                "proxy": {
                    "ftp": {
                        "enabled": "False",
                        "password": "None",
                        "port": "-1",
                        "server": "",
                        "username": "None"
                    },
                    "http": {
                        "enabled": "True",
                        "password": "None",
                        "port": "80",
                        "server": "http://localhost",
                        "username": "None"
                    },
                    "https": {
                        "enabled": "False",
                        "password": "None",
                        "port": "-1",
                        "server": "",
                        "username": "None"
                    },
                    "noproxy": [
                        "localhost",
                        "127.0.0.1"
                    ]
                }
            },
            "services": {
                "appliance-shutdown": {
                    "description": "/etc/rc.local.shutdown Compatibility",
                    "state": "STOPPED"
                },
            },
            "summary": {
                "build_number": "21560480",
                "health": {
                    "cpu": "green",
                    "database": "green",
                    "memory": "green",
                    "overall": "green",
                    "storage": "green",
                    "swap": "green"
                },
                "hostname": [
                    "vcenter.local"
                ],
                "product": "VMware vCenter Server",
                "sso": {},
                "uptime": "12531937.54",
                "version": "8.0.1.00000"
            },
            "syslog": {
                "forwarding": []
            },
            "time": {
                "time_sync": {
                    "current": {
                        "date": "Tue 03-26-2024",
                        "seconds_since_epoch": "1711465124.5183642",
                        "time": "02:58:44 PM",
                        "timezone": "UTC"
                    },
                    "mode": "NTP",
                    "servers": [
                        "time.google.com"
                    ]
                },
                "time_zone": "Etc/UTC"
            }
        }
    }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec


class VmwareApplianceInfo(ModuleRestBase):
    def __init__(self, module):
        super(VmwareApplianceInfo, self).__init__(module)
        self.module = module
        self.params = module.params

    def get_appliance_info(self):
        app = self.api_client.appliance

        gather = self.module.params.get('properties')

        appliance = {}
        if 'summary' in gather or 'all' in gather:
            appliance['summary'] = self._get_summary(app)

        if 'access' in gather or 'all' in gather:
            appliance['access'] = self._get_access(app)

        if 'networking' in gather or 'all' in gather:
            appliance['networking'] = self._get_networking(app)

        if 'firewall' in gather or 'all' in gather:
            appliance['firewall'] = self._get_firewall(app)

        if 'time' in gather or 'all' in gather:
            appliance['time'] = self._get_time(app)

        if 'services' in gather or 'all' in gather:
            appliance['services'] = self._get_services(app)

        if 'syslog' in gather or 'all' in gather:
            appliance['syslog'] = self._get_syslog(app)

        if 'update' in gather or 'all' in gather:
            appliance['update'] = self._get_update(app)

        return appliance

    def _vvars(self, vmware_obj):
        return {k: str(v) for k, v in vars(vmware_obj).items() if not k.startswith('_')}

    def _gget(self, fn):
        try:
            return fn()
        except Exception:
            return ''

    def _get_summary(self, app):
        version = app.system.Version.get()
        hostname = app.networking.dns.Hostname.get()

        return {
            'hostname': hostname,
            'product': version.product,
            'version': version.version,
            'build_number': version.build,
            'uptime': str(self._gget(app.system.Uptime.get)),
            'health': {
                'overall': self._gget(app.health.System.get),
                'cpu': self._gget(app.health.Load.get),
                'memory': self._gget(app.health.Mem.get),
                'database': self._gget(app.health.Database.get),
                'storage': self._gget(app.health.Storage.get),
                'swap': self._gget(app.health.Swap.get),
            },
        }

    def _get_access(self, app):
        return {
            'access': {
                'dcui': self._gget(app.access.Dcui.get),
                'consolecli': self._gget(app.access.Consolecli.get),
                'shell': self._vvars(self._gget(app.access.Shell.get)),
                'ssh': self._gget(app.access.Ssh.get),
            }
        }

    def _get_networking(self, app):
        hostname = self._gget(app.networking.dns.Hostname.get)
        return {
            'network': {
                'hostname': hostname,
                'dns_servers': app.networking.dns.Servers.get().servers,
                'nics': {k: self._vvars(v) for k, v in app.Networking.get().interfaces.items()},
            },
            'proxy': {
                'noproxy': app.networking.NoProxy.get(),
                'http': self._vvars(app.networking.Proxy.get('http')),
                'https': self._vvars(app.networking.Proxy.get('https')),
                'ftp': self._vvars(app.networking.Proxy.get('ftp')),
            },
        }

    def _get_firewall(self, app):
        return {
            'inbound': [self._vvars(i) for i in app.networking.firewall.Inbound.get()]
        }

    def _get_time(self, app):
        return {
            'time_zone': app.system.time.Timezone.get(),
            'time_sync': {
                'mode': app.Timesync.get(),
                'servers': app.Ntp.get(),
                'current': self._vvars(app.system.Time.get()),
            },
        }

    def _get_services(self, app):
        return {k: self._vvars(v) for k, v in app.Services.list().items()}

    def _get_syslog(self, app):
        return {
            'forwarding': [self._vvars(f) for f in app.logging.Forwarding.get()]
        }

    def _get_update(self, app):
        return self._vvars(app.Update.get())


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            properties=dict(
                type='list',
                elements='str',
                choices=['summary', 'access', 'networking', 'firewall', 'time', 'services', 'update', 'syslog', 'all'],
                default='all'
            )
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )

    vmware_appliance_mgr = VmwareApplianceInfo(module)
    appliance = vmware_appliance_mgr.get_appliance_info()
    module.exit_json(changed=False, appliance=appliance)


if __name__ == '__main__':
    main()
