#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2023, Ansible Cloud Team (@ansible-collections)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r'''
---
module: vcsa_settings
short_description: Configure vCenter Server Appliance settings
version_added: 1.2.0
description:
  - Configure vCenter Server Appliance settings.
author:
  - Ansible Cloud Team (@ansible-collections)
requirements:
  - vSphere Automation SDK
options:
  timezone:
    description:
      - Set time zone.
    type: str
  global_fips:
    description:
      - "Enable/Disable Global FIPS mode for the appliance. Caution: Changing the value of this setting will reboot the Appliance."
    type: bool
  resize_storage:
    description:
      - Resize all partitions to 100 percent of disk size.
    type: bool
    default: false
  dns_mode:
    choices:
      - is_static
      - dhcp
    description:
      - Set the DNS mode.
    type: str
  dns_append:
    description:
      - If V(true) items from O(dns_domains) and O(dns_servers) will be added to already configured DNS domains/servers.
      - If V(false) domains/servers will be overridden.
    type: bool
    default: true
  dns_hostname:
    description:
      - DNS hostname.
    type: str
  dns_servers:
    description:
      - List of DNS servers.
    type: list
    elements: str
  dns_domains:
    description:
      - List of DNS domains.
    type: list
    elements: str
  timesync_mode:
    description:
      - Set time synchronization mode.
    type: str
    choices:
      - disabled
      - host
      - ntp
  ntp_servers:
    description:
      - List of NTP servers. This method updates old NTP servers from configuration and sets the input NTP servers in the configuration.
      - If NTP based time synchronization is used internally, the NTP daemon will be restarted to reload given NTP configuration.
      - In case NTP based time synchronization is not used, this method only replaces servers in the NTP configuration.
    type: list
    elements: str
  noproxy:
    description:
      - List of hosts that should be ignored by proxy configuration.
    type: list
    elements: str
  proxy:
    elements: dict
    type: list
    description:
      - A list of proxy configurations.
    suboptions:
        enabled:
          description:
            - Define if this proxy configuration should be enabled.
          type: bool
          required: true
        url:
          description:
            - Define the URL of the proxy server (including protocol ie. http://...).
          type: str
          required: true
        port:
          description:
            - Define the port of the proxy server.
          type: int
          required: true
        protocol:
          description:
            - Define the protocol of the proxy server(FTP, HTTP, HTTPS).
          type: str
          required: true
        username:
          description:
            - Define username for the proxy server if proxy requires authentication.
          type: str
        password:
          description:
            - Define password for the proxy server if proxy requires authentication.
          type: str
        always_update_password:
            description:
                - If true and O(proxy[].password) is set, this module will always report a change and
                  set the password value to O(proxy[].password) .
                - If false, other properties are still checked for differences. If a difference is found,
                  the value of O(proxy[].password) is still used.
                - If O(proxy[].password) is unset, this parameter is ignored.
                - This option is needed because there is no way to check the current password value and
                  compare it against the desired password value.
            default: true
            type: bool
  dcui_enabled:
    description:
      - Enable/Disable state of Direct Console User Interface (DCUI TTY2).
    type: bool
  shell_enabled:
    description:
      - Enable/Disable state of BASH, that is, access to BASH from within the controlled CLI.
    type: bool
  shell_timeout:
    description:
      - The timeout (in seconds) specifies how long you enable the Shell access. The maximum timeout is 86400 seconds(1 day).
      - This parameter is mandatory in case O(shell_enabled=true).
    type: int
  ssh_enabled:
    description:
      - Enable/Disable state of the SSH-based controlled CLI.
    type: bool
  consolecli_enabled:
    description:
      - Enable/Disable state of the console-based controlled CLI (TTY1).
    type: bool
  firewall_rules:
    description:
      - Set the ordered list of firewall rules to allow or deny traffic from one or more incoming IP addresses.
      - Within the list of traffic rules, rules are processed in order of appearance, from top to bottom.
    type: list
    elements: dict
    suboptions:
      address:
        description:
          - IPv4 or IPv6 address.
        type: str
      prefix:
        description:
          - CIDR prefix used to mask address. For example, an IPv4 prefix of 24 ignores the low-order 8 bits of address.
        type: int
      policy:
        description:
          - Defines firewall rule policies.
        type: str
        choices:
          - ACCEPT
          - IGNORE
          - REJECT
          - RETURN
      interface_name:
        description:
          - The interface to which this rule applies. An I(*) indicates that the rule applies to all interfaces.
        type: str
  firewall_rules_append:
    description:
      - If false the rules overwrites the existing firewall rules and creates a new rule list. If true we append the rules to existing rules.
    type: bool
    default: true
attributes:
  check_mode:
    description: The check_mode support.
    support: full
extends_documentation_fragment:
    - vmware.vmware.base_options
    - vmware.vmware.additional_rest_options
'''

EXAMPLES = r'''
- name: Enable shell and SSH
  vmware.vmware.vcsa_settings:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    ssh_enabled: true
    shell_enabled: true
    shell_timeout: 120

- name: Set firewall rules
  vmware.vmware.vcsa_settings:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    firewall_rules:
      - address: '1.2.3.7'
        interface_name: '*'
        prefix: 24
        policy: 'ACCEPT'

- name: Set NTP servers
  vmware.vmware.vcsa_settings:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    timesync_mode: ntp
    ntp_servers:
      - time.google.com

- name: Enable HTTP proxy
  vmware.vmware.vcsa_settings:
    hostname: "https://vcenter"
    username: "username"
    password: "password"
    proxy:
      - enabled: true
        protocol: 'http'
        url: 'http://myproxy'
        port: 8080
'''

RETURN = r'''
vcsa_settings:
  description:
    - Information about appliance.
  returned: On success
  type: dict
  sample: {
    "consolecli_enabled": false,
    "dcui_enabled": true,
    "dns_domains": ["abc.com"],
    "dns_mode": null,
    "noproxy": ["abc.com"],
    "ntp_servers": ["time.google.com"],
    "proxy": [{"enabled": true, "password": null, "port": 80, "protocol": "http", "url": "http://127.0.0.1", "username": null}],
    "resize_storage": false,
    "shell_timeout": 350,
    "ssh_enabled": true,
    "timesync_mode": "ntp"
  }
vcsa:
  description:
    - Identifying information about the appliance
  returned: On success
  type: dict
  sample: {
    "vcsa": {
      "hostname": "my-appliance",
      "port": 443
    },
  }
'''

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.vmware.vmware.plugins.module_utils._module_rest_base import ModuleRestBase
from ansible_collections.vmware.vmware.plugins.module_utils.argument_spec import rest_compatible_argument_spec


class VmwareVcsaSettings(ModuleRestBase):
    def __init__(self, module):
        super(VmwareVcsaSettings, self).__init__(module)
        self.api_system = self.api_client.appliance.system
        self.api_networking = self.api_client.appliance.networking
        self.api_access = self.api_client.appliance.access
        self.module = module
        self.params = module.params
        self.changed = False
        self.info = {}

    def vcsa_settings(self):
        # Security
        self.__ssh_enabled()
        self.__shell_enabled()
        self.__consolecli_enabled()
        self.__dcui_enabled()
        self.__firewall_rules()

        # Proxy
        self.__proxy()
        self.__noproxy()
        # Ntp
        self.__ntp_servers()
        self.__timesync_mode()

        # DNS
        self.__dns_servers()
        self.__dns_mode()
        self.__dns_domains()
        self.__dns_hostname()

        # General
        self.__timezone()
        self.__global_fips()
        self.__resize_storage()

    # General
    def __timezone(self):
        self.set_param(
            'timezone',
            lambda p: p != self.api_system.time.Timezone.get(),
            self.api_system.time.Timezone.set
        )

    def __global_fips(self):
        self.set_param(
            'global_fips',
            lambda p: p != self.api_system.security.GlobalFips.get().enabled,
            lambda p: self.api_system.security.GlobalFips.set(
                self.api_system.security.GlobalFips.Info(enabled=p)
            )
        )

    def __resize_storage(self):
        self.set_param(
            'resize_storage',
            lambda p: p,
            lambda _: self.api_system.Storage.resize()
        )

    # DNS
    def __dns_mode(self):
        dns_mode = self.params.get('dns_mode')
        self.info['dns_mode'] = dns_mode
        if dns_mode is None:
            return

        dns_config = self.api_networking.dns.Servers.get()
        if dns_mode == str(dns_config.mode):
            return

        if not self.module.check_mode:
            self.api_networking.dns.Servers.set(
                self.api_networking.dns.Servers.DNSServerConfig(
                    mode=self.api_networking.dns.Servers.DNSServerMode(dns_mode),
                    servers=[] if dns_config.servers is None else dns_config.servers,
                )
            )
        self.changed = True

    def __dns_servers(self):
        dns_servers = self.params.get('dns_servers')
        if dns_servers is None:
            return

        dns_append = self.params.get('dns_append')
        dns_config = self.api_networking.dns.Servers.get()
        current = dns_config.servers
        if dns_append:
            servers_diff = set(dns_servers) - set(current)
            if len(servers_diff) == 0:
                return
            self.changed = True
            if not self.module.check_mode:
                for s in servers_diff:
                    self.api_networking.dns.Servers.add(s)
            self.info['dns_servers'] = current + servers_diff
        else:
            if set(dns_servers) == set(current):
                return
            self.changed = True
            if not self.module.check_mode:
                self.api_networking.dns.Servers.set(
                    self.api_networking.dns.Servers.DNSServerConfig(
                        mode=self.api_networking.dns.Servers.DNSServerMode(str(dns_config.mode)),
                        servers=self.params.get('dns_servers')
                    )
                )
            self.info['dns_servers'] = dns_servers

    def __dns_domains(self):
        dns_domains = self.params.get('dns_domains')
        if dns_domains is None:
            return

        dns_append = self.params.get('dns_append')
        current = self.api_networking.dns.Domains.list()
        if dns_append:
            domains_diff = list(set(dns_domains) - set(current))
            if len(domains_diff) == 0:
                return

            self.changed = True
            if not self.module.check_mode:
                for d in domains_diff:
                    self.api_networking.dns.Domains.add(d)
            self.info['dns_domains'] = current + domains_diff
        else:
            if set(dns_domains) == set(current):
                return

            self.changed = True
            if not self.module.check_mode:
                self.api_networking.dns.Domains.set(dns_domains)
            self.info['dns_domains'] = dns_domains

    def __dns_hostname(self):
        self.set_param(
            'dns_hostname',
            lambda p: p != self.api_networking.dns.Hostname.get(),
            self.api_networking.dns.Hostname.set
        )

    # Ntp
    def __timesync_mode(self):
        self.set_param(
            'timesync_mode',
            lambda p: p.lower() != str(self.api_client.appliance.Timesync.get()).lower(),
            self.api_client.appliance.Ntp.set
        )

    def __ntp_servers(self):
        self.set_param(
            'ntp_servers',
            lambda p: p != self.api_client.appliance.Ntp.get(),
            self.api_client.appliance.Ntp.set
        )

    # Proxy
    def __proxy(self):
        proxy = self.params.get('proxy')
        if proxy is None:
            return

        current = self.api_networking.Proxy.list()
        for p in proxy:
            c = current[p['protocol']]
            if p['enabled']:
                change_required = any([
                    c.enabled != p['enabled'],
                    c.server != p['url'],
                    c.port != p['port'],
                    getattr(c, 'username', None) != p.get('username', None),
                    p.get('password', None) is not None and p.get('always_update_password')
                ])
            else:
                change_required = bool(c.enabled != p['enabled'])

            if change_required:
                self.changed = True
                if not self.module.check_mode:
                    current = self.api_networking.Proxy.set(
                        protocol=p['protocol'],
                        config=self.api_networking.Proxy.Config(
                            server=p['url'],
                            port=p['port'],
                            username=p.get('username', None),
                            password=p.get('password', None),
                            enabled=p['enabled']
                        )
                    )
        self.info['proxy'] = proxy

    def __noproxy(self):
        self.set_param(
            'noproxy',
            lambda p: len((set(p) | set(['localhost', '127.0.0.1'])) ^ set(self.api_networking.NoProxy.get())) > 0,
            self.api_networking.NoProxy.set
        )

    # Security
    def __firewall_rules(self):
        appendrules = self.params.get('firewall_rules_append')
        firewall_rules = self.params.get('firewall_rules')
        if firewall_rules is None:
            return

        # Fetch the rules:
        current_rules = []
        for r in self.api_networking.firewall.Inbound.get():
            inboud_dict = {}
            self.obj_to_dict(r, inboud_dict)
            current_rules.append(inboud_dict)

        if appendrules:
            if all(elem in current_rules for elem in firewall_rules):
                return
            current_rules.extend(firewall_rules)
            self.__firwall_rules_set(current_rules)
        else:
            if current_rules == firewall_rules:
                return
            self.__firwall_rules_set(firewall_rules)

    def __firwall_rules_set(self, firewall_rules):
        # Update the dictionary with user provided values:
        self.changed = True
        self.info['firewall_rules'] = firewall_rules

        # Update the rules:
        if self.module.check_mode:
            return

        rules = []
        for r in firewall_rules:
            rules.append(
                self.api_networking.firewall.Inbound.Rule(
                    address=r['address'],
                    prefix=r['prefix'],
                    policy=self.api_networking.firewall.Inbound.Policy(r['policy']),
                    interface_name=r['interface_name'],
                )
            )
        self.api_networking.firewall.Inbound.set(rules)

    def __consolecli_enabled(self):
        self.set_param(
            'consolecli_enabled',
            lambda p: self.api_access.Consolecli.get() != p,
            self.api_access.Consolecli.set
        )

    def __dcui_enabled(self):
        self.set_param(
            'dcui_enabled',
            lambda p: self.api_access.Dcui.get() != p,
            self.api_access.Dcui.set
        )

    def __ssh_enabled(self):
        self.set_param(
            'ssh_enabled',
            lambda p: self.api_access.Ssh.get() != p,
            self.api_access.Ssh.set
        )

    def __shell_enabled(self):
        shell_enabled = self.params.get('shell_enabled')
        shell_timeout = self.params.get('shell_timeout')
        if shell_enabled is None and shell_timeout is None:
            return

        shell = self.api_access.Shell.get()
        if shell_enabled is not None and shell.enabled != shell_enabled:
            shell.enabled = shell_enabled
            self.info['shell_enabled'] = shell_enabled
            self.changed = True

        if shell_timeout is not None and shell.timeout != shell_timeout and shell_enabled:
            shell.timeout = shell_timeout
            self.info['shell_timeout'] = shell_timeout
            self.changed = True

        if not self.module.check_mode:
            self.api_access.Shell.set(shell)


def main():
    argument_spec = rest_compatible_argument_spec()
    argument_spec.update(
        dict(
            ssh_enabled=dict(type='bool'),
            shell_enabled=dict(type='bool'),
            shell_timeout=dict(type='int'),
            consolecli_enabled=dict(type='bool'),
            dcui_enabled=dict(type='bool'),
            firewall_rules_append=dict(type='bool', default=True),
            firewall_rules=dict(type='list', elements='dict', options=dict(
                address=dict(type='str'),
                prefix=dict(type='int'),
                interface_name=dict(type='str'),
                policy=dict(type='str', choices=['ACCEPT', 'IGNORE', 'REJECT', 'RETURN']),
            )),
            noproxy=dict(type='list', elements='str'),
            proxy=dict(type='list', elements='dict', options=dict(
                enabled=dict(type='bool', required=True),
                url=dict(type='str', required=True),
                port=dict(type='int', required=True),
                protocol=dict(type='str', required=True),
                username=dict(type='str'),
                password=dict(type='str', no_log=True),
                always_update_password=dict(type='bool', default=True),
            )),
            dns_servers=dict(type='list', elements='str'),
            dns_domains=dict(type='list', elements='str'),
            dns_hostname=dict(type='str'),
            dns_mode=dict(type='str', choices=['is_static', 'dhcp']),
            dns_append=dict(type='bool', default=True),
            timesync_mode=dict(type='str', choices=['disabled', 'host', 'ntp']),
            ntp_servers=dict(type='list', elements='str'),
            timezone=dict(type='str'),
            global_fips=dict(type='bool'),
            resize_storage=dict(type='bool', default=False),
        )
    )
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        required_if=[
            ('shell_enabled', True, ('shell_timeout',)),
        ],
    )

    vmware_system = VmwareVcsaSettings(module)
    vmware_system.vcsa_settings()
    module.exit_json(
        changed=vmware_system.changed,
        vcsa_settings=vmware_system.info,
        vcsa={
            'hostname': module.params['hostname'],
            'port': module.params['port']
        }
    )


if __name__ == '__main__':
    main()
