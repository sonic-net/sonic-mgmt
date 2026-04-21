#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_ldap
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = """
---
module: sonic_ldap
author: 'Santhosh Kumar T(@santhosh-kt)'
version_added: '2.5.0'
notes:
- Supports C(check_mode).
short_description: Configure global LDAP server settings on SONiC.
description:
  - This module provides configuration management of global LDAP server parameters on devices running SONiC.
  - Configure VRF instance before configuring VRF to be used for LDAP server connection.
options:
  config:
    description:
      - Specifies the LDAP server related configuration.
    type: list
    elements: dict
    suboptions:
      name:
        description:
          - Specifies the LDAP type.
        type: str
        choices:
          - global
          - nss
          - pam
          - sudo
        required: true
      base:
        description:
          - Configure base distinguished name.
        type: str
      bind_timelimit:
        description:
          - Configure connect time limit (0 to 65535).
        type: int
      binddn:
        description:
          - Configure distinguished name to bind.
        type: str
      bindpw:
        description:
          - Configure credentials to bind
        type: dict
        suboptions:
          pwd:
            description:
              - Authentication password for the bind.
            type: str
            required: true
          encrypted:
            description:
              - Indicates whether the password is encrypted text.
            type: bool
      servers:
        description:
          - Configure host name or IP address for a LDAP server.
          - Applicable only for global.
        type: list
        elements: dict
        suboptions:
          address:
            description:
              - Hostname or IP address of LDAP server.
            type: str
            required: true
          port:
            description:
              - Configure server port number (1 to 65535).
            type: int
          priority:
            description:
              - Configure priority (1 to 99).
            type: int
          retry:
            description:
              - Configure retransmit attempt (0 to 10).
            type: int
          ssl:
            description:
              - Configure TLS configuration.
            type: str
            choices:
              - "on"
              - "off"
              - "start_tls"
          server_type:
            description:
              - Configure server type.
            type: str
            choices:
              - all
              - nss
              - sudo
              - pam
              - nss_sudo
              - nss_pam
              - sudo_pam
      idle_timelimit:
        description:
         - Configure NSS idle time limit (0 to 65535).
         - Applicable only for global and nss.
        type: int
      map:
        description:
          - Configure LDAP server for map.
          - Applicable only for global.
        type: dict
        suboptions:
          attribute:
            description:
              - Configure attribute map.
              - I(from) and I(to) are required together.
            type: list
            elements: dict
            suboptions:
              from:
                description:
                  - Configure attribute map key.
                type: str
              to:
                description:
                  - Configure attribute map value.
                type: str
          default_attribute:
            description:
              - Configure default attribute map.
              - I(from) and I(to) are required together.
            type: list
            elements: dict
            suboptions:
              from:
                description:
                  - Configure default attribute map key.
                type: str
              to:
                description:
                  - Configure default attribute map value.
                type: str
          map_remote_groups_to_sonic_roles:
            description:
              - Configure mapping for remote groups to sonic roles.
              - I(remote_group) and I(sonic_roles) are required together.
            type: list
            elements: dict
            suboptions:
              remote_group:
                description:
                  - Map remote groups to SONiC roles.
                type: str
              sonic_roles:
                description:
                  - Configure SONiC roles.
                type: list
                elements: str
                choices:
                  - admin
                  - operator
                  - netadmin
                  - secadmin
          objectclass:
            description:
              - Configure Objectclass map.
              - I(from) and I(to) are required together.
            type: list
            elements: dict
            suboptions:
              from:
                description:
                  - Configure Objectclass map key.
                type: str
              to:
                description:
                  - Configure Objectclass map value.
                type: str
          override_attribute:
            description:
              - Configure override attribute map.
              - I(from) and I(to) are required together.
            type: list
            elements: dict
            suboptions:
              from:
                description:
                  - Configure override attribute map key.
                type: str
              to:
                description:
                  - Configure override attribute map value.
                type: str
      nss_base_group:
        description:
          - Configure NSS search base for group map.
          - Applicable only for global and nss.
        type: str
      nss_base_netgroup:
        description:
          - Configure NSS search base for netgroup map.
          - Applicable only for global and nss.
        type: str
      nss_base_passwd:
        description:
          - Configure NSS search base for passwd map.
          - Applicable only for global, nss and pam.
        type: str
      nss_base_shadow:
        description:
          - Configure NSS search base for shadow map.
          - Applicable only for global and nss.
        type: str
      nss_base_sudoers:
        description:
          - Configure NSS search base for sudoers map.
          - Applicable only for global and nss.
        type: str
      nss_initgroups_ignoreusers:
        description:
          - Configure NSS init groups ignore users.
          - Applicable only for global and nss.
        type: str
      nss_skipmembers:
        description:
          - Configure NSS skipmembers
        type: bool
      pam_filter:
        description:
          - Configure PAM filter.
          - Applicable only for global and pam.
        type: str
      pam_group_dn:
        description:
          - Configure PAM Group Distinguished name.
          - Applicable only for global and pam.
        type: str
      pam_login_attribute:
        description:
          - Configure PAM Login attribute.
          - Applicable only for global and pam.
        type: str
      pam_member_attribute:
        description:
          - Configure PAM Member attribute.
          - Applicable only for global and pam.
        type: str
      port:
        description:
          - Configure server port (1 to 65535).
        type: int
      retry:
        description:
          - Configure retransmit attempt (0 to 10).
        type: int
      scope:
        description:
          - Configure the search scope.
          - Applicable only for global, nss and pam.
        type: str
        choices:
          - sub
          - one
          - base
      source_interface:
        description:
          - Configure source interface to be used as source IP for the LDAP packets.
          - Applicable only for global.
          - Full name of the Layer 3 interface, i.e. Eth1/1.
        type: str
      security_profile:
        description:
          - Configure security profile for LDAP.
          - Applicable only for global.
        type: str
      ssl:
        description:
          - Configure TLS configuration.
        type: str
        choices:
          - "on"
          - "off"
          - "start_tls"
      sudoers_base:
        description:
          - Configure sudo base distinguished name for queries.
          - Applicable only for global and sudo.
        type: str
      sudoers_search_filter:
        description:
          - Configure sudo search filter for queries.
          - Applicable only for global and sudo.
        type: str
      timelimit:
        description:
          - Configure search time limit (1 to 65535).
        type: int
      version:
        description:
          - Configure LDAP version 2 or 3.
        type: int
        choices:
          - 2
          - 3
      vrf:
        description:
          - Configure VRF to be used for LDAP server connection.
          - Applicable only for global.
        type: str
  state:
    description:
      - Specifies the operation to be performed on the LDAP server configured on the device.
      - In case of merged, the input configuration will be merged with the existing LDAP server configuration on the device.
      - In case of deleted, the existing LDAP server configuration will be removed from the device.
      - In case of overridden, all the existing LDAP server configuration will be deleted and the specified input configuration will be installed.
      - In case of replaced, the existing LDAP server configuration on the device will be replaced by the configuration in the playbook
        for each LDAP server group configured by the playbook.
    default: merged
    choices: ['merged', 'deleted', 'replaced', 'overridden']
    type: str
"""

EXAMPLES = """
# Using "deleted" state
#
# Before state:
# -------------
#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss-base-passwd password
# ldap-server nss-initgroups-ignoreusers username1
# ldap-server nss scope sub
# ldap-server nss timelimit 15
# ldap-server nss idle-timelimit 25
# ldap-server nss nss-base-group group1
# ldap-server nss nss-base-sudoers sudo1
# ldap-server pam base admin
# ldap-server pam binddn CN=example.com
# ldap-server pam pam-login-attribute loginattrstring
# ldap-server sudo retry 10
# ldap-server sudo ssl start_tls
# ldap-server sudo bind-timelimit 15
# ldap-server vrf Vrf_1
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host 20.20.20.10 retry 1
# ldap-server host example.com priority 10 ssl off
# ldap-server map default-attribute-value attr1 to attr2
# ldap-server map default-attribute-value attr3 to attr4
# ldap-server map objectclass attr1 to attr3
# sonic#

- name: Delete the LDAP server configurations
  sonic_ldap:
    config:
      - name: "global"
        servers:
          - address: "example.com"
        vrf: "Vrf_1"
      - name: "nss"
        idle_timelimit: 25
        scope: "sub"
      - name: "sudo"
    state: deleted

# After state:
# ------------
#
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss-base-passwd password
# ldap-server nss-initgroups-ignoreusers username1
# ldap-server nss timelimit 15
# ldap-server nss nss-base-group group1
# ldap-server nss nss-base-sudoers sudo1
# ldap-server pam base admin
# ldap-server pam binddn CN=example.com
# ldap-server pam pam-login-attribute loginattrstring
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host 20.20.20.10 retry 1
# ldap-server map default-attribute-value attr1 to attr2
# ldap-server map default-attribute-value attr3 to attr4
# ldap-server map objectclass attr1 to attr3
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# !
# sonic# show running-configuration | grep ldap
# sonic#

- name: Add the LDAP server configurations
  sonic_ldap:
    config:
      - name: "global"
        servers:
          - address: "example.com"
            priority: 10
            ssl: "on"
          - address: "10.10.10.1"
            priority: 5
            port: 1550
        port: 389
        version: 2
        nss_base_passwd: password
      - name: "pam"
        base: "admin"
        binddn: "CN=example.com"
        pam_login_attribute: "loginattrstring"
      - name: "sudo"
        bind_timelimit: 20
        retry: 10
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss-base-passwd password
# ldap-server pam base admin
# ldap-server pam binddn CN=example.com
# ldap-server pam pam-login-attribute loginattrstring
# ldap-server sudo retry 10
# ldap-server sudo bind-timelimit 20
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host example.com priority 10 ssl on
# sonic#


# Using "merged" state
#
# Before state:
# -------------
#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# !
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss-base-passwd password
# ldap-server pam base admin
# ldap-server pam binddn CN=example.com
# ldap-server pam pam-login-attribute loginattrstring
# ldap-server sudo retry 10
# ldap-server sudo bind-timelimit 20
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host example.com priority 10 ssl on
# sonic#

- name: Add the LDAP server configurations
  sonic_ldap:
    config:
      - name: "global"
        servers:
          - address: "example.com"
            ssl: "off"
          - address: "20.20.20.10"
            retry: 1
        nss_base_passwd: password
        pam_login_attribute: "globallogin"
        nss_initgroups_ignoreusers: "username1"
        vrf: "Vrf_1"
        map:
          default_attribute:
            - from: "attr1"
              to: "attr2"
            - from: "attr3"
              to: "attr4"
          objectclass:
            - from: "attr1"
              to: "attr3"
          map_remote_groups_to_sonic_roles:
            - remote_group: "group1"
              sonic_roles:
                - admin
                - operator
      - name: "nss"
        nss_base_netgroup: "group1"
        idle_timelimit: 25
        timelimit: 15
        scope: "sub"
        nss_base_sudoers: "sudo1"
      - name: "sudo"
        bind_timelimit: 15
        ssl: "start_tls"
    state: merged

# After state:
# ------------
#
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss-base-passwd password
# ldap-server pam-login-attribute globallogin
# ldap-server nss-initgroups-ignoreusers username1
# ldap-server nss scope sub
# ldap-server nss timelimit 15
# ldap-server nss idle-timelimit 25
# ldap-server nss nss-base-group group1
# ldap-server nss nss-base-sudoers sudo1
# ldap-server pam base admin
# ldap-server pam binddn CN=example.com
# ldap-server pam pam-login-attribute loginattrstring
# ldap-server sudo retry 10
# ldap-server sudo ssl start_tls
# ldap-server sudo bind-timelimit 15
# ldap-server vrf Vrf_1
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host 20.20.20.10 retry 1
# ldap-server host example.com priority 10 ssl off
# ldap-server map default-attribute-value attr1 to attr2
# ldap-server map default-attribute-value attr3 to attr4
# ldap-server map objectclass attr1 to attr3
# ldap-server map remote-groups-override-to-sonic-roles group1 to admin,operator
# sonic#


# Using "replaced" state
#
# Before state:
# -------------
#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss-base-passwd password
# ldap-server nss-initgroups-ignoreusers username1
# ldap-server nss idle-timelimit 25
# ldap-server nss nss-base-group group1
# ldap-server nss nss-base-sudoers sudo1
# ldap-server pam base admin
# ldap-server pam binddn CN=example.com
# ldap-server pam pam-login-attribute loginattrstring
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host 20.20.20.10 retry 1
# ldap-server map default-attribute-value attr1 to attr2
# ldap-server map default-attribute-value attr3 to attr4
# ldap-server map objectclass attr1 to attr3
# sonic#

- name: Replace the LDAP server configurations
  sonic_ldap:
    config:
      - name: "nss"
        scope: "one"
        bindpw:
          pwd: "password"
      - name: "pam"
        version: 3
        port: 2000
        timelimit: 20
        pam_group_dn: "DNAME"
      - name: "sudo"
        sudoers_search_filter: "filter1"
        base: "base_name"
        version: 3
    state: replaced

# After state:
# ------------
#
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss scope one
# ldap-server nss bindpw U2FsdGVkX1+t8PR9IIi+qjZpYoNwjmd78D1WDBdkLxs= encrypted
# ldap-server pam version 3
# ldap-server pam port 2000
# ldap-server pam timelimit 20
# ldap-server pam pam-group-dn DNAME
# ldap-server sudo version 3
# ldap-server sudo base base_name
# ldap-server sudo sudoers-search-filter filter1
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host 20.20.20.10 retry 1
# ldap-server map default-attribute-value attr1 to attr2
# ldap-server map default-attribute-value attr3 to attr4
# ldap-server map objectclass attr1 to attr3
# sonic#


# Using "overridden" state
#
# Before state:
# -------------
#
# sonic# show running-configuration vrf Vrf_1
# !
# ip vrf Vrf_1
# sonic# show running-configuration | grep ldap
# ldap-server port 389
# ldap-server version 2
# ldap-server nss scope one
# ldap-server nss bindpw U2FsdGVkX1+t8PR9IIi+qjZpYoNwjmd78D1WDBdkLxs= encrypted
# ldap-server pam version 3
# ldap-server pam port 2000
# ldap-server pam timelimit 20
# ldap-server pam pam-group-dn DNAME
# ldap-server sudo version 3
# ldap-server sudo base base_name
# ldap-server sudo sudoers-search-filter filter1
# ldap-server host 10.10.10.1 port 1550 priority 5
# ldap-server host 20.20.20.10 retry 1
# ldap-server map default-attribute-value attr1 to attr2
# ldap-server map default-attribute-value attr3 to attr4
# ldap-server map objectclass attr1 to attr3
# sonic#

- name: Override the LDAP server configurations
  sonic_ldap:
    config:
      - name: "global"
        source_interface: "Eth1/1"
        security_profile: "default"
        vrf: "Vrf_1"
        servers:
          - address: "client.com"
          - address: "host.com"
            server_type: "sudo_pam"
        map:
          override_attribute:
            - from: "attr1"
              to: "attr2"
          map_remote_groups_to_sonic_roles:
            - remote_group: "group1"
              sonic_roles:
                - admin
                - operator
        idle_timelimit: 20
      - name: "pam"
        ssl: "off"
        scope: "base"
    state: overridden

# After state:
# ------------
#
# sonic# show running-configuration | grep ldap
# ldap-server idle-timelimit 20
# ldap-server pam ssl off
# ldap-server pam scope base
# ldap-server source-interface Eth1/1
# ldap-server security-profile default
# ldap-server vrf Vrf_1
# ldap-server host client.com
# ldap-server host host.com use-type sudo_pam
# ldap-server map override-attribute-value attr1 to attr2
# ldap-server map remote-groups-override-to-sonic-roles group1 to admin,operator
# sonic#
"""

RETURN = """
before:
  description: The configuration prior to the module invocation.
  returned: always
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after:
  description: The resulting configuration module invocation.
  returned: when changed
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
after(generated):
  description: The generated configuration module invocation.
  returned: when C(check_mode)
  type: list
  sample: >
    The configuration returned will always be in the same format
     as the parameters above.
commands:
  description: The set of commands pushed to the remote device.
  returned: always
  type: list
  sample: ['command 1', 'command 2', 'command 3']
"""


from ansible.module_utils.basic import AnsibleModule
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.argspec.ldap.ldap import LdapArgs
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.config.ldap.ldap import Ldap


def main():
    """
    Main entry point for module execution

    :returns: the result from module invocation
    """
    module = AnsibleModule(argument_spec=LdapArgs.argument_spec,
                           supports_check_mode=True)

    result = Ldap(module).execute_module()
    module.exit_json(**result)


if __name__ == '__main__':
    main()
