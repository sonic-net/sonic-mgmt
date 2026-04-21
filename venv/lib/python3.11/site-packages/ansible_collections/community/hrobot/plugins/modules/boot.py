#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2019 Felix Fontein <felix@fontein.de>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: boot
short_description: Set boot configuration
version_added: 1.2.0
author:
  - Felix Fontein (@felixfontein)
description:
  - Set the boot configuration for a dedicated server.
seealso:
  - module: community.hrobot.ssh_key
    description: Add, remove or update SSH key.
  - module: community.hrobot.ssh_key_info
    description: Query information on SSH keys.
extends_documentation_fragment:
  - community.hrobot.robot
  - community.hrobot.attributes
  - community.hrobot.attributes.actiongroup_robot

attributes:
  action_group:
    version_added: 1.6.0
  check_mode:
    support: full
  diff_mode:
    support: none
  idempotent:
    support: full

options:
  server_number:
    description:
      - The server number of the server whose boot configuration to adjust.
    type: int
    required: true
  regular_boot:
    description:
      - If this option is provided, all special boot configurations are removed and the installed operating system will be
        booted up next (assuming it is bootable).
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: bool
    choices:
      - true
  rescue:
    description:
      - If this option is provided, the rescue system will be activated for the next boot.
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: dict
    suboptions:
      os:
        description:
          - The operating system to use for the rescue system. Possible choices can change over time.
          - Currently, V(linux), V(linuxold), V(freebsd), V(freebsdold), V(freebsdax), V(freebsdbetaax), V(vkvm), and V(vkvmold)
            seem to be available.
        type: str
        required: true
      arch:
        description:
          - The architecture to use for the rescue system.
          - Not all architectures are available for all operating systems.
          - Defaults to V(64).
          - This option is deprecated and will be removed in community.hrobot 3.0.0.
        type: int
        choices:
          - 32
          - 64
      authorized_keys:
        description:
          - One or more SSH key fingerprints to equip the rescue system with. You can also specify the public key itself,
            the module will compute its fingerprint and pass it on to the Robot API.
          - Only fingerprints for SSH keys deposited in the Robot API can be used.
          - You can use the M(community.hrobot.ssh_key_info) module to query the SSH keys you can use, and the M(community.hrobot.ssh_key)
            module to add or update SSH keys.
        type: list
        elements: str
  install_linux:
    description:
      - If this option is provided, a Linux system install will be activated for the next boot.
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: dict
    suboptions:
      dist:
        description:
          - The distribution to install.
        type: str
        required: true
      arch:
        description:
          - The architecture to use for the install.
          - Not all architectures are available for all distributions.
          - Defaults to V(64).
          - This option is deprecated and will be removed in community.hrobot 3.0.0.
        type: int
        choices:
          - 32
          - 64
      lang:
        description:
          - The language to use for the operating system.
        type: str
        required: true
      authorized_keys:
        description:
          - One or more SSH key fingerprints to equip the rescue system with. You can also specify the public key itself,
            the module will compute its fingerprint and pass it on to the Robot API.
          - Only fingerprints for SSH keys deposited in the Robot API can be used.
          - You can use the M(community.hrobot.ssh_key_info) module to query the SSH keys you can use, and the M(community.hrobot.ssh_key)
            module to add or update SSH keys.
        type: list
        elements: str
  install_vnc:
    description:
      - If this option is provided, a VNC installation will be activated for the next boot.
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: dict
    suboptions:
      dist:
        description:
          - The distribution to install.
        type: str
        required: true
      arch:
        description:
          - The architecture to use for the install.
          - Not all architectures are available for all distributions.
          - Defaults to V(64).
          - This option is deprecated and will be removed in community.hrobot 3.0.0.
        type: int
        choices:
          - 32
          - 64
      lang:
        description:
          - The language to use for the operating system.
        type: str
        required: true
  install_windows:
    description:
      - If this option is provided, a Windows installation will be activated for the next boot.
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: dict
    suboptions:
      lang:
        description:
          - The language to use for Windows.
        type: str
        required: true
  install_plesk:
    description:
      - If this option is provided, a Plesk installation will be activated for the next boot.
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: dict
    suboptions:
      dist:
        description:
          - The distribution to install.
        type: str
        required: true
      arch:
        description:
          - The architecture to use for the install.
          - Not all architectures are available for all distributions.
          - Defaults to V(64).
          - This option is deprecated and will be removed in community.hrobot 3.0.0.
        type: int
        choices:
          - 32
          - 64
      lang:
        description:
          - The language to use for the operating system.
        type: str
        required: true
      hostname:
        description:
          - The hostname.
        type: str
        required: true
  install_cpanel:
    description:
      - If this option is provided, a cPanel installation will be activated for the next boot.
      - Precisely one of O(regular_boot), O(rescue), O(install_linux), O(install_vnc), O(install_windows), O(install_plesk),
        and O(install_cpanel) must be provided.
    type: dict
    suboptions:
      dist:
        description:
          - The distribution to install.
        type: str
        required: true
      arch:
        description:
          - The architecture to use for the install.
          - Not all architectures are available for all distributions.
          - Defaults to V(64).
          - This option is deprecated and will be removed in community.hrobot 3.0.0.
        type: int
        choices:
          - 32
          - 64
      lang:
        description:
          - The language to use for the operating system.
        type: str
        required: true
      hostname:
        description:
          - The hostname.
        type: str
        required: true
"""

EXAMPLES = r"""
---
- name: Disable all special boot configurations
  community.hrobot.boot:
    hetzner_user: foo
    hetzner_password: bar
    regular_boot: true

- name: Enable a rescue system (64bit Linux) for the next boot
  community.hrobot.boot:
    hetzner_user: foo
    hetzner_password: bar
    rescue:
      os: linux

- name: Enable a Linux install for the next boot
  community.hrobot.boot:
    hetzner_user: foo
    hetzner_password: bar
    install_linux:
      dist: CentOS 5.5 minimal
      lang: en
      authorized_keys:
        - 56:29:99:a4:5d:ed:ac:95:c1:f5:88:82:90:5d:dd:10
        - 15:28:b0:03:95:f0:77:b3:10:56:15:6b:77:22:a5:bb
"""

RETURN = r"""
configuration_type:
  description:
    - Describes the active boot configuration.
  returned: success
  type: str
  choices:
    - regular_boot
    - rescue
    - install_linux
    - install_vnc
    - install_windows
    - install_plesk
    - install_cpanel
password:
  description:
    - The root password for the active boot configuration, if available.
    - For non-rescue boot configurations, it is avised to change the root password as soon as possible.
  returned: success and if RV(configuration_type) is not V(regular_boot)
  type: str
"""

from ansible.module_utils.basic import AnsibleModule

from ansible_collections.community.hrobot.plugins.module_utils.robot import (
    BASE_URL,
    ROBOT_DEFAULT_ARGUMENT_SPEC,
    fetch_url_json,
)

from ansible_collections.community.hrobot.plugins.module_utils.ssh import (
    FingerprintError,
    extract_fingerprint,
)

try:
    from urllib.parse import urlencode
except ImportError:
    # Python 2.x fallback:
    from urllib import urlencode


BOOT_CONFIGURATION_DATA = [
    ('rescue', 'rescue', {
        'os': ('os', 'os'),
        'arch': ('arch', 'arch'),
        'authorized_keys': ('authorized_key', 'authorized_key[]'),
    }),
    ('install_linux', 'linux', {
        'dist': ('dist', 'dist'),
        'arch': ('arch', 'arch'),
        'lang': ('lang', 'lang'),
        'authorized_keys': ('authorized_key', 'authorized_key[]'),
    }),
    ('install_vnc', 'vnc', {
        'dist': ('dist', 'dist'),
        'arch': ('arch', 'arch'),
        'lang': ('lang', 'lang'),
    }),
    ('install_windows', 'windows', {
        'lang': ('lang', 'lang'),
    }),
    ('install_plesk', 'plesk', {
        'dist': ('dist', 'dist'),
        'arch': ('arch', 'arch'),
        'lang': ('lang', 'lang'),
        'hostname': ('hostname', 'hostname'),
    }),
    ('install_cpanel', 'cpanel', {
        'dist': ('dist', 'dist'),
        'arch': ('arch', 'arch'),
        'lang': ('lang', 'lang'),
        'hostname': ('hostname', 'hostname'),
    }),
]


def main():
    argument_spec = dict(
        server_number=dict(type='int', required=True),
        regular_boot=dict(type='bool', choices=[True]),
        rescue=dict(type='dict', options=dict(
            os=dict(type='str', required=True),
            arch=dict(type='int', choices=[32, 64], removed_in_version='3.0.0', removed_from_collection='community.hrobot'),
            authorized_keys=dict(type='list', elements='str', no_log=False),
        )),
        install_linux=dict(type='dict', options=dict(
            dist=dict(type='str', required=True),
            arch=dict(type='int', choices=[32, 64], removed_in_version='3.0.0', removed_from_collection='community.hrobot'),
            lang=dict(type='str', required=True),
            authorized_keys=dict(type='list', elements='str', no_log=False),
        )),
        install_vnc=dict(type='dict', options=dict(
            dist=dict(type='str', required=True),
            arch=dict(type='int', choices=[32, 64], removed_in_version='3.0.0', removed_from_collection='community.hrobot'),
            lang=dict(type='str', required=True),
        )),
        install_windows=dict(type='dict', options=dict(
            lang=dict(type='str', required=True),
        )),
        install_plesk=dict(type='dict', options=dict(
            dist=dict(type='str', required=True),
            arch=dict(type='int', choices=[32, 64], removed_in_version='3.0.0', removed_from_collection='community.hrobot'),
            lang=dict(type='str', required=True),
            hostname=dict(type='str', required=True),
        )),
        install_cpanel=dict(type='dict', options=dict(
            dist=dict(type='str', required=True),
            arch=dict(type='int', choices=[32, 64], removed_in_version='3.0.0', removed_from_collection='community.hrobot'),
            lang=dict(type='str', required=True),
            hostname=dict(type='str', required=True),
        )),
    )
    argument_spec.update(ROBOT_DEFAULT_ARGUMENT_SPEC)
    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
        mutually_exclusive=[('regular_boot', 'rescue', 'install_linux', 'install_vnc', 'install_windows', 'install_plesk', 'install_cpanel')],
        required_one_of=[('regular_boot', 'rescue', 'install_linux', 'install_vnc', 'install_windows', 'install_plesk', 'install_cpanel')],
    )

    server_number = module.params['server_number']
    changed = False

    # Retrieve current boot config
    url = "{0}/boot/{1}".format(BASE_URL, server_number)
    result, error = fetch_url_json(module, url, accept_errors=['SERVER_NOT_FOUND', 'BOOT_NOT_AVAILABLE'])
    if error is not None:
        if error == 'SERVER_NOT_FOUND':
            module.fail_json(msg='This server does not exist, or you do not have access rights for it')
        if error == 'BOOT_NOT_AVAILABLE':
            module.fail_json(msg='There is no boot configuration available for this server')
        raise AssertionError('Unexpected error {0}'.format(error))  # pragma: no cover

    # Deactivate current boot configurations that are not requested
    for option_name, other_name, dummy in BOOT_CONFIGURATION_DATA:
        if (result['boot'].get(other_name) or {}).get('active') and not module.params[option_name]:
            changed = True
            if not module.check_mode:
                url = "{0}/boot/{1}/{2}".format(BASE_URL, server_number, other_name)
                fetch_url_json(module, url, method='DELETE', allow_empty_result=True)

    # Enable/compare boot configuration
    return_values = {
        'configuration_type': 'regular_boot',
        'password': None,
    }
    for option_name, other_name, options in BOOT_CONFIGURATION_DATA:
        if module.params[option_name]:
            return_values['configuration_type'] = option_name
            existing = result['boot'].get(other_name) or {}
            return_values['password'] = existing.get('password')
            data = {}
            for option_key, (result_key, data_key) in options.items():
                option = module.params[option_name][option_key]
                if option is None or option == []:
                    continue
                data[data_key] = option
            # Normalize options
            option_key = 'authorized_keys'
            if module.params[option_name].get(option_key):
                should = module.params[option_name][option_key]
                for index, key in enumerate(should):
                    if ' ' in key:
                        try:
                            should[index] = extract_fingerprint(key)
                        except FingerprintError as exc:
                            module.fail_json(
                                msg="Error while extracting fingerprint of {option_name}.{option_key}[{idx}]'s value {key!r}: {exc}".format(
                                    option_name=option_name,
                                    option_key=option_key,
                                    idx=index + 1,
                                    key=key,
                                    exc=exc,
                                ),
                            )
                module.params[option_name][option_key] = should
            # Idempotence check
            if existing.get('active'):
                needs_change = False
                for option_key, (result_key, data_key) in options.items():
                    should = module.params[option_name][option_key]
                    if should is None:
                        continue
                    # unfold the return object for the idempotence check to work correctly
                    has = existing.get(result_key)
                    if has and option_key == 'authorized_keys':
                        has = [x['key']['fingerprint'] for x in has]
                    if isinstance(has, list):
                        has = sorted(has)
                        if not isinstance(should, list):
                            should = [should]  # pragma: no cover
                        should = sorted(should)
                    if should != has:
                        needs_change = True
            else:
                needs_change = True

            if needs_change:
                changed = True
                if not module.check_mode:
                    url = "{0}/boot/{1}/{2}".format(BASE_URL, server_number, other_name)
                    if existing.get('active'):
                        # Deactivate existing boot configuration
                        fetch_url_json(module, url, method='DELETE', allow_empty_result=True)
                    # Enable new boot configuration
                    headers = {"Content-type": "application/x-www-form-urlencoded"}
                    result, dummy = fetch_url_json(
                        module,
                        url,
                        data=urlencode(data, True),
                        headers=headers,
                        method='POST',
                    )
                    return_values['password'] = (result.get(other_name) or {}).get('password')
                else:
                    return_values['password'] = None

    module.exit_json(changed=changed, **return_values)


if __name__ == '__main__':  # pragma: no cover
    main()  # pragma: no cover
