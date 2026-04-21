#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright 2025 Dell Inc. or its subsidiaries. All Rights Reserved.
# GNU General Public License v3.0+
# (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

"""
The module file for sonic_image_management
"""

from __future__ import absolute_import, division, print_function
__metaclass__ = type

DOCUMENTATION = """
---
module: sonic_image_management
version_added: '2.4.0'
short_description: Manage installation of Enterprise SONiC image, software patch and firmware updater
description:
  - Manage installation of Enterprise SONiC image, software patch and firmware updater.
author: 'Arun Saravanan Balachandran (@ArunSaravananBalachandran), Aravind Mani (@aravindmani-1)'

options:
  image:
    description:
      - Manage installation of Enterprise SONiC image.
    type: dict
    suboptions:
      command:
        description:
          - Specifies the image manangement operation to be performed.
          - C(install) - Install image specified by I(path).
          - C(cancel) - Cancel image installation.
          - C(remove) - Remove image specified by I(name).
          - C(set-default) - Set the image specified by I(name) as default boot image.
          - C(get-list) - Retrieve list of installed images.
          - C(get-status) - Retrieve image installation status.
          - C(gpg-key) - Install GPG key.
          - C(verify) - Verify the image specified by I(path) using GPG or PKI method.
        type: str
        choices:
          - install
          - cancel
          - remove
          - set-default
          - get-list
          - get-status
          - gpg-key
          - verify
        required: true
      path:
        description:
          - When I(command=install) or I(command=verify) specifies the path of the image to be installed.
          - Path can be a file in the device (file://filepath) or URL (http:// or https://).
        type: str
      name:
        description:
          - When I(command=remove) or I(command=set-default) specifies the name of the image.
          - When I(command=remove), name can be specified as C(all) to remove all images which are not current or next.
        type: str
      keyserver:
        version_added: '3.0.0'
        description:
          - GPG Key server URL.
          - Required when I(command=gpg-key).
        type: str
      pubkeyid:
        version_added: '3.0.0'
        description:
          - GPG Key ID to be installed.
          - Required when I(command=gpg-key).
        type: str
      signaturefile:
        version_added: '3.0.0'
        description:
          - GPG/PKI file to be verified.
          - Required when I(command=verify).
        type: str
      pubkeyfilename:
        version_added: '3.0.0'
        description:
          - Specifies the certificate for signature file.
          - Required when I(command=verify) and I(verifymethod=pki).
        type: str
      verifymethod:
        version_added: '3.0.0'
        description:
          - Image verification GPG or PKI method
          - Required when I(command=verify).
        type: str
        choices:
          - gpg
          - pki
  patch:
    description:
      - Manage installation of software patch.
    type: dict
    suboptions:
      command:
        description:
          - Specifies the patch manangement operation to be performed.
          - C(install) - Install patch specified by I(path).
          - C(rollback) - Remove an installed patch specified by I(name).
          - C(get-history) - Retrieve history of patches applied/rolled back.
          - C(get-list) - Retrieve list of installed patches.
          - C(get-status) - Retrieve patch installation/removal status.
        type: str
        choices:
          - install
          - rollback
          - get-history
          - get-list
          - get-status
        required: true
      path:
        description:
          - When I(command=install), specifies the path of the patch to be installed.
          - Path can be a file in the device (file://filepath) or URL (http:// or https://).
        type: str
      name:
        description:
         - When I(command=rollback), specifies the name of the patch.
        type: str
  firmware:
    description:
      - Manage installation of Firmware updater
    type: dict
    suboptions:
      command:
        description:
          - Specifies the firmware updater manangement operation to be performed.
          - C(install) - Stage firmware updater specified by I(path).
          - C(cancel) - Cancel a pending firmware updater.
          - C(get-list) - Retrieve details of pending firmware updater and result of installed firmware updater.
          - C(get-status) - Retrieve firmware updater staging status.
        type: str
        choices:
          - install
          - cancel
          - get-list
          - get-status
        required: true
      path:
        description:
          - When I(command=install), specifies the path of the firmware updater to be staged.
          - Path can be a file in the device (file://filepath) or URL (http:// or https://).
        type: str
"""

EXAMPLES = """

- name: Install Enterprise SONiC image
  dellemc.enterprise_sonic.sonic_image_management:
    image:
      command: install
      path: 'file://home/admin/sonic.bin'

- name: Get image installation status
  dellemc.enterprise_sonic.sonic_image_management:
    image:
      command: get-status

- name: Get list of installed images
  dellemc.enterprise_sonic.sonic_image_management:
    image:
      command: get-list

- name: Stage a firmware updater
  dellemc.enterprise_sonic.sonic_image_management:
    firmware:
      command: install
      path: 'file://home/admin/onie-update-full.bin'

- name: Install GPG Key for image verification
  dellemc.enterprise_sonic.sonic_image_management:
    image:
      command: gpg-key
      keyserver: 'hkp://keyserver.ubuntu.com:80'
      pubkeyid: 'DAFWQGEW12345678'

- name: Verify Enterprise SONiC image
  dellemc.enterprise_sonic.sonic_image_management:
    image:
      command: verify
      path: 'home://sonic.bin'
      verifymethod: 'gpg'
      signaturefile: 'sign.gpg'
"""

RETURN = """
status:
  description: Status of the operation performed.
  returned: when I(command) is not C(get-status), C(get-list) and C(get-history)
  type: str
  sample: SUCCESS
info:
  description: Details returned by the specified get operation.
  returned: when I(command=get-status) or I(command=get-list) or I(command=get-history)
  type: dict
  sample: >
    {
            "file-download-speed" : "106200",
            "file-progress" : 100,
            "file-size" : "1304997870",
            "file-transfer-bytes" : "1304997870",
            "install-end-time" : "1695714740",
            "install-start-time" : "1695714698",
            "install-status" : "INSTALL_STATE_SUCCESS",
            "install-status-detail" : "Image install success",
            "operation-status" : "GLOBAL_STATE_SUCCESS",
            "transfer-end-time" : "1695714669",
            "transfer-start-time" : "1695714657",
            "transfer-status" : "TRANSFER_STATE_SUCCESS",
            "transfer-status-detail" : "DOWNLOADING IMAGE"
    }
"""


from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import ConnectionError
from ansible_collections.dellemc.enterprise_sonic.plugins.module_utils.network.sonic.sonic import (
    to_request,
    edit_config
)


def validate_and_retrieve_params(module, warnings):
    """
    Validates the module parameters
    """
    params = {}
    for category in ('image', 'patch', 'firmware'):
        if module.params.get(category) and module.params[category].get('command'):
            if params.get('category') is None:
                params['category'] = category
                params.update(module.params[category])
            else:
                module.fail_json(msg="Only one image management operation can be performed at a time")

    if module.check_mode and not params['command'].startswith('get-'):
        module.fail_json(msg='Only get commands are supported while using check mode, but {0} was provided'.format(params['command']))

    if params['command'] == 'install':
        if not params.get('path'):
            module.fail_json(msg="{0} -> path is required when {0} -> command = install".format(params['category']))
        if params.get('name'):
            warnings.append("{0} -> name is ignored when {0} -> command = install".format(params['category']))
    elif params['command'] in ('remove', 'set-default', 'rollback'):
        if not params.get('name'):
            module.fail_json(msg="{0} -> name is required when {0} -> command = {1}".format(params['category'], params['command']))
        if params.get('path'):
            warnings.append("{0} -> path is ignored when {0} -> command = {1}".format(params['category'], params['command']))
    elif params['command'] == 'gpg-key':
        if not params.get('keyserver') or not params.get('pubkeyid'):
            module.fail_json(msg="{0} -> keyserver URL and Key ID are required when {0} -> command = {1}".format(params['category'], params['command']))
    elif params['command'] == 'verify':
        if not params.get('verifymethod'):
            module.fail_json(msg="{0} -> verifymethod is required when {0} -> command = verify".format(params['category']))
        if params.get('verifymethod') == 'gpg':
            if not params.get('path') or not params.get('signaturefile'):
                module.fail_json(msg="{0} -> Image path and GPG signature are required when {0} -> command = {1}".format(params['category'], params['command']))
        else:
            if not params.get('path') or not params.get('signaturefile') or not params.get('pubkeyfilename'):
                module.fail_json(
                    msg="{0} -> Image path, PKI signature and certificate are required when {0} -> command = {1}".format(params['category'], params['command']))
    return params


def execute_command(module, params, result):
    """
    Executes the specified command and updates the result
    """
    command_map = {
        'image': {
            'install': {
                'path': 'operations/openconfig-image-management:image-install',
                'status': 'Check image -> command = get-status for image install progress'
            },
            'cancel': {
                'path': 'operations/openconfig-image-management:image-install-cancel'
            },
            'remove': {
                'path': 'operations/openconfig-image-management:image-remove'
            },
            'set-default': {
                'path': 'operations/openconfig-image-management:image-default'
            },
            'get-status': {
                'path': 'data/openconfig-image-management:image-management/install/state',
                'response_key': 'openconfig-image-management:state'
            },
            'get-list': {
                'path': 'data/openconfig-image-management:image-management',
                'response_key': 'openconfig-image-management:image-management'
            },
            'gpg-key': {
                'path': 'operations/openconfig-image-management:image-gpg-install'
            },
            'verify': {
                'path': 'operations/openconfig-image-management:image-verify'
            }
        },
        'patch': {
            'install': {
                'path': 'operations/openconfig-image-management:do-patch-install',
                'status': 'Check patch -> command = get-status for patch install progress'
            },
            'rollback': {
                'path': 'operations/openconfig-image-management:do-patch-rollback',
                'status': 'Check patch -> command = get-status for patch rollback progress'
            },
            'get-history': {
                'path': 'data/openconfig-image-management:patch-management/patch-history',
                'response_key': 'openconfig-image-management:patch-history'
            },
            'get-status': {
                'path': 'data/openconfig-image-management:patch-management/patch-install',
                'response_key': 'openconfig-image-management:patch-install'
            },
            'get-list': {
                'path': 'data/openconfig-image-management:patch-management/patch-list',
                'response_key': 'openconfig-image-management:patch-list'
            }
        },
        'firmware': {
            'install': {
                'path': 'operations/openconfig-image-management:do-fwpkg-install',
                'status': 'Check firmware -> command = get-status for firmware package staging progress'
            },
            'cancel': {
                'path': 'operations/openconfig-image-management:do-fwpkg-install-cancel'
            },
            'get-list': {
                'path': 'data/openconfig-image-management:fwpkg-management',
                'response_key': 'openconfig-image-management:fwpkg-management'
            },
            'get-status': {
                'path': 'data/openconfig-image-management:fwpkg-management/fwpkg-install',
                'response_key': 'openconfig-image-management:fwpkg-install'
            }
        }
    }

    path = command_map[params['category']][params['command']]['path']
    if params['command'].startswith('get-'):
        method = 'GET'
        request = [{'path': path, 'method': method}]

        try:
            response = edit_config(module, to_request(module, request))
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        info = {}
        response = response[0][1].get(command_map[params['category']][params['command']]['response_key'])
        if response:
            if params['category'] == 'image':
                if params['command'] == 'get-list':
                    if response.get('global') and response['global'].get('state'):
                        if response['global']['state'].get('current'):
                            info['current'] = response['global']['state']['current']
                        if response['global']['state'].get('next-boot'):
                            info['next'] = response['global']['state']['next-boot']
                    if response.get('images') and response['images'].get('image'):
                        info['available'] = []
                        for element in response['images']['image']:
                            if element.get('image-name'):
                                info['available'].append(element['image-name'])

                elif params['command'] == 'get-status':
                    keys = list(response.keys())
                    info.update(response)
                    install_status = info.get('install-status', 'IDLE')
                    transfer_status = info.get('transfer-status', 'IDLE')
                    for key in keys:
                        if ((key.startswith(('file', 'transfer')) and 'IDLE' in transfer_status)
                                or (key.startswith('install') and 'IDLE' in install_status)):
                            del info[key]

            elif params['category'] == 'patch':
                if params['command'] in ('get-history', 'get-list'):
                    info_key = params['command'].split('-')[1]
                    if response.get('patch'):
                        patches = sorted(response['patch'], key=lambda item: (item['patch-time']), reverse=True)
                        info[info_key] = []
                        for patch in patches:
                            if patch.get('state'):
                                info[info_key].append(patch['state'])

                elif params['command'] == 'get-status':
                    install_state = response.get('install-state', {})
                    download_state = response.get('download-state', {})
                    if install_state.get('trigger') == 'install' and 'IDLE' not in download_state.get('transfer-status', 'IDLE'):
                        info.update(download_state)

                    for oper_type in ('install', 'rollback', 'recovery'):
                        if 'IDLE' not in install_state.get('{0}-status'.format(oper_type), 'IDLE'):
                            for key in install_state.keys():
                                if key.startswith(oper_type):
                                    info[key] = install_state[key]

            elif params['category'] == 'firmware':
                if params['command'] == 'get-list':
                    for info_key in ('pending', 'result'):
                        key = 'fwpkg-{0}'.format(info_key)
                        if response.get(key) and response[key].get('fwpkg'):
                            info[info_key] = []
                            for entry in response[key]['fwpkg']:
                                info[info_key].append(entry['state'])

                elif params['command'] == 'get-status':
                    if response.get('download-state') and 'IDLE' not in response['download-state'].get('transfer-status', 'IDLE'):
                        info.update(response['download-state'])
                    if response.get('stage-state') and 'IDLE' not in response['stage-state'].get('stage-status', 'IDLE'):
                        info.update(response['stage-state'])

        result['info'] = info

    else:
        method = 'POST'
        payload = {'openconfig-image-management:input': {}}
        if params['category'] == 'image':
            if params['command'] == 'install':
                payload['openconfig-image-management:input'] = {'image-name': params['path']}
            elif (params['command'] == 'remove' and params['name'] != 'all') or params['command'] == 'set-default':
                payload['openconfig-image-management:input'] = {'image-name': params['name']}
            elif params['command'] == 'gpg-key':
                payload['openconfig-image-management:input'] = {"key-server": params['keyserver'], "key-id": params['pubkeyid']}
            elif params['command'] == 'verify':
                if params['verifymethod'] == 'gpg':
                    payload['openconfig-image-management:input'] = {
                        "image-name": params['path'], "verify-method": params['verifymethod'], "sigfilename": params['signaturefile']
                    }
                else:
                    payload['openconfig-image-management:input'] = {
                        "image-name": params['path'], "verify-method": params['verifymethod'],
                        "sigfilename": params['signaturefile'], "keyfilename": params['pubkeyfilename']
                    }
        elif params['category'] == 'patch':
            if params['command'] == 'install':
                payload['openconfig-image-management:input'] = {'patch-name': params['path'], 'skip-image-check': ''}
            elif params['command'] == 'rollback':
                payload['openconfig-image-management:input'] = {'patch-name': params['name']}
        elif params['category'] == 'firmware':
            if params['command'] == 'install':
                payload['openconfig-image-management:input'] = {'fwpkg-name': params['path']}

        request = [{'path': path, 'method': method, 'data': payload}]
        try:
            response = edit_config(module, to_request(module, request))
        except ConnectionError as exc:
            module.fail_json(msg=str(exc), code=exc.code)

        status = ''
        response = response[0][1].get('openconfig-image-management:output')
        if response:
            if response['status'] != 0:
                status = response['status-detail']
            else:
                status = command_map[params['category']][params['command']].get('status', response['status-detail'])

        result['status'] = status


def main():
    """
    Main entry point for module execution
    """
    argument_spec = {
        'image': {
            'type': 'dict',
            'options': {
                'command': {
                    'type': 'str',
                    'required': True,
                    'choices': ['install', 'cancel', 'remove', 'set-default', 'get-list', 'get-status', 'gpg-key', 'verify']
                },
                'name': {'type': 'str'},
                'path': {'type': 'str'},
                'keyserver': {'type': 'str'},
                'pubkeyid': {'type': 'str'},
                'pubkeyfilename': {'type': 'str'},
                'signaturefile': {'type': 'str'},
                'verifymethod': {
                    'type': 'str',
                    'choices': ['gpg', 'pki']
                }
            }
        },
        'patch': {
            'type': 'dict',
            'options': {
                'command': {
                    'type': 'str',
                    'required': True,
                    'choices': ['install', 'rollback', 'get-history', 'get-list', 'get-status']
                },
                'name': {'type': 'str'},
                'path': {'type': 'str'}
            }
        },
        'firmware': {
            'type': 'dict',
            'options': {
                'command': {
                    'type': 'str',
                    'required': True,
                    'choices': ['install', 'cancel', 'get-list', 'get-status']
                },
                'path': {'type': 'str'}
            }
        }
    }

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    warnings = []
    result = {'changed': False, 'warnings': warnings}

    params = validate_and_retrieve_params(module, warnings)
    execute_command(module, params, result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()
