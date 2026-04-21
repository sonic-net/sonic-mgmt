# -*- coding: utf-8 -*-

# Copyright (c) 2022, Felix Fontein (@felixfontein) <felix@fontein.de>
# Copyright (c) 2020, Nikolay Dachev <nikolay@dachev.info>
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


from ansible.module_utils.basic import missing_required_lib
from ansible.module_utils.common.text.converters import to_native

import ssl
import traceback

LIB_IMP_ERR = None
try:
    from librouteros import connect
    from librouteros.exceptions import LibRouterosError  # noqa: F401, pylint: disable=unused-import
    HAS_LIB = True
except Exception as e:
    HAS_LIB = False
    LIB_IMP_ERR = traceback.format_exc()


def check_has_library(module):
    if not HAS_LIB:
        module.fail_json(
            msg=missing_required_lib('librouteros'),
            exception=LIB_IMP_ERR,
        )


def api_argument_spec():
    return dict(
        username=dict(type='str', required=True),
        password=dict(type='str', required=True, no_log=True),
        hostname=dict(type='str', required=True),
        port=dict(type='int'),
        tls=dict(type='bool', default=False, aliases=['ssl']),
        force_no_cert=dict(type='bool', default=False),
        validate_certs=dict(type='bool', default=True),
        validate_cert_hostname=dict(type='bool', default=False),
        ca_path=dict(type='path'),
        encoding=dict(type='str', default='ASCII'),
        timeout=dict(type='int', default=10),
    )


def _ros_api_connect(module, username, password, host, port, use_tls, force_no_cert, validate_certs, validate_cert_hostname, ca_path, encoding, timeout):
    '''Connect to RouterOS API.'''
    if not port:
        if use_tls:
            port = 8729
        else:
            port = 8728
    try:
        params = dict(
            username=username,
            password=password,
            host=host,
            port=port,
            encoding=encoding,
            timeout=timeout,
        )
        if use_tls:
            ctx = ssl.create_default_context(cafile=ca_path)
            wrap_context = ctx.wrap_socket
            if force_no_cert:
                ctx.check_hostname = False
                ctx.set_ciphers("ADH:@SECLEVEL=0")
            elif not validate_certs:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            elif not validate_cert_hostname:
                ctx.check_hostname = False
            else:
                # Since librouteros does not pass server_hostname,
                # we have to do this ourselves:
                def wrap_context(*args, **kwargs):
                    kwargs.pop('server_hostname', None)
                    return ctx.wrap_socket(*args, server_hostname=host, **kwargs)
            params['ssl_wrapper'] = wrap_context
        api = connect(**params)
    except Exception as e:
        connection = {
            'username': username,
            'hostname': host,
            'port': port,
            'ssl': use_tls,
            'status': 'Error while connecting: %s' % to_native(e),
        }
        module.fail_json(msg=connection['status'], connection=connection)
    return api


def create_api(module):
    """Create an API object."""
    return _ros_api_connect(
        module,
        module.params['username'],
        module.params['password'],
        module.params['hostname'],
        module.params['port'],
        module.params['tls'],
        module.params['force_no_cert'],
        module.params['validate_certs'],
        module.params['validate_cert_hostname'],
        module.params['ca_path'],
        module.params['encoding'],
        module.params['timeout'],
    )


def get_api_version(api):
    """Given an API object, query the system's version."""
    system_info = list(api.path().join('system', 'resource'))[0]
    return system_info['version'].split(' ', 1)[0]
