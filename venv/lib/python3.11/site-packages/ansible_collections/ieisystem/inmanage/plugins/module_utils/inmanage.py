# -*- coding:utf-8 -*-
# Copyright(C) 2023 IEIT Inc. All Rights Reserved.

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

try:
    import inmanage
    inmanage_temp = True
except ImportError:
    inmanage_temp = False
from ansible.module_utils.basic import env_fallback
from ansible.module_utils.six import iteritems

inmanage_provider_spec = {
    'host': dict(type='str'),
    'username': dict(type='str', fallback=(env_fallback, ['ANSIBLE_NET_USERNAME'])),
    'password': dict(type='str', fallback=(env_fallback, ['ANSIBLE_NET_PASSWORD']), no_log=True),
}
inmanage_argument_spec = {
    'provider': dict(type='dict', options=inmanage_provider_spec),
}
inmanage_top_spec = {
    'host': dict(type='str'),
    'username': dict(type='str'),
    'password': dict(type='str', no_log=True),
}
inmanage_argument_spec.update(inmanage_top_spec)


def load_params(module):
    """load_params"""
    provider = module.params.get('provider') or dict()
    for key, value in iteritems(provider):
        if key in inmanage_argument_spec:
            if module.params.get(key) is None and value is not None:
                module.params[key] = value


def get_connection(module):
    """get_connection"""
    load_params(module)
    # result = dict()
    # if module.check_mode:
    #     result['changed'] = True
    #     result['state'] = 'Success'
    #     result['message'] = module.params['subcommand']
    # else:
    dict_param = module.params
    if not inmanage_temp:
        module.fail_json(msg='inmanage_sdk must be installed to use this module')
    result = inmanage.main(dict_param)
    return result
