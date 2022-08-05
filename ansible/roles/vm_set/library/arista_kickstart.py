#!/usr/bin/python

from ansible.module_utils.serial_utils import AristaSerial, core

def session(new_params):
    seq = [
        ('enable', [r'#']),
        ('configure terminal', [r'\(config\)#']),
        ('aaa authorization exec default local', [r'\(config\)#']),
        ('wr mem', [r'\(config\)#']),
        ('exit', [r'#']),
        ('zerotouch disable', None),
        ('exit', None)
    ]

    ss = AristaSerial(new_params['telnet_port'])
    ss.login(new_params['new_login'], new_params['new_password'])
    ss.configure(seq)
    ss.logout()
    ss.cleanup()
    return

def main():
    module = AnsibleModule(argument_spec=dict(
        telnet_port = dict(required=True),
        login = dict(required=True),
        password = dict(required=True),
        hostname = dict(required=True),
        mgmt_ip = dict(required=True),
        mgmt_gw = dict(required=True),
        new_login = dict(required=True),
        new_password = dict(required=True),
        new_root_password = dict(required=True),
    ))

    result = core(module, session, 'kickstart')
    module.exit_json(**result)
    return

from ansible.module_utils.basic import *
main()
