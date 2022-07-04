#!/usr/bin/python

from ansible.module_utils.serial_utils import JuniperSerial, core

def session(new_params):
    seq = [
        ('cli', [r'>']),
        ('configure', [r'#']),
        ('set system host-name %s' % str(new_params['hostname']), [r'#']),
        ('set system services ssh root-login allow', [r'#']),
        ('set interfaces fxp0 unit 0 family inet address %s' % str(new_params['mgmt_ip']), [r'#']),
        ('commit', [r'#']),
    ]

    ss = JuniperSerial(new_params['telnet_port'])
    ss.login(new_params['login'], new_params['password'])
    ss.configure(seq)
    ss.set_password(new_params['new_password'])
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
