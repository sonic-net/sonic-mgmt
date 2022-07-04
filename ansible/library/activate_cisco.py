#!/usr/bin/python

from ansible.module_utils.serial_utils import CiscoSerial, core

def session(new_params):
    seq = [
        ('configure terminal', [r'\(config\)#\s*$']),
        ('load harddisk:/cisco_config.conf', [r'\(config\)#\s*$']),
        ('commit', [r'\(config\)#\s*$']),
        ('exit', [r'#\s*$'])
    ]

    ss = CiscoSerial(new_params['telnet_port'])
    ss.login(new_params['login'], new_params['password'])
    ss.configure(seq)
    ss.logout()
    ss.cleanup()
    return

def main():

    module = AnsibleModule(argument_spec=dict(
        telnet_port = dict(required=True),
        login = dict(required=True),
        password = dict(required=True),
    ))

    result = core(module, session, 'activate')
    module.exit_json(**result)
    return

from ansible.module_utils.basic import *
main()
