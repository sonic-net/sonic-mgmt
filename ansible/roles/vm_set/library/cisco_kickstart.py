#!/usr/bin/python
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.serial_utils import CiscoSerial, core


def session(new_params):
    seq = [
        ('configure terminal', ['RP/0/RP0/CPU0:ios\\(config\\)#']),
        ('interface mgmtEth 0/RP0/CPU0/0', ['RP/0/RP0/CPU0:ios\\(config-if\\)#']),
        ('no shutdown', ['RP/0/RP0/CPU0:ios\\(config-if\\)#']),
        ('ipv4 address %s' % str(new_params['mgmt_ip']), ['RP/0/RP0/CPU0:ios\\(config-if\\)#']),
        ('exit', ['RP/0/RP0/CPU0:ios\\(config\\)#']),
        ('ssh server v2', ['RP/0/RP0/CPU0:ios\\(config\\)#']),
        ('hostname %s' % str(new_params['hostname']), ['RP/0/RP0/CPU0:ios\\(config\\)#']),
        ('commit', ['RP/0/RP0/CPU0:%s\\(config\\)#' % str(new_params['hostname'])]),
        ('exit', ['RP/0/RP0/CPU0:%s#' % str(new_params['hostname'])])
    ]

    ss = CiscoSerial(new_params['telnet_port'])
    ss.set_account(new_params['login'], new_params['password'])
    ss.login(new_params['login'], new_params['password'])
    ss.configure(seq)
    ss.logout()
    ss.cleanup()
    return


def main():
    module = AnsibleModule(argument_spec=dict(
        telnet_port=dict(required=True),
        login=dict(required=True),
        password=dict(required=True),
        hostname=dict(required=True),
        mgmt_ip=dict(required=True),
        mgmt_gw=dict(required=True),
    ))

    result = core(module, session, 'kickstart')
    module.exit_json(**result)
    return


main()
