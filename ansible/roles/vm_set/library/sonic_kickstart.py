#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
from telnetlib import Telnet  # nosemgrep: telnetlib
import logging
from ansible.module_utils.debug_utils import config_module_logging

config_module_logging('sonic_kickstart')


class EMatchNotFound(Exception):
    def __init__(self, console_output=None):
        super(EMatchNotFound, self).__init__()
        self.console_output = console_output


class SerialSession(object):
    def __init__(self, port):
        logging.debug('Starting')
        self.tn = Telnet('127.0.0.1', port)
        self.tn.write(b"\r\n")

        return

    def __del__(self):
        self.cleanup()

        return

    def cleanup(self):
        if self.tn:
            self.tn.close()
            self.tn = None

        return

    def pair(self, action, wait_for, timeout=60, capture_output=False):
        # lgtm [py/clear-text-logging-sensitive-data]
        logging.debug('output: %s' % action)
        logging.debug('match: %s' % ",".join(wait_for))
        self.tn.write(b"%s\n" % action.encode('ascii'))
        if wait_for is not None:
            index, match, text = self.tn.expect(
                [x.encode('ascii') for x in wait_for], timeout)
            logging.debug('Result of matching: %d %s %s' %
                          (index, str(match), text))
            if index == -1:
                raise EMatchNotFound(text if capture_output else None)
        else:
            index = 0

        return index

    def login(self, user, passwords):
        while True:
            index = self.pair(
                '\r', [r'login:', r'assword:'], 300, capture_output=True)
            if index == 0:
                break

        for password in passwords:
            index = self.pair(user, [r'assword:', r'\$', r'\#'])
            if index == 0:
                index = self.pair(password, [r'login:', r'\$', r'\#'])
                if index == 1:
                    break

        return

    def configure(self, seq):
        self.pair('sudo bash', [r'#'])
        for cmd in seq:
            if len(cmd) == 2:
                (action, wait_for) = cmd
                self.pair(action, wait_for)
            else:
                (action, wait_for, timeout) = cmd
                self.pair(action, wait_for, timeout)
        self.pair('exit', [r'\$', r'\#'])

        return

    def logout(self):
        self.pair('exit', [r'login:'])

        return


def session(new_params):
    seq = [
        ('while true; do if [ $(systemctl is-active swss) == "active" ]; then break; fi; '
         'echo $(systemctl is-active swss); sleep 1; done', [r'#'], 180),
    ]

    seq.extend([
        ('pkill dhclient', [r'#']),
        ('hostname %s' % str(new_params['hostname']), [r'#']),
        ('if grep -q "sonic" /etc/hosts; then sed -i s:sonic:%s: /etc/hosts; \
            else echo "127.0.0.1 %s" >> /etc/hosts; fi' %
            (str(new_params['hostname']), str(new_params['hostname'])), [r'#']),
        ('ifconfig eth0 %s' % str(new_params['mgmt_ip']), [r'#']),
        ('ifconfig eth0', [r'#']),
        ('ip route add 0.0.0.0/0 via %s table default' %
         str(new_params['mgmt_gw']), [r'#']),
        ('ip route', [r'#']),
        ('arping -c 2 -U -P -I eth0 %s' % str(new_params['mgmt_ip']).split("/")[0], [r'#']),
        ('echo %s:%s | chpasswd' %
         (str(new_params['login']), str(new_params['new_password'])), [r'#']),
    ])
    # For multi-asic VS there is no default config generated.
    # interfaces-config service will not add eth0 IP address as there
    # no default config. Multiple SWSS service will not start until
    # topology service is loaded. Hence remove swss check and proceed
    # with eth0 IP address assignment.
    if int(new_params['num_asic']) > 1:
        seq.pop(0)

    ss = SerialSession(new_params['telnet_port'])
    ss.login(new_params['login'], new_params['passwords'])
    ss.configure(seq)
    ss.logout()
    ss.cleanup()

    return


def core(module):
    session(module.params)

    return {'kickstart_code': 0, 'changed': True, 'msg': 'Kickstart completed'}


def format_console_tail(console_output, limit=4096):
    if not console_output:
        return ''

    decoded = console_output.decode('utf-8', errors='replace')
    printable = ''.join(
        char if char in '\r\n\t' or 32 <= ord(char) < 127 else '?'
        for char in decoded
    )
    return printable[-limit:]


def main():

    module = AnsibleModule(argument_spec=dict(
        telnet_port=dict(required=True),
        login=dict(required=True),
        passwords=dict(required=True, type='list'),
        hostname=dict(required=True),
        mgmt_ip=dict(required=True),
        mgmt_gw=dict(required=True),
        new_password=dict(required=True),
        num_asic=dict(required=True),
    ))

    try:
        result = core(module)
    except EOFError:
        result = {'kickstart_code': -1, 'changed': False,
                  'msg': 'EOF during the chat'}
    except EMatchNotFound as e:
        console_tail = format_console_tail(e.console_output)
        msg = "Match for output isn't found"
        if console_tail:
            msg += "\nPre-login console tail:\n%s" % console_tail
        result = {'kickstart_code': -1, 'changed': False,
                  'msg': msg}
    except Exception as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)

    return


main()
