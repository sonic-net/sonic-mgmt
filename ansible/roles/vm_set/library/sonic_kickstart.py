#!/usr/bin/python

import datetime
from telnetlib import Telnet


class MyDebug(object):
    def __init__(self, filename, enabled=True):
        if enabled:
            self.fp = open(filename, 'w')
        else:
            self.fp = None

        return

    def cleanup(self):
        if self.fp:
            self.fp.close()
            self.fp = None

        return

    def __del__(self):
        self.cleanup()

        return

    def debug(self, msg):
        if self.fp:
            self.fp.write('%s\n' % msg)
            self.fp.flush()

        return


class EMatchNotFound(Exception):
    pass


class SerialSession(object):
    def __init__(self, port, debug):
        self.d = debug
        self.d.debug('Starting')
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
            self.d.cleanup()

        return

    def pair(self, action, wait_for, timeout=60):
        self.d.debug('output: %s' % action)
        self.d.debug('match: %s' % ",".join(wait_for))
        self.tn.write(b"%s\n" % action.encode('ascii'))
        if wait_for is not None:
            index, match, text = self.tn.expect([ x.encode('ascii') for x in wait_for ], timeout)
            self.d.debug('Result of matching: %d %s %s' % (index, str(match), text))
            if index == -1:
                raise EMatchNotFound
        else:
            index = 0

        return index

    def login(self, user, passwords):
        while True:
            index = self.pair('\r', [r'login:', r'assword:'], 300)
            if index == 0:
                break

        for password in passwords:
            index = self.pair(user, [r'assword:', r'\$'])
            if index == 0:
                index = self.pair(password, [r'login:', r'\$'])
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
        self.pair('exit', [r'\$'])

        return

    def logout(self):
        self.pair('exit', [r'login:'])

        return

def session(new_params):
    seq = [
        ('while true; do if [ $(systemctl is-active swss) == "active" ]; then break; fi; echo $(systemctl is-active swss); sleep 1; done', [r'#'], 180),
        ('pkill dhclient', [r'#']),
        ('hostname %s' % str(new_params['hostname']), [r'#']),
        ('sed -i s:sonic:%s: /etc/hosts' % str(new_params['hostname']), [r'#']),
        ('ifconfig eth0 %s' % str(new_params['mgmt_ip']), [r'#']),
        ('ifconfig eth0', [r'#']),
        ('ip route add 0.0.0.0/0 via %s table default' % str(new_params['mgmt_gw']), [r'#']),
        ('ip route', [r'#']),
        ('echo %s:%s | chpasswd' % (str(new_params['login']), str(new_params['new_password'])), [r'#']),
    ]
    # For multi-asic VS there is no default config generated.
    # interfaces-config service will not add eth0 IP address as there
    # no default config. Multiple SWSS service will not start until
    # topology service is loaded. Hence remove swss check and proceed
    # with eth0 IP address assignment.
    if int(new_params['num_asic']) > 1:	
        seq.pop(0)

    curtime = datetime.datetime.now().isoformat()
    debug = MyDebug('/tmp/debug.%s.%s.txt' % (new_params['hostname'], curtime), enabled=True)
    ss = SerialSession(new_params['telnet_port'], debug)
    ss.login(new_params['login'], new_params['passwords'])
    ss.configure(seq)
    ss.logout()
    ss.cleanup()

    return


def core(module):
    session(module.params)

    return {'kickstart_code': 0, 'changed': True, 'msg': 'Kickstart completed'}


def main():

    module = AnsibleModule(argument_spec=dict(
        telnet_port = dict(required=True),
        login = dict(required=True),
        passwords = dict(required=True, type='list'),
        hostname = dict(required=True),
        mgmt_ip = dict(required=True),
        mgmt_gw = dict(required=True),
        new_password = dict(required=True),
        num_asic = dict(required=True),
    ))

    try:
        result = core(module)
    except EOFError:
        result = {'kickstart_code': -1, 'changed': False, 'msg': 'EOF during the chat'}
    except EMatchNotFound:
        result = {'kickstart_code': -1, 'changed': False, 'msg': "Match for output isn't found"}
    except Exception as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)

    return


from ansible.module_utils.basic import *
main()
