#!/usr/bin/python

import datetime
from telnetlib import Telnet

def encode(arg):
    if (sys.version_info.major == 3 and sys.version_info.minor >= 5):
        return arg.encode("ascii")
    else:
        return arg


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


class ELoginPromptNotFound(Exception):
    pass


class EWrongDefaultPassword(Exception):
    pass


class ENotInEnabled(Exception):
    pass


class SerialSession(object):
    def __init__(self, port, debug):
        self.enabled = False
        self.d = debug
        self.d.debug('Starting')
        self.tn = Telnet('127.0.0.1', port)
        self.tn.write(encode('\r\n'))

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

    def pair(self, action, wait_for, timeout):
        self.d.debug('output: %s' % action)
        self.d.debug('match: %s' % ",".join(wait_for))
        self.tn.write(encode("%s\n" % action))
        if wait_for is not None:
            index, match, text = self.tn.expect([encode(i) for i in wait_for], timeout)
            self.d.debug('Result of matching: %d %s %s' % (index, str(match), text))
            if index == -1:
                raise EMatchNotFound
        else:
            index = 0

        return index

    def login(self, user, password):
        try:
            self.d.debug('## Getting the login prompt')
            self.pair('\r', [r'login:'], 240)
        except EMatchNotFound:
            self.d.debug('No login prompt is found')
            raise ELoginPromptNotFound

        self.d.debug('## Getting the password prompt')
        index_password = self.pair(user, [r'assword:', r'>'], 20)
        if index_password == 0:
            try:
                self.d.debug('## Inputing password')
                self.pair(password, [r'>'], 10)
            except EMatchNotFound:
                self.d.debug('The original password "%s" is not working' % password)
                raise EWrongDefaultPassword

        return

    def enable(self):
        self.pair('enable', [r'#'], 10)
        self.enabled = True

        return

    def configure(self, seq):
        if self.enabled:
            self.pair('configure terminal', [r'\(config\)#'], 10)
            for action, wait_for in seq:
                self.pair(action, wait_for, 10)
            self.pair('exit', [r'#'], 10)
            self.pair('wr mem', [r'#'], 10)
        else:
            raise ENotInEnabled()

        return

    def wait_for_warmup(self):
        if self.enabled:
            self.pair('wait-for-warmup', [r'#'], 200)
        else:
            raise ENotInEnabled()

        return

    def rename_boot(self, seq):
        if self.enabled:
            self.pair('rename flash:vEOS-lab.swi flash:vEOS.swi', [r'#'], 10)
            config_add = ('boot system flash:vEOS.swi', [r'\(config\)#'])
            seq.append(config_add)
        else:
            raise ENotInEnabled()

        return

    def logout(self):
        self.pair('exit', [r'login:'], 10)

        return

def session(new_params):
    seq = [
        ('hostname %s' % str(new_params['hostname']), [r'\(config\)#']),
        ('vrf definition MGMT', [r'\(config-vrf-MGMT\)#']),
        ('rd 1:1', [r'\(config-vrf-MGMT\)#']),
        ('exit', [r'\(config\)#']),
        ('ip routing vrf MGMT', [r'\(config\)#']),
        ('interface management 1', [r'\(config-if-Ma1\)#']),
        ('no shutdown', [r'\(config-if-Ma1\)#']),
        ('vrf forwarding MGMT', [r'\(config-if-Ma1\)#']),
        ('ip address %s' % str(new_params['mgmt_ip']), [r'\(config-if-Ma1\)#']),
        ('exit', [r'\(config\)#']),
        ('ip route vrf MGMT 0.0.0.0/0 %s' % str(new_params['mgmt_gw']), [r'\(config\)#']),
        ('username %s privilege 15 role network-admin secret 0 %s' % (str(new_params['new_login']), str(new_params['new_password'])), [r'\(config\)#']),
        ('aaa root secret 0 %s' % str(new_params['new_root_password']), [r'\(config\)#']),
    ]

    curtime = datetime.datetime.now().isoformat()
    debug = MyDebug('/tmp/debug.%s.%s.txt' % (new_params['hostname'], curtime), enabled=True)
    ss = SerialSession(new_params['telnet_port'], debug)
    ss.login(new_params['login'], new_params['password'])
    ss.enable()
    ss.wait_for_warmup()
    ss.rename_boot(seq) # FIXME: do we need this rename?
    ss.configure(seq)
    ss.wait_for_warmup()
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
        password = dict(required=True),
        hostname = dict(required=True),
        mgmt_ip = dict(required=True),
        mgmt_gw = dict(required=True),
        new_login = dict(required=True),
        new_password = dict(required=True),
        new_root_password = dict(required=True),
    ))

    try:
        result = core(module)
    except ELoginPromptNotFound:
        result = {'kickstart_code': -1, 'changed': False, 'msg': 'Login prompt not found'}
    except EWrongDefaultPassword:
        result = {'kickstart_code': -2, 'changed': False, 'msg': 'Wrong default password, kickstart of VM has been done'}
    except EOFError:
        result = {'kickstart_code': -3, 'changed': False, 'msg': 'EOF during the chat'}
    except EMatchNotFound:
        result = {'kickstart_code': -4, 'changed': False, 'msg': "Match for output isn't found"}
    except ENotInEnabled:
        result = {'kickstart_code': -5, 'changed': False, 'msg': "Not in enabled mode"}
    except Exception as e:
        result = {'kickstart_code': -6, 'changed': False, 'msg': str(e)}

    module.exit_json(**result)

    return


from ansible.module_utils.basic import *
main()
