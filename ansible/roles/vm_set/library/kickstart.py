#!/usr/bin/python

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


class ENotInEnabled(Exception):
    pass


class SerialSession(object):
    def __init__(self, port, debug):
        self.enabled = False
        self.d = debug
        self.d.debug('Starting')
        self.tn = Telnet('127.0.0.1', port)
        self.tn.write('\r\n')

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
        self.tn.write("%s\n" % action)
        if wait_for is not None:
            index, match, text = self.tn.expect(wait_for, timeout)
            self.d.debug('Result of matching: %d %s %s' % (index, str(match), text))
            if index == -1:
                raise EMatchNotFound
        else:
            index = 0

        return index

    def login(self, user, password):
        self.pair('\r', [r'login:'], 240)
        index_password = self.pair(user, [r'assword:', r'>'], 20)
        if index_password == 0:
            self.pair(password, [r'>'], 10)

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


def session(port, login, password, new_params):
    templates = {
        'hostname': [
            ('hostname %s' % str(new_params['hostname']), [r'\(config\)#']),
        ],
        'mgmt_ip': [
            ('interface management 1', [r'\(config-if-Ma1\)#']),
            ('no shutdown', [r'\(config-if-Ma1\)#']),
            ('ip address %s' % str(new_params['mgmt_ip']), [r'\(config-if-Ma1\)#']),
            ('exit', [r'\(config\)#']),
        ],
        'mgmt_gw': [
            ('ip route 0.0.0.0/0 %s' % str(new_params['mgmt_gw']), [r'\(config\)#']),
        ],
        'new_login': [
            ('username %s privilege 15 role network-admin secret 0 %s' % (str(new_params['new_login']), str(new_params['new_password'])), [r'\(config\)#']),
        ],
        'new_password': [], # empty. All data in new_login
        'new_root_password': [
            ('aaa root secret 0 %s' % str(new_params['new_root_password']), [r'\(config\)#']),
        ],
    }

    seq = []
    for key, param in new_params.iteritems():
        if param is not None:
            seq.extend(templates[key])

    debug = MyDebug('/tmp/debug.txt', enabled=False)
    ss = SerialSession(port, debug)
    ss.login(login, password)
    ss.enable()
    ss.wait_for_warmup()
    ss.rename_boot(seq)
    ss.configure(seq)
    ss.wait_for_warmup()
    ss.logout()
    ss.cleanup()

    return


def core(module):
    telnet_port = module.params.get('telnet_port', None)
    login = module.params.get('login', None)
    password = module.params.get('password', None)

    new_params = {}
    new_params['hostname'] = module.params.get('hostname', None)
    new_params['mgmt_ip'] = module.params.get('mgmt_ip', None)
    new_params['mgmt_gw'] = module.params.get('mgmt_gw', None)
    new_params['new_login'] = module.params.get('new_login', None)
    new_params['new_password'] = module.params.get('new_password', None)
    new_params['new_root_password'] = module.params.get('new_root_password', None)

    if (new_params['new_login'] is not None and new_params['new_password'] is None):
        module.fail_json(msg = 'new_password is required')

    if (new_params['new_login'] is None and new_params['new_password'] is not None):
        module.fail_json(msg = 'new_login is required')

    if telnet_port is None:
        module.fail_json(msg = 'telnet port number is required')

    session(telnet_port, login, password, new_params)

    return {'kickstart_code': 0, 'changed': True, 'msg': 'Kickstart completed'}


def main():

    module = AnsibleModule(argument_spec=dict(
        telnet_port = dict(required=True),
        login = dict(required=True),
        password = dict(required=True),
        hostname = dict(),
        mgmt_ip = dict(),
        mgmt_gw = dict(),
        new_login = dict(),
        new_password = dict(),
        new_root_password = dict(),
    ))

    try:
        result = core(module)
    except EOFError:
        result = {'kickstart_code': -1, 'changed': False, 'msg': 'EOF during the chat'}
    except EMatchNotFound:
        result = {'kickstart_code': -1, 'changed': False, 'msg': "Match for output isn't found"}
    except ENotInEnabled:
        module.fail_json(msg='Not in enabled mode')
    except Exception, e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)

    return


from ansible.module_utils.basic import *
main()

