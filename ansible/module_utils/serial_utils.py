import sys
import time
import logging
from telnetlib import Telnet
from ansible.module_utils.debug_utils import config_module_logging

config_module_logging('serial_utils')


def encode(arg):
    if (sys.version_info.major == 3 and sys.version_info.minor >= 5):
        return arg.encode("ascii")
    else:
        return arg


class EMatchNotFound(Exception):
    pass


class ELoginPromptNotFound(Exception):
    pass


class EWrongDefaultPassword(Exception):
    pass


class ENotInConfigMode(Exception):
    pass


class EPasswordSetFailed(Exception):
    pass


class SerialSession(object):
    def __init__(self, port):
        self.port = port
        self.enabled = False
        logging.debug('Telnet to serial port :%s' % port)
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
        return

    def pair(self, action, wait_for, timeout=20):
        logging.debug('output: %s' % action)
        self.tn.write(encode("%s\n" % action))
        if wait_for is not None:
            index, match, text = self.tn.expect([encode(i) for i in wait_for], timeout)
            logging.debug('Result of matching: %d %s %s' % (index, str(match), text))
            if index == -1:
                raise EMatchNotFound
        else:
            index = 0
        return index

    def configure(self, seq):
        for action, wait_for in seq:
            self.pair(action, wait_for)
        return

    def logout(self):
        self.pair('exit', None, 10)
        time.sleep(10)
        return


class CiscoSerial(SerialSession):
    def __init__(self, port):
        super(CiscoSerial, self).__init__(port)

    def set_account(self, user, password):
        try:
            time.sleep(60*5)
            logging.debug('## Waiting system start up')
            self.pair('\r\n', [r'Press RETURN to get started.', r'Enter root-system username:'], 900)
            logging.debug('## Getting the login prompt')
            self.pair('\r\n', [r'Enter root-system username:'], 300)
        except EMatchNotFound:
            logging.debug('No login prompt is found')
            raise ELoginPromptNotFound

        logging.debug('## Getting the password prompt')
        try:
            self.pair(user, [r'Enter secret:'])
            self.pair(password, [r'Enter secret again:'])
            self.pair(password, None)
        except EMatchNotFound:
            logging.debug('The original password is not working')
            raise EWrongDefaultPassword
        return

    def wait_ztp(self, retry_cnt):
        for retry in range(1, retry_cnt):
            try:
                index = self.pair('show ztp log | include Exiting SUCCESSFULLY',
                                  [r'INF: Exiting SUCCESSFULLY'], 10*retry)
                if index == 0:
                    return
            except EMatchNotFound:
                logging.debug('Wait ztp finished, retry {} times'.format(retry))
        return

    def login(self, user, password):
        self.pair('\n', [r'Username:'])
        self.pair(user, [r'Password'])
        self.pair(password, None)
        # wait for ZTP Exited, otherwise mgmt port will be shutdown by ztp
        self.wait_ztp(20)
        self.pair('show ztp log | include Exiting SUCCESSFULLY', [r'INF: Exiting SUCCESSFULLY'])
        return


class JuniperSerial(SerialSession):
    def __init__(self, port):
        super(JuniperSerial, self).__init__(port)

    def login(self, user, password):
        try:
            logging.debug('## Getting the login prompt')
            # the last characters should be 'login:', sometimes with one space followed
            self.pair('\r\n', [r'login:\s*$'], 1200)
        except EMatchNotFound:
            logging.debug('No login prompt is found')
            raise ELoginPromptNotFound

        logging.debug('## Getting the password prompt')
        try:
            index = self.pair(user, [r'#\s*$', r'assword:$'])
            logging.debug('## Inputing password')
            # Input the password only if the prompt is 'Password:'
            if index == 1:
                self.pair(password, [r'#\s*$'])
        except EMatchNotFound:
            logging.debug('The original password is not working')
            raise EWrongDefaultPassword
        return

    def set_password(self, password):
        try:
            self.pair('set system root-authentication plain-text-password', [r'New password:\s*$'])
            self.pair(password, [r'Retype new password:\s*$'])
            self.pair(password, [r'#\s*$'])
            self.pair('commit', [r'#\s*$'])
        except EMatchNotFound:
            logging.debug('Setting password failed')
            raise EPasswordSetFailed
        return

    def logout(self):
        # For Juniper OS, need to exit configure mode first
        self.pair('exit', [r'>\s*$'], 10)
        time.sleep(10)
        self.pair('exit', [r'#\s*$'], 10)
        time.sleep(10)
        super().logout()
        return


def core(module, session, name):
    prompt_code = name + '_code'
    try:
        if session is not None:
            session(module.params)
        result = {prompt_code: 0, 'changed': True, 'msg': '%s completed' % name}
    except ELoginPromptNotFound:
        result = {prompt_code: -1, 'changed': False, 'msg': 'Login prompt not found'}
    except EWrongDefaultPassword:
        result = {prompt_code: -2, 'changed': False, 'msg': 'Wrong default password'}
    except EOFError:
        result = {prompt_code: -3, 'changed': False, 'msg': 'EOF during the chat'}
    except EMatchNotFound:
        result = {prompt_code: -4, 'changed': False, 'msg': "Match for output isn't found."}
    except ENotInConfigMode:
        result = {prompt_code: -5, 'changed': False, 'msg': "Not in configure mode"}
    except Exception as e:
        result = {prompt_code: -6, 'changed': False, 'msg': str(e)}
    return result
