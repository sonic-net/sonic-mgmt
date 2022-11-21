'''
This file contains the default consts used by the scripts on the same folder:
manufactue.py and test_first_time_boot_password_change.py
'''


class DefaultConsts:
    '''
    @summary: a constants class used by the tests
    '''
    DEFAULT_USER = 'admin'
    DEFAULT_PASSWORD = 'YourPaSsWoRd'
    NEW_PASSWORD = 'Jg_GRK9BJB58s_5H'
    ONIE_USER = 'root'
    ONIE_PASSWORD = 'root'

    # connection command
    SSH_COMMAND = 'ssh  -tt -q -o ControlMaster=auto -o ControlPersist=60s -o ' \
                  'ControlPath=/tmp/ansible-ssh-%h-%p-%r -o StrictHostKeyChecking=no ' \
                  '-o UserKnownHostsFile=/dev/null -o GSSAPIAuthentication=no ' \
                  '-o PubkeyAuthentication=no -p 22 -l {} '

    SCP_COMMNAD = 'scp -o ControlMaster=auto ' \
                  '-o ControlPersist=60s -o ControlPath=/tmp/ansible-ssh-%h-%p-%r' \
                  ' -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ' \
                  'GSSAPIAuthentication=no -o PubkeyAuthentication=no   {} {}@{}:{}'

    ONIE_INSTALL_PATH = 'platform_tests/test_first_time_boot_password_change/onie_install.sh'
    # expired password message regex
    PASSWORD_REGEX = 'assword'
    SONIC_PROMPT = '$'
    ONIE_PROMPT = '#'
    DEFAULT_PROMPT = [SONIC_PROMPT, ONIE_PROMPT]
    LONG_PERIOD = 30
    APPLY_CONFIGURATIONS = 10
    STABILIZATION_TIME = 60
    SLEEP_AFTER_MANUFACTURE = 60
    NEW_PASSWORD_REGEX = 'New password'
    RETYPE_PASSWORD_REGEX = 'Retype new password'
    # expired password message regex
    EXPIRED_PASSWORD_MSG = 'You are required to change your password immediately'

    # visual colors used for manufacture script
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
