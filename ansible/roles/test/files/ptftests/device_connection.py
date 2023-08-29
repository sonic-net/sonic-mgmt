import paramiko
import logging
import socket
import sys
from paramiko.ssh_exception import BadHostKeyException, AuthenticationException, SSHException
from pip._vendor.retrying import retry
logger = logging.getLogger(__name__)

DEFAULT_CMD_EXECUTION_TIMEOUT_SEC = 10

class DeviceConnection:
    '''
    DeviceConnection uses Paramiko module to connect to devices

    Paramiko module uses fallback mechanism where it would first try to use
    ssh key and that fails, it will attempt username/password combination
    '''
    def __init__(self, hostname, username, password=None, alt_password=None):
        '''
        Class constructor

        @param hostname: hostname of device to connect to
        @param username: username for device connection
        @param password: password for device connection
        '''
        self.hostname = hostname
        self.username = username
        self.password = password
        self.alt_password = alt_password


    @retry(
        stop_max_attempt_number=2,
        retry_on_exception=lambda e: isinstance(e, AuthenticationException)
    )
    def execCommand(self, cmd, timeout=DEFAULT_CMD_EXECUTION_TIMEOUT_SEC):
        '''
        Executes command on remote device

        @param cmd: command to be run on remote device
        @param timeout: timeout for command run session
        @return: stdout, stderr, value
            stdout is a list of lines of the remote stdout gathered during command execution
            stderr is a list of lines of the remote stderr gathered during command execution
            value: 0 if command execution raised no exception
                   nonzero if exception is raised
        '''
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        if isinstance(cmd, list):
            cmd = ' '.join(cmd)

        stdOut = stdErr = []
        retValue = 1
        try:
            client.connect(self.hostname, username=self.username, password=self.password, allow_agent=False)
            si, so, se = client.exec_command(cmd, timeout=timeout)
            stdOut = so.readlines()
            stdErr = se.readlines()
            retValue = 0
        except AuthenticationException as authenticationException:
            logger.error('SSH Authentication failure with message: %s' % authenticationException)
            if self.alt_password is not None:
                # attempt retry with alt_password
                self.password = self.alt_password
                raise AuthenticationException
        except SSHException as sshException:
            logger.error('SSH Command failed with message: %s' % sshException)
        except BadHostKeyException as badHostKeyException:
            logger.error('SSH Authentication failure with message: %s' % badHostKeyException)
        except socket.timeout as e:
            # The ssh session will timeout in case of a successful reboot
            logger.error('Caught exception socket.timeout: {}, {}, {}'.format(repr(e), str(e), type(e)))
            retValue = 255
        except Exception as e:
            logger.error('Exception caught: {}, {}, type: {}'.format(repr(e), str(e), type(e)))
            logger.error(sys.exc_info())
        finally:
            client.close()

        return stdOut, stdErr, retValue
