# Copyright (C) 2024 IBM CORPORATION
# Author(s): Shilpi Jain <shilpi.jain1@ibm.com>
#            Sandip G. Rajbanshi <sandip.rajbanshi@ibm.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

""" Support class for IBM SVC generic ansible module """

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import inspect
import uuid
from ansible.module_utils.compat.paramiko import paramiko
from ansible_collections.ibm.storage_virtualize.plugins.module_utils.ibm_svc_utils import get_logger

COLLECTION_VERSION = "2.7.4"


class IBMSVCssh(object):
    """ Communicate with SVC through SSH
        The module uses paramiko to connect SVC
    """

    def __init__(self, module, clustername, domain, username, password,
                 look_for_keys, key_filename, log_path):
        """ Initialize module with what we need for initial connection
        :param clustername: name of the SVC cluster
        :type clustername: string
        :param domain: domain to create FQDN of SVC system
        :type domain: string
        :param username: SVC username
        :type username: string
        :param password: Password for user
        :type password: string
        :param look_for_keys: whether to look for keys or not
        :type look_for_keys: boolean
        :param key_filename: SSH client private key file
        :type key_filename: string
        :param log_path: log file
        :type log_path: string
        """
        self.module = module
        self.clustername = clustername
        self.domain = domain
        self.username = username
        self.password = password
        self.look_for_keys = look_for_keys
        self.key_filename = key_filename

        self.is_client_connected = False

        # logging setup
        log = get_logger(self.__class__.__name__, log_path)
        self.log = log.info

        self.client_type = 'paramiko'
        if paramiko is None:
            self.module.fail_json(msg='paramiko is not installed')
        self.client = paramiko.SSHClient()

        # connect through SSH
        self.is_client_connected = self._svc_connect()
        if not self.is_client_connected:
            self.module.fail_json(msg='Failed to connect')

    def _svc_connect(self):
        """
        Initialize a SSH connection with properties
        which were set up in constructor.
        :return: True or False
        """
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self.hostname = self.clustername
        self.log(self.domain)
        if self.domain:
            self.hostname = f"{self.clustername}.{self.domain}"
        self.log(self.hostname)
        try:
            self.client.connect(
                hostname=self.hostname,
                username=self.username,
                password=self.password,
                look_for_keys=self.look_for_keys,
                key_filename=self.key_filename)
            self.register_plugin()
            return True
        except paramiko.BadHostKeyException as e:
            self.log("BadHostKeyException %s", e)
        except paramiko.AuthenticationException as e:
            self.log("AuthenticationException %s", e)
        except paramiko.SSHException as e:
            self.log("SSHException %s", e)
        except Exception as e:
            self.log("SSH connection failed %s", e)
        return False

    def is_connected(self):
        return self.is_client_connected

    def _svc_disconnect(self):
        """
        Disconnect from the SSH server.
        """
        try:
            self.client.close()
            self.is_client_connected = False
            self.log("SSH disconnected")
            return True
        except Exception as e:
            self.log("SSH Disconnection failed %s", e)
            return False

    def register_plugin(self):
        try:
            cmd = 'svctask registerplugin'
            cmdopts = {}
            name = "Ansible"
            unique_key = self.username + "_" + str(uuid.getnode())
            caller_class = inspect.stack()[2].frame.f_locals.get('self', None)
            caller_class_name = caller_class.__class__.__name__
            module_name = str(inspect.stack()[3].filename).rsplit('/', maxsplit=1)[-1]
            metadata = module_name[:-3] + " module with class " + str(caller_class_name) + " has been executed by " + self.username

            cmdopts['name'] = name
            cmdopts['uniquekey'] = unique_key
            cmdopts['version'] = COLLECTION_VERSION
            cmdopts['metadata'] = metadata

            for cmdoptions in cmdopts:
                cmd = cmd + " -" + cmdoptions + " '" + cmdopts[cmdoptions] + "'"
            self.client.exec_command(cmd)
            return True
        except Exception as e:
            return False
