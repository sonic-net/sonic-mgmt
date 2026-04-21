# -*- coding: utf-8 -*-
# This code is part of the Ansible collection community.docker, but is an independent component.
# This particular file, and this file only, is based on the Docker SDK for Python (https://github.com/docker/docker-py/)
#
# Copyright (c) 2016-2022 Docker, Inc.
#
# It is licensed under the Apache 2.0 license (see LICENSES/Apache-2.0.txt in this collection)
# SPDX-License-Identifier: Apache-2.0

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import errno
import json
import subprocess

from ansible_collections.community.docker.plugins.module_utils._six import PY3, binary_type

from . import constants
from . import errors
from .utils import create_environment_dict
from .utils import find_executable


class Store(object):
    def __init__(self, program, environment=None):
        """ Create a store object that acts as an interface to
            perform the basic operations for storing, retrieving
            and erasing credentials using `program`.
        """
        self.program = constants.PROGRAM_PREFIX + program
        self.exe = find_executable(self.program)
        self.environment = environment
        if self.exe is None:
            raise errors.InitializationError(
                '{0} not installed or not available in PATH'.format(
                    self.program
                )
            )

    def get(self, server):
        """ Retrieve credentials for `server`. If no credentials are found,
            a `StoreError` will be raised.
        """
        if not isinstance(server, binary_type):
            server = server.encode('utf-8')
        data = self._execute('get', server)
        result = json.loads(data.decode('utf-8'))

        # docker-credential-pass will return an object for inexistent servers
        # whereas other helpers will exit with returncode != 0. For
        # consistency, if no significant data is returned,
        # raise CredentialsNotFound
        if result['Username'] == '' and result['Secret'] == '':
            raise errors.CredentialsNotFound(
                'No matching credentials in {0}'.format(self.program)
            )

        return result

    def store(self, server, username, secret):
        """ Store credentials for `server`. Raises a `StoreError` if an error
            occurs.
        """
        data_input = json.dumps({
            'ServerURL': server,
            'Username': username,
            'Secret': secret
        }).encode('utf-8')
        return self._execute('store', data_input)

    def erase(self, server):
        """ Erase credentials for `server`. Raises a `StoreError` if an error
            occurs.
        """
        if not isinstance(server, binary_type):
            server = server.encode('utf-8')
        self._execute('erase', server)

    def list(self):
        """ List stored credentials. Requires v0.4.0+ of the helper.
        """
        data = self._execute('list', None)
        return json.loads(data.decode('utf-8'))

    def _execute(self, subcmd, data_input):
        output = None
        env = create_environment_dict(self.environment)
        try:
            if PY3:
                output = subprocess.check_output(
                    [self.exe, subcmd], input=data_input, env=env,
                )
            else:
                process = subprocess.Popen(
                    [self.exe, subcmd], stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE, env=env,
                )
                output, dummy = process.communicate(data_input)
                if process.returncode != 0:
                    raise subprocess.CalledProcessError(
                        returncode=process.returncode, cmd='', output=output
                    )
        except subprocess.CalledProcessError as e:
            raise errors.process_store_error(e, self.program)
        except OSError as e:
            if e.errno == errno.ENOENT:
                raise errors.StoreError(
                    '{0} not installed or not available in PATH'.format(
                        self.program
                    )
                )
            else:
                raise errors.StoreError(
                    'Unexpected OS error "{0}", errno={1}'.format(
                        e.strerror, e.errno
                    )
                )
        return output
