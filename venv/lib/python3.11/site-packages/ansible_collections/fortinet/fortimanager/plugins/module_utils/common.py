# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# (c) 2017-2020 Fortinet, Inc
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
#
#    * Redistributions of source code must retain the above copyright
#      notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
# PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
# USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
from __future__ import absolute_import, division, print_function

__metaclass__ = type


# BEGIN STATIC DATA / MESSAGES
class FMGRMethods:
    GET = "get"
    SET = "set"
    EXEC = "exec"
    EXECUTE = "exec"
    UPDATE = "update"
    ADD = "add"
    DELETE = "delete"
    REPLACE = "replace"
    CLONE = "clone"
    MOVE = "move"


BASE_HEADERS = {"Content-Type": "application/json",
                "Accept": "application/json"}

COMMON_SCHEMA = {
    'access_token': {'type': 'str', 'no_log': True},
    'bypass_validation': {'type': 'bool', 'default': False},
    'enable_log': {'type': 'bool', 'default': False},
    'forticloud_access_token': {'type': 'str', 'no_log': True},
    'rc_succeeded': {'type': 'list', 'elements': 'int'},
    'rc_failed': {'type': 'list', 'elements': 'int'},
    'workspace_locking_adom': {'type': 'str'},
    'workspace_locking_timeout': {'type': 'int', 'default': 300}
}


def get_module_arg_spec(task_type):
    arg_spec = {}
    for key in COMMON_SCHEMA:
        arg_spec[key] = COMMON_SCHEMA[key]
    if task_type != 'exec':
        arg_spec['proposed_method'] = {
            'type': 'str',
            'required': False,
            'choices': ['set', 'update', 'add']
        }
    if task_type in ['full crud', 'object member']:
        arg_spec['state'] = {
            'type': 'str',
            'required': True,
            'choices': ['present', 'absent']
        }
    return arg_spec


# BEGIN ERROR EXCEPTIONS
class FMGBaseException(Exception):
    """Wrapper to catch the unexpected"""

    def __init__(self, msg=None, *args, **kwargs):
        if msg is None:
            msg = "An exception occurred within the fortimanager.py httpapi connection plugin."
        super(FMGBaseException, self).__init__(msg, *args)

# END ERROR CLASSES


# BEGIN CLASSES
class FMGRCommon(object):
    @staticmethod
    def format_request(method, url, *args, **kwargs):
        """
        Formats the payload from the module, into a payload the API handler can use.

        :param url: Connection URL to access
        :type url: string
        :param method: The preferred API Request method (GET, ADD, POST, etc....)
        :type method: basestring
        :param kwargs: The payload dictionary from the module to be converted.

        :return: Properly formatted dictionary payload for API Request via Connection Plugin.
        :rtype: dict
        """

        params = [{"url": url}]
        if args:
            for arg in args:
                params[0].update(arg)
        if kwargs:
            keylist = list(kwargs)
            for k in keylist:
                kwargs[k.replace("__", "-")] = kwargs.pop(k)
            if method == "get" or method == "clone":
                params[0].update(kwargs)
            else:
                if kwargs.get("data", False):
                    params[0]["data"] = kwargs["data"]
                else:
                    params[0]["data"] = kwargs
        return params

    @staticmethod
    def syslog(module, msg):
        try:
            module.log(msg=msg)
        except BaseException:
            pass
