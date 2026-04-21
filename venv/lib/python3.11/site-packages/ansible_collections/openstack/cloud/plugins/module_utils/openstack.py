#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This code is part of Ansible, but is an independent component.
# This particular file snippet, and this file snippet only, is BSD licensed.
# Modules you write using this snippet, which is embedded dynamically by Ansible
# still belong to the author of the module, and may assign their own license
# to the complete work.
#
# Copyright 2019 Red Hat, Inc.
# Copyright (c) 2014 Hewlett-Packard Development Company, L.P.
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

import abc
import copy
from ansible.module_utils.six import raise_from
try:
    from ansible.module_utils.compat.version import StrictVersion
except ImportError:
    try:
        from distutils.version import StrictVersion
    except ImportError as exc:
        raise_from(ImportError('To use this plugin or module with ansible-core'
                               ' < 2.11, you need to use Python < 3.12 with '
                               'distutils.version present'), exc)
import importlib
import os

from ansible.module_utils.basic import AnsibleModule

OVERRIDES = {}

CUSTOM_VAR_PARAMS = ['min_ver', 'max_ver']

MINIMUM_SDK_VERSION = '1.0.0'
MAXIMUM_SDK_VERSION = None


def ensure_compatibility(version, min_version=None, max_version=None):
    """ Raises ImportError if the specified version does not
        meet the minimum and maximum version requirements"""

    if min_version and MINIMUM_SDK_VERSION:
        min_version = max(StrictVersion(MINIMUM_SDK_VERSION),
                          StrictVersion(min_version))
    elif MINIMUM_SDK_VERSION:
        min_version = StrictVersion(MINIMUM_SDK_VERSION)

    if max_version and MAXIMUM_SDK_VERSION:
        max_version = min(StrictVersion(MAXIMUM_SDK_VERSION),
                          StrictVersion(max_version))
    elif MAXIMUM_SDK_VERSION:
        max_version = StrictVersion(MAXIMUM_SDK_VERSION)

    if min_version and StrictVersion(version) < min_version:
        raise ImportError(
            "Version MUST be >={min_version} and <={max_version}, but"
            " {version} is smaller than minimum version {min_version}"
            .format(version=version,
                    min_version=min_version,
                    max_version=max_version))

    if max_version and StrictVersion(version) > max_version:
        raise ImportError(
            "Version MUST be >={min_version} and <={max_version}, but"
            " {version} is larger than maximum version {max_version}"
            .format(version=version,
                    min_version=min_version,
                    max_version=max_version))


def openstack_argument_spec():
    # DEPRECATED: This argument spec is only used for the deprecated old
    # OpenStack modules. It turns out that modern OpenStack auth is WAY
    # more complex than this.
    # Consume standard OpenStack environment variables.
    # This is mainly only useful for ad-hoc command line operation as
    # in playbooks one would assume variables would be used appropriately
    OS_AUTH_URL = os.environ.get('OS_AUTH_URL', 'http://127.0.0.1:35357/v2.0/')
    OS_PASSWORD = os.environ.get('OS_PASSWORD', None)
    OS_REGION_NAME = os.environ.get('OS_REGION_NAME', None)
    OS_USERNAME = os.environ.get('OS_USERNAME', 'admin')
    OS_TENANT_NAME = os.environ.get('OS_TENANT_NAME', OS_USERNAME)

    spec = dict(
        login_username=dict(default=OS_USERNAME),
        auth_url=dict(default=OS_AUTH_URL),
        region_name=dict(default=OS_REGION_NAME),
    )
    if OS_PASSWORD:
        spec['login_password'] = dict(default=OS_PASSWORD)
    else:
        spec['login_password'] = dict(required=True)
    if OS_TENANT_NAME:
        spec['login_tenant_name'] = dict(default=OS_TENANT_NAME)
    else:
        spec['login_tenant_name'] = dict(required=True)
    return spec


def openstack_full_argument_spec(**kwargs):
    spec = dict(
        cloud=dict(type='raw'),
        auth_type=dict(),
        auth=dict(type='dict', no_log=True),
        region_name=dict(),
        validate_certs=dict(type='bool', aliases=['verify']),
        ca_cert=dict(aliases=['cacert']),
        client_cert=dict(aliases=['cert']),
        client_key=dict(no_log=True, aliases=['key']),
        wait=dict(default=True, type='bool'),
        timeout=dict(default=180, type='int'),
        api_timeout=dict(type='int'),
        interface=dict(
            default='public', choices=['public', 'internal', 'admin'],
            aliases=['endpoint_type']),
        sdk_log_path=dict(),
        sdk_log_level=dict(
            default='INFO', choices=['INFO', 'DEBUG']),
    )
    # Filter out all our custom parameters before passing to AnsibleModule
    kwargs_copy = copy.deepcopy(kwargs)
    for v in kwargs_copy.values():
        for c in CUSTOM_VAR_PARAMS:
            v.pop(c, None)
    spec.update(kwargs_copy)
    return spec


def openstack_module_kwargs(**kwargs):
    ret = {}
    for key in ('mutually_exclusive', 'required_together', 'required_one_of'):
        if key in kwargs:
            if key in ret:
                ret[key].extend(kwargs[key])
            else:
                ret[key] = kwargs[key]
    return ret


# for compatibility with old versions
def openstack_cloud_from_module(module, min_version=None, max_version=None):
    try:
        # Due to the name shadowing we should import other way
        sdk = importlib.import_module('openstack')
    except ImportError:
        module.fail_json(msg='openstacksdk is required for this module')

    try:
        ensure_compatibility(sdk.version.__version__,
                             min_version, max_version)
    except ImportError as e:
        module.fail_json(
            msg="Incompatible openstacksdk library found: {error}."
                .format(error=str(e)))

    cloud_config = module.params.pop('cloud', None)
    try:
        if isinstance(cloud_config, dict):
            fail_message = (
                "A cloud config dict was provided to the cloud parameter"
                " but also a value was provided for {param}. If a cloud"
                " config dict is provided, {param} should be"
                " excluded.")
            for param in (
                    'auth', 'region_name', 'validate_certs',
                    'ca_cert', 'client_cert', 'client_key', 'api_timeout', 'auth_type'):
                if module.params[param] is not None:
                    module.fail_json(msg=fail_message.format(param=param))
            # For 'interface' parameter, fail if we receive a non-default value
            if module.params['interface'] != 'public':
                module.fail_json(msg=fail_message.format(param='interface'))
            return sdk, sdk.connect(**cloud_config)
        else:
            return sdk, sdk.connect(
                cloud=cloud_config,
                auth_type=module.params['auth_type'],
                auth=module.params['auth'],
                region_name=module.params['region_name'],
                verify=module.params['validate_certs'],
                cacert=module.params['ca_cert'],
                key=module.params['client_key'],
                cert=module.params['client_cert'],
                api_timeout=module.params['api_timeout'],
                interface=module.params['interface'],
            )
    except sdk.exceptions.SDKException as e:
        # Probably a cloud configuration/login error
        module.fail_json(msg=str(e))


class OpenStackModule:
    """Openstack Module is a base class for all Openstack Module classes.

    The class has `run` function that should be overriden in child classes,
    the provided methods include:

    Methods:
        params: Dictionary of Ansible module parameters.
        module_name: Module name (i.e. server_action)
        sdk_version: Version of used OpenstackSDK.
        results: Dictionary for return of Ansible module,
                 must include `changed` keyword.
        exit, exit_json: Exit module and return data inside, must include
                         changed` keyword in a data.
        fail, fail_json: Exit module with failure, has `msg` keyword to
                         specify a reason of failure.
        conn: Connection to SDK object.
        log: Print message to system log.
        debug: Print debug message to system log, prints if Ansible Debug is
               enabled or verbosity is more than 2.
        check_deprecated_names: Function that checks if module was called with
                                a deprecated name and prints the correct name
                                with deprecation warning.
        check_versioned: helper function to check that all arguments are known
                         in the current SDK version.
        run: method that executes and shall be overriden in inherited classes.

    Args:
        deprecated_names: Should specify deprecated modules names for current
                          module.
        argument_spec: Used for construction of Openstack common arguments.
        module_kwargs: Additional arguments for Ansible Module.
    """

    deprecated_names = ()
    argument_spec = {}
    module_kwargs = {}
    module_min_sdk_version = None
    module_max_sdk_version = None

    def __init__(self):
        """Initialize Openstack base class.

        Set up variables, connection to SDK and check if there are
        deprecated names.
        """
        self.ansible = AnsibleModule(
            openstack_full_argument_spec(**self.argument_spec),
            **self.module_kwargs)
        self.params = self.ansible.params
        self.module_name = self.ansible._name
        self.check_mode = self.ansible.check_mode
        self.sdk_version = None
        self.results = {'changed': False}
        self.exit = self.exit_json = self.ansible.exit_json
        self.fail = self.fail_json = self.ansible.fail_json
        self.warn = self.ansible.warn
        self.sdk, self.conn = self.openstack_cloud_from_module()
        self.check_deprecated_names()
        self.setup_sdk_logging()

    def log(self, msg):
        """Prints log message to system log.

        Arguments:
            msg {str} -- Log message
        """
        self.ansible.log(msg)

    def debug(self, msg):
        """Prints debug message to system log

        Arguments:
            msg {str} -- Debug message.
        """
        if self.ansible._debug or self.ansible._verbosity > 2:
            self.ansible.log(
                " ".join(['[DEBUG]', msg]))

    def setup_sdk_logging(self):
        log_path = self.params.get('sdk_log_path')
        if log_path is not None:
            log_level = self.params.get('sdk_log_level')
            self.sdk.enable_logging(
                debug=True if log_level == 'DEBUG' else False,
                http_debug=True if log_level == 'DEBUG' else False,
                path=log_path
            )

    def check_deprecated_names(self):
        """Check deprecated module names if `deprecated_names` variable is set.
        """
        new_module_name = OVERRIDES.get(self.module_name)
        if self.module_name in self.deprecated_names and new_module_name:
            self.ansible.deprecate(
                "The '%s' module has been renamed to '%s' in openstack "
                "collection: openstack.cloud.%s" % (
                    self.module_name, new_module_name, new_module_name),
                version='3.0.0', collection_name='openstack.cloud')

    def openstack_cloud_from_module(self):
        """Sets up connection to cloud using provided options. Checks if all
           provided variables are supported for the used SDK version.
        """
        try:
            # Due to the name shadowing we should import other way
            sdk = importlib.import_module('openstack')
            self.sdk_version = sdk.version.__version__
        except ImportError:
            self.fail_json(msg='openstacksdk is required for this module')

        try:
            ensure_compatibility(self.sdk_version,
                                 self.module_min_sdk_version,
                                 self.module_max_sdk_version)
        except ImportError as e:
            self.fail_json(
                msg="Incompatible openstacksdk library found: {error}."
                    .format(error=str(e)))

        # Fail if there are set unsupported for this version parameters
        # New parameters should NOT use 'default' but rely on SDK defaults
        for param in self.argument_spec:
            if (self.params[param] is not None
                and 'min_ver' in self.argument_spec[param]
                    and StrictVersion(self.sdk_version) < self.argument_spec[param]['min_ver']):
                self.fail_json(
                    msg="To use parameter '{param}' with module '{module}', the installed version of "
                    "the openstacksdk library MUST be >={min_version}.".format(
                        min_version=self.argument_spec[param]['min_ver'],
                        param=param,
                        module=self.module_name))
            if (self.params[param] is not None
                and 'max_ver' in self.argument_spec[param]
                    and StrictVersion(self.sdk_version) > self.argument_spec[param]['max_ver']):
                self.fail_json(
                    msg="To use parameter '{param}' with module '{module}', the installed version of "
                    "the openstacksdk library MUST be <={max_version}.".format(
                        max_version=self.argument_spec[param]['max_ver'],
                        param=param,
                        module=self.module_name))

        cloud_config = self.params.pop('cloud', None)
        if isinstance(cloud_config, dict):
            fail_message = (
                "A cloud config dict was provided to the cloud parameter"
                " but also a value was provided for {param}. If a cloud"
                " config dict is provided, {param} should be"
                " excluded.")
            for param in (
                    'auth', 'region_name', 'validate_certs',
                    'ca_cert', 'client_cert', 'client_key', 'api_timeout', 'auth_type'):
                if self.params[param] is not None:
                    self.fail_json(msg=fail_message.format(param=param))
            # For 'interface' parameter, fail if we receive a non-default value
            if self.params['interface'] != 'public':
                self.fail_json(msg=fail_message.format(param='interface'))
        else:
            cloud_config = dict(
                cloud=cloud_config,
                auth_type=self.params['auth_type'],
                auth=self.params['auth'],
                region_name=self.params['region_name'],
                verify=self.params['validate_certs'],
                cacert=self.params['ca_cert'],
                key=self.params['client_key'],
                cert=self.params['client_cert'],
                api_timeout=self.params['api_timeout'],
                interface=self.params['interface'],
            )
        try:
            return sdk, sdk.connect(**cloud_config)
        except sdk.exceptions.SDKException as e:
            # Probably a cloud configuration/login error
            self.fail_json(msg=str(e))

    # Filter out all arguments that are not from current SDK version
    def check_versioned(self, **kwargs):
        """Check that provided arguments are supported by current SDK version

        Returns:
            versioned_result {dict} dictionary of only arguments that are
                                    supported by current SDK version. All others
                                    are dropped.
        """
        versioned_result = {}
        for var_name in kwargs:
            if ('min_ver' in self.argument_spec[var_name]
                    and StrictVersion(self.sdk_version) < self.argument_spec[var_name]['min_ver']):
                continue
            if ('max_ver' in self.argument_spec[var_name]
                    and StrictVersion(self.sdk_version) > self.argument_spec[var_name]['max_ver']):
                continue
            versioned_result.update({var_name: kwargs[var_name]})
        return versioned_result

    @abc.abstractmethod
    def run(self):
        """Function for overriding in inhetired classes, it's executed by default.
        """
        pass

    def __call__(self):
        """Execute `run` function when calling the class.
        """
        try:
            results = self.run()
            if results and isinstance(results, dict):
                self.ansible.exit_json(**results)
        except self.sdk.exceptions.OpenStackCloudException as e:
            params = {
                'msg': str(e),
                'extra_data': {
                    'data': getattr(e, 'extra_data', 'None'),
                    'details': getattr(e, 'details', 'None'),
                    'response': getattr(getattr(e, 'response', ''),
                                        'text', 'None')
                }
            }
            self.ansible.fail_json(**params)
        # if we got to this place, modules didn't exit
        self.ansible.exit_json(**self.results)
