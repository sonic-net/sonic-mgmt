# -*- coding: utf-8 -*-
# Copyright (c) 2021 Brian Scholer (@briantist)
# Simplified BSD License (see LICENSES/BSD-2-Clause.txt or https://opensource.org/licenses/BSD-2-Clause)
# SPDX-License-Identifier: BSD-2-Clause

'''Python versions supported: >=3.8'''

# FOR INTERNAL COLLECTION USE ONLY
# The interfaces in this file are meant for use within the community.hashi_vault collection
# and may not remain stable to outside uses. Changes may be made in ANY release, even a bugfix release.
# See also: https://github.com/ansible/community/issues/539#issuecomment-780839686
# Please open an issue if you have questions about this.

from __future__ import absolute_import, division, print_function
__metaclass__ = type

import os


class HashiVaultValueError(ValueError):
    '''Use in common code to raise an Exception that can be turned into AnsibleError or used to fail_json()'''


class HashiVaultHVACError(ImportError):
    '''Use in common code to signal HVAC is missing.'''
    def __init__(self, error, msg):
        super().__init__(error)
        self.msg = msg
        self.error = error


class HashiVaultHelper():
    def __init__(self):
        try:
            import hvac
            self.hvac = hvac
        except ImportError as e:
            from ansible.module_utils.basic import missing_required_lib
            raise HashiVaultHVACError(error=str(e), msg=missing_required_lib('hvac'))

    def get_hvac(self):
        return self.hvac

    def get_vault_client(
        self,
        hashi_vault_logout_inferred_token=True, hashi_vault_revoke_on_logout=False,
        **kwargs
    ):
        '''
        creates a Vault client with the given kwargs

        :param hashi_vault_logout_inferred_token: if True performs "logout" after creation to remove any token that
        the hvac library itself may have read in. Only used if "token" is not included in kwargs.
        :type hashi_vault_logout_implied_token: bool

        :param hashi_vault_revoke_on_logout: if True revokes any current token on logout. Only used if a logout is performed. Not recommended.
        :type hashi_vault_revoke_on_logout: bool
        '''

        client = self.hvac.Client(**kwargs)

        # logout to prevent accidental use of inferred tokens
        # https://github.com/ansible-collections/community.hashi_vault/issues/13
        if hashi_vault_logout_inferred_token and 'token' not in kwargs:
            client.logout(revoke_token=hashi_vault_revoke_on_logout)

        return client


class HashiVaultOptionAdapter(object):
    '''
    The purpose of this class is to provide a standard interface for option getting/setting
    within module_utils code, since the processes are so different in plugins and modules.

    Attention is paid to ensuring that in plugins we use the methods provided by Config Manager,
    but to allow flexibility to create an adapter to work with other sources, hence the design
    of defining specific methods exposed, and having them call provided function references.
    '''
    # More context on the need to call Config Manager methods:
    #
    # Some issues raised around deprecations in plugins not being processed led to comments
    # from core maintainers around the need to use Config Manager and also to ensure any
    # option needed is always retrieved using AnsiblePlugin.get_option(). At the time of this
    # writing, based on the way Config Manager is implemented, that's not actually necessary,
    # and calling AnsiblePlugin.set_options() to initialize them is enough. But that's not
    # guaranteed to stay that way, if get_option() is used to "trigger" internal events.
    #
    # More reading:
    # - https://github.com/ansible-collections/community.hashi_vault/issues/35
    # - https://github.com/ansible/ansible/issues/73051
    # - https://github.com/ansible/ansible/pull/73058
    # - https://github.com/ansible/ansible/pull/73239
    # - https://github.com/ansible/ansible/pull/73240

    @classmethod
    def from_dict(cls, dict):
        return cls(
            getter=dict.__getitem__,
            setter=dict.__setitem__,
            haver=lambda key: key in dict,
            updater=dict.update,
            defaultsetter=dict.setdefault,
            defaultgetter=dict.get,
        )

    @classmethod
    def from_ansible_plugin(cls, plugin):
        return cls(
            getter=plugin.get_option,
            setter=plugin.set_option,
            haver=plugin.has_option if hasattr(plugin, 'has_option') else None,
            # AnsiblePlugin.has_option was added in 2.10, see https://github.com/ansible/ansible/pull/61078
        )

    @classmethod
    def from_ansible_module(cls, module):
        return cls.from_dict(module.params)

    def __init__(
            self,
            getter, setter,
            haver=None, updater=None, getitems=None, getfiltereditems=None, getfilleditems=None, defaultsetter=None, defaultgetter=None):

        def _default_default_setter(key, default=None):
            try:
                value = self.get_option(key)
                return value
            except KeyError:
                self.set_option(key, default)
                return default

        def _default_updater(**kwargs):
            for key, value in kwargs.items():
                self.set_option(key, value)

        def _default_haver(key):
            try:
                self.get_option(key)
                return True
            except KeyError:
                return False

        def _default_getitems(*args):
            return dict((key, self.get_option(key)) for key in args)

        def _default_getfiltereditems(filter, *args):
            return dict((key, value) for key, value in self.get_options(*args).items() if filter(key, value))

        def _default_getfilleditems(*args):
            return self.get_filtered_options(lambda k, v: v is not None, *args)

        def _default_default_getter(key, default):
            try:
                return self.get_option(key)
            except KeyError:
                return default

        self._getter = getter
        self._setter = setter

        self._haver = haver or _default_haver
        self._updater = updater or _default_updater
        self._getitems = getitems or _default_getitems
        self._getfiltereditems = getfiltereditems or _default_getfiltereditems
        self._getfilleditems = getfilleditems or _default_getfilleditems
        self._defaultsetter = defaultsetter or _default_default_setter
        self._defaultgetter = defaultgetter or _default_default_getter

    def get_option(self, key):
        return self._getter(key)

    def get_option_default(self, key, default=None):
        return self._defaultgetter(key, default)

    def set_option(self, key, value):
        return self._setter(key, value)

    def set_option_default(self, key, default=None):
        return self._defaultsetter(key, default)

    def has_option(self, key):
        return self._haver(key)

    def set_options(self, **kwargs):
        return self._updater(**kwargs)

    def get_options(self, *args):
        return self._getitems(*args)

    def get_filtered_options(self, filter, *args):
        return self._getfiltereditems(filter, *args)

    def get_filled_options(self, *args):
        return self._getfilleditems(*args)


class HashiVaultOptionGroupBase:
    '''A base class for class option group classes'''

    def __init__(self, option_adapter):
        self._options = option_adapter

    def process_late_binding_env_vars(self, option_vars):
        '''looks through a set of options, and if empty/None, looks for a value in specified env vars, or sets an optional default'''
        # see https://github.com/ansible-collections/community.hashi_vault/issues/10
        #
        # Options which seek to use environment vars that are not Ansible-specific
        # should load those as values of last resort, so that INI values can override them.
        # For default processing, list such options and vars here.
        # Alternatively, process them in another appropriate place like an auth method's
        # validate_ method.
        #
        # key = option_name
        # value = dict with "env" key which is a list of env vars (in order of those checked first; process stops when value is found),
        # and an optional "default" key whose value will be set if none of the env vars are found.
        # An optional boolean "required" key can be used to specify that a value is required, so raise if one is not found.

        for opt, config in option_vars.items():
            for env in config['env']:
                # we use has_option + get_option rather than get_option_default
                # because we will only override if the option exists and
                # is None, not if it's missing. For plugins, that is the usual,
                # but for modules, they may have to set the default to None
                # in the argspec if it has late binding env vars.
                if self._options.has_option(opt) and self._options.get_option(opt) is None:
                    self._options.set_option(opt, os.environ.get(env))

            if 'default' in config and self._options.has_option(opt) and self._options.get_option(opt) is None:
                self._options.set_option(opt, config['default'])

            if 'required' in config and self._options.get_option_default(opt) is None:
                raise HashiVaultValueError("Required option %s was not set." % opt)


class HashiVaultAuthMethodBase(HashiVaultOptionGroupBase):
    '''Base class for individual auth method implementations'''

    def __init__(self, option_adapter, warning_callback, deprecate_callback):
        super(HashiVaultAuthMethodBase, self).__init__(option_adapter)
        self._warner = warning_callback
        self._deprecator = deprecate_callback

    def validate(self):
        '''Validates the given auth method as much as possible without calling Vault.'''
        raise NotImplementedError('validate must be implemented')

    def authenticate(self, client, use_token=True):
        '''Authenticates against Vault, returns a token.'''
        raise NotImplementedError('authenticate must be implemented')

    def validate_by_required_fields(self, *field_names):
        missing = [field for field in field_names if self._options.get_option_default(field) is None]

        if missing:
            raise HashiVaultValueError("Authentication method %s requires options %r to be set, but these are missing: %r" % (self.NAME, field_names, missing))

    def warn(self, message):
        self._warner(message)

    def deprecate(self, message, version=None, date=None, collection_name=None):
        self._deprecator(message, version=version, date=date, collection_name=collection_name)
