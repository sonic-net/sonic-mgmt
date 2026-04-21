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

from ansible.module_utils.common.text.converters import to_text

from ansible.module_utils.common.validation import (
    check_type_dict,
    check_type_str,
    check_type_bool,
    check_type_int,
)

from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_common import HashiVaultOptionGroupBase

# we implement retries via the urllib3 Retry class
# https://github.com/ansible-collections/community.hashi_vault/issues/58
HAS_RETRIES = False
try:
    from requests import Session
    from requests.adapters import HTTPAdapter
    try:
        # try for a standalone urllib3
        import urllib3
        HAS_RETRIES = True
    except ImportError:
        try:
            # failing that try for a vendored version within requests
            from requests.packages import urllib3
            HAS_RETRIES = True
        except ImportError:
            pass
except ImportError:
    pass


class HashiVaultConnectionOptions(HashiVaultOptionGroupBase):
    '''HashiVault option group class for connection options'''

    OPTIONS = ['url', 'proxies', 'ca_cert', 'validate_certs', 'namespace', 'timeout', 'retries', 'retry_action']

    ARGSPEC = dict(
        url=dict(type='str', default=None),
        proxies=dict(type='raw'),
        ca_cert=dict(type='str', aliases=['cacert'], default=None),
        validate_certs=dict(type='bool'),
        namespace=dict(type='str', default=None),
        timeout=dict(type='int'),
        retries=dict(type='raw'),
        retry_action=dict(type='str', choices=['ignore', 'warn'], default='warn'),
    )

    _LATE_BINDING_ENV_VAR_OPTIONS = {
        'url': dict(env=['VAULT_ADDR'], required=True),
        'ca_cert': dict(env=['VAULT_CACERT']),
        'namespace': dict(env=['VAULT_NAMESPACE']),
    }

    _RETRIES_DEFAULT_PARAMS = {
        'status_forcelist': [
            # https://www.vaultproject.io/api#http-status-codes
            # 429 is usually a "too many requests" status, but in Vault it's the default health status response for standby nodes.
            412,    # Precondition failed. Returned on Enterprise when a request can't be processed yet due to some missing eventually consistent data.
                    # Should be retried, perhaps with a little backoff.
            500,    # Internal server error. An internal error has occurred, try again later. If the error persists, report a bug.
            502,    # A request to Vault required Vault making a request to a third party; the third party responded with an error of some kind.
            503,    # Vault is down for maintenance or is currently sealed. Try again later.
        ],
        (
            # this field name changed in 1.26.0, and in the interest of supporting a wider range of urllib3 versions
            # we'll use the new name whenever possible, but fall back seamlessly when needed.
            # See also:
            # - https://github.com/urllib3/urllib3/issues/2092
            # - https://github.com/urllib3/urllib3/blob/main/CHANGES.rst#1260-2020-11-10
            "allowed_methods" if HAS_RETRIES and hasattr(urllib3.util.Retry.DEFAULT, "allowed_methods") else "method_whitelist"
        ): None,  # None allows retries on all methods, including those which may not be considered idempotent, like POST
        'backoff_factor': 0.3,
    }

    def __init__(self, option_adapter, retry_callback_generator=None):
        super(HashiVaultConnectionOptions, self).__init__(option_adapter)
        self._retry_callback_generator = retry_callback_generator

    def get_hvac_connection_options(self):
        '''returns kwargs to be used for constructing an hvac.Client'''

        # validate_certs is only used to optionally change the value of ca_cert
        def _filter(k, v):
            return v is not None and k not in ('validate_certs', 'ca_cert')

        # our transformed ca_cert value will become the verify parameter for the hvac client
        hvopts = self._options.get_filtered_options(_filter, *self.OPTIONS)
        hvopts['verify'] = self._conopt_verify

        retry_action = hvopts.pop('retry_action')
        if 'retries' in hvopts:
            hvopts['session'] = self._get_custom_requests_session(new_callback=self._retry_callback_generator(retry_action), **hvopts.pop('retries'))
            hvopts['session'].verify = self._conopt_verify

        return hvopts

    def process_connection_options(self):
        '''executes special processing required for certain options'''
        self.process_late_binding_env_vars(self._LATE_BINDING_ENV_VAR_OPTIONS)

        self._boolean_or_cacert()
        self._process_option_proxies()
        self._process_option_retries()

    def _get_custom_requests_session(self, **retry_kwargs):
        '''returns a requests.Session to pass to hvac (or None)'''

        if not HAS_RETRIES:
            # because hvac requires requests which requires urllib3 it's unlikely we'll ever reach this condition.
            raise NotImplementedError("Retries are unavailable. This may indicate very old versions of one or more of the following: hvac, requests, urllib3.")

        # This is defined here because Retry may not be defined if its import failed.
        # As mentioned above, that's very unlikely, but it'll fail sanity tests nonetheless if defined with other classes.
        class CallbackRetry(urllib3.util.Retry):
            def __init__(self, *args, **kwargs):
                self._newcb = kwargs.pop('new_callback')
                super(CallbackRetry, self).__init__(*args, **kwargs)

            def new(self, **kwargs):
                if self._newcb is not None:
                    self._newcb(self)

                kwargs['new_callback'] = self._newcb
                return super(CallbackRetry, self).new(**kwargs)

        # We don't want the Retry class raising its own exceptions because that will prevent
        # hvac from raising its own on various response codes.
        # We set this here, rather than in the defaults, because if the caller sets their own
        # dict for retries, we use it directly, but we don't want them to have to remember to always
        # set raise_on_status=False themselves to get proper error handling.
        # On the off chance someone does set it, we leave it alone, even though it's probably a mistake.
        # That will be mentioned in the parameter docs.
        if 'raise_on_status' not in retry_kwargs:
            retry_kwargs['raise_on_status'] = False
            # needs urllib 1.15+ https://github.com/urllib3/urllib3/blob/main/CHANGES.rst#115-2016-04-06
            # but we should always have newer ones via requests, via hvac

        retry = CallbackRetry(**retry_kwargs)

        adapter = HTTPAdapter(max_retries=retry)
        sess = Session()
        sess.mount("https://", adapter)
        sess.mount("http://", adapter)

        return sess

    def _process_option_retries(self):
        '''check if retries option is int or dict and interpret it appropriately'''
        # this method focuses on validating the option, and setting a valid Retry object construction dict
        # it intentionally does not build the Session object, which will be done elsewhere

        retries_opt = self._options.get_option('retries')

        if retries_opt is None:
            return

        # we'll start with a copy of our defaults
        retries = self._RETRIES_DEFAULT_PARAMS.copy()

        try:
            # try int
            # on int, retry the specified number of times, and use the defaults for everything else
            # on zero, disable retries
            retries_int = check_type_int(retries_opt)

            if retries_int < 0:
                raise ValueError("Number of retries must be >= 0 (got %i)" % retries_int)
            elif retries_int == 0:
                retries = None
            else:
                retries['total'] = retries_int

        except TypeError:
            try:
                # try dict
                # on dict, use the value directly (will be used as the kwargs to initialize the Retry instance)
                retries = check_type_dict(retries_opt)
            except TypeError:
                raise TypeError("retries option must be interpretable as int or dict. Got: %r" % retries_opt)

        self._options.set_option('retries', retries)

    def _process_option_proxies(self):
        '''check if 'proxies' option is dict or str and set it appropriately'''

        proxies_opt = self._options.get_option('proxies')

        if proxies_opt is None:
            return

        try:
            # if it can be interpreted as dict
            # do it
            proxies = check_type_dict(proxies_opt)
        except TypeError:
            # if it can't be interpreted as dict
            proxy = check_type_str(proxies_opt)
            # but can be interpreted as str
            # use this str as http and https proxy
            proxies = {
                'http': proxy,
                'https': proxy,
            }

        # record the new/interpreted value for 'proxies' option
        self._options.set_option('proxies', proxies)

    def _boolean_or_cacert(self):
        # This is needed because of this (https://hvac.readthedocs.io/en/stable/source/hvac_v1.html):
        #
        # # verify (Union[bool,str]) - Either a boolean to indicate whether TLS verification should
        # # be performed when sending requests to Vault, or a string pointing at the CA bundle to use for verification.
        #
        '''return a bool or cacert'''
        ca_cert = self._options.get_option('ca_cert')

        validate_certs = self._options.get_option('validate_certs')

        if validate_certs is None:
            # Validate certs option was not explicitly set

            # Check if VAULT_SKIP_VERIFY is set
            vault_skip_verify = os.environ.get('VAULT_SKIP_VERIFY')

            if vault_skip_verify is not None:
                # VAULT_SKIP_VERIFY is set
                try:
                    # Check that we have a boolean value
                    vault_skip_verify = check_type_bool(vault_skip_verify)
                except TypeError:
                    # Not a boolean value fallback to default value (True)
                    validate_certs = True
                else:
                    # Use the inverse of VAULT_SKIP_VERIFY
                    validate_certs = not vault_skip_verify
            else:
                validate_certs = True

        if not (validate_certs and ca_cert):
            self._conopt_verify = validate_certs
        else:
            self._conopt_verify = to_text(ca_cert, errors='surrogate_or_strict')
