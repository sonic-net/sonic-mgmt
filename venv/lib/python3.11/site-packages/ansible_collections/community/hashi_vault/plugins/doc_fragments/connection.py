# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
    options:
      url:
        description:
          - URL to the Vault service.
          - If not specified by any other means, the value of the C(VAULT_ADDR) environment variable will be used.
          - If C(VAULT_ADDR) is also not defined then an error will be raised.
        type: str
      proxies:
        description:
          - URL(s) to the proxies used to access the Vault service.
          - It can be a string or a dict.
          - If it's a dict, provide the scheme (eg. C(http) or C(https)) as the key, and the URL as the value.
          - If it's a string, provide a single URL that will be used as the proxy for both C(http) and C(https) schemes.
          - A string that can be interpreted as a dictionary will be converted to one (see examples).
          - You can specify a different proxy for HTTP and HTTPS resources.
          - If not specified, L(environment variables from the Requests library,https://requests.readthedocs.io/en/master/user/advanced/#proxies) are used.
        type: raw
        version_added: 1.1.0
      ca_cert:
        description:
          - Path to certificate to use for authentication.
          - If not specified by any other means, the C(VAULT_CACERT) environment variable will be used.
        aliases: [ cacert ]
        type: str
      validate_certs:
        description:
          - Controls verification and validation of SSL certificates, mostly you only want to turn off with self signed ones.
          - Will be populated with the inverse of C(VAULT_SKIP_VERIFY) if that is set and I(validate_certs) is not explicitly provided.
          - Will default to C(true) if neither I(validate_certs) or C(VAULT_SKIP_VERIFY) are set.
        type: bool
      namespace:
        description:
          - Vault namespace where secrets reside. This option requires HVAC 0.7.0+ and Vault 0.11+.
          - Optionally, this may be achieved by prefixing the authentication mount point and/or secret path with the namespace
            (e.g C(mynamespace/secret/mysecret)).
          - If environment variable C(VAULT_NAMESPACE) is set, its value will be used last among all ways to specify I(namespace).
        type: str
      timeout:
        description:
          - Sets the connection timeout in seconds.
          - If not set, then the C(hvac) library's default is used.
        type: int
        version_added: 1.3.0
      retries:
        description:
          - "Allows for retrying on errors, based on
            the L(Retry class in the urllib3 library,https://urllib3.readthedocs.io/en/latest/reference/urllib3.util.html#urllib3.util.Retry)."
          - This collection defines recommended defaults for retrying connections to Vault.
          - This option can be specified as a positive number (integer) or dictionary.
          - If this option is not specified or the number is C(0), then retries are disabled.
          - A number sets the total number of retries, and uses collection defaults for the other settings.
          - A dictionary value is used directly to initialize the C(Retry) class, so it can be used to fully customize retries.
          - For detailed information on retries, see the collection User Guide.
        type: raw
        version_added: 1.3.0
      retry_action:
        description:
          - Controls whether and how to show messages on I(retries).
          - This has no effect if a request is not retried.
        type: str
        choices:
          - ignore
          - warn
        default: warn
        version_added: 1.3.0
    '''

    PLUGINS = r'''
      options:
        url:
          env:
            - name: ANSIBLE_HASHI_VAULT_ADDR
              version_added: 0.2.0
          ini:
            - section: hashi_vault_collection
              key: url
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_url
              version_added: 1.2.0
            - name: ansible_hashi_vault_addr
              version_added: 1.2.0
        proxies:
          env:
            - name: ANSIBLE_HASHI_VAULT_PROXIES
          ini:
            - section: hashi_vault_collection
              key: proxies
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_proxies
              version_added: 1.2.0
          type: raw
          version_added: 1.1.0
        ca_cert:
          env:
            - name: ANSIBLE_HASHI_VAULT_CA_CERT
              version_added: 1.2.0
          ini:
            - section: hashi_vault_collection
              key: ca_cert
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_ca_cert
              version_added: 1.2.0
        validate_certs:
          vars:
            - name: ansible_hashi_vault_validate_certs
              version_added: 1.2.0
        namespace:
          env:
            - name: ANSIBLE_HASHI_VAULT_NAMESPACE
              version_added: 0.2.0
          ini:
            - section: hashi_vault_collection
              key: namespace
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_namespace
              version_added: 1.2.0
        timeout:
          env:
            - name: ANSIBLE_HASHI_VAULT_TIMEOUT
          ini:
            - section: hashi_vault_collection
              key: timeout
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_timeout
        retries:
          env:
            - name: ANSIBLE_HASHI_VAULT_RETRIES
          ini:
            - section: hashi_vault_collection
              key: retries
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_retries
        retry_action:
          env:
            - name: ANSIBLE_HASHI_VAULT_RETRY_ACTION
          ini:
            - section: hashi_vault_collection
              key: retry_action
              version_added: 1.4.0
          vars:
            - name: ansible_hashi_vault_retry_action
      '''
