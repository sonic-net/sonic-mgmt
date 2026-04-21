# -*- coding: utf-8 -*-
#
# Copyright (c) 2017-2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


from ansible_collections.community.dns.plugins.module_utils.argspec import ArgumentSpec
from ansible_collections.community.dns.plugins.module_utils.hosttech.json_api import (
    HostTechJSONAPI,
)
from ansible_collections.community.dns.plugins.module_utils.hosttech.wsdl_api import (
    HostTechWSDLAPI,
)
from ansible_collections.community.dns.plugins.module_utils.provider import (
    ProviderInformation,
)
from ansible_collections.community.dns.plugins.module_utils.wsdl import HAS_LXML_ETREE
from ansible_collections.community.dns.plugins.module_utils.zone_record_api import (
    DNSAPIError,
)


class HosttechProviderInformation(ProviderInformation):
    def get_supported_record_types(self):
        """
        Return a list of supported record types.
        """
        return ['A', 'CNAME', 'MX', 'AAAA', 'TXT', 'PTR', 'SRV', 'SPF', 'NS', 'CAA']

    def get_zone_id_type(self):
        """
        Return the (short) type for zone IDs, like ``'int'`` or ``'str'``.
        """
        return 'int'

    def get_record_id_type(self):
        """
        Return the (short) type for record IDs, like ``'int'`` or ``'str'``.
        """
        return 'int'

    def get_record_default_ttl(self):
        """
        Return the default TTL for records, like 300, 3600 or None.
        None means that some other TTL (usually from the zone) will be used.
        """
        return 3600

    def normalize_prefix(self, prefix):
        """
        Given a prefix (string or None), return its normalized form.

        The result should always be None for the trivial prefix, and a non-zero length DNS name
        for a non-trivial prefix.

        If a provider supports other identifiers for the trivial prefix, such as '@', this
        function needs to convert them to None as well.
        """
        return prefix or None

    def txt_record_handling(self):
        """
        Return how the API handles TXT records.

        Returns one of the following strings:
        * 'decoded' - the API works with unencoded values
        * 'encoded' - the API works with encoded values
        * 'encoded-no-char-encoding' - the API works with encoded values, but without character encoding
        """
        return 'decoded'


def create_hosttech_provider_information():
    return HosttechProviderInformation()


def create_hosttech_argument_spec():
    return ArgumentSpec(
        argument_spec={
            'hosttech_username': {'type': 'str'},
            'hosttech_password': {'type': 'str', 'no_log': True},
            'hosttech_token': {'type': 'str', 'no_log': True, 'aliases': ['api_token']},
        },
        required_together=[('hosttech_username', 'hosttech_password')],
        mutually_exclusive=[('hosttech_username', 'hosttech_token')],
    )


def create_hosttech_api(option_provider, http_helper):
    username = option_provider.get_option('hosttech_username')
    password = option_provider.get_option('hosttech_password')
    if username is not None and password is not None:
        if not HAS_LXML_ETREE:
            raise DNSAPIError('Needs lxml Python module (pip install lxml)')

        return HostTechWSDLAPI(http_helper, username, password, debug=False)

    token = option_provider.get_option('hosttech_token')
    if token is not None:
        return HostTechJSONAPI(http_helper, token)

    raise DNSAPIError('One of hosttech_token or both hosttech_username and hosttech_password must be provided!')
