# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 Felix Fontein
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function


__metaclass__ = type


import warnings

from ansible.module_utils.common.text.converters import to_text
from ansible_collections.community.dns.plugins.module_utils._six import raise_from
from ansible_collections.community.dns.plugins.module_utils.conversion.base import (
    DNSConversionError,
)
from ansible_collections.community.dns.plugins.module_utils.conversion.txt import (
    decode_txt_value,
    encode_txt_value,
)
from ansible_collections.community.dns.plugins.module_utils.record import DNSRecord


class RecordConverter(object):
    def __init__(self, provider_information, option_provider):
        """
        Create a record converter.
        """
        self._provider_information = provider_information
        self._option_provider = option_provider

        # Valid values: 'decoded', 'encoded', 'encoded-no-octal' (deprecated), 'encoded-no-char-encoding'
        self._txt_api_handling = self._provider_information.txt_record_handling()
        if self._txt_api_handling == 'encoded-no-octal':
            warnings.warn('provider_information.txt_record_handling() returned deprecated value "encoded-no-octal"')
        self._txt_api_character_encoding = self._provider_information.txt_character_encoding()
        # Valid values: 'api', 'quoted', 'unquoted'
        self._txt_transformation = self._option_provider.get_option('txt_transformation')
        # Valid values: 'decimal', 'octal'
        self._txt_character_encoding = self._option_provider.get_option('txt_character_encoding')

    def emit_deprecations(self, deprecator):
        pass

    def _handle_txt_api(self, to_api, record):
        """
        Handle TXT records for sending to/from the API.
        """
        if self._txt_transformation == 'api':
            # Do not touch record values
            return

        # We assume that records internally use decoded values
        if self._txt_api_handling in ('encoded', 'encoded-no-octal', 'encoded-no-char-encoding'):
            if to_api:
                record.target = encode_txt_value(
                    record.target,
                    use_character_encoding=self._txt_api_handling == 'encoded',
                    character_encoding=self._txt_api_character_encoding)
            else:
                record.target = decode_txt_value(record.target, character_encoding=self._txt_api_character_encoding)

    def _handle_txt_user(self, to_user, record):
        """
        Handle TXT records for sending to/from the user.
        """
        if self._txt_transformation == 'api':
            # Do not touch record values
            return

        # We assume that records internally use decoded values
        if self._txt_transformation == 'quoted':
            if to_user:
                record.target = encode_txt_value(record.target, character_encoding=self._txt_character_encoding)
            else:
                record.target = decode_txt_value(record.target, character_encoding=self._txt_character_encoding)

    def process_from_api(self, record):
        """
        Process a record object (DNSRecord) after receiving from API.
        Modifies the record in-place.
        """
        try:
            record.target = to_text(record.target)
            if record.type == 'TXT':
                self._handle_txt_api(False, record)
            return record
        except DNSConversionError as e:
            raise_from(DNSConversionError(u'While processing record from API: {0}'.format(e.error_message)), e)

    def process_to_api(self, record):
        """
        Process a record object (DNSRecord) for sending to API.
        Modifies the record in-place.
        """
        try:
            if record.type == 'TXT':
                self._handle_txt_api(True, record)
            return record
        except DNSConversionError as e:
            raise_from(DNSConversionError(u'While processing record for the API: {0}'.format(e.error_message)), e)

    def process_from_user(self, record):
        """
        Process a record object (DNSRecord) after receiving from the user.
        Modifies the record in-place.
        """
        try:
            record.target = to_text(record.target)
            if record.type == 'TXT':
                self._handle_txt_user(False, record)
            return record
        except DNSConversionError as e:
            raise_from(DNSConversionError(u'While processing record from the user: {0}'.format(e.error_message)), e)

    def process_to_user(self, record):
        """
        Process a record object (DNSRecord) for sending to the user.
        Modifies the record in-place.
        """
        try:
            if record.type == 'TXT':
                self._handle_txt_user(True, record)
            return record
        except DNSConversionError as e:
            raise_from(DNSConversionError(u'While processing record for the user: {0}'.format(e.error_message)), e)

    def clone_from_api(self, record):
        """
        Process a record object (DNSRecord) after receiving from API.
        Return a modified clone of the record; the original will not be modified.
        """
        record = record.clone()
        self.process_from_api(record)
        return record

    def clone_to_api(self, record):
        """
        Process a record object (DNSRecord) for sending to API.
        Return a modified clone of the record; the original will not be modified.
        """
        record = record.clone()
        self.process_to_api(record)
        return record

    def clone_multiple_from_api(self, records):
        """
        Process a list of record object (DNSRecord) after receiving from API.
        Return a list of modified clones of the records; the originals will not be modified.
        """
        return [self.clone_from_api(record) for record in records]

    def clone_multiple_to_api(self, records):
        """
        Process a list of record objects (DNSRecord) for sending to API.
        Return a list of modified clones of the records; the originals will not be modified.
        """
        return [self.clone_to_api(record) for record in records]

    def process_multiple_from_api(self, records):
        """
        Process a list of record object (DNSRecord) after receiving from API.
        Modifies the records in-place.
        """
        for record in records:
            self.process_from_api(record)
        return records

    def process_multiple_to_api(self, records):
        """
        Process a list of record objects (DNSRecord) for sending to API.
        Modifies the records in-place.
        """
        for record in records:
            self.process_to_api(record)
        return records

    def process_multiple_from_user(self, records):
        """
        Process a list of record object (DNSRecord) after receiving from the user.
        Modifies the records in-place.
        """
        for record in records:
            self.process_from_user(record)
        return records

    def process_multiple_to_user(self, records):
        """
        Process a list of record objects (DNSRecord) for sending to the user.
        Modifies the records in-place.
        """
        for record in records:
            self.process_to_user(record)
        return records

    def process_value_from_user(self, record_type, value):
        """
        Process a record value (string) after receiving from the user.
        """
        record = DNSRecord()
        record.type = record_type
        record.target = value
        self.process_from_user(record)
        return record.target

    def process_values_from_user(self, record_type, values):
        """
        Process a list of record values (strings) after receiving from the user.
        """
        return [self.process_value_from_user(record_type, value) for value in values]

    def process_value_to_user(self, record_type, value):
        """
        Process a record value (string) for sending to the user.
        """
        record = DNSRecord()
        record.type = record_type
        record.target = value
        self.process_to_user(record)
        return record.target

    def process_values_to_user(self, record_type, values):
        """
        Process a list of record values (strings) for sending to the user.
        """
        return [self.process_value_to_user(record_type, value) for value in values]
