# -*- coding: utf-8 -*-
#
# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class EncryptionSpec(object):
    def __init__(self,
                 enabled=False,
                 certificate_path=None,
                 ca_cert_path=None,
                 generate_key=False,
                 key_path=None,
                 output_path=None):
        self.enabled = enabled
        self.certificate_path = certificate_path
        self.ca_cert_path = ca_cert_path
        self.generate_key = generate_key
        self.key_path = key_path
        self.output_path = output_path


class DatabaseSpec(object):
    def __init__(self, url, name, replication_factor=None, settings=None, encryption=None, members=None):
        if settings is None:
            settings = {}
        if encryption is None:
            encryption = EncryptionSpec()
        if members is None:
            members = []

        self.url = url
        self.name = name
        self.replication_factor = replication_factor
        self.settings = settings
        self.encryption = encryption
        self.members = members
