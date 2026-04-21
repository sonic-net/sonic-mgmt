# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class TLSConfig(object):

    def __init__(self, certificate_path=None, ca_cert_path=None):
        self.certificate_path = certificate_path
        self.ca_cert_path = ca_cert_path

    def to_requests_tuple(self):
        """
        Decide what to pass to requests for TLS.
        Returns a tuple: (cert, verify)
        """
        cert = None
        verify = True

        if self.certificate_path:
            cert = self.certificate_path
            verify = self.ca_cert_path if self.ca_cert_path else False
        elif self.ca_cert_path:
            verify = self.ca_cert_path

        return cert, verify
