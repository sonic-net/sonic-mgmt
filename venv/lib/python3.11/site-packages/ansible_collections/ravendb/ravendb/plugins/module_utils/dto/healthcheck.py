# -*- coding: utf-8 -*-

# Copyright (c), RavenDB
# GNU General Public License v3.0 or later (see COPYING or
# https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class HealthcheckSpec(object):
    def __init__(
        self, url, validate_certificate, certificate_path, ca_cert_path,
        checks,
        max_time_to_wait, retry_interval_seconds, db_retry_interval_seconds,
        on_db_timeout
    ):
        self.url = url
        self.validate_certificate = bool(validate_certificate)
        self.certificate_path = certificate_path
        self.ca_cert_path = ca_cert_path
        self.checks = list(checks or [])
        self.max_time_to_wait = int(max_time_to_wait)
        self.retry_interval_seconds = int(retry_interval_seconds)
        self.db_retry_interval_seconds = int(db_retry_interval_seconds)
        self.on_db_timeout = on_db_timeout
