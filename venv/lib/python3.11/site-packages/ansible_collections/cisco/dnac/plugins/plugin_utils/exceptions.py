#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class AnsibleDNACException(Exception):
    """Base class for all Ansible DNAC package exceptions."""

    pass


class InconsistentParameters(AnsibleDNACException):
    """Provided parameters are not consistent."""

    pass


class AnsibleSDAException(Exception):
    def __init__(self, response):
        self._response = response
