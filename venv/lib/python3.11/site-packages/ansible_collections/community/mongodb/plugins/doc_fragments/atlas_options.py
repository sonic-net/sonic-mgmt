# -*- coding: utf-8 -*-
#
# Copyright (c) 2021 T-Systems MMS
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
#
# This module is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Documentation for global options that are always the same
    DOCUMENTATION = r'''
options:
  api_username:
    description:
      - The username for use in authentication with the Atlas API.
      - Can use API users and tokens (public key is username)
    type: str
    required: True
    aliases: [apiUsername]
  api_password:
    description:
      - The password for use in authentication with the Atlas API.
      - Can use API users and tokens (private key is password)
    type: str
    required: True
    aliases: [apiPassword]
  group_id:
    description:
      - Unique identifier for the Atlas project.
    type: str
    required: True
    aliases: [groupId]
  state:
    description:
      - State of the ressource.
    choices: [ "present", "absent" ]
    default: present
    type: str
'''
