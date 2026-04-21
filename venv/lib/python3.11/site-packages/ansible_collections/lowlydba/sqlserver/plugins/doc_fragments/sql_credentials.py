# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Options for authenticating with SQL Authentication.

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  sql_instance:
    description:
      - The SQL Server instance to modify.
    type: str
    required: true
  sql_username:
    description:
      - Username for SQL Authentication.
    type: str
    required: false
  sql_password:
    description:
      - Password for SQL Authentication.
    type: str
    required: false
'''
