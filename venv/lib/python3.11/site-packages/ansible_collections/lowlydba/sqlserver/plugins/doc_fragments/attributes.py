# -*- coding: utf-8 -*-

# (c) 2022, John McCall (@lowlydba)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options: {}
'''

    CHECK_MODE = r'''
options: {}
attributes:
  check_mode:
    support: full
    description: Can run in check_mode and return changed status prediction without modifying target.
'''

    CHECK_MODE_READ_ONLY = r'''
options: {}
attributes:
  check_mode:
    support: full
    description: This module is "read only" and operates the same regardless of check mode.
'''

    PLATFORM_ALL = r'''
options: {}
attributes:
  platform:
    platforms: all
    support: full
    description: Target OS/families that can be operated against.
'''

    PLATFORM_WIN = r'''
options: {}
attributes:
  platform:
    platforms: Windows
    support: full
    description: Target OS/families that can be operated against.
'''
