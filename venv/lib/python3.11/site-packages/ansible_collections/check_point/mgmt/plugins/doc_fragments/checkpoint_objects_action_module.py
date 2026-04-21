# -*- coding: utf-8 -*-

# Copyright: (c) 2019, Or Soffer <orso@checkpoint.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  auto_publish_session:
    description:
      - Publish the current session if changes have been performed
        after task completes.
    type: bool
    default: False
  wait_for_task_timeout:
    description:
      - How many minutes to wait until throwing a timeout error.
    type: int
    default: 30
  version:
    description:
      - Version of checkpoint. If not given one, the latest version taken.
    type: str
"""
