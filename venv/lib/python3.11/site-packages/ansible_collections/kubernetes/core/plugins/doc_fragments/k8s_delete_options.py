# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Red Hat | Ansible
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# Options for specifying object wait

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r"""
options:
  delete_options:
    type: dict
    version_added: 1.2.0
    description:
    - Configure behavior when deleting an object.
    - Only used when I(state=absent).
    suboptions:
      propagationPolicy:
        type: str
        description:
        - Use to control how dependent objects are deleted.
        - If not specified, the default policy for the object type will be used. This may vary across object types.
        choices:
        - "Foreground"
        - "Background"
        - "Orphan"
      gracePeriodSeconds:
        type: int
        description:
        - Specify how many seconds to wait before forcefully terminating.
        - Only implemented for Pod resources.
        - If not specified, the default grace period for the object type will be used.
      preconditions:
        type: dict
        description:
        - Specify condition that must be met for delete to proceed.
        suboptions:
          resourceVersion:
            type: str
            description:
            - Specify the resource version of the target object.
          uid:
            type: str
            description:
            - Specify the UID of the target object.
"""
