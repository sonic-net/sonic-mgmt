# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  annotation:
    description:
    - User-defined string for annotating an object.
    - If the value is not specified in the task, the value of environment variable C(ACI_ANNOTATION) will be used instead.
    - If the value is not specified in the task and environment variable C(ACI_ANNOTATION) then the default value will be used.
    type: str
    default: orchestrator:ansible
"""
