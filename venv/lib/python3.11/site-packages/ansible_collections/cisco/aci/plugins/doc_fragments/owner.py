# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  owner_key:
    description:
    - User-defined string for the ownerKey attribute of an ACI object.
    - This attribute represents a key for enabling clients to own their data for entity correlation.
    - If the value is not specified in the task, the value of environment variable C(ACI_OWNER_KEY) will be used instead.
    type: str
  owner_tag:
    description:
    - User-defined string for the ownerTag attribute of an ACI object.
    - This attribute represents a tag for enabling clients to add their own data.
    - For example, to indicate who created this object.
    - If the value is not specified in the task, the value of environment variable C(ACI_OWNER_TAG) will be used instead.
    type: str
"""
