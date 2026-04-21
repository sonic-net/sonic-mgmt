# Copyright: (c) 2019, NetApp Ansible Team <ng-ansibleteam@netapp.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r"""
options:
  - See respective platform section for more details
requirements:
  - See respective platform section for more details
notes:
  - This is documentation for NetApp's StorageGRID modules.
"""

    # Documentation fragment for StorageGRID
    SG = """
options:
  auth_token:
    required: true
    type: str
    description:
    - The authorization token for the API request
  api_url:
    required: true
    type: str
    description:
    - The url to the StorageGRID Admin Node REST API.
  validate_certs:
    required: false
    default: true
    description:
    - Should https certificates be validated?
    type: bool
notes:
  - The modules prefixed with C(na_sg) are built to manage NetApp StorageGRID.
"""
