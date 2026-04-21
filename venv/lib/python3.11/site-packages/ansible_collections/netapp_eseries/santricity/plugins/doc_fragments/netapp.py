# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Sumit Kumar <sumit4@netapp.com>, chris Archibald <carchi@netapp.com>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r'''
options:
  - See respective platform section for more details
requirements:
  - See respective platform section for more details
notes:
  - Ansible modules are available for the following NetApp Storage Platforms: E-Series, ONTAP, SolidFire
'''

    # Documentation fragment for E-Series
    ESERIES = r'''
options:
  api_username:
    required: true
    type: str
    description:
    - The username to authenticate with the SANtricity Web Services Proxy or Embedded Web Services API.
  api_password:
    required: true
    type: str
    description:
    - The password to authenticate with the SANtricity Web Services Proxy or Embedded Web Services API.
  api_url:
    required: true
    type: str
    description:
    - The url to the SANtricity Web Services Proxy or Embedded Web Services API.
      Example https://prod-1.wahoo.acme.com/devmgr/v2
  validate_certs:
    required: false
    default: true
    description:
        - Should https certificates be validated?
    type: bool
  ssid:
    required: false
    type: str
    default: "1"
    description:
    - The ID of the array to manage. This value must be unique for each array.

notes:
  - The E-Series Ansible modules require either an instance of the Web Services Proxy (WSP), to be available to manage
    the storage-system, or an E-Series storage-system that supports the Embedded Web Services API.
  - Embedded Web Services is currently available on the E2800, E5700, EF570, and newer hardware models.
  - M(netapp_eseries.santricity.netapp_e_storage_system) may be utilized for configuring the systems managed by
    a WSP instance.
'''
