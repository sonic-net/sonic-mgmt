# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    # Standard files documentation fragment
    DOCUMENTATION = r"""
options:
  ptp:
    description:
    - The Precision Time Protocol (PTP) configuration for the interface.
    - Providing an empty dictionary O(ptp={}) will remove the PTP configuration from the interface.
    type: dict
    suboptions:
      mode:
        description:
        - The PTP mode.
        - If this parameter is unspecified, NDO defaults to O(ptp.mode=multicast_dynamic).
        type: str
        choices: [ multicast_dynamic, multicast_master, unicast_master ]
      source_address:
        description:
        - The PTP source address.
        - If this parameter is unspecified, NDO defaults to O(ptp.source_address=0.0.0.0).
        type: str
      user_profile:
        description:
        - The PTP user profile.
        type: dict
        suboptions:
          uuid:
            description:
            - The UUID of the PTP user profile.
            type: str
          reference:
            description:
            - The reference details of the PTP user profile.
            type: dict
            aliases: [ ref ]
            suboptions:
              name:
                description:
                - The name of the PTP user profile.
                type: str
                required: true
              template:
                description:
                - The name of the template that contains the PTP user profile.
                - This parameter or O(ptp.user_profile.reference.template_id) is required.
                type: str
              template_id:
                description:
                - The ID of the template that contains the PTP user profile.
                - This parameter or O(ptp.user_profile.reference.template) is required.
                type: str
      unicast_destinations:
        description:
        - The PTP unicast destination IP addresses.
        - The old O(ptp.unicast_destinations) will be replaced with the new O(ptp.unicast_destinations) during an update.
        - The PTP unicast destinations IP addresses can only be configured if O(ptp.mode=unicast_master).
        type: list
        elements: str
"""
