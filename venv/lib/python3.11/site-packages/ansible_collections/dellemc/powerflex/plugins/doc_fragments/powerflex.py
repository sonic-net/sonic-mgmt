# Copyright: (c) 2024-2025, Dell Technologies.
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


class ModuleDocFragment(object):
    # Documentation fragment for PowerFlex
    DOCUMENTATION = r'''
    options:
        hostname:
            required: true
            description:
            - IP or FQDN of the PowerFlex host.
            type: str
            aliases:
            - gateway_host
        username:
            type: str
            required: true
            description:
            - The username of the PowerFlex host.
        password:
            type: str
            required: true
            description:
            - The password of the PowerFlex host.
        validate_certs:
            type: bool
            default: true
            aliases:
            - verifycert
            description:
            - Boolean variable to specify whether or not to validate SSL
              certificate.
            - C(true) - Indicates that the SSL certificate should be verified.
            - C(false) - Indicates that the SSL certificate should not be
              verified.
        port:
            description:
            - Port number through which communication happens with PowerFlex
              host.
            type: int
            default: 443
        timeout:
            description:
            - Time after which connection will get terminated.
            - It is to be mentioned in seconds.
            type: int
            required: false
            default: 120
    requirements:
      - A Dell PowerFlex storage system version 3.6 or later.
      - PyPowerFlex 1.14.1.
    notes:
      - The modules present in the collection named as 'dellemc.powerflex'
        are built to support the Dell PowerFlex storage platform.
'''
