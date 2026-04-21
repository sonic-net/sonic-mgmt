# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Rémi REY (@rrey)
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type


class ModuleDocFragment(object):
    DOCUMENTATION = r"""options:
  url:
    description:
      - The Grafana URL.
    required: true
    type: str
    aliases: [ grafana_url ]
  url_username:
    description:
      - The Grafana user for API authentication.
    default: admin
    type: str
    aliases: [ grafana_user ]
  url_password:
    description:
      - The Grafana password for API authentication.
    default: admin
    type: str
    aliases: [ grafana_password ]
  use_proxy:
    description:
      - If C(false), it will not use a proxy, even if one is defined in an environment variable on the target hosts.
    type: bool
    default: true
  client_cert:
    description:
      - PEM formatted certificate chain file to be used for SSL client authentication.
      - This file can also include the key as well, and if the key is included, I(client_key) is not required
    type: path
  client_key:
    description:
      - PEM formatted file that contains your private key to be used for SSL client authentication.
      - If I(client_cert) contains both the certificate and key, this option is not required.
    type: path
  validate_certs:
    description:
      - If C(false), SSL certificates will not be validated.
      - This should only set to C(false) used on personally controlled sites using self-signed certificates.
    type: bool
    default: true
    """
