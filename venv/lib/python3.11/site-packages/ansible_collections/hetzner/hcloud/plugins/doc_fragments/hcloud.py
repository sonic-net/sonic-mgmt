# Copyright: (c) 2019, Hetzner Cloud GmbH <info@hetzner-cloud.de>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import annotations


class ModuleDocFragment:
    DOCUMENTATION = """
options:
  api_token:
    description:
      - The API Token for the Hetzner Cloud.
      - You can also set this option by using the C(HCLOUD_TOKEN) environment variable.
    required: True
    type: str
  api_endpoint:
    description:
      - The API Endpoint for the Hetzner Cloud.
      - You can also set this option by using the C(HCLOUD_ENDPOINT) environment variable.
    default: https://api.hetzner.cloud/v1
    type: str
    aliases: [endpoint]

requirements:
  - python-dateutil >= 2.7.5
  - requests >=2.20

seealso:
  - name: Documentation for Hetzner Cloud API
    description: Complete reference for the Hetzner Cloud API.
    link: https://docs.hetzner.cloud
"""
