#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: organizations_inventory_onboarding_cloud_monitoring_prepare
short_description: Resource module for organizations _inventory _onboarding _cloud _monitoring _prepare
description:
  - Manage operation create of the resource organizations _inventory _onboarding _cloud _monitoring _prepare. - > Initiates or updates an import
    session. An import ID will be generated and used when you are ready to commit the import.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  devices:
    description: A set of devices to import (or update).
    elements: dict
    suboptions:
      sudi:
        description: Device SUDI certificate.
        type: str
      tunnel:
        description: TLS Related Parameters.
        suboptions:
          certificateName:
            description: Name of the configured TLS certificate.
            type: str
          localInterface:
            description: Number of the vlan expected to be used to connect to the cloud.
            type: int
          loopbackNumber:
            description: Number of the configured Loopback Interface used for TLS overlay.
            type: int
          name:
            description: Name of the configured TLS tunnel.
            type: str
        type: dict
      user:
        description: User parameters.
        suboptions:
          username:
            description: The name of the device user for Meraki monitoring.
            type: str
        type: dict
      vty:
        description: VTY Related Parameters.
        suboptions:
          accessList:
            description: AccessList details.
            suboptions:
              vtyIn:
                description: VTY in ACL.
                suboptions:
                  name:
                    description: Name.
                    type: str
                type: dict
              vtyOut:
                description: VTY out ACL.
                suboptions:
                  name:
                    description: Name.
                    type: str
                type: dict
            type: dict
          authentication:
            description: VTY AAA authentication.
            suboptions:
              group:
                description: Group Details.
                suboptions:
                  name:
                    description: Group Name.
                    type: str
                type: dict
            type: dict
          authorization:
            description: VTY AAA authorization.
            suboptions:
              group:
                description: Group Details.
                suboptions:
                  name:
                    description: Group Name.
                    type: str
                type: dict
            type: dict
          endLineNumber:
            description: Ending line VTY number.
            type: int
          rotaryNumber:
            description: SSH rotary number.
            type: int
          startLineNumber:
            description: Starting line VTY number.
            type: int
        type: dict
    type: list
  options:
    description: Additional options for the import.
    suboptions:
      skipCommit:
        description: Flag to skip adding the device to RDM.
        type: bool
    type: dict
  organizationId:
    description: OrganizationId path parameter. Organization ID.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for organizations createOrganizationInventoryOnboardingCloudMonitoringPrepare
    description: Complete reference of the createOrganizationInventoryOnboardingCloudMonitoringPrepare API.
    link: https://developer.cisco.com/meraki/api-v1/#!create-organization-inventory-onboarding-cloud-monitoring-prepare
notes:
  - SDK Method used are
    organizations.Organizations.create_organization_inventory_onboarding_cloud_monitoring_prepare,
  - Paths used are
    post /organizations/{organizationId}/inventory/onboarding/cloudMonitoring/prepare,
"""

EXAMPLES = r"""
- name: Create
  cisco.meraki.organizations_inventory_onboarding_cloud_monitoring_prepare:
    meraki_api_key: "{{ meraki_api_key }}"
    meraki_base_url: "{{ meraki_base_url }}"
    meraki_single_request_timeout: "{{ meraki_single_request_timeout }}"
    meraki_certificate_path: "{{ meraki_certificate_path }}"
    meraki_requests_proxy: "{{ meraki_requests_proxy }}"
    meraki_wait_on_rate_limit: "{{ meraki_wait_on_rate_limit }}"
    meraki_nginx_429_retry_wait_time: "{{ meraki_nginx_429_retry_wait_time }}"
    meraki_action_batch_retry_wait_time: "{{ meraki_action_batch_retry_wait_time }}"
    meraki_retry_4xx_error: "{{ meraki_retry_4xx_error }}"
    meraki_retry_4xx_error_wait_time: "{{ meraki_retry_4xx_error_wait_time }}"
    meraki_maximum_retries: "{{ meraki_maximum_retries }}"
    meraki_output_log: "{{ meraki_output_log }}"
    meraki_log_file_prefix: "{{ meraki_log_file_prefix }}"
    meraki_log_path: "{{ meraki_log_path }}"
    meraki_print_console: "{{ meraki_print_console }}"
    meraki_suppress_logging: "{{ meraki_suppress_logging }}"
    meraki_simulate: "{{ meraki_simulate }}"
    meraki_be_geo_id: "{{ meraki_be_geo_id }}"
    meraki_caller: "{{ meraki_caller }}"
    meraki_use_iterator_for_get_pages: "{{ meraki_use_iterator_for_get_pages }}"
    meraki_inherit_logging_config: "{{ meraki_inherit_logging_config }}"
    devices:
      - sudi: '-----BEGIN CERTIFICATE----- MIIEKjCCAxKgAwIBAgIRANb+lsED3eb4+6YKLFFYqEkwDQYJKoZIhvcNAQELBQAw
          gYcxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMREwDwYDVQQHDAhT YW4gSm9zZTEcMBoGA1UECgwTQ2lzY28gU3lzdGVtcywgSW5jLjESMBAGA1UECwwJ
          RE5BU3BhY2VzMR4wHAYDVQQDDBVjaXNjby5vcGVucm9hbWluZy5vcmcwHhcNMjAx MTA1MjEzMzM1WhcNMjExMTA1MjIzMzM1WjCBpDEcMBoGCgmSJomT8ixkAQETDGRu
          YXNwYWNlczpVUzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAkNBMQ4wDAYDVQQKEwVD aXNjbzEcMBoGA1UECxMTV0JBOldSSVggRW5kLUVudGl0eTE8MDoGA1UEAxMzNjQ3
          MDcwNDM4NDQ5NjQxMjAwMDAuMTg4MzQuaHMuY2lzY28ub3BlbnJvYW1pbmcub3Jn MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoqjP9QgRGyUO3p7SH9QK
          uTq6UYK7nAyjImgS4yQxeBkyZ5f2EUkX8m/AOcewpPxxPBhjPKRwxGeX3S50ksiA ayFomUeslR0S0Z7RN9rzJa+CFyi9MwWIHMbLgXpB8tsSpgTAqwrzoTzOGq9fgC6u
          pZhdZrBkg3FeJgD88goCi9mZDsY2YAoeGRLFJ2fR8iICqIVQy+Htq9pE22WBLpnS KjL3+mR9FArHNFtWlhKF2YHMUqyHHrnZnF/Ns7QNoMMF7/CK18iAKgnb+2wuGKM2
          aEMddOeOTtz+i/rgjkp/RGMt011EdCsso0/cTo9qqX/bxOOCE4/Mne/ChMkQPnNU CwIDAQABo3IwcDAJBgNVHRMEAjAAMB8GA1UdIwQYMBaAFIG+4l5yiB01gP0sw4ML
          USopqYcuMB0GA1UdDgQWBBSby1T9leYVOVVdOZXiHCSaDDEMiDAOBgNVHQ8BAf8E BAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwDQYJKoZIhvcNAQELBQADggEBAEyE
          1mjSUyY6uNp6W4l20w7SskALSJDRKkOeZxAgF3VMxlsCuEl70s9oEfntwIpyQtSa jON/9yJHbwm/Az824bmk8Dc7AXIPhay+dftXb8j529gPuYB9AKoPNg0NctkyYCQh
          a/3YQVdDWX7XgmEiXkL57M7G6+IdcPDONLArfjOcT9qHdkVVq1AIjlMSx3OQQmm/ uoLb/G9q/97QA2/l8shG/Na8HjVqGLcl5TNZdbNhs2w9ogxr/GNzqdvym6RQ8vT/
          UR2n+uwH4n1MUxmHYYeyot5dnIV1IJ6hQ54JAncM9HvCLFk1WHz6RKshQUCuPBiJ wTw70BVktzJnb0VLeDg=
          -----END CERTIFICATE-----'
        tunnel:
          certificateName: DeviceSUDI
          localInterface: 1
          loopbackNumber: 1000
          name: MERAKI
        user:
          username: Meraki
        vty:
          accessList:
            vtyIn:
              name: MERAKI_IN
            vtyOut:
              name: MERAKI_OUT
          authentication:
            group:
              name: ''
          authorization:
            group:
              name: MERAKI
          endLineNumber: 17
          rotaryNumber: 50
          startLineNumber: 16
    options:
      skipCommit: false
    organizationId: string
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: list
  sample: >
    [
      {
        "configParams": {
          "cloudStaticIp": "string",
          "tunnel": {
            "host": "string",
            "mode": "string",
            "name": "string",
            "port": "string",
            "rootCertificate": {
              "content": "string",
              "name": "string"
            }
          },
          "user": {
            "publicKey": "string",
            "secret": {
              "hash": "string"
            },
            "username": "string"
          }
        },
        "deviceId": "string",
        "message": "string",
        "status": "string",
        "udi": "string"
      }
    ]
"""
