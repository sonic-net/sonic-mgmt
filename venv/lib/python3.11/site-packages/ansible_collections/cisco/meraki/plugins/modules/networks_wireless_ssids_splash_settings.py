#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
module: networks_wireless_ssids_splash_settings
short_description: Resource module for networks _wireless _ssids _splash _settings
description:
  - Manage operation update of the resource networks _wireless _ssids _splash _settings.
  - Modify the splash page settings for the given SSID.
version_added: '1.0.0'
extends_documentation_fragment:
  - cisco.meraki.module
author: Francisco Munoz (@fmunoz)
options:
  allowSimultaneousLogins:
    description: Whether or not to allow simultaneous logins from different devices.
    type: bool
  billing:
    description: Details associated with billing splash.
    suboptions:
      freeAccess:
        description: Details associated with a free access plan with limits.
        suboptions:
          durationInMinutes:
            description: How long a device can use a network for free.
            type: int
          enabled:
            description: Whether or not free access is enabled.
            type: bool
        type: dict
      prepaidAccessFastLoginEnabled:
        description: Whether or not billing uses the fast login prepaid access option.
        type: bool
      replyToEmailAddress:
        description: The email address that receives replies from clients.
        type: str
    type: dict
  blockAllTrafficBeforeSignOn:
    description: How restricted allowing traffic should be. If true, all traffic types are blocked until the splash page is acknowledged. If false,
      all non-HTTP traffic is allowed before the splash page is acknowledged.
    type: bool
  controllerDisconnectionBehavior:
    description: How login attempts should be handled when the controller is unreachable. Can be either 'open', 'restricted', or 'default'.
    type: str
  guestSponsorship:
    description: Details associated with guest sponsored splash.
    suboptions:
      durationInMinutes:
        description: Duration in minutes of sponsored guest authorization. Must be between 1 and 60480 (6 weeks).
        type: int
      guestCanRequestTimeframe:
        description: Whether or not guests can specify how much time they are requesting.
        type: bool
    type: dict
  networkId:
    description: NetworkId path parameter. Network ID.
    type: str
  number:
    description: Number path parameter.
    type: str
  redirectUrl:
    description: The custom redirect URL where the users will go after the splash page.
    type: str
  selfRegistration:
    description: Self-registration settings for splash with Meraki authentication.
    suboptions:
      authorizationType:
        description: How created user accounts should be authorized. Must be included in admin, auto, self_email.
        type: str
      enabled:
        description: Whether or not to allow users to create their own account on the network.
        type: bool
    type: dict
  sentryEnrollment:
    description: Systems Manager sentry enrollment splash settings.
    suboptions:
      enforcedSystems:
        description: The system types that the Sentry enforces. Must be included in 'iOS, 'Android', 'macOS', and 'Windows'.
        elements: str
        type: list
      strength:
        description: The strength of the enforcement of selected system types. Must be one of 'focused', 'click-through', and 'strict'.
        type: str
      systemsManagerNetwork:
        description: Systems Manager network targeted for sentry enrollment.
        suboptions:
          id:
            description: The network ID of the Systems Manager network.
            type: str
        type: dict
    type: dict
  splashImage:
    description: The image used in the splash page.
    suboptions:
      extension:
        description: The extension of the image file.
        type: str
      image:
        description: Properties for setting a new image.
        suboptions:
          contents:
            description: The file contents (a base 64 encoded string) of your new image.
            type: str
          format:
            description: The format of the encoded contents. Supported formats are 'png', 'gif', and jpg'.
            type: str
        type: dict
      md5:
        description: The MD5 value of the image file. Setting this to null will remove the image from the splash page.
        type: str
    type: dict
  splashLogo:
    description: The logo used in the splash page.
    suboptions:
      extension:
        description: The extension of the logo file.
        type: str
      image:
        description: Properties for setting a new image.
        suboptions:
          contents:
            description: The file contents (a base 64 encoded string) of your new logo.
            type: str
          format:
            description: The format of the encoded contents. Supported formats are 'png', 'gif', and jpg'.
            type: str
        type: dict
      md5:
        description: The MD5 value of the logo file. Setting this to null will remove the logo from the splash page.
        type: str
    type: dict
  splashPrepaidFront:
    description: The prepaid front image used in the splash page.
    suboptions:
      extension:
        description: The extension of the prepaid front image file.
        type: str
      image:
        description: Properties for setting a new image.
        suboptions:
          contents:
            description: The file contents (a base 64 encoded string) of your new prepaid front.
            type: str
          format:
            description: The format of the encoded contents. Supported formats are 'png', 'gif', and jpg'.
            type: str
        type: dict
      md5:
        description: The MD5 value of the prepaid front image file. Setting this to null will remove the prepaid front from the splash page.
        type: str
    type: dict
  splashTimeout:
    description: Splash timeout in minutes. This will determine how often users will see the splash page.
    type: int
  splashUrl:
    description: Optional The custom splash URL of the click-through splash page. Note that the URL can be configured without necessarily being
      used. In order to enable the custom URL, see 'useSplashUrl'.
    type: str
  themeId:
    description: The id of the selected splash theme.
    type: str
  useRedirectUrl:
    description: The Boolean indicating whether the the user will be redirected to the custom redirect URL after the splash page. A custom redirect
      URL must be set if this is true.
    type: bool
  useSplashUrl:
    description: Optional Boolean indicating whether the users will be redirected to the custom splash url. A custom splash URL must be set if
      this is true. Note that depending on your SSID's access control settings, it may not be possible to use the custom splash URL.
    type: bool
  welcomeMessage:
    description: The welcome message for the users on the splash page.
    type: str
requirements:
  - meraki >= 2.4.9
  - python >= 3.5
seealso:
  - name: Cisco Meraki documentation for wireless updateNetworkWirelessSsidSplashSettings
    description: Complete reference of the updateNetworkWirelessSsidSplashSettings API.
    link: https://developer.cisco.com/meraki/api-v1/#!update-network-wireless-ssid-splash-settings
notes:
  - SDK Method used are
    wireless.Wireless.update_network_wireless_ssid_splash_settings,
  - Paths used are
    put /networks/{networkId}/wireless/ssids/{number}/splash/settings,
"""

EXAMPLES = r"""
- name: Update all
  cisco.meraki.networks_wireless_ssids_splash_settings:
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
    state: present
    allowSimultaneousLogins: false
    billing:
      freeAccess:
        durationInMinutes: 120
        enabled: true
      prepaidAccessFastLoginEnabled: true
      replyToEmailAddress: user@email.com
    blockAllTrafficBeforeSignOn: false
    controllerDisconnectionBehavior: default
    guestSponsorship:
      durationInMinutes: 30
      guestCanRequestTimeframe: false
    networkId: string
    number: string
    redirectUrl: https://example.com
    selfRegistration:
      authorizationType: admin
      enabled: true
    sentryEnrollment:
      enforcedSystems:
        - iOS
      strength: focused
      systemsManagerNetwork:
        id: N_1234
    splashImage:
      extension: jpg
      image:
        contents: Q2lzY28gTWVyYWtp
        format: jpg
      md5: 542cccac8d7dedee0f185311d154d194
    splashLogo:
      extension: jpg
      image:
        contents: Q2lzY28gTWVyYWtp
        format: jpg
      md5: abcd1234
    splashPrepaidFront:
      extension: jpg
      image:
        contents: Q2lzY28gTWVyYWtp
        format: jpg
      md5: 542cccac8d7dedee0f185311d154d194
    splashTimeout: 1440
    splashUrl: https://www.custom_splash_url.com
    themeId: c3ddcb4f16785ee747ab5ffc10867d6c8ea704be
    useRedirectUrl: true
    useSplashUrl: true
    welcomeMessage: Welcome!
"""
RETURN = r"""
meraki_response:
  description: A dictionary or list with the response returned by the Cisco Meraki Python SDK
  returned: always
  type: dict
  sample: >
    {
      "allowSimultaneousLogins": true,
      "billing": {
        "freeAccess": {
          "durationInMinutes": 0,
          "enabled": true
        },
        "prepaidAccessFastLoginEnabled": true,
        "replyToEmailAddress": "string"
      },
      "blockAllTrafficBeforeSignOn": true,
      "controllerDisconnectionBehavior": "string",
      "guestSponsorship": {
        "durationInMinutes": 0,
        "guestCanRequestTimeframe": true
      },
      "redirectUrl": "string",
      "selfRegistration": {
        "authorizationType": "string",
        "enabled": true
      },
      "sentryEnrollment": {
        "enforcedSystems": [
          "string"
        ],
        "strength": "string",
        "systemsManagerNetwork": {
          "id": "string"
        }
      },
      "splashImage": {
        "extension": "string",
        "md5": "string"
      },
      "splashLogo": {
        "extension": "string",
        "md5": "string"
      },
      "splashPage": "string",
      "splashPrepaidFront": {
        "extension": "string",
        "md5": "string"
      },
      "splashTimeout": 0,
      "splashUrl": "string",
      "ssidNumber": 0,
      "themeId": "string",
      "useRedirectUrl": true,
      "useSplashUrl": true,
      "welcomeMessage": "string"
    }
"""
