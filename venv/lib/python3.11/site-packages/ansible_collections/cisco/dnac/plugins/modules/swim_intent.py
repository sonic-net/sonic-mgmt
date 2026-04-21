#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = "Madhan Sankaranarayanan, Rishita Chowdhary, Abhishek Maheshwari"
DOCUMENTATION = r"""
---
module: swim_intent
short_description: Intent module for SWIM related functions
description:
  - Manage operation related to image importation, distribution,
    activation and tagging image as golden
  - API to fetch a software image from remote file system
    using URL for HTTP/FTP and upload it to Catalyst
    Center. Supported image files extensions are bin,
    img, tar, smu, pie, aes, iso, ova, tar_gz and qcow2.
  - API to fetch a software image from local file system
    and upload it to Catalyst Center Supported image
    files extensions are bin, img, tar, smu, pie, aes,
    iso, ova, tar_gz and qcow2.
  - API to tag/untag image as golen for a given family
    of devices
  - API to distribute a software image on a given device.
    Software image must be imported successfully into
    Catalyst Center before it can be distributed.
  - API to activate a software image on a given device.
    Software image must be present in the device flash.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Madhan Sankaranarayanan (@madhansansel) Rishita
  Chowdhary (@rishitachowdhary) Abhishek Maheshwari
  (@abmahesh)
options:
  config_verify:
    description: Set to True to verify the Cisco Catalyst
      Center config after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of Catalyst Center after
      module completion.
    type: str
    choices: [merged]
    default: merged
  config:
    description: List of details of SWIM image being
      managed
    type: list
    elements: dict
    required: true
    suboptions:
      import_image_details:
        description: Details of image being imported
        type: dict
        suboptions:
          type:
            description: Specifies the import source,
              supporting local file import (local) or
              remote url import (remote).
            type: str
          local_image_details:
            description: Details of the local path of
              the image to be imported.
            type: dict
            suboptions:
              file_path:
                description: Provide the absolute file
                  path needed to import an image from
                  your local system (Eg "/path/to/your/file").
                  Accepted files formats are - .gz,.bin,.img,.tar,.smu,.pie,.aes,.iso,.ova,.tar_gz,.qcow2,.nfvispkg,.zip,.spa,.rpm.
                type: str
              is_third_party:
                description: Query parameter to determine
                  if the image is from a third party
                  (optional).
                type: bool
              third_party_application_type:
                description: Specify the ThirdPartyApplicationType
                  query parameter to indicate the type
                  of third-party application. Allowed
                  values include WLC, LINUX, FIREWALL,
                  WINDOWS, LOADBALANCER, THIRDPARTY,
                  etc.(optional). WLC (Wireless LAN
                  Controller) - It's a network device
                  that manages and controls multiple
                  wireless access points (APs) in a
                  centralized manner. LINUX - It's an
                  open-source operating system that
                  provides a complete set of software
                  packages and utilities. FIREWALL -
                  It's a network security device that
                  monitors and controls incoming and
                  outgoing network traffic based on
                  predetermined security rules.It acts
                  as a barrier between a trusted internal
                  network and untrusted external networks
                  (such as the internet), preventing
                  unauthorized access. WINDOWS - It's
                  an operating system known for its
                  graphical user interface (GUI) support,
                  extensive compatibility with hardware
                  and software, and widespread use across
                  various applications. LOADBALANCER
                  - It's a network device or software
                  application that distributes incoming
                  network traffic across multiple servers
                  or resources. THIRDPARTY - It refers
                  to third-party images or applications
                  that are not part of the core system.
                  NAM (Network Access Manager) - It's
                  a network management tool or software
                  application that provides centralized
                  control and monitoring of network
                  access policies, user authentication,
                  and device compliance. WAN Optimization
                  - It refers to techniques and technologies
                  used to improve the performance and
                  efficiency of WANs. It includes various
                  optimization techniques such as data
                  compression, caching, protocol optimization,
                  and traffic prioritization to reduce
                  latency, increase throughput, and
                  improve user experience over WAN connections.
                  Unknown - It refers to an unspecified
                  or unrecognized application type.
                  Router - It's a network device that
                  forwards data packets between computer
                  networks. They are essential for connecting
                  multiple networks together and directing
                  traffic between them.
                type: str
              third_party_image_family:
                description: Provide the ThirdPartyImageFamily
                  query parameter to identify the family
                  of the third-party image. Image Family
                  name like PALOALTO, RIVERBED, FORTINET,
                  CHECKPOINT, SILVERPEAK etc. (optional).
                type: str
              third_party_vendor:
                description: Include the ThirdPartyVendor
                  query parameter to specify the vendor
                  of the third party.
                type: str
          url_details:
            description: URL details for SWIM import
            type: dict
            suboptions:
              payload:
                description: Swim Import Via Url's payload.
                type: list
                elements: dict
                suboptions:
                  application_type:
                    description: An optional parameter
                      that specifies the type of application.
                      Allowed values include WLC, LINUX,
                      FIREWALL, WINDOWS, LOADBALANCER,
                      THIRDPARTY, etc. This is only
                      applicable for third-party image
                      types(optional). WLC (Wireless
                      LAN Controller) - It's network
                      device that manages and controls
                      multiple wireless access points
                      (APs) in a centralized manner.
                      LINUX - It's an open source which
                      provide complete operating system
                      with a wide range of software
                      packages and utilities. FIREWALL
                      - It's a network security device
                      that monitors and controls incoming
                      and outgoing network traffic based
                      on predetermined security rules.It
                      acts as a barrier between a trusted
                      internal network and untrusted
                      external networks (such as the
                      internet), preventing unauthorized
                      access. WINDOWS - It's an OS which
                      provides GUI support for various
                      applications, and extensive compatibility
                      with hardware and software. LOADBALANCER
                      - It's a network device or software
                      application that distributes incoming
                      network traffic across multiple
                      servers or resources. THIRDPARTY
                      - It refers to third-party images
                      or applications that are not part
                      of the core system. NAM (Network
                      Access Manager) - It's a network
                      management tool or software application
                      that provides centralized control
                      and monitoring of network access
                      policies, user authentication,
                      and device compliance. WAN Optimization
                      - It refers to techniques and
                      technologies used to improve the
                      performance and efficiency of
                      WANs. It includes various optimization
                      techniques such as data compression,
                      caching, protocol optimization,
                      and traffic prioritization to
                      reduce latency, increase throughput,
                      and improve user experience over
                      WAN connections. Unknown - It
                      refers to an unspecified or unrecognized
                      application type. Router - It's
                      a network device that forwards
                      data packets between computer
                      networks. They are essential for
                      connecting multiple networks together
                      and directing traffic between
                      them.
                    type: str
                  image_family:
                    description: Represents the name
                      of the image family and is applicable
                      only when uploading third-party
                      images. Image Family name like
                      PALOALTO, RIVERBED, FORTINET,
                      CHECKPOINT, SILVERPEAK etc. (optional).
                    type: str
                  source_url:
                    description: A mandatory parameter
                      for importing a SWIM image via
                      a remote URL. This parameter is
                      required when using a URL to import
                      an image.(For example, http://{host}/swim/cat9k_isoxe.16.12.10s.SPA.bin,
                      ftp://user:password@{host}/swim/cat9k_isoxe.16.12.10s.SPA.iso)
                    type: str
                  is_third_party:
                    description: Flag indicates whether
                      the image is uploaded from a third
                      party (optional).
                    type: bool
                  vendor:
                    description: The name of the vendor,
                      that applies only to third-party
                      image types when importing via
                      URL (optional).
                    type: str
              schedule_at:
                description: ScheduleAt query parameter.
                  Epoch Time (The number of milli-seconds
                  since January 1 1970 UTC) at which
                  the distribution should be scheduled
                  (optional).
                type: str
              schedule_desc:
                description: ScheduleDesc query parameter.
                  Custom Description (optional).
                type: str
              schedule_origin:
                description: ScheduleOrigin query parameter.
                  Originator of this call (optional).
                type: str
      tagging_details:
        description: Details for tagging or untagging
          an image as golden
        type: dict
        suboptions:
          image_name:
            description: SWIM image name which will
              be tagged or untagged as golden.
            type: str
          device_role:
            description: Defines the device role, with
              permissible values including ALL, UNKNOWN,
              ACCESS, BORDER ROUTER, DISTRIBUTION, and
              CORE. ALL - This role typically represents
              all devices within the network, regardless
              of their specific roles or functions.
              UNKNOWN - This role is assigned to devices
              whose roles or functions have not been
              identified or classified within Cisco
              Catalsyt Center. This could happen if
              the platform is unable to determine the
              device's role based on available information.
              ACCESS - This role typically represents
              switches or access points that serve as
              access points for end-user devices to
              connect to the network. These devices
              are often located at the edge of the network
              and provide connectivity to end-user devices.
              BORDER ROUTER - These are devices that
              connect different network domains or segments
              together. They often serve as gateways
              between different networks, such as connecting
              an enterprise network to the internet
              or connecting multiple branch offices.
              DISTRIBUTION - This role represents function
              as distribution switches or routers in
              hierarchical network designs. They aggregate
              traffic from access switches and route
              it toward the core of the network or toward
              other distribution switches. CORE - This
              role typically represents high-capacity
              switches or routers that form the backbone
              of the network. They handle large volumes
              of traffic and provide connectivity between
              different parts of network, such as connecting
              distribution switches or providing interconnection
              between different network segments.
            type: str
          device_image_family_name:
            description: Device Image family name(Eg
              Cisco Catalyst 9300 Switch)
            type: str
          site_name:
            description: Site name for which SWIM image
              will be tagged/untagged as golden. If
              not provided, SWIM image will be mapped
              to global site.
            type: str
          device_series_name:
            description: This parameter specifies the
              name of the device series. It is used
              to identify a specific series of devices,
              such as Cisco Catalyst 9300 Series Switches,
              within the Cisco Catalyst Center.
            type: str
            version_added: 6.12.0
          tagging:
            description: Booelan value to tag/untag
              SWIM image as golden If True then the
              given image will be tagged as golden.
              If False then the given image will be
              un-tagged as golden.
            type: bool
      image_distribution_details:
        description: Details for SWIM image distribution.
          Device on which the image needs to distributed
          can be speciifed using any of the following
          parameters - deviceSerialNumber, deviceIPAddress,
          deviceHostname or deviceMacAddress.
        type: dict
        suboptions:
          device_role:
            description: Defines the device role, with
              permissible values including ALL, UNKNOWN,
              ACCESS, BORDER ROUTER, DISTRIBUTION, and
              CORE. ALL - This role typically represents
              all devices within the network, regardless
              of their specific roles or functions.
              UNKNOWN - This role is assigned to devices
              whose roles or functions have not been
              identified or classified within Cisco
              Catalsyt Center. This could happen if
              the platform is unable to determine the
              device's role based on available information.
              ACCESS - This role typically represents
              switches or access points that serve as
              access points for end-user devices to
              connect to the network. These devices
              are often located at the edge of the network
              and provide connectivity to end-user devices.
              BORDER ROUTER - These are devices that
              connect different network domains or segments
              together. They often serve as gateways
              between different networks, such as connecting
              an enterprise network to the internet
              or connecting multiple branch offices.
              DISTRIBUTION - This role represents function
              as distribution switches or routers in
              hierarchical network designs. They aggregate
              traffic from access switches and route
              it toward the core of the network or toward
              other distribution switches. CORE - This
              role typically represents high-capacity
              switches or routers that form the backbone
              of the network. They handle large volumes
              of traffic and provide connectivity between
              different parts of network, such as connecting
              distribution switches or providing interconnection
              between different network segments.
            type: str
          device_family_name:
            description: Specify the name of the device
              family such as Switches and Hubs, etc.
            type: str
          site_name:
            description: Used to get device details
              associated to this site.
            type: str
          device_series_name:
            description: This parameter specifies the
              name of the device series. It is used
              to identify a specific series of devices,
              such as Cisco Catalyst 9300 Series Switches,
              within the Cisco Catalyst Center.
            type: str
            version_added: 6.12.0
          image_name:
            description: SWIM image's name
            type: str
          device_serial_number:
            description: Device serial number where
              the image needs to be distributed
            type: str
          device_ip_address:
            description: Device IP address where the
              image needs to be distributed
            type: str
          device_hostname:
            description: Device hostname where the image
              needs to be distributed
            type: str
          device_mac_address:
            description: Device MAC address where the
              image needs to be distributed
            type: str
      image_activation_details:
        description: Details for SWIM image activation.
          Device on which the image needs to activated
          can be speciifed using any of the following
          parameters - deviceSerialNumber, deviceIPAddress,
          deviceHostname or deviceMacAddress.
        type: dict
        suboptions:
          device_role:
            description: Defines the device role, with
              permissible values including ALL, UNKNOWN,
              ACCESS, BORDER ROUTER, DISTRIBUTION, and
              CORE. ALL - This role typically represents
              all devices within the network, regardless
              of their specific roles or functions.
              UNKNOWN - This role is assigned to devices
              whose roles or functions have not been
              identified or classified within Cisco
              Catalsyt Center. This could happen if
              the platform is unable to determine the
              device's role based on available information.
              ACCESS - This role typically represents
              switches or access points that serve as
              access points for end-user devices to
              connect to the network. These devices
              are often located at the edge of the network
              and provide connectivity to end-user devices.
              BORDER ROUTER - These are devices that
              connect different network domains or segments
              together. They often serve as gateways
              between different networks, such as connecting
              an enterprise network to the internet
              or connecting multiple branch offices.
              DISTRIBUTION - This role represents function
              as distribution switches or routers in
              hierarchical network designs. They aggregate
              traffic from access switches and route
              it toward the core of the network or toward
              other distribution switches. CORE - This
              role typically represents high-capacity
              switches or routers that form the backbone
              of the network. They handle large volumes
              of traffic and provide connectivity between
              different parts of network, such as connecting
              distribution switches or providing interconnection
              between different network segments.
            type: str
          device_family_name:
            description: Specify the name of the device
              family such as Switches and Hubs, etc.
            type: str
          site_name:
            description: Used to get device details
              associated to this site.
            type: str
          activate_lower_image_version:
            description: ActivateLowerImageVersion flag.
            type: bool
          device_upgrade_mode:
            description: It specifies the mode of upgrade
              to be applied to the devices having the
              following values - 'install', 'bundle',
              and 'currentlyExists'. install - This
              mode instructs Cisco Catalyst Center to
              perform a clean installation of the new
              image on the target devices. When this
              mode is selected, the existing image on
              the device is completely replaced with
              the new image during the upgrade process.
              This ensures that the device runs only
              the new image version after the upgrade
              is completed. bundle - This mode instructs
              Cisco Catalyst Center bundles the new
              image with the existing image on the device
              before initiating the upgrade process.
              This mode allows for a more efficient
              upgrade process by preserving the existing
              image on the device while adding the new
              image as an additional bundle. After the
              upgrade, the device can run either the
              existing image or the new bundled image,
              depending on the configuration. currentlyExists
              - This mode instructs Cisco Catalyst Center
              to checks if the target devices already
              have the desired image version installed.
              If image already present on devices, no
              action is taken and upgrade process is
              skipped for those devices. This mode is
              useful for avoiding unnecessary upgrades
              on devices that already have the correct
              image version installed, thereby saving
              time.
            type: str
          distribute_if_needed:
            description: Enable the distribute_if_needed
              option when activating the SWIM image.
            type: bool
          image_name:
            description: SWIM image's name
            type: str
          device_serial_number:
            description: Device serial number where
              the image needs to be activated
            type: str
          device_ip_address:
            description: Device IP address where the
              image needs to be activated
            type: str
          device_hostname:
            description: Device hostname where the image
              needs to be activated
            type: str
          device_mac_address:
            description: Device MAC address where the
              image needs to be activated
            type: str
          schedule_validate:
            description: ScheduleValidate query parameter.
              ScheduleValidate, validates data before
              schedule (optional).
            type: bool
requirements:
  - dnacentersdk == 2.4.5
  - python >= 3.9
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.import_software_image_via_url,
    software_image_management_swim.SoftwareImageManagementSwim.tag_as_golden_image,
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_distribution,
    software_image_management_swim.SoftwareImageManagementSwim.trigger_software_image_activation,
  - Paths used are
    post /dna/intent/api/v1/image/importation/source/url,
    post /dna/intent/api/v1/image/importation/golden,
    post /dna/intent/api/v1/image/distribution,
    post
    /dna/intent/api/v1/image/activation/device,
    - Added
    the parameter 'dnac_api_task_timeout',
    'dnac_task_poll_interval'
    options in v6.13.2.
"""
EXAMPLES = r"""
---
- name: Import an image from a URL, tag it as golden
    and load it on device
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: remote
          url_details:
            payload:
              - source_url: "http://10.10.10.10/stda/cat9k_iosxe.17.12.01.SPA.bin"
                is_third_party: false
        tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
        image_distribution_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_serial_number: FJC2327U0S2
        image_activation_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          schedule_validate: false
          activate_lower_image_version: false
          distribute_if_needed: true
          device_serial_number: FJC2327U0S2
- name: Import an image from local, tag it as golden.
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - import_image_details:
          type: local
          local_image_details:
            file_path: /Users/Downloads/cat9k_iosxe.17.12.01.SPA.bin
            is_third_party: false
        tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
- name: Tag the given image as golden and load it on
    device
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: true
- name: Un-tagged the given image as golden and load
    it on device
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - tagging_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          device_role: ACCESS
          device_image_family_name: Cisco Catalyst 9300
            Switch
          site_name: Global/USA/San Francisco/BGL_18
          tagging: false
- name: Distribute the given image on devices associated
    to that site with specified role.
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - image_distribution_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          site_name: Global/USA/San Francisco/BGL_18
          device_role: ALL
          device_family_name: Switches and Hubs
          device_series_name: Cisco Catalyst 9300 Series
            Switches
- name: Activate the given image on devices associated
    to that site with specified role.
  cisco.dnac.swim_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log_level: "{{dnac_log_level}}"
    dnac_log: true
    config:
      - image_activation_details:
          image_name: cat9k_iosxe.17.12.01.SPA.bin
          site_name: Global/USA/San Francisco/BGL_18
          device_role: ALL
          device_family_name: Switches and Hubs
          device_series_name: Cisco Catalyst 9300 Series
            Switches
          scehdule_validate: false
          activate_lower_image_version: true
          distribute_if_needed: true
"""
RETURN = r"""
#Case: SWIM image is successfully imported, tagged as golden, distributed and activated on a device
response:
  description: A dictionary with activation details as returned by the Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
                        "additionalStatusURL": String,
                        "data": String,
                        "endTime": 0,
                        "id": String,
                        "instanceTenantId": String,
                        "isError": bool,
                        "lastUpdate": 0,
                        "progress": String,
                        "rootId": String,
                        "serviceType": String,
                        "startTime": 0,
                        "version": 0
                  },
      "msg": String
    }
"""

from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
)
from ansible.module_utils.basic import AnsibleModule
import os
import time


class DnacSwims(DnacBase):
    """Class containing member attributes for Swim intent module"""

    def __init__(self, module):
        super().__init__(module)
        self.supported_states = ["merged"]

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
          - self: The instance of the class containing the 'config' attribute to be validated.
        Returns:
          The method returns an instance of the class with updated attributes:
          - self.msg: A message describing the validation result.
          - self.status: The status of the validation (either 'success' or 'failed').
          - self.validated_config: If successful, a validated version of 'config' parameter.
        Example:
            To use this method, create an instance of the class and call 'validate_input' on it.
          If the validation succeeds, 'self.status' will be 'success' and 'self.validated_config'
          will contain the validated configuration. If it fails, 'self.status' will be 'failed',
          'self.msg' will describe the validation issues.
        """

        if not self.config:
            self.status = "success"
            self.msg = "Configuration is not available in the playbook for validation"
            self.log(self.msg, "ERROR")
            return self

        temp_spec = dict(
            import_image_details=dict(type="dict"),
            tagging_details=dict(type="dict"),
            image_distribution_details=dict(type="dict"),
            image_activation_details=dict(type="dict"),
        )
        self.config = self.camel_to_snake_case(self.config)

        # Validate swim params
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(invalid_params)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.msg = "Successfully validated playbook config params: {0}".format(
            str(valid_temp)
        )
        self.log(self.msg, "INFO")
        self.status = "success"

        return self

    def site_exists(self, site_name):
        """
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            tuple: A tuple containing two values:
            - site_exists (bool): A boolean indicating whether the site exists (True) or not (False).
            - site_id (str or None): The ID of the site if it exists, or None if the site is not found.
        Description:
            This method checks the existence of a site in the Catalyst Center. If the site is found,it sets 'site_exists' to True,
            retrieves the site's ID, and returns both values in a tuple. If the site does not exist, 'site_exists' is set
            to False, and 'site_id' is None. If an exception occurs during the site lookup, an exception is raised.
        """

        site_exists = False
        site_id = None
        response = None
        try:
            response = self.dnac._exec(
                family="sites",
                function="get_site",
                op_modifies=True,
                params={"name": site_name},
            )
        except Exception as e:
            self.msg = "An exception occurred: Site '{0}' does not exist in the Cisco Catalyst Center".format(
                site_name
            )
            self.log(self.msg, "ERROR")
            self.module.fail_json(msg=self.msg)

        if response:
            self.log(
                "Received API response from 'get_site': {0}".format(str(response)),
                "DEBUG",
            )
            site = response.get("response")
            site_id = site[0].get("id")
            site_exists = True

        return (site_exists, site_id)

    def get_image_id(self, name):
        """
        Retrieve the unique image ID based on the provided image name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the software image to search for.
        Returns:
            str: The unique image ID (UUID) corresponding to the given image name.
        Raises:
            AnsibleFailJson: If the image is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve details about a software image based on its name.
            It extracts and returns the image ID if a single matching image is found. If no image or multiple
            images are found with the same name, it raises an exception.
        """

        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            op_modifies=True,
            params={"image_name": name},
        )
        self.log(
            "Received API response from 'get_software_image_details': {0}".format(
                str(image_response)
            ),
            "DEBUG",
        )
        image_list = image_response.get("response")

        if len(image_list) == 1:
            image_id = image_list[0].get("imageUuid")
            self.log("SWIM image '{0}' has the ID: {1}".format(name, image_id), "INFO")
        else:
            error_message = "SWIM image '{0}' could not be found".format(name)
            self.log(error_message, "ERROR")
            self.module.fail_json(msg=error_message, response=image_response)

        return image_id

    def get_image_name_from_id(self, image_id):
        """
        Retrieve the unique image name based on the provided image id.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            id (str): The unique image ID (UUID) of the software image to search for.
        Returns:
            str: The image name corresponding to the given unique image ID (UUID)
        Raises:
            AnsibleFailJson: If the image is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve details about a software image based on its id.
            It extracts and returns the image name if a single matching image is found. If no image or multiple
            images are found with the same name, it raises an exception.
        """

        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            op_modifies=True,
            params={"image_uuid": image_id},
        )
        self.log(
            "Received API response from 'get_software_image_details': {0}".format(
                str(image_response)
            ),
            "DEBUG",
        )
        image_list = image_response.get("response")

        if len(image_list) == 1:
            image_name = image_list[0].get("name")
            self.log(
                "SWIM image '{0}' has been fetched successfully from Cisco Catalyst Center".format(
                    image_name
                ),
                "INFO",
            )
        else:
            error_message = "SWIM image with Id '{0}' could not be found in Cisco Catalyst Center".format(
                image_id
            )
            self.log(error_message, "ERROR")
            self.module.fail_json(msg=error_message, response=image_response)

        return image_name

    def is_image_exist(self, name):
        """
        Retrieve the unique image ID based on the provided image name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            name (str): The name of the software image to search for.
        Returns:
            str: The unique image ID (UUID) corresponding to the given image name.
        Raises:
            AnsibleFailJson: If the image is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve details about a software image based on its name.
            It extracts and returns the image ID if a single matching image is found. If no image or multiple
            images are found with the same name, it raises an exception.
        """

        image_exist = False
        image_response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_software_image_details",
            op_modifies=True,
            params={"image_name": name},
        )
        self.log(
            "Received API response from 'get_software_image_details': {0}".format(
                str(image_response)
            ),
            "DEBUG",
        )
        image_list = image_response.get("response")

        if len(image_list) == 1:
            image_exist = True

        return image_exist

    def get_device_id(self, params):
        """
        Retrieve the unique device ID based on the provided parameters.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            params (dict): A dictionary containing parameters to filter devices.
        Returns:
            str: The unique device ID corresponding to the filtered device.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve a list of devices based on the provided
            filtering parameters. If a single matching device is found, it extracts and returns the device ID. If
            no device or multiple devices match the criteria, it raises an exception.
        """
        device_id = None
        response = self.dnac._exec(
            family="devices",
            function="get_device_list",
            op_modifies=True,
            params=params,
        )
        self.log(
            "Received API response from 'get_device_list': {0}".format(str(response)),
            "DEBUG",
        )

        device_list = response.get("response")
        if len(device_list) == 1:
            device_id = device_list[0].get("id")
            self.log("Device Id: {0}".format(str(device_id)), "INFO")
        else:
            self.msg = "Device with params: '{0}' not found in Cisco Catalyst Center so can't fetch the device id".format(
                str(params)
            )
            self.log(self.msg, "WARNING")

        return device_id

    def get_device_uuids(
        self, site_name, device_family, device_role, device_series_name=None
    ):
        """
        Retrieve a list of device UUIDs based on the specified criteria.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            site_name (str): The name of the site for which device UUIDs are requested.
            device_family (str): The family/type of devices to filter on.
            device_role (str): The role of devices to filter on. If None, 'ALL' roles are considered.
            device_series_name(str): Specifies the name of the device series.
        Returns:
            list: A list of device UUIDs that match the specified criteria.
        Description:
            The function checks the reachability status and role of devices in the given site.
            Only devices with "Reachable" status are considered, and filtering is based on the specified
            device family and role (if provided).
        """

        device_uuid_list = []
        if not site_name:
            site_name = "Global"
            self.log(
                "Since site name is not given so it will be fetch all the devices under Global and mark site name as 'Global'",
                "INFO",
            )

        (site_exists, site_id) = self.site_exists(site_name)
        if not site_exists:
            self.log(
                """Site '{0}' is not found in the Cisco Catalyst Center, hence unable to fetch associated
                        devices.""".format(
                    site_name
                ),
                "INFO",
            )
            return device_uuid_list

        if device_series_name:
            if device_series_name.startswith(".*") and device_series_name.endswith(
                ".*"
            ):
                self.log(
                    "Device series name '{0}' is already in the regex format".format(
                        device_series_name
                    ),
                    "INFO",
                )
            else:
                device_series_name = ".*" + device_series_name + ".*"

        site_params = {"site_id": site_id, "device_family": device_family}

        try:
            response = self.dnac._exec(
                family="sites",
                function="get_membership",
                op_modifies=True,
                params=site_params,
            )
        except Exception as e:
            self.log(
                "Unable to fetch the device(s) associated to the site '{0}' due to '{1}'".format(
                    site_name, str(e)
                ),
                "WARNING",
            )
            return device_uuid_list

        self.log(
            "Received API response from 'get_membership': {0}".format(str(response)),
            "DEBUG",
        )
        response = response["device"]

        site_response_list = []
        for item in response:
            if item["response"]:
                for item_dict in item["response"]:
                    site_response_list.append(item_dict)

        if device_role.upper() == "ALL":
            device_role = None

        device_params = {
            "series": device_series_name,
            "family": device_family,
            "role": device_role,
        }
        offset = 0
        limit = self.get_device_details_limit()
        initial_exec = False
        site_memberships_ids, device_response_ids = [], []

        while True:
            try:
                if initial_exec:
                    device_params["limit"] = limit
                    device_params["offset"] = offset * limit
                    device_list_response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                        params=device_params,
                    )
                else:
                    initial_exec = True
                    device_list_response = self.dnac._exec(
                        family="devices",
                        function="get_device_list",
                        op_modifies=True,
                        params=device_params,
                    )
                offset = offset + 1
                device_response = device_list_response.get("response")

                if not response or not device_response:
                    self.log(
                        "Failed to retrieve devices associated with the site '{0}' due to empty API response.".format(
                            site_name
                        ),
                        "INFO",
                    )
                    break

                for item in site_response_list:
                    if item["reachabilityStatus"] != "Reachable":
                        self.log(
                            """Device '{0}' is currently '{1}' and cannot be included in the SWIM distribution/activation
                                    process.""".format(
                                item["managementIpAddress"], item["reachabilityStatus"]
                            ),
                            "INFO",
                        )
                        continue
                    self.log(
                        """Device '{0}' from site '{1}' is ready for the SWIM distribution/activation
                                process.""".format(
                            item["managementIpAddress"], site_name
                        ),
                        "INFO",
                    )
                    site_memberships_ids.append(item["instanceUuid"])

                for item in device_response:
                    if item["reachabilityStatus"] != "Reachable":
                        self.log(
                            """Unable to proceed with the device '{0}' for SWIM distribution/activation as its status is
                                    '{1}'.""".format(
                                item["managementIpAddress"], item["reachabilityStatus"]
                            ),
                            "INFO",
                        )
                        continue
                    self.log(
                        """Device '{0}' matches to the specified filter requirements and is set for SWIM
                            distribution/activation.""".format(
                            item["managementIpAddress"]
                        ),
                        "INFO",
                    )
                    device_response_ids.append(item["instanceUuid"])
            except Exception as e:
                self.msg = "An exception occured while fetching the device uuids from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(self.msg, "ERROR")
                return device_uuid_list

        if not device_response_ids or not site_memberships_ids:
            self.log(
                "Failed to retrieve devices associated with the site '{0}' due to empty API response.".format(
                    site_name
                ),
                "INFO",
            )
            return device_uuid_list

        # Find the intersection of device IDs with the response get from get_membership api and get_device_list api with provided filters
        device_uuid_list = set(site_memberships_ids).intersection(
            set(device_response_ids)
        )

        return device_uuid_list

    def get_device_family_identifier(self, family_name):
        """
        Retrieve and store the device family identifier based on the provided family name.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            family_name (str): The name of the device family for which to retrieve the identifier.
        Returns:
            None
        Raises:
            AnsibleFailJson: If the family name is not found in the response.
        Description:
            This function sends a request to Cisco Catalyst Center to retrieve a list of device family identifiers.It then
            searches for a specific family name within the response and stores its associated identifier. If the family
            name is found, the identifier is stored; otherwise, an exception is raised.
        """

        have = {}
        response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_device_family_identifiers",
        )
        self.log(
            "Received API response from 'get_device_family_identifiers': {0}".format(
                str(response)
            ),
            "DEBUG",
        )
        device_family_db = response.get("response")

        if device_family_db:
            device_family_details = get_dict_result(
                device_family_db, "deviceFamily", family_name
            )

            if device_family_details:
                device_family_identifier = device_family_details.get(
                    "deviceFamilyIdentifier"
                )
                have["device_family_identifier"] = device_family_identifier
                self.log(
                    "Family device indentifier: {0}".format(
                        str(device_family_identifier)
                    ),
                    "INFO",
                )
            else:
                self.msg = "Device Family: {0} not found".format(str(family_name))
                self.log(self.msg, "ERROR")
                self.module.fail_json(msg=self.msg, response=[self.msg])
            self.have.update(have)

    def get_have(self):
        """
        Retrieve and store various software image and device details based on user-provided information.
        Returns:
            self: The current instance of the class with updated 'have' attributes.
        Raises:
            AnsibleFailJson: If required image or device details are not provided.
        Description:
            This function populates the 'have' dictionary with details related to software images, site information,
            device families, distribution devices, and activation devices based on user-provided data in the 'want' dictionary.
            It validates and retrieves the necessary information from Cisco Catalyst Center to support later actions.
        """

        if self.want.get("tagging_details"):
            have = {}
            tagging_details = self.want.get("tagging_details")
            if tagging_details.get("image_name"):
                name = tagging_details.get("image_name").split("/")[-1]
                image_id = self.get_image_id(name)
                have["tagging_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["tagging_image_id"] = self.have.get("imported_image_id")

            else:
                self.log("Image details for tagging not provided", "CRITICAL")
                self.module.fail_json(
                    msg="Image details for tagging not provided", response=[]
                )

            # check if given site exists, store siteid
            # if not then use global site
            site_name = tagging_details.get("site_name")
            if site_name and site_name != "Global":
                site_exists = False
                (site_exists, site_id) = self.site_exists(site_name)
                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "Site {0} exists having the site id: {1}".format(
                            site_name, str(site_id)
                        ),
                        "DEBUG",
                    )
            else:
                # For global site, use -1 as siteId
                have["site_id"] = "-1"
                self.log("Site Name not given by user. Using global site.", "WARNING")

            self.have.update(have)
            # check if given device family name exists, store indentifier value
            family_name = tagging_details.get("device_image_family_name")
            self.get_device_family_identifier(family_name)

        if self.want.get("distribution_details"):
            have = {}
            distribution_details = self.want.get("distribution_details")
            site_name = distribution_details.get("site_name")
            if site_name:
                site_exists = False
                (site_exists, site_id) = self.site_exists(site_name)

                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "Site '{0}' exists and has the site ID: {1}".format(
                            site_name, str(site_id)
                        ),
                        "DEBUG",
                    )

            # check if image for distributon is available
            if distribution_details.get("image_name"):
                name = distribution_details.get("image_name").split("/")[-1]
                image_id = self.get_image_id(name)
                have["distribution_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["distribution_image_id"] = self.have.get("imported_image_id")

            else:
                self.log(
                    "Image details required for distribution have not been provided",
                    "ERROR",
                )
                self.module.fail_json(
                    msg="Image details required for distribution have not been provided",
                    response=[],
                )

            device_params = dict(
                hostname=distribution_details.get("device_hostname"),
                serialNumber=distribution_details.get("device_serial_number"),
                managementIpAddress=distribution_details.get("device_ip_address"),
                macAddress=distribution_details.get("device_mac_address"),
            )
            device_id = self.get_device_id(device_params)

            if device_id is not None:
                have["distribution_device_id"] = device_id

            self.have.update(have)

        if self.want.get("activation_details"):
            have = {}
            activation_details = self.want.get("activation_details")
            # check if image for activation is available
            if activation_details.get("image_name"):
                name = activation_details.get("image_name").split("/")[-1]
                image_id = self.get_image_id(name)
                have["activation_image_id"] = image_id

            elif self.have.get("imported_image_id"):
                have["activation_image_id"] = self.have.get("imported_image_id")
            else:
                self.log(
                    "Image details required for activation have not been provided",
                    "ERROR",
                )
                self.module.fail_json(
                    msg="Image details required for activation have not been provided",
                    response=[],
                )

            site_name = activation_details.get("site_name")
            if site_name:
                site_exists = False
                (site_exists, site_id) = self.site_exists(site_name)
                if site_exists:
                    have["site_id"] = site_id
                    self.log(
                        "The site '{0}' exists and has the site ID '{1}'".format(
                            site_name, str(site_id)
                        ),
                        "INFO",
                    )

            device_params = dict(
                hostname=activation_details.get("device_hostname"),
                serialNumber=activation_details.get("device_serial_number"),
                managementIpAddress=activation_details.get("device_ip_address"),
                macAddress=activation_details.get("device_mac_address"),
            )
            device_id = self.get_device_id(device_params)

            if device_id is not None:
                have["activation_device_id"] = device_id
            self.have.update(have)
            self.log("Current State (have): {0}".format(str(self.have)), "INFO")

        return self

    def get_want(self, config):
        """
        Retrieve and store import, tagging, distribution, and activation details from playbook configuration.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing image import and other details.
        Returns:
            self: The current instance of the class with updated 'want' attributes.
        Raises:
            AnsibleFailJson: If an incorrect import type is specified.
        Description:
            This function parses the playbook configuration to extract information related to image
            import, tagging, distribution, and activation. It stores these details in the 'want' dictionary
            for later use in the Ansible module.
        """

        want = {}
        if config.get("import_image_details"):
            want["import_image"] = True
            want["import_type"] = config.get("import_image_details").get("type").lower()
            if want["import_type"] == "remote":
                want["url_import_details"] = config.get("import_image_details").get(
                    "url_details"
                )
            elif want["import_type"] == "local":
                want["local_import_details"] = config.get("import_image_details").get(
                    "local_image_details"
                )
            else:
                self.log(
                    "The import type '{0}' provided is incorrect. Only 'local' or 'remote' are supported.".format(
                        want["import_type"]
                    ),
                    "CRITICAL",
                )
                self.module.fail_json(
                    msg="Incorrect import type. Supported Values: local or remote"
                )

        want["tagging_details"] = config.get("tagging_details")
        want["distribution_details"] = config.get("image_distribution_details")
        want["activation_details"] = config.get("image_activation_details")

        self.want = want
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        return self

    def get_diff_import(self):
        """
        Check the image import type and fetch the image ID for the imported image for further use.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function checks the type of image import (URL or local) and proceeds with the import operation accordingly.
            It then monitors the import task's progress and updates the 'result' dictionary. If the operation is successful,
            'changed' is set to True.
            Additionally, if tagging, distribution, or activation details are provided, it fetches the image ID for the
            imported image and stores it in the 'have' dictionary for later use.
        """

        try:
            import_type = self.want.get("import_type")

            if not import_type:
                self.status = "success"
                self.msg = "Error: Details required for importing SWIM image. Please provide the necessary information."
                self.result["msg"] = self.msg
                self.log(self.msg, "WARNING")
                self.result["changed"] = False
                return self

            if import_type == "remote":
                image_name = (
                    self.want.get("url_import_details")
                    .get("payload")[0]
                    .get("source_url")
                )
            else:
                image_name = self.want.get("local_import_details").get("file_path")

            # Code to check if the image already exists in Catalyst Center
            name = image_name.split("/")[-1]
            image_exist = self.is_image_exist(name)

            import_key_mapping = {
                "source_url": "sourceURL",
                "image_family": "imageFamily",
                "application_type": "applicationType",
                "is_third_party": "thirdParty",
            }

            if image_exist:
                image_id = self.get_image_id(name)
                self.have["imported_image_id"] = image_id
                self.msg = (
                    "Image '{0}' already exists in the Cisco Catalyst Center".format(
                        name
                    )
                )
                self.result["msg"] = self.msg
                self.log(self.msg, "INFO")
                self.status = "success"
                self.result["changed"] = False
                return self

            if self.want.get("import_type") == "remote":
                import_payload_dict = {}
                temp_payload = self.want.get("url_import_details").get("payload")[0]
                keys_to_change = list(import_key_mapping.keys())

                for key, val in temp_payload.items():
                    if key in keys_to_change:
                        api_key_name = import_key_mapping[key]
                        import_payload_dict[api_key_name] = val

                import_image_payload = [import_payload_dict]
                import_params = dict(
                    payload=import_image_payload,
                    scheduleAt=self.want.get("url_import_details").get("schedule_at"),
                    scheduleDesc=self.want.get("url_import_details").get(
                        "schedule_desc"
                    ),
                    scheduleOrigin=self.want.get("url_import_details").get(
                        "schedule_origin"
                    ),
                )
                import_function = "import_software_image_via_url"
            else:
                file_path = self.want.get("local_import_details").get("file_path")
                import_params = dict(
                    is_third_party=self.want.get("local_import_details").get(
                        "is_third_party"
                    ),
                    third_party_vendor=self.want.get("local_import_details").get(
                        "third_party_vendor"
                    ),
                    third_party_image_family=self.want.get("local_import_details").get(
                        "third_party_image_family"
                    ),
                    third_party_application_type=self.want.get(
                        "local_import_details"
                    ).get("third_party_application_type"),
                    multipart_fields={
                        "file": (
                            os.path.basename(file_path),
                            open(file_path, "rb"),
                            "application/octet-stream",
                        )
                    },
                    multipart_monitor_callback=None,
                )
                import_function = "import_local_software_image"

            response = self.dnac._exec(
                family="software_image_management_swim",
                function=import_function,
                op_modifies=True,
                params=import_params,
            )
            self.log(
                "Received API response from {0}: {1}".format(
                    import_function, str(response)
                ),
                "DEBUG",
            )

            task_details = {}
            task_id = response.get("response").get("taskId")

            while True:
                task_details = self.get_task_details(task_id)
                name = image_name.split("/")[-1]

                if task_details and (
                    "completed successfully" in task_details.get("progress").lower()
                ):
                    self.result["changed"] = True
                    self.status = "success"
                    self.msg = "Swim Image {0} imported successfully".format(name)
                    self.result["msg"] = self.msg
                    self.log(self.msg, "INFO")
                    break

                if task_details and task_details.get("isError"):
                    if "already exists" in task_details.get("failureReason", ""):
                        self.msg = "SWIM Image {0} already exists in the Cisco Catalyst Center".format(
                            name
                        )
                        self.result["msg"] = self.msg
                        self.log(self.msg, "INFO")
                        self.status = "success"
                        self.result["changed"] = False
                        break
                    else:
                        self.status = "failed"
                        self.msg = task_details.get(
                            "failureReason",
                            "SWIM Image {0} seems to be invalid".format(image_name),
                        )
                        self.log(self.msg, "WARNING")
                        self.result["response"] = self.msg
                        return self

            self.result["response"] = task_details if task_details else response

            # Fetch image_id for the imported image for further use
            image_name = image_name.split("/")[-1]
            image_id = self.get_image_id(image_name)
            self.have["imported_image_id"] = image_id

            return self

        except Exception as e:
            self.status = "failed"
            self.msg = """Error: Import image details are not provided in the playbook, or the Import Image API was not
                 triggered successfully. Please ensure the necessary details are provided and verify the status of the Import Image process."""
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg

        return self

    def get_diff_tagging(self):
        """
        Tag or untag a software image as golden based on provided tagging details.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function tags or untags a software image as a golden image in Cisco Catalyst Center based on the provided
            tagging details. The tagging action is determined by the value of the 'tagging' attribute
            in the 'tagging_details' dictionary.If 'tagging' is True, the image is tagged as golden, and if 'tagging'
            is False, the golden tag is removed. The function sends the appropriate request to Cisco Catalyst Center and updates the
            task details in the 'result' dictionary. If the operation is successful, 'changed' is set to True.
        """

        tagging_details = self.want.get("tagging_details")
        tag_image_golden = tagging_details.get("tagging")
        image_name = self.get_image_name_from_id(self.have.get("tagging_image_id"))

        image_params = dict(
            image_id=self.have.get("tagging_image_id"),
            site_id=self.have.get("site_id"),
            device_family_identifier=self.have.get("device_family_identifier"),
            device_role=tagging_details.get("device_role", "ALL").upper(),
        )

        response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_golden_tag_status_of_an_image",
            op_modifies=True,
            params=image_params,
        )
        self.log(
            "Received API response from 'get_golden_tag_status_of_an_image': {0}".format(
                str(response)
            ),
            "DEBUG",
        )

        response = response.get("response")
        if response:
            image_status = response["taggedGolden"]
            if image_status and image_status == tag_image_golden:
                self.status = "success"
                self.result["changed"] = False
                self.msg = "SWIM Image '{0}' already tagged as Golden image in Cisco Catalyst Center".format(
                    image_name
                )
                self.result["msg"] = self.msg
                self.log(self.msg, "INFO")
                return self

            if not image_status and image_status == tag_image_golden:
                self.status = "success"
                self.result["changed"] = False
                self.msg = "SWIM Image '{0}' already un-tagged from Golden image in Cisco Catalyst Center".format(
                    image_name
                )
                self.result["msg"] = self.msg
                self.log(self.msg, "INFO")
                return self

        if tag_image_golden:
            image_params = dict(
                imageId=self.have.get("tagging_image_id"),
                siteId=self.have.get("site_id"),
                deviceFamilyIdentifier=self.have.get("device_family_identifier"),
                deviceRole=tagging_details.get("device_role", "ALL").upper(),
            )
            self.log(
                "Parameters for tagging the image as golden: {0}".format(
                    str(image_params)
                ),
                "INFO",
            )

            response = self.dnac._exec(
                family="software_image_management_swim",
                function="tag_as_golden_image",
                op_modifies=True,
                params=image_params,
            )
            self.log(
                "Received API response from 'tag_as_golden_image': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

        else:
            self.log(
                "Parameters for un-tagging the image as golden: {0}".format(
                    str(image_params)
                ),
                "INFO",
            )

            response = self.dnac._exec(
                family="software_image_management_swim",
                function="remove_golden_tag_for_image",
                op_modifies=True,
                params=image_params,
            )
            self.log(
                "Received API response from 'remove_golden_tag_for_image': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

        if not response:
            self.status = "failed"
            self.msg = "Did not get the response of API so cannot check the Golden tagging status of image - {0}".format(
                image_name
            )
            self.log(self.msg, "ERROR")
            self.result["response"] = self.msg
            return self

        task_details = {}
        task_id = response.get("response").get("taskId")

        while True:
            task_details = self.get_task_details(task_id)

            if not task_details.get("isError") and "successful" in task_details.get(
                "progress"
            ):
                self.status = "success"
                self.result["changed"] = True
                self.msg = task_details.get("progress")
                self.result["msg"] = self.msg
                self.result["response"] = self.msg
                self.log(self.msg, "INFO")
                break
            elif task_details.get("isError"):
                failure_reason = task_details.get("failureReason", "")
                if (
                    failure_reason
                    and "An inheritted tag cannot be un-tagged" in failure_reason
                ):
                    self.status = "failed"
                    self.result["changed"] = False
                    self.msg = failure_reason
                    self.result["msg"] = failure_reason
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    break
                else:
                    error_message = task_details.get(
                        "failureReason",
                        "Error: while tagging/un-tagging the golden swim image.",
                    )
                    self.status = "failed"
                    self.msg = error_message
                    self.result["msg"] = error_message
                    self.log(self.msg, "ERROR")
                    self.result["response"] = self.msg
                    break

        return self

    def get_device_ip_from_id(self, device_id):
        """
        Retrieve the management IP address of a device from Cisco Catalyst Center using its ID.
        Parameters:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - device_id (str): The unique identifier of the device in Cisco Catalyst Center.
        Returns:
            str: The management IP address of the specified device.
        Raises:
            Exception: If there is an error while retrieving the response from Cisco Catalyst Center.
        Description:
            This method queries Cisco Catalyst Center for the device details based on its unique identifier (ID).
            It uses the 'get_device_list' function in the 'devices' family, extracts the management IP address
            from the response, and returns it. If any error occurs during the process, an exception is raised
            with an appropriate error message logged.
        """

        try:
            response = self.dnac._exec(
                family="devices",
                function="get_device_list",
                op_modifies=True,
                params={"id": device_id},
            )
            self.log(
                "Received API response from 'get_device_list': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )
            response = response.get("response")[0]
            device_ip = response.get("managementIpAddress")

            return device_ip
        except Exception as e:
            error_message = "Error occurred while getting the response of device from Cisco Catalyst Center: {0}".format(
                str(e)
            )
            self.log(error_message, "ERROR")
            raise Exception(error_message)

    def check_swim_task_status(self, swim_task_dict, swim_task_name):
        """
        Check the status of the SWIM (Software Image Management) task for each device.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            swim_task_dict (dict): A dictionary containing the mapping of device IP address to the respective task ID.
            swim_task_name (str): The name of the SWIM task being checked which is either Distribution or Activation.
        Returns:
            tuple: A tuple containing two elements:
                - device_ips_list (list): A list of device IP addresses for which the SWIM task failed.
                - device_count (int): The count of devices for which the SWIM task was successful.
        Description:
            This function iterates through the distribution_task_dict, which contains the mapping of
            device IP address to their respective task ID. It checks the status of the SWIM task for each device by
            repeatedly querying for task details until the task is either completed successfully or fails. If the task
            is successful, the device count is incremented. If the task fails, an error message is logged, and the device
            IP is appended to the device_ips_list and return a tuple containing the device_ips_list and device_count.
        """

        device_ips_list = []
        device_count = 0

        for device_ip, task_id in swim_task_dict.items():
            start_time = time.time()
            max_timeout = self.params.get("dnac_api_task_timeout")

            while True:
                end_time = time.time()
                if (end_time - start_time) >= max_timeout:
                    self.log(
                        """Max timeout of {0} sec has reached for the task id '{1}' for the device '{2}' and unexpected
                                 task status so moving out to next task id""".format(
                            max_timeout, task_id, device_ip
                        ),
                        "WARNING",
                    )
                    device_ips_list.append(device_ip)
                    break

                task_details = self.get_task_details(task_id)

                if not task_details.get("isError") and (
                    "completed successfully" in task_details.get("progress")
                ):
                    self.result["changed"] = True
                    self.status = "success"
                    self.log(
                        "Image {0} successfully for the device '{1}".format(
                            swim_task_name, device_ip
                        ),
                        "INFO",
                    )
                    device_count += 1
                    break

                if task_details.get("isError"):
                    error_msg = "Image {0} gets failed for the device '{1}'".format(
                        swim_task_name, device_ip
                    )
                    self.log(error_msg, "ERROR")
                    self.result["response"] = task_details
                    device_ips_list.append(device_ip)
                    break
                time.sleep(self.params.get("dnac_task_poll_interval"))

        return device_ips_list, device_count

    def get_diff_distribution(self):
        """
        Get image distribution parameters from the playbook and trigger image distribution.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function retrieves image distribution parameters from the playbook's 'distribution_details' and triggers
            the distribution of the specified software image to the specified device. It monitors the distribution task's
            progress and updates the 'result' dictionary. If the operation is successful, 'changed' is set to True.
        """

        distribution_details = self.want.get("distribution_details")
        site_name = distribution_details.get("site_name")
        device_family = distribution_details.get("device_family_name")
        device_role = distribution_details.get("device_role", "ALL")
        device_series_name = distribution_details.get("device_series_name")
        device_uuid_list = self.get_device_uuids(
            site_name, device_family, device_role, device_series_name
        )
        image_id = self.have.get("distribution_image_id")
        self.complete_successful_distribution = False
        self.partial_successful_distribution = False
        self.single_device_distribution = False

        if self.have.get("distribution_device_id"):

            distribution_params = dict(
                payload=[
                    dict(
                        deviceUuid=self.have.get("distribution_device_id"),
                        imageUuid=image_id,
                    )
                ]
            )
            self.log(
                "Distribution Params: {0}".format(str(distribution_params)), "INFO"
            )

            response = self.dnac._exec(
                family="software_image_management_swim",
                function="trigger_software_image_distribution",
                op_modifies=True,
                params=distribution_params,
            )
            self.log(
                "Received API response from 'trigger_software_image_distribution': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            if response:
                task_details = {}
                task_id = response.get("response").get("taskId")

                while True:
                    task_details = self.get_task_details(task_id)

                    if not task_details.get("isError") and (
                        "completed successfully" in task_details.get("progress")
                    ):
                        self.result["changed"] = True
                        self.status = "success"
                        self.single_device_distribution = True
                        self.result["msg"] = (
                            "Image with Id {0} Distributed Successfully".format(
                                image_id
                            )
                        )
                        break

                    if task_details.get("isError"):
                        self.status = "failed"
                        self.msg = "Image with Id {0} Distribution Failed".format(
                            image_id
                        )
                        self.log(self.msg, "ERROR")
                        self.result["response"] = task_details
                        break

                    self.result["response"] = task_details if task_details else response

            return self

        if len(device_uuid_list) == 0:
            self.status = "success"
            self.msg = "The SWIM image distribution task could not proceed because no eligible devices were found."
            self.result["msg"] = self.msg
            self.log(self.msg, "WARNING")
            return self

        self.log(
            "Device UUIDs involved in Image Distribution: {0}".format(
                str(device_uuid_list)
            ),
            "INFO",
        )
        distribution_task_dict = {}

        for device_uuid in device_uuid_list:
            device_management_ip = self.get_device_ip_from_id(device_uuid)
            distribution_params = dict(
                payload=[dict(deviceUuid=device_uuid, imageUuid=image_id)]
            )
            self.log(
                "Distribution Params: {0}".format(str(distribution_params)), "INFO"
            )
            response = self.dnac._exec(
                family="software_image_management_swim",
                function="trigger_software_image_distribution",
                op_modifies=True,
                params=distribution_params,
            )
            self.log(
                "Received API response from 'trigger_software_image_distribution': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            if response:
                task_details = {}
                task_id = response.get("response").get("taskId")
                distribution_task_dict[device_management_ip] = task_id

        device_ips_list, device_distribution_count = self.check_swim_task_status(
            distribution_task_dict, "Distribution"
        )

        if device_distribution_count == 0:
            self.status = "failed"
            self.msg = "Image with Id {0} Distribution Failed for all devices".format(
                image_id
            )
        elif device_distribution_count == len(device_uuid_list):
            self.result["changed"] = True
            self.status = "success"
            self.complete_successful_distribution = True
            self.msg = (
                "Image with Id {0} Distributed Successfully for all devices".format(
                    image_id
                )
            )
        else:
            self.result["changed"] = True
            self.status = "success"
            self.partial_successful_distribution = False
            self.msg = (
                "Image with Id '{0}' Distributed and partially successfull".format(
                    image_id
                )
            )
            self.log(
                "For device(s) {0} image Distribution gets failed".format(
                    str(device_ips_list)
                ),
                "CRITICAL",
            )

        self.result["msg"] = self.msg
        self.log(self.msg, "INFO")

        return self

    def get_diff_activation(self):
        """
        Get image activation parameters from the playbook and trigger image activation.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This function retrieves image activation parameters from the playbook's 'activation_details' and triggers the
            activation of the specified software image on the specified device. It monitors the activation task's progress and
            updates the 'result' dictionary. If the operation is successful, 'changed' is set to True.
        """

        activation_details = self.want.get("activation_details")
        site_name = activation_details.get("site_name")
        device_family = activation_details.get("device_family_name")
        device_role = activation_details.get("device_role", "ALL")
        device_series_name = activation_details.get("device_series_name")
        device_uuid_list = self.get_device_uuids(
            site_name, device_family, device_role, device_series_name
        )
        image_id = self.have.get("activation_image_id")
        self.complete_successful_activation = False
        self.partial_successful_activation = False
        self.single_device_activation = False

        if self.have.get("activation_device_id"):
            payload = [
                dict(
                    activateLowerImageVersion=activation_details.get(
                        "activate_lower_image_version"
                    ),
                    deviceUpgradeMode=activation_details.get("device_upgrade_mode"),
                    distributeIfNeeded=activation_details.get("distribute_if_needed"),
                    deviceUuid=self.have.get("activation_device_id"),
                    imageUuidList=[image_id],
                )
            ]

            activation_params = dict(
                schedule_validate=activation_details.get("scehdule_validate"),
                payload=payload,
            )
            self.log("Activation Params: {0}".format(str(activation_params)), "INFO")

            response = self.dnac._exec(
                family="software_image_management_swim",
                function="trigger_software_image_activation",
                op_modifies=True,
                params=activation_params,
            )
            self.log(
                "Received API response from 'trigger_software_image_activation': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            task_details = {}
            task_id = response.get("response").get("taskId")

            while True:
                task_details = self.get_task_details(task_id)

                if not task_details.get("isError") and (
                    "completed successfully" in task_details.get("progress")
                ):
                    self.result["changed"] = True
                    self.result["msg"] = "Image Activated successfully"
                    self.status = "success"
                    self.single_device_activation = True
                    break

                if task_details.get("isError"):
                    self.msg = "Activation for Image with Id '{0}' gets failed".format(
                        image_id
                    )
                    self.status = "failed"
                    self.result["response"] = task_details
                    self.log(self.msg, "ERROR")
                    return self

            self.result["response"] = task_details if task_details else response

            return self

        if len(device_uuid_list) == 0:
            self.status = "success"
            self.msg = "The SWIM image activation task could not proceed because no eligible devices were found."
            self.result["msg"] = self.msg
            self.log(self.msg, "WARNING")
            return self

        self.log(
            "Device UUIDs involved in Image Activation: {0}".format(
                str(device_uuid_list)
            ),
            "INFO",
        )
        activation_task_dict = {}

        for device_uuid in device_uuid_list:
            device_management_ip = self.get_device_ip_from_id(device_uuid)
            payload = [
                dict(
                    activateLowerImageVersion=activation_details.get(
                        "activate_lower_image_version"
                    ),
                    deviceUpgradeMode=activation_details.get("device_upgrade_mode"),
                    distributeIfNeeded=activation_details.get("distribute_if_needed"),
                    deviceUuid=device_uuid,
                    imageUuidList=[image_id],
                )
            ]

            activation_params = dict(
                schedule_validate=activation_details.get("scehdule_validate"),
                payload=payload,
            )
            self.log("Activation Params: {0}".format(str(activation_params)), "INFO")

            response = self.dnac._exec(
                family="software_image_management_swim",
                function="trigger_software_image_activation",
                op_modifies=True,
                params=activation_params,
            )
            self.log(
                "Received API response from 'trigger_software_image_activation': {0}".format(
                    str(response)
                ),
                "DEBUG",
            )

            if response:
                task_details = {}
                task_id = response.get("response").get("taskId")
                activation_task_dict[device_management_ip] = task_id

        device_ips_list, device_activation_count = self.check_swim_task_status(
            activation_task_dict, "Activation"
        )

        if device_activation_count == 0:
            self.status = "failed"
            self.msg = "Image with Id '{0}' activation failed for all devices".format(
                image_id
            )
        elif device_activation_count == len(device_uuid_list):
            self.result["changed"] = True
            self.status = "success"
            self.complete_successful_activation = True
            self.msg = (
                "Image with Id '{0}' activated successfully for all devices".format(
                    image_id
                )
            )
        else:
            self.result["changed"] = True
            self.status = "success"
            self.partial_successful_activation = True
            self.msg = "Image with Id '{0}' activated and partially successfull".format(
                image_id
            )
            self.log(
                "For Device(s) {0} Image activation gets Failed".format(
                    str(device_ips_list)
                ),
                "CRITICAL",
            )

        self.result["msg"] = self.msg
        self.log(self.msg, "INFO")

        return self

    def get_diff_merged(self, config):
        """
        Get tagging details and then trigger distribution followed by activation if specified in the playbook.
        Parameters:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            config (dict): The configuration dictionary containing tagging, distribution, and activation details.
        Returns:
            self: The current instance of the class with updated 'result' and 'have' attributes.
        Description:
            This function checks the provided playbook configuration for tagging, distribution, and activation details. It
            then triggers these operations in sequence if the corresponding details are found in the configuration.The
            function monitors the progress of each task and updates the 'result' dictionary accordingly. If any of the
            operations are successful, 'changed' is set to True.
        """

        if config.get("tagging_details"):
            self.get_diff_tagging().check_return_status()

        if config.get("image_distribution_details"):
            self.get_diff_distribution().check_return_status()

        if config.get("image_activation_details"):
            self.get_diff_activation().check_return_status()

        return self

    def verify_diff_imported(self, import_type):
        """
        Verify the successful import of a software image into Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            import_type (str): The type of import, either 'remote' or 'local'.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the successful import of a software image into Cisco Catalyst Center.
            It checks whether the image exists in Catalyst Center based on the provided import type.
            If the image exists, the status is set to 'success', and a success message is logged.
            If the image does not exist, a warning message is logged indicating a potential import failure.
        """

        if import_type == "remote":
            image_name = (
                self.want.get("url_import_details").get("payload")[0].get("source_url")
            )
        else:
            image_name = self.want.get("local_import_details").get("file_path")

        # Code to check if the image already exists in Catalyst Center
        name = image_name.split("/")[-1]
        image_exist = self.is_image_exist(name)
        if image_exist:
            self.status = "success"
            self.msg = "The requested Image '{0}' imported in the Cisco Catalyst Center and Image presence has been verified.".format(
                name
            )
            self.log(self.msg, "INFO")
        else:
            self.log(
                """The playbook input for SWIM Image '{0}' does not align with the Cisco Catalyst Center, indicating that image
                        may not have imported successfully.""".format(
                    name
                ),
                "INFO",
            )

        return self

    def verify_diff_tagged(self):
        """
        Verify the Golden tagging status of a software image in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the tagging status of a software image in Cisco Catalyst Center.
            It retrieves tagging details from the input, including the desired tagging status and image ID.
            Using the provided image ID, it obtains image parameters required for checking the image status.
            The method then queries Catalyst Center to get the golden tag status of the image.
            If the image status matches the desired tagging status, a success message is logged.
            If there is a mismatch between the playbook input and the Catalyst Center, a warning message is logged.
        """

        tagging_details = self.want.get("tagging_details")
        tag_image_golden = tagging_details.get("tagging")
        image_id = self.have.get("tagging_image_id")
        image_name = self.get_image_name_from_id(image_id)

        image_params = dict(
            image_id=self.have.get("tagging_image_id"),
            site_id=self.have.get("site_id"),
            device_family_identifier=self.have.get("device_family_identifier"),
            device_role=tagging_details.get("device_role", "ALL").upper(),
        )
        self.log(
            "Parameters for checking the status of image: {0}".format(
                str(image_params)
            ),
            "INFO",
        )

        response = self.dnac._exec(
            family="software_image_management_swim",
            function="get_golden_tag_status_of_an_image",
            op_modifies=True,
            params=image_params,
        )
        self.log(
            "Received API response from 'get_golden_tag_status_of_an_image': {0}".format(
                str(response)
            ),
            "DEBUG",
        )

        response = response.get("response")
        if response:
            image_status = response["taggedGolden"]
            if image_status == tag_image_golden:
                if tag_image_golden:
                    self.msg = """The requested image '{0}' has been tagged as golden in the Cisco Catalyst Center and
                             its status has been successfully verified.""".format(
                        image_name
                    )
                    self.log(self.msg, "INFO")
                else:
                    self.msg = """The requested image '{0}' has been un-tagged as golden in the Cisco Catalyst Center and
                            image status has been verified.""".format(
                        image_name
                    )
                    self.log(self.msg, "INFO")
        else:
            self.log(
                """Mismatch between the playbook input for tagging/un-tagging image as golden and the Cisco Catalyst Center indicates that
                        the tagging/un-tagging task was not executed successfully.""",
                "INFO",
            )

        return self

    def verify_diff_distributed(self):
        """
        Verify the distribution status of a software image in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            import_type (str): The type of import, either 'url' or 'local'.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the distribution status of a software image in Cisco Catalyst Center.
            It retrieves the image ID and name from the input and if distribution device ID is provided, it checks the distribution status for that
            list of specific device and logs the info message based on distribution status.
        """

        image_id = self.have.get("distribution_image_id")
        image_name = self.get_image_name_from_id(image_id)

        if self.have.get("distribution_device_id"):
            if self.single_device_distribution:
                self.msg = """The requested image '{0}', associated with the device ID '{1}', has been successfully distributed in the Cisco Catalyst Center
                     and its status has been verified.""".format(
                    image_name, self.have.get("distribution_device_id")
                )
                self.log(self.msg, "INFO")
            else:
                self.log(
                    """Mismatch between the playbook input for distributing the image to the device with ID '{0}' and the actual state in the
                         Cisco Catalyst Center suggests that the distribution task might not have been executed
                         successfully.""".format(
                        self.have.get("distribution_device_id")
                    ),
                    "INFO",
                )
        elif self.complete_successful_distribution:
            self.msg = """The requested image '{0}', with ID '{1}', has been successfully distributed to all devices within the specified
                     site in the Cisco Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        elif self.partial_successful_distribution:
            self.msg = """T"The requested image '{0}', with ID '{1}', has been partially distributed across some devices in the Cisco Catalyst
                     Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        else:
            self.msg = """The requested image '{0}', with ID '{1}', failed to be distributed across devices in the Cisco Catalyst
                     Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")

        return self

    def verify_diff_activated(self):
        """
        Verify the activation status of a software image in Cisco Catalyst Center.
        Args:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Returns:
            self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method verifies the activation status of a software image in Cisco Catalyst Center and retrieves the image ID and name from
            the input. If activation device ID is provided, it checks the activation status for that specific device. Based on activation status
            a corresponding message is logged.
        """

        image_id = self.have.get("activation_image_id")
        image_name = self.get_image_name_from_id(image_id)

        if self.have.get("activation_device_id"):
            if self.single_device_activation:
                self.msg = """The requested image '{0}', associated with the device ID '{1}', has been successfully activated in the Cisco Catalyst
                         Center and its status has been verified.""".format(
                    image_name, self.have.get("activation_device_id")
                )
                self.log(self.msg, "INFO")
            else:
                self.log(
                    """Mismatch between the playbook's input for activating the image '{0}' on the device with ID '{1}' and the actual state in
                         the Cisco Catalyst Center suggests that the activation task might not have been executed
                         successfully.""".format(
                        image_name, self.have.get("activation_device_id")
                    ),
                    "INFO",
                )
        elif self.complete_successful_activation:
            self.msg = """The requested image '{0}', with ID '{1}', has been successfully activated on all devices within the specified site in the
                     Cisco Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        elif self.partial_successful_activation:
            self.msg = """"The requested image '{0}', with ID '{1}', has been partially activated on some devices in the Cisco
                     Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")
        else:
            self.msg = """The activation of the requested image '{0}', with ID '{1}', failed on devices in the Cisco
                     Catalyst Center.""".format(
                image_name, image_id
            )
            self.log(self.msg, "INFO")

        return self

    def verify_diff_merged(self, config):
        """
        Verify the merged status(Importing/Tagging/Distributing/Actiavting) the SWIM Image in devices in Cisco Catalyst Center.
        Args:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
            - config (dict): The configuration details to be verified.
        Return:
            - self (object): An instance of a class used for interacting with Cisco Catalyst Center.
        Description:
            This method checks the merged status of a configuration in Cisco Catalyst Center by retrieving the current state
            (have) and desired state (want) of the configuration, logs the states, and validates whether the specified
            SWIM operation performed or not.
        """

        self.get_have()
        self.log("Current State (have): {0}".format(str(self.have)), "INFO")
        self.log("Desired State (want): {0}".format(str(self.want)), "INFO")

        import_type = self.want.get("import_type")
        if import_type:
            self.verify_diff_imported(import_type).check_return_status()

        tagged = self.want.get("tagging_details")
        if tagged:
            self.verify_diff_tagged().check_return_status()

        distribution_details = self.want.get("distribution_details")
        if distribution_details:
            self.verify_diff_distributed().check_return_status()

        activation_details = self.want.get("activation_details")
        if activation_details:
            self.verify_diff_activated().check_return_status()

        return self


def main():
    """main entry point for module execution"""

    element_spec = {
        "dnac_host": {"required": True, "type": "str"},
        "dnac_port": {"type": "str", "default": "443"},
        "dnac_username": {"type": "str", "default": "admin", "aliases": ["user"]},
        "dnac_password": {"type": "str", "no_log": True},
        "dnac_verify": {"type": "bool", "default": "True"},
        "dnac_version": {"type": "str", "default": "2.2.3.3"},
        "dnac_debug": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "dnac_log": {"type": "bool", "default": False},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged"]},
    }

    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)

    dnac_swims = DnacSwims(module)
    state = dnac_swims.params.get("state")

    if state not in dnac_swims.supported_states:
        dnac_swims.status = "invalid"
        dnac_swims.msg = "State {0} is invalid".format(state)
        dnac_swims.check_return_status()

    dnac_swims.validate_input().check_return_status()
    config_verify = dnac_swims.params.get("config_verify")

    for config in dnac_swims.validated_config:
        dnac_swims.reset_values()
        dnac_swims.get_want(config).check_return_status()
        dnac_swims.get_diff_import().check_return_status()
        dnac_swims.get_have().check_return_status()
        dnac_swims.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            dnac_swims.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**dnac_swims.result)


if __name__ == "__main__":
    main()
