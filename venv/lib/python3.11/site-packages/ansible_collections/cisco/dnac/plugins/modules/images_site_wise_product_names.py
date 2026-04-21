#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: images_site_wise_product_names
short_description: Resource module for Images Site Wise
  Product Names
description:
  - Manage operations create, update and delete of the
    resource Images Site Wise Product Names. - > Assign
    network device product name and sites for the given
    image identifier. Refer `/dna/intent/api/v1/images`
    API for obtaining imageId.
  - This API unassigns the network device product name
    from all the sites for the given software image.
    - > Update the list of sites for the network device
    product name assigned to the software image. Refer
    to `/dna/intent/api/v1/images` and `/dna/intent/api/v1/images/{imageId}/siteWiseProductNames`
    GET APIs for obtaining `imageId` and `productNameOrdinal`
    respectively.
version_added: '6.15.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  imageId:
    description: ImageId path parameter. Software image
      identifier. Refer `/dna/intent/api/v1/images`
      API for obtaining `imageId`.
    type: str
  productNameOrdinal:
    description: Product name ordinal is unique value
      for each network device product.
    type: float
  siteIds:
    description: Sites where this image needs to be
      assigned. Ref https //developer.cisco.com/docs/dna-center/#!sites.
    elements: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) AssignNetworkDeviceProductNameToTheGivenSoftwareImage
    description: Complete reference of the AssignNetworkDeviceProductNameToTheGivenSoftwareImage
      API.
    link: https://developer.cisco.com/docs/dna-center/#!assign-network-device-product-name-to-the-given-software-image
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) UnassignNetworkDeviceProductNameFromTheGivenSoftwareImage
    description: Complete reference of the UnassignNetworkDeviceProductNameFromTheGivenSoftwareImage
      API.
    link: https://developer.cisco.com/docs/dna-center/#!unassign-network-device-product-name-from-the-given-software-image
  - name: Cisco DNA Center documentation for Software
      Image Management (SWIM) UpdateTheListOfSitesForTheNetworkDeviceProductNameAssignedToTheSoftwareImage
    description: Complete reference of the UpdateTheListOfSitesForTheNetworkDeviceProductNameAssignedToTheSoftwareImage
      API.
    link: https://developer.cisco.com/docs/dna-center/#!update-the-list-of-sites-for-the-network-device-product-name-assigned-to-the-software-image
notes:
  - SDK Method used are
    software_image_management_swim.SoftwareImageManagementSwim.assign_network_device_product_name_to_the_given_software_image,
    software_image_management_swim.SoftwareImageManagementSwim.unassign_network_device_product_name_from_the_given_software_image,
    software_image_management_swim.SoftwareImageManagementSwim.update_the_list_of_sites_for_the_network_device_product_name_assigned_to_the_software_image,
  - Paths used are
    post /dna/intent/api/v1/images/{imageId}/siteWiseProductNames,
    delete /dna/intent/api/v1/images/{imageId}/siteWiseProductNames/{productNameOrdinal},
    put /dna/intent/api/v1/images/{imageId}/siteWiseProductNames/{productNameOrdinal},
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.images_site_wise_product_names:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    imageId: string
    productNameOrdinal: 0
    siteIds:
      - string
- name: Delete by name
  cisco.dnac.images_site_wise_product_names:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    imageId: string
    productNameOrdinal: 0
- name: Update by name
  cisco.dnac.images_site_wise_product_names:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    imageId: string
    productNameOrdinal: 0
    siteIds:
      - string
"""
RETURN = r"""
dnac_response:
  description: A dictionary or list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
        "taskId": "string",
        "url": "string"
      },
      "version": "string"
    }
"""
