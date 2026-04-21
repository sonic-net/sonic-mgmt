#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: applications_v2
short_description: Resource module for Applications
  V2
description:
  - Manage operations create, update and delete of the
    resource Applications V2.
  - Create new custom application/s.
  - Delete existing custom application by id.
  - Edit the attributes of an existing application.
version_added: '6.14.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  id:
    description: Id path parameter. Id of custom application
      to delete.
    type: str
  payload:
    description: Applications V2's payload.
    elements: dict
    suboptions:
      displayName:
        description: Display name.
        type: str
      id:
        description: Application id.
        type: str
      indicativeNetworkIdentity:
        description: Applications V2's indicativeNetworkIdentity.
        elements: dict
        suboptions:
          displayName:
            description: Display name.
            type: str
          id:
            description: Id.
            type: str
          lowerPort:
            description: Lower port.
            type: float
          ports:
            description: Ports.
            type: str
          protocol:
            description: Protocol.
            type: str
          upperPort:
            description: Upper port.
            type: float
        type: list
      instanceId:
        description: Instance id.
        type: int
      instanceVersion:
        description: Instance version.
        type: float
      name:
        description: Application name.
        type: str
      namespace:
        description: Namespace.
        type: str
      networkApplications:
        description: Applications V2's networkApplications.
        elements: dict
        suboptions:
          appProtocol:
            description: App protocol.
            type: str
          applicationSubType:
            description: Application sub type, LEARNED
              discovered application, NONE nbar and
              custom application.
            type: str
          applicationType:
            description: Application type, DEFAULT nbar
              application, DEFAULT_MODIFIED nbar modified
              application, CUSTOM custom application.
            type: str
          categoryId:
            description: Category id.
            type: str
          displayName:
            description: Display name.
            type: str
          dscp:
            description: Dscp.
            type: str
          engineId:
            description: Engine id.
            type: str
          helpString:
            description: Help string.
            type: str
          id:
            description: Id.
            type: str
          ignoreConflict:
            description: Ignore conflict, true or false.
            type: bool
          longDescription:
            description: Long description.
            type: str
          name:
            description: Application name.
            type: str
          popularity:
            description: Popularity.
            type: float
          rank:
            description: Rank, any value between 1 to
              65535.
            type: int
          selectorId:
            description: Selector id.
            type: str
          serverName:
            description: Server name.
            type: str
          trafficClass:
            description: Traffic class.
            type: str
          url:
            description: Url.
            type: str
        type: list
      networkIdentity:
        description: Applications V2's networkIdentity.
        elements: dict
        suboptions:
          displayName:
            description: Display name.
            type: str
          id:
            description: Id.
            type: str
          ipv4Subnet:
            description: Ipv4 subnet.
            elements: str
            type: list
          ipv6Subnet:
            description: Ipv6 subnet.
            elements: dict
            type: list
          lowerPort:
            description: Lower port.
            type: float
          ports:
            description: Ports.
            type: str
          protocol:
            description: Protocol.
            type: str
          upperPort:
            description: Upper port.
            type: float
        type: list
      parentScalableGroup:
        description: Applications V2's parentScalableGroup.
        suboptions:
          idRef:
            description: Id reference to parent application
              set.
            type: str
        type: dict
      qualifier:
        description: Qualifier, valid value application.
        type: str
      scalableGroupExternalHandle:
        description: Scalable group external handle,
          should be equal to Application name.
        type: str
      scalableGroupType:
        description: Scalable group type, valid value
          APPLICATION.
        type: str
      type:
        description: Type, valid value scalablegroup.
        type: str
    type: list
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Application
      Policy CreateApplicationsV2
    description: Complete reference of the CreateApplicationsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!create-applications-v-2
  - name: Cisco DNA Center documentation for Application
      Policy DeleteApplicationV2
    description: Complete reference of the DeleteApplicationV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!delete-application-v-2
  - name: Cisco DNA Center documentation for Application
      Policy EditApplicationsV2
    description: Complete reference of the EditApplicationsV2
      API.
    link: https://developer.cisco.com/docs/dna-center/#!edit-applications-v-2
notes:
  - SDK Method used are
    application_policy.ApplicationPolicy.create_applications_v2,
    application_policy.ApplicationPolicy.delete_application_v2,
    application_policy.ApplicationPolicy.edit_applications_v2,
  - Paths used are
    post /dna/intent/api/v2/applications,
    delete /dna/intent/api/v2/applications/{id},
    put
    /dna/intent/api/v2/applications,
"""

EXAMPLES = r"""
---
- name: Update all
  cisco.dnac.applications_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - displayName: string
        id: string
        indicativeNetworkIdentity:
          - displayName: string
            id: string
            lowerPort: 0
            ports: string
            protocol: string
            upperPort: 0
        instanceId: 0
        instanceVersion: 0
        name: string
        namespace: string
        networkApplications:
          - appProtocol: string
            applicationSubType: string
            applicationType: string
            categoryId: string
            displayName: string
            dscp: string
            engineId: string
            helpString: string
            id: string
            ignoreConflict: true
            longDescription: string
            name: string
            popularity: 0
            rank: 0
            selectorId: string
            serverName: string
            trafficClass: string
            url: string
        networkIdentity:
          - displayName: string
            id: string
            ipv4Subnet:
              - string
            ipv6Subnet:
              - {}
            lowerPort: 0
            ports: string
            protocol: string
            upperPort: 0
        parentScalableGroup:
          idRef: string
        qualifier: string
        scalableGroupExternalHandle: string
        scalableGroupType: string
        type: string
- name: Create
  cisco.dnac.applications_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: present
    payload:
      - indicativeNetworkIdentity:
          - ipv4Subnet:
              - string
            ipv6Subnet:
              - string
            lowerPort: 0
            ports: string
            protocol: string
            upperPort: 0
        name: string
        networkApplications:
          - appProtocol: string
            applicationType: string
            categoryId: string
            dscp: string
            engineId: 0
            helpString: string
            ignoreConflict: true
            rank: 0
            serverName: string
            trafficClass: string
            type: string
            url: string
        networkIdentity:
          - ipv4Subnet:
              - string
            lowerPort: 0
            ports: string
            protocol: string
            upperPort: 0
        parentScalableGroup:
          idRef: string
        scalableGroupType: string
        type: string
- name: Delete by id
  cisco.dnac.applications_v2:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    state: absent
    id: string
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
