#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r"""
---
module: configuration_template_import_template
short_description: Resource module for Configuration
  Template Import Template
description:
  - Manage operation create of the resource Configuration
    Template Import Template.
  - Imports the templates provided in the DTO by project
    Name.
version_added: '3.1.0'
extends_documentation_fragment:
  - cisco.dnac.module
author: Rafael Campos (@racampos)
options:
  doVersion:
    description: DoVersion query parameter. If this
      flag is true then it creates a new version of
      the template with the imported contents in case
      if the templates already exists. " If this flag
      is false and if template already exists, then
      operation fails with 'Template already exists'
      error.
    type: bool
  payload:
    description: Configuration Template Import Template's
      payload.
    elements: dict
    suboptions:
      author:
        description: Author of template.
        type: str
      composite:
        description: Is it composite template.
        type: bool
      containingTemplates:
        description: Configuration Template Import Template's
          containingTemplates.
        elements: dict
        suboptions:
          composite:
            description: Is it composite template.
            type: bool
          description:
            description: Description of template.
            type: str
          deviceTypes:
            description: Configuration Template Import
              Template's deviceTypes.
            elements: dict
            suboptions:
              productFamily:
                description: Device family.
                type: str
              productSeries:
                description: Device series.
                type: str
              productType:
                description: Device type.
                type: str
            type: list
          id:
            description: UUID of template.
            type: str
          language:
            description: Template language (JINJA or
              VELOCITY).
            type: str
          name:
            description: Name of template.
            type: str
          projectName:
            description: Project name.
            type: str
          rollbackTemplateParams:
            description: Configuration Template Import
              Template's rollbackTemplateParams.
            elements: dict
            suboptions:
              binding:
                description: Bind to source.
                type: str
              customOrder:
                description: CustomOrder of template
                  param.
                type: int
              dataType:
                description: Datatype of template param.
                type: str
              defaultValue:
                description: Default value of template
                  param.
                type: str
              description:
                description: Description of template
                  param.
                type: str
              displayName:
                description: Display name of param.
                type: str
              group:
                description: Group.
                type: str
              id:
                description: UUID of template param.
                type: str
              instructionText:
                description: Instruction text for param.
                type: str
              key:
                description: Key.
                type: str
              notParam:
                description: Is it not a variable.
                type: bool
              order:
                description: Order of template param.
                type: int
              paramArray:
                description: Is it an array.
                type: bool
              parameterName:
                description: Name of template param.
                type: str
              provider:
                description: Provider.
                type: str
              range:
                description: Configuration Template
                  Import Template's range.
                elements: dict
                suboptions:
                  id:
                    description: UUID of range.
                    type: str
                  maxValue:
                    description: Max value of range.
                    type: int
                  minValue:
                    description: Min value of range.
                    type: int
                type: list
              required:
                description: Is param required.
                type: bool
              selection:
                description: Configuration Template
                  Import Template's selection.
                suboptions:
                  defaultSelectedValues:
                    description: Default selection values.
                    elements: str
                    type: list
                  id:
                    description: UUID of selection.
                    type: str
                  selectionType:
                    description: Type of selection(SINGLE_SELECT
                      or MULTI_SELECT).
                    type: str
                  selectionValues:
                    description: Selection values.
                    type: dict
                type: dict
            type: list
          tags:
            description: Configuration Template Import
              Template's tags.
            elements: dict
            suboptions:
              id:
                description: UUID of tag.
                type: str
              name:
                description: Name of tag.
                type: str
            type: list
          templateContent:
            description: Template content.
            type: str
          templateParams:
            description: Configuration Template Import
              Template's templateParams.
            elements: dict
            suboptions:
              binding:
                description: Bind to source.
                type: str
              customOrder:
                description: CustomOrder of template
                  param.
                type: int
              dataType:
                description: Datatype of template param.
                type: str
              defaultValue:
                description: Default value of template
                  param.
                type: str
              description:
                description: Description of template
                  param.
                type: str
              displayName:
                description: Display name of param.
                type: str
              group:
                description: Group.
                type: str
              id:
                description: UUID of template param.
                type: str
              instructionText:
                description: Instruction text for param.
                type: str
              key:
                description: Key.
                type: str
              notParam:
                description: Is it not a variable.
                type: bool
              order:
                description: Order of template param.
                type: int
              paramArray:
                description: Is it an array.
                type: bool
              parameterName:
                description: Name of template param.
                type: str
              provider:
                description: Provider.
                type: str
              range:
                description: Configuration Template
                  Import Template's range.
                elements: dict
                suboptions:
                  id:
                    description: UUID of range.
                    type: str
                  maxValue:
                    description: Max value of range.
                    type: int
                  minValue:
                    description: Min value of range.
                    type: int
                type: list
              required:
                description: Is param required.
                type: bool
              selection:
                description: Configuration Template
                  Import Template's selection.
                suboptions:
                  defaultSelectedValues:
                    description: Default selection values.
                    elements: str
                    type: list
                  id:
                    description: UUID of selection.
                    type: str
                  selectionType:
                    description: Type of selection(SINGLE_SELECT
                      or MULTI_SELECT).
                    type: str
                  selectionValues:
                    description: Selection values.
                    type: dict
                type: dict
            type: list
          version:
            description: Current version of template.
            type: str
        type: list
      createTime:
        description: Create time of template.
        type: int
      customParamsOrder:
        description: Custom Params Order.
        type: bool
      description:
        description: Description of template.
        type: str
      deviceTypes:
        description: Configuration Template Import Template's
          deviceTypes.
        elements: dict
        suboptions:
          productFamily:
            description: Device family.
            type: str
          productSeries:
            description: Device series.
            type: str
          productType:
            description: Device type.
            type: str
        type: list
      failurePolicy:
        description: Define failure policy if template
          provisioning fails.
        type: str
      id:
        description: UUID of template.
        type: str
      language:
        description: Template language (JINJA or VELOCITY).
        type: str
      lastUpdateTime:
        description: Update time of template.
        type: int
      latestVersionTime:
        description: Latest versioned template time.
        type: int
      name:
        description: Name of template.
        type: str
      parentTemplateId:
        description: Parent templateID.
        type: str
      projectId:
        description: Project UUID.
        type: str
      projectName:
        description: Project name.
        type: str
      rollbackTemplateContent:
        description: Rollback template content.
        type: str
      rollbackTemplateParams:
        description: Configuration Template Import Template's
          rollbackTemplateParams.
        elements: dict
        suboptions:
          binding:
            description: Bind to source.
            type: str
          customOrder:
            description: CustomOrder of template param.
            type: int
          dataType:
            description: Datatype of template param.
            type: str
          defaultValue:
            description: Default value of template param.
            type: str
          description:
            description: Description of template param.
            type: str
          displayName:
            description: Display name of param.
            type: str
          group:
            description: Group.
            type: str
          id:
            description: UUID of template param.
            type: str
          instructionText:
            description: Instruction text for param.
            type: str
          key:
            description: Key.
            type: str
          notParam:
            description: Is it not a variable.
            type: bool
          order:
            description: Order of template param.
            type: int
          paramArray:
            description: Is it an array.
            type: bool
          parameterName:
            description: Name of template param.
            type: str
          provider:
            description: Provider.
            type: str
          range:
            description: Configuration Template Import
              Template's range.
            elements: dict
            suboptions:
              id:
                description: UUID of range.
                type: str
              maxValue:
                description: Max value of range.
                type: int
              minValue:
                description: Min value of range.
                type: int
            type: list
          required:
            description: Is param required.
            type: bool
          selection:
            description: Configuration Template Import
              Template's selection.
            suboptions:
              defaultSelectedValues:
                description: Default selection values.
                elements: str
                type: list
              id:
                description: UUID of selection.
                type: str
              selectionType:
                description: Type of selection(SINGLE_SELECT
                  or MULTI_SELECT).
                type: str
              selectionValues:
                description: Selection values.
                type: dict
            type: dict
        type: list
      softwareType:
        description: Applicable device software type.
        type: str
      softwareVariant:
        description: Applicable device software variant.
        type: str
      softwareVersion:
        description: Applicable device software version.
        type: str
      tags:
        description: Configuration Template Import Template's
          tags.
        elements: dict
        suboptions:
          id:
            description: UUID of tag.
            type: str
          name:
            description: Name of tag.
            type: str
        type: list
      templateContent:
        description: Template content.
        type: str
      templateParams:
        description: Configuration Template Import Template's
          templateParams.
        elements: dict
        suboptions:
          binding:
            description: Bind to source.
            type: str
          customOrder:
            description: CustomOrder of template param.
            type: int
          dataType:
            description: Datatype of template param.
            type: str
          defaultValue:
            description: Default value of template param.
            type: str
          description:
            description: Description of template param.
            type: str
          displayName:
            description: Display name of param.
            type: str
          group:
            description: Group.
            type: str
          id:
            description: UUID of template param.
            type: str
          instructionText:
            description: Instruction text for param.
            type: str
          key:
            description: Key.
            type: str
          notParam:
            description: Is it not a variable.
            type: bool
          order:
            description: Order of template param.
            type: int
          paramArray:
            description: Is it an array.
            type: bool
          parameterName:
            description: Name of template param.
            type: str
          provider:
            description: Provider.
            type: str
          range:
            description: Configuration Template Import
              Template's range.
            elements: dict
            suboptions:
              id:
                description: UUID of range.
                type: str
              maxValue:
                description: Max value of range.
                type: int
              minValue:
                description: Min value of range.
                type: int
            type: list
          required:
            description: Is param required.
            type: bool
          selection:
            description: Configuration Template Import
              Template's selection.
            suboptions:
              defaultSelectedValues:
                description: Default selection values.
                elements: str
                type: list
              id:
                description: UUID of selection.
                type: str
              selectionType:
                description: Type of selection(SINGLE_SELECT
                  or MULTI_SELECT).
                type: str
              selectionValues:
                description: Selection values.
                type: dict
            type: dict
        type: list
      validationErrors:
        description: Configuration Template Import Template's
          validationErrors.
        suboptions:
          rollbackTemplateErrors:
            description: Validation or design conflicts
              errors of rollback template.
            type: dict
          templateErrors:
            description: Validation or design conflicts
              errors.
            type: dict
          templateId:
            description: UUID of template.
            type: str
          templateVersion:
            description: Current version of template.
            type: str
        type: dict
      version:
        description: Current version of template.
        type: str
    type: list
  projectName:
    description: ProjectName path parameter. Project
      name to create template under the project.
    type: str
requirements:
  - dnacentersdk >= 2.10.1
  - python >= 3.5
seealso:
  - name: Cisco DNA Center documentation for Configuration
      Templates ImportsTheTemplatesProvided
    description: Complete reference of the ImportsTheTemplatesProvided
      API.
    link: https://developer.cisco.com/docs/dna-center/#!imports-the-templates-provided
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.imports_the_templates_provided,
  - Paths used are
    post /dna/intent/api/v1/template-programmer/project/name/{projectName}/template/importtemplates,
"""

EXAMPLES = r"""
---
- name: Create
  cisco.dnac.configuration_template_import_template:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    doVersion: true
    payload:
      - author: string
        composite: true
        containingTemplates:
          - composite: true
            description: string
            deviceTypes:
              - productFamily: string
                productSeries: string
                productType: string
            id: string
            language: string
            name: string
            projectName: string
            rollbackTemplateParams:
              - binding: string
                customOrder: 0
                dataType: string
                defaultValue: string
                description: string
                displayName: string
                group: string
                id: string
                instructionText: string
                key: string
                notParam: true
                order: 0
                paramArray: true
                parameterName: string
                provider: string
                range:
                  - id: string
                    maxValue: 0
                    minValue: 0
                required: true
                selection:
                  defaultSelectedValues:
                    - string
                  id: string
                  selectionType: string
                  selectionValues: {}
            tags:
              - id: string
                name: string
            templateContent: string
            templateParams:
              - binding: string
                customOrder: 0
                dataType: string
                defaultValue: string
                description: string
                displayName: string
                group: string
                id: string
                instructionText: string
                key: string
                notParam: true
                order: 0
                paramArray: true
                parameterName: string
                provider: string
                range:
                  - id: string
                    maxValue: 0
                    minValue: 0
                required: true
                selection:
                  defaultSelectedValues:
                    - string
                  id: string
                  selectionType: string
                  selectionValues: {}
            version: string
        createTime: 0
        customParamsOrder: true
        description: string
        deviceTypes:
          - productFamily: string
            productSeries: string
            productType: string
        failurePolicy: string
        id: string
        language: string
        lastUpdateTime: 0
        latestVersionTime: 0
        name: string
        parentTemplateId: string
        projectId: string
        projectName: string
        rollbackTemplateContent: string
        rollbackTemplateParams:
          - binding: string
            customOrder: 0
            dataType: string
            defaultValue: string
            description: string
            displayName: string
            group: string
            id: string
            instructionText: string
            key: string
            notParam: true
            order: 0
            paramArray: true
            parameterName: string
            provider: string
            range:
              - id: string
                maxValue: 0
                minValue: 0
            required: true
            selection:
              defaultSelectedValues:
                - string
              id: string
              selectionType: string
              selectionValues: {}
        softwareType: string
        softwareVariant: string
        softwareVersion: string
        tags:
          - id: string
            name: string
        templateContent: string
        templateParams:
          - binding: string
            customOrder: 0
            dataType: string
            defaultValue: string
            description: string
            displayName: string
            group: string
            id: string
            instructionText: string
            key: string
            notParam: true
            order: 0
            paramArray: true
            parameterName: string
            provider: string
            range:
              - id: string
                maxValue: 0
                minValue: 0
            required: true
            selection:
              defaultSelectedValues:
                - string
              id: string
              selectionType: string
              selectionValues: {}
        validationErrors:
          rollbackTemplateErrors: {}
          templateErrors: {}
          templateId: string
          templateVersion: string
        version: string
    projectName: string
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
