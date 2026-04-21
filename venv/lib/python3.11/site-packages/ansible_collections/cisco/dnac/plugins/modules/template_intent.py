#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2022, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on project and templates in DNAC."""
from __future__ import absolute_import, division, print_function

__metaclass__ = type
__author__ = [
    "Madhan Sankaranarayanan, Rishita Chowdhary, Akash Bhaskaran, Muthu Rakesh"
]
DOCUMENTATION = r"""
---
module: template_intent
short_description: Resource module for Template functions
description:
  - Manage operations create, update and delete of the
    resource Configuration Template.
  - API to create a template by project name and template
    name.
  - API to update a template by template name and project
    name.
  - API to delete a template by template name and project
    name.
  - API to export the projects for given projectNames.
  - API to export the templates for given templateIds.
  - API to manage operation create of the resource Configuration
    Template Import Project.
  - API to manage operation create of the resource Configuration
    Template Import Template.
version_added: '6.6.0'
extends_documentation_fragment:
  - cisco.dnac.intent_params
author: Madhan Sankaranarayanan (@madhansansel) Rishita
  Chowdhary (@rishitachowdhary) Akash Bhaskaran (@akabhask)
  Muthu Rakesh (@MUTHU-RAKESH-27)
options:
  config_verify:
    description: Set to True to verify the Cisco DNA
      Center after applying the playbook config.
    type: bool
    default: false
  state:
    description: The state of DNAC after module completion.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description:
      - List of details of templates being managed.
    type: list
    elements: dict
    required: true
    suboptions:
      configuration_templates:
        description: Create/Update/Delete template.
        type: dict
        suboptions:
          author:
            description: Author of template.
            type: str
          composite:
            description: Is it composite template.
            type: bool
          containing_templates:
            description: Configuration Template Create's
              containingTemplates.
            suboptions:
              composite:
                description: Is it composite template.
                type: bool
              description:
                description: Description of template.
                type: str
              device_types:
                description: deviceTypes on which templates
                  would be applied.
                type: list
                elements: dict
                suboptions:
                  product_family:
                    description: Device family.
                    type: str
                  product_series:
                    description: Device series.
                    type: str
                  product_type:
                    description: Device type.
                    type: str
              id:
                description: UUID of template.
                type: str
              language:
                description: Template language
                choices:
                  - JINJA
                  - VELOCITY
                type: str
              name:
                description: Name of template.
                type: str
              project_name:
                description: Name of the project under
                  which templates are managed.
                type: str
              project_description:
                description: Description of the project
                  created.
                type: str
              rollback_template_params:
                description: Params required for template
                  rollback.
                type: list
                elements: dict
                suboptions:
                  binding:
                    description: Bind to source.
                    type: str
                  custom_order:
                    description: CustomOrder of template
                      param.
                    type: int
                  data_type:
                    description: Datatype of template
                      param.
                    type: str
                  default_value:
                    description: Default value of template
                      param.
                    type: str
                  description:
                    description: Description of template
                      param.
                    type: str
                  display_name:
                    description: Display name of param.
                    type: str
                  group:
                    description: Group.
                    type: str
                  id:
                    description: UUID of template param.
                    type: str
                  instruction_text:
                    description: Instruction text for
                      param.
                    type: str
                  key:
                    description: Key.
                    type: str
                  not_param:
                    description: Is it not a variable.
                    type: bool
                  order:
                    description: Order of template param.
                    type: int
                  param_array:
                    description: Is it an array.
                    type: bool
                  parameter_name:
                    description: Name of template param.
                    type: str
                  provider:
                    description: Provider.
                    type: str
                  range:
                    description: Configuration Template
                      Create's range.
                    type: list
                    elements: dict
                    suboptions:
                      id:
                        description: UUID of range.
                        type: str
                      max_value:
                        description: Max value of range.
                        type: int
                      min_value:
                        description: Min value of range.
                        type: int
                  required:
                    description: Is param required.
                    type: bool
                  selection:
                    description: Configuration Template
                      Create's selection.
                    suboptions:
                      default_selected_values:
                        description: Default selection
                          values.
                        elements: str
                        type: list
                      id:
                        description: UUID of selection.
                        type: str
                      selection_type:
                        description: Type of selection(SINGLE_SELECT
                          or MULTI_SELECT).
                        type: str
                      selection_values:
                        description: Selection values.
                        type: dict
                    type: dict
              tags:
                description: Configuration Template
                  Create's tags.
                suboptions:
                  id:
                    description: UUID of tag.
                    type: str
                  name:
                    description: Name of tag.
                    type: str
                type: list
                elements: dict
              template_content:
                description: Template content.
                type: str
              template_params:
                description: Configuration Template
                  Create's templateParams.
                elements: dict
                suboptions:
                  binding:
                    description: Bind to source.
                    type: str
                  custom_order:
                    description: CustomOrder of template
                      param.
                    type: int
                  data_type:
                    description: Datatype of template
                      param.
                    type: str
                  default_value:
                    description: Default value of template
                      param.
                    type: str
                  description:
                    description: Description of template
                      param.
                    type: str
                  display_name:
                    description: Display name of param.
                    type: str
                  group:
                    description: Group.
                    type: str
                  id:
                    description: UUID of template param.
                    type: str
                  instruction_text:
                    description: Instruction text for
                      param.
                    type: str
                  key:
                    description: Key.
                    type: str
                  not_param:
                    description: Is it not a variable.
                    type: bool
                  order:
                    description: Order of template param.
                    type: int
                  param_array:
                    description: Is it an array.
                    type: bool
                  parameter_name:
                    description: Name of template param.
                    type: str
                  provider:
                    description: Provider.
                    type: str
                  range:
                    description: Configuration Template
                      Create's range.
                    suboptions:
                      id:
                        description: UUID of range.
                        type: str
                      max_value:
                        description: Max value of range.
                        type: int
                      min_value:
                        description: Min value of range.
                        type: int
                    type: list
                    elements: dict
                  required:
                    description: Is param required.
                    type: bool
                  selection:
                    description: Configuration Template
                      Create's selection.
                    suboptions:
                      default_selected_values:
                        description: Default selection
                          values.
                        elements: str
                        type: list
                      id:
                        description: UUID of selection.
                        type: str
                      selection_type:
                        description: Type of selection(SINGLE_SELECT
                          or MULTI_SELECT).
                        type: str
                      selection_values:
                        description: Selection values.
                        type: dict
                    type: dict
                type: list
              version:
                description: Current version of template.
                type: str
            type: list
            elements: dict
          create_time:
            description: Create time of template.
            type: int
          custom_params_order:
            description: Custom Params Order.
            type: bool
          template_description:
            description: Description of template.
            type: str
          device_types:
            description: Configuration Template Create's
              deviceTypes. This field is mandatory to
              create a new template.
            suboptions:
              product_family:
                description: Device family.
                type: str
              product_series:
                description: Device series.
                type: str
              product_type:
                description: Device type.
                type: str
            type: list
            elements: dict
          failure_policy:
            description: Define failure policy if template
              provisioning fails.
            type: str
          id:
            description: UUID of template.
            type: str
          language:
            description: Template language
            choices:
              - JINJA
              - VELOCITY
            type: str
          last_update_time:
            description: Update time of template.
            type: int
          latest_version_time:
            description: Latest versioned template time.
            type: int
          template_name:
            description: Name of template. This field
              is mandatory to create a new template.
            type: str
          parent_template_id:
            description: Parent templateID.
            type: str
          project_id:
            description: Project UUID.
            type: str
          project_name:
            description: Project name.
            type: str
          project_description:
            description: Project Description.
            type: str
          rollback_template_content:
            description: Rollback template content.
            type: str
          rollback_template_params:
            description: Configuration Template Create's
              rollbackTemplateParams.
            suboptions:
              binding:
                description: Bind to source.
                type: str
              custom_order:
                description: CustomOrder of template
                  param.
                type: int
              data_type:
                description: Datatype of template param.
                type: str
              default_value:
                description: Default value of template
                  param.
                type: str
              description:
                description: Description of template
                  param.
                type: str
              display_name:
                description: Display name of param.
                type: str
              group:
                description: Group.
                type: str
              id:
                description: UUID of template param.
                type: str
              instruction_text:
                description: Instruction text for param.
                type: str
              key:
                description: Key.
                type: str
              not_param:
                description: Is it not a variable.
                type: bool
              order:
                description: Order of template param.
                type: int
              param_array:
                description: Is it an array.
                type: bool
              parameter_name:
                description: Name of template param.
                type: str
              provider:
                description: Provider.
                type: str
              range:
                description: Configuration Template
                  Create's range.
                suboptions:
                  id:
                    description: UUID of range.
                    type: str
                  max_value:
                    description: Max value of range.
                    type: int
                  min_value:
                    description: Min value of range.
                    type: int
                type: list
                elements: dict
              required:
                description: Is param required.
                type: bool
              selection:
                description: Configuration Template
                  Create's selection.
                suboptions:
                  default_selected_values:
                    description: Default selection values.
                    elements: str
                    type: list
                  id:
                    description: UUID of selection.
                    type: str
                  selection_type:
                    description: Type of selection(SINGLE_SELECT
                      or MULTI_SELECT).
                    type: str
                  selection_values:
                    description: Selection values.
                    type: dict
                type: dict
            type: list
            elements: dict
          software_type:
            description: Applicable device software
              type. This field is mandatory to create
              a new template.
            type: str
          software_variant:
            description: Applicable device software
              variant.
            type: str
          software_version:
            description: Applicable device software
              version.
            type: str
          template_tag:
            description: Configuration Template Create's
              tags.
            suboptions:
              id:
                description: UUID of tag.
                type: str
              name:
                description: Name of tag.
                type: str
            type: list
            elements: dict
          template_content:
            description: Template content.
            type: str
          template_params:
            description: Configuration Template Create's
              templateParams.
            suboptions:
              binding:
                description: Bind to source.
                type: str
              custom_order:
                description: CustomOrder of template
                  param.
                type: int
              data_type:
                description: Datatype of template param.
                type: str
              default_value:
                description: Default value of template
                  param.
                type: str
              description:
                description: Description of template
                  param.
                type: str
              display_name:
                description: Display name of param.
                type: str
              group:
                description: Group.
                type: str
              id:
                description: UUID of template param.
                type: str
              instruction_text:
                description: Instruction text for param.
                type: str
              key:
                description: Key.
                type: str
              not_param:
                description: Is it not a variable.
                type: bool
              order:
                description: Order of template param.
                type: int
              param_array:
                description: Is it an array.
                type: bool
              parameter_name:
                description: Name of template param.
                type: str
              provider:
                description: Provider.
                type: str
              range:
                description: Configuration Template
                  Create's range.
                suboptions:
                  id:
                    description: UUID of range.
                    type: str
                  max_value:
                    description: Max value of range.
                    type: int
                  min_value:
                    description: Min value of range.
                    type: int
                type: list
                elements: dict
              required:
                description: Is param required.
                type: bool
              selection:
                description: Configuration Template
                  Create's selection.
                suboptions:
                  default_selected_values:
                    description: Default selection values.
                    elements: str
                    type: list
                  id:
                    description: UUID of selection.
                    type: str
                  selection_type:
                    description: Type of selection(SINGLE_SELECT
                      or MULTI_SELECT).
                    type: str
                  selection_values:
                    description: Selection values.
                    type: dict
                type: dict
            type: list
            elements: dict
          validation_errors:
            description: Configuration Template Create's
              validationErrors.
            suboptions:
              rollback_template_errors:
                description: Validation or design conflicts
                  errors of rollback template.
                elements: dict
                type: list
              template_errors:
                description: Validation or design conflicts
                  errors.
                elements: dict
                type: list
              template_id:
                description: UUID of template.
                type: str
              template_version:
                description: Current version of template.
                type: str
            type: dict
          version:
            description: Current version of template.
            type: str
          version_description:
            description: Template version comments.
            type: str
      export:
        description: Export the project/template details.
        type: dict
        suboptions:
          project:
            description: Export the project.
            type: list
            elements: str
          template:
            description: Export the template.
            type: list
            elements: dict
            suboptions:
              project_name:
                description: Name of the project under
                  the template available.
                type: str
              template_name:
                description: Name of the template which
                  we need to export
                type: str
      import:
        description: Import the project/template details.
        type: dict
        suboptions:
          project:
            description: Import the project details.
            type: dict
            suboptions:
              do_version:
                description: DoVersion query parameter.
                  If this flag is true, creates a new
                  version of the template with the imported
                  contents, if the templates already
                  exists. " If false and if template
                  already exists, then operation fails
                  with 'Template already exists' error.
                type: bool
          template:
            description: Import the template details.
            type: dict
            suboptions:
              do_version:
                description: DoVersion query parameter.
                  If this flag is true, creates a new
                  version of the template with the imported
                  contents, if the templates already
                  exists. " If false and if template
                  already exists, then operation fails
                  with 'Template already exists' error.
                type: bool
              payload:
                description: Configuration Template
                  Import Template's payload.
                elements: dict
                suboptions:
                  author:
                    description: Author of template.
                    type: str
                  composite:
                    description: Is it composite template.
                    type: bool
                  containing_templates:
                    description: Configuration Template
                      Import Template's containingTemplates.
                    elements: dict
                    suboptions:
                      composite:
                        description: Is it composite
                          template.
                        type: bool
                      description:
                        description: Description of
                          template.
                        type: str
                      device_types:
                        description: Configuration Template
                          Import Template's deviceTypes.
                        elements: dict
                        suboptions:
                          product_family:
                            description: Device family.
                            type: str
                          product_series:
                            description: Device series.
                            type: str
                          product_type:
                            description: Device type.
                            type: str
                        type: list
                      id:
                        description: UUID of template.
                        type: str
                      language:
                        description: Template language
                          (JINJA or VELOCITY).
                        type: str
                      name:
                        description: Name of template.
                        type: str
                      project_name:
                        description: Project name.
                        type: str
                      rollback_template_params:
                        description: Configuration Template
                          Import Template's rollbackTemplateParams.
                        elements: dict
                        suboptions:
                          binding:
                            description: Bind to source.
                            type: str
                          custom_order:
                            description: CustomOrder
                              of template param.
                            type: int
                          data_type:
                            description: Datatype of
                              template param.
                            type: str
                          default_value:
                            description: Default value
                              of template param.
                            type: str
                          description:
                            description: Description
                              of template param.
                            type: str
                          display_name:
                            description: Display name
                              of param.
                            type: str
                          group:
                            description: Group.
                            type: str
                          id:
                            description: UUID of template
                              param.
                            type: str
                          instruction_text:
                            description: Instruction
                              text for param.
                            type: str
                          key:
                            description: Key.
                            type: str
                          not_param:
                            description: Is it not a
                              variable.
                            type: bool
                          order:
                            description: Order of template
                              param.
                            type: int
                          param_array:
                            description: Is it an array.
                            type: bool
                          parameter_name:
                            description: Name of template
                              param.
                            type: str
                          provider:
                            description: Provider.
                            type: str
                          range:
                            description: Configuration
                              Template Import Template's
                              range.
                            elements: dict
                            suboptions:
                              id:
                                description: UUID of
                                  range.
                                type: str
                              max_value:
                                description: Max value
                                  of range.
                                type: int
                              min_value:
                                description: Min value
                                  of range.
                                type: int
                            type: list
                          required:
                            description: Is param required.
                            type: bool
                          selection:
                            description: Configuration
                              Template Import Template's
                              selection.
                            suboptions:
                              default_selected_values:
                                description: Default
                                  selection values.
                                elements: str
                                type: list
                              id:
                                description: UUID of
                                  selection.
                                type: str
                              selection_type:
                                description: Type of
                                  selection(SINGLE_SELECT
                                  or MULTI_SELECT).
                                type: str
                              selection_values:
                                description: Selection
                                  values.
                                type: dict
                            type: dict
                        type: list
                      tags:
                        description: Configuration Template
                          Import Template's tags.
                        elements: dict
                        suboptions:
                          id:
                            description: UUID of tag.
                            type: str
                          name:
                            description: Name of tag.
                            type: str
                        type: list
                      template_content:
                        description: Template content.
                        type: str
                      template_params:
                        description: Configuration Template
                          Import Template's templateParams.
                        elements: dict
                        suboptions:
                          binding:
                            description: Bind to source.
                            type: str
                          custom_order:
                            description: CustomOrder
                              of template param.
                            type: int
                          data_type:
                            description: Datatype of
                              template param.
                            type: str
                          default_value:
                            description: Default value
                              of template param.
                            type: str
                          description:
                            description: Description
                              of template param.
                            type: str
                          display_name:
                            description: Display name
                              of param.
                            type: str
                          group:
                            description: Group.
                            type: str
                          id:
                            description: UUID of template
                              param.
                            type: str
                          instruction_text:
                            description: Instruction
                              text for param.
                            type: str
                          key:
                            description: Key.
                            type: str
                          not_param:
                            description: Is it not a
                              variable.
                            type: bool
                          order:
                            description: Order of template
                              param.
                            type: int
                          param_array:
                            description: Is it an array.
                            type: bool
                          parameter_name:
                            description: Name of template
                              param.
                            type: str
                          provider:
                            description: Provider.
                            type: str
                          range:
                            description: Configuration
                              Template Import Template's
                              range.
                            elements: dict
                            suboptions:
                              id:
                                description: UUID of
                                  range.
                                type: str
                              max_value:
                                description: Max value
                                  of range.
                                type: int
                              min_value:
                                description: Min value
                                  of range.
                                type: int
                            type: list
                          required:
                            description: Is param required.
                            type: bool
                          selection:
                            description: Configuration
                              Template Import Template's
                              selection.
                            suboptions:
                              default_selected_values:
                                description: Default
                                  selection values.
                                elements: str
                                type: list
                              id:
                                description: UUID of
                                  selection.
                                type: str
                              selection_type:
                                description: Type of
                                  selection(SINGLE_SELECT
                                  or MULTI_SELECT).
                                type: str
                              selection_values:
                                description: Selection
                                  values.
                                type: dict
                            type: dict
                        type: list
                      version:
                        description: Current version
                          of template.
                        type: str
                    type: list
                  create_time:
                    description: Create time of template.
                    type: int
                  custom_params_order:
                    description: Custom Params Order.
                    type: bool
                  description:
                    description: Description of template.
                    type: str
                  device_types:
                    description: Configuration Template
                      Import Template's deviceTypes.
                    elements: dict
                    suboptions:
                      product_family:
                        description: Device family.
                        type: str
                      product_series:
                        description: Device series.
                        type: str
                      product_type:
                        description: Device type.
                        type: str
                    type: list
                  failure_policy:
                    description: Define failure policy
                      if template provisioning fails.
                    type: str
                  id:
                    description: UUID of template.
                    type: str
                  language:
                    description: Template language (JINJA
                      or VELOCITY).
                    type: str
                  last_update_time:
                    description: Update time of template.
                    type: int
                  latest_version_time:
                    description: Latest versioned template
                      time.
                    type: int
                  name:
                    description: Name of template.
                    type: str
                  parent_template_id:
                    description: Parent templateID.
                    type: str
                  project_id:
                    description: Project UUID.
                    type: str
                  project_name:
                    description: Project name.
                    type: str
                  rollback_template_content:
                    description: Rollback template content.
                    type: str
                  rollback_template_params:
                    description: Configuration Template
                      Import Template's rollbackTemplateParams.
                    elements: dict
                    suboptions:
                      binding:
                        description: Bind to source.
                        type: str
                      custom_order:
                        description: CustomOrder of
                          template param.
                        type: int
                      data_type:
                        description: Datatype of template
                          param.
                        type: str
                      default_value:
                        description: Default value of
                          template param.
                        type: str
                      description:
                        description: Description of
                          template param.
                        type: str
                      display_name:
                        description: Display name of
                          param.
                        type: str
                      group:
                        description: Group.
                        type: str
                      id:
                        description: UUID of template
                          param.
                        type: str
                      instruction_text:
                        description: Instruction text
                          for param.
                        type: str
                      key:
                        description: Key.
                        type: str
                      not_param:
                        description: Is it not a variable.
                        type: bool
                      order:
                        description: Order of template
                          param.
                        type: int
                      param_array:
                        description: Is it an array.
                        type: bool
                      parameter_name:
                        description: Name of template
                          param.
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
                          max_value:
                            description: Max value of
                              range.
                            type: int
                          min_value:
                            description: Min value of
                              range.
                            type: int
                        type: list
                      required:
                        description: Is param required.
                        type: bool
                      selection:
                        description: Configuration Template
                          Import Template's selection.
                        suboptions:
                          default_selected_values:
                            description: Default selection
                              values.
                            elements: str
                            type: list
                          id:
                            description: UUID of selection.
                            type: str
                          selection_type:
                            description: Type of selection(SINGLE_SELECT
                              or MULTI_SELECT).
                            type: str
                          selection_values:
                            description: Selection values.
                            type: dict
                        type: dict
                    type: list
                  software_type:
                    description: Applicable device software
                      type.
                    type: str
                  software_variant:
                    description: Applicable device software
                      variant.
                    type: str
                  software_version:
                    description: Applicable device software
                      version.
                    type: str
                  tags:
                    description: Configuration Template
                      Import Template's tags.
                    elements: dict
                    suboptions:
                      id:
                        description: UUID of tag.
                        type: str
                      name:
                        description: Name of tag.
                        type: str
                    type: list
                  template_content:
                    description: Template content.
                    type: str
                  template_params:
                    description: Configuration Template
                      Import Template's templateParams.
                    elements: dict
                    suboptions:
                      binding:
                        description: Bind to source.
                        type: str
                      custom_order:
                        description: CustomOrder of
                          template param.
                        type: int
                      data_type:
                        description: Datatype of template
                          param.
                        type: str
                      default_value:
                        description: Default value of
                          template param.
                        type: str
                      description:
                        description: Description of
                          template param.
                        type: str
                      display_name:
                        description: Display name of
                          param.
                        type: str
                      group:
                        description: Group.
                        type: str
                      id:
                        description: UUID of template
                          param.
                        type: str
                      instruction_text:
                        description: Instruction text
                          for param.
                        type: str
                      key:
                        description: Key.
                        type: str
                      not_param:
                        description: Is it not a variable.
                        type: bool
                      order:
                        description: Order of template
                          param.
                        type: int
                      param_array:
                        description: Is it an array.
                        type: bool
                      parameter_name:
                        description: Name of template
                          param.
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
                          max_value:
                            description: Max value of
                              range.
                            type: int
                          min_value:
                            description: Min value of
                              range.
                            type: int
                        type: list
                      required:
                        description: Is param required.
                        type: bool
                      selection:
                        description: Configuration Template
                          Import Template's selection.
                        suboptions:
                          default_selected_values:
                            description: Default selection
                              values.
                            elements: str
                            type: list
                          id:
                            description: UUID of selection.
                            type: str
                          selection_type:
                            description: Type of selection(SINGLE_SELECT
                              or MULTI_SELECT).
                            type: str
                          selection_values:
                            description: Selection values.
                            type: dict
                        type: dict
                    type: list
                  validation_errors:
                    description: Configuration Template
                      Import Template's validationErrors.
                    suboptions:
                      rollback_template_errors:
                        description: Validation or design
                          conflicts errors of rollback
                          template.
                        type: dict
                      template_errors:
                        description: Validation or design
                          conflicts errors.
                        type: dict
                      template_id:
                        description: UUID of template.
                        type: str
                      template_version:
                        description: Current version
                          of template.
                        type: str
                    type: dict
                  version:
                    description: Current version of
                      template.
                    type: str
                type: list
              project_name:
                description: ProjectName path parameter.
                  Project name to create template under
                  the project.
                type: str
requirements:
  - dnacentersdk == 2.4.5
  - python >= 3.9
notes:
  - SDK Method used are
    configuration_templates.ConfigurationTemplates.create_template,
    configuration_templates.ConfigurationTemplates.deletes_the_template,
    configuration_templates.ConfigurationTemplates.update_template,
    configuration_templates.ConfigurationTemplates.export_projects,
    configuration_templates.ConfigurationTemplates.export_templates,
    configuration_templates.ConfigurationTemplates.imports_the_projects_provided,
    configuration_templates.ConfigurationTemplates.imports_the_templates_provided,
  - Paths used are
    post /dna/intent/api/v1/template-programmer/project/{projectId}/template,
    delete /dna/intent/api/v1/template-programmer/template/{templateId},
    put /dna/intent/api/v1/template-programmer/template,
    post /dna/intent/api/v1/template-programmer/project/name/exportprojects,
    post /dna/intent/api/v1/template-programmer/template/exporttemplates,
    post /dna/intent/api/v1/template-programmer/project/importprojects,
    post /dna/intent/api/v1/template-programmer/project/name/{projectName}/template/importtemplates,
"""
EXAMPLES = r"""
---
- name: Create a new template, export and import the
    project and template.
  cisco.dnac.template_intent:
    dnac_host: "{{dnac_host}}"
    dnac_username: "{{dnac_username}}"
    dnac_password: "{{dnac_password}}"
    dnac_verify: "{{dnac_verify}}"
    dnac_port: "{{dnac_port}}"
    dnac_version: "{{dnac_version}}"
    dnac_debug: "{{dnac_debug}}"
    dnac_log: true
    dnac_log_level: "{{dnac_log_level}}"
    state: merged
    config_verify: true
    config:
      - configuration_templates:
          author: string
          composite: true
          create_time: 0
          custom_params_order: true
          description: string
          device_types:
            - product_family: string
              product_series: string
              product_type: string
          failure_policy: string
          id: string
          language: string
          last_update_time: 0
          latest_version_time: 0
          name: string
          parent_template_id: string
          project_id: string
          project_name: string
          project_description: string
          rollback_template_content: string
          software_type: string
          software_variant: string
          software_version: string
          tags:
            - id: string
              name: string
          template_content: string
          validation_errors:
            rollback_template_errors:
              - {}
            template_errors:
              - {}
            template_id: string
            template_version: string
          version: string
        export:
          project:
            - string
          template:
            - project_name: string
              template_name: string
        import:
          project:
            do_version: true
          export:
            do_version: true
            payload:
              - author: string
                composite: true
                containing_templates:
                  - composite: true
                    description: string
                    device_types:
                      - product_family: string
                        product_series: string
                        product_type: string
                    id: string
                    language: string
                    name: string
                    project_name: string
                    rollback_template_params:
                      - binding: string
                        custom_order: 0
                        data_type: string
                        default_value: string
                        description: string
                        display_name: string
                        group: string
                        id: string
                        instruction_text: string
                        key: string
                        not_param: true
                        order: 0
                        param_array: true
                        parameter_name: string
                        provider: string
                        range:
                          - id: string
                project_name: string
"""
RETURN = r"""
# Case_1: Successful creation/updation/deletion of template/project
response_1:
  description: A dictionary with versioning details of the template as returned by the DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {
                        "endTime": 0,
                        "version": 0,
                        "data": String,
                        "startTime": 0,
                        "username": String,
                        "progress": String,
                        "serviceType": String, "rootId": String,
                        "isError": bool,
                        "instanceTenantId": String,
                        "id": String
                        "version": 0
                  },
      "msg": String
    }
# Case_2: Error while deleting a template or when given project is not found
response_2:
  description: A list with the response returned by the Cisco DNAC Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }
# Case_3: Given template already exists and requires no update
response_3:
  description: A dictionary with the exisiting template deatails as returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "msg": String
    }
# Case_4: Given template list that needs to be exported
response_4:
  description: Details of the templates in the list as returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "msg": String
    }
# Case_5: Given project list that needs to be exported
response_5:
  description: Details of the projects in the list as returned by the Cisco DNAC Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "msg": String
    }
"""

import copy
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    DnacBase,
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
)


class DnacTemplate(DnacBase):
    """Class containing member attributes for template intent module"""

    def __init__(self, module):
        super().__init__(module)
        self.have_project = {}
        self.have_template = {}
        self.supported_states = ["merged", "deleted"]
        self.accepted_languages = ["JINJA", "VELOCITY"]
        self.export_template = []
        self.result["response"].append({})

    def validate_input(self):
        """
        Validate the fields provided in the playbook.
        Checks the configuration provided in the playbook against a predefined specification
        to ensure it adheres to the expected structure and data types.
        Parameters:
            self: The instance of the class containing the 'config' attribute to be validated.
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
            self.msg = "config not available in playbook for validattion"
            self.status = "success"
            return self

        temp_spec = {
            "configuration_templates": {
                "type": "dict",
                "tags": {"type": "list"},
                "author": {"type": "str"},
                "composite": {"type": "bool"},
                "containing_templates": {"type": "list"},
                "create_time": {"type": "int"},
                "custom_params_order": {"type": "bool"},
                "description": {"type": "str"},
                "device_types": {
                    "type": "list",
                    "elements": "dict",
                    "product_family": {"type": "str"},
                    "product_series": {"type": "str"},
                    "product_type": {"type": "str"},
                },
                "failure_policy": {"type": "str"},
                "id": {"type": "str"},
                "language": {"type": "str"},
                "last_update_time": {"type": "int"},
                "latest_version_time": {"type": "int"},
                "name": {"type": "str"},
                "parent_template_id": {"type": "str"},
                "project_id": {"type": "str"},
                "project_name": {"type": "str"},
                "project_description": {"type": "str"},
                "rollback_template_content": {"type": "str"},
                "rollback_template_params": {"type": "list"},
                "software_type": {"type": "str"},
                "software_variant": {"type": "str"},
                "software_version": {"type": "str"},
                "template_content": {"type": "str"},
                "template_params": {"type": "list"},
                "template_name": {"type": "str"},
                "validation_errors": {"type": "dict"},
                "version": {"type": "str"},
                "version_description": {"type": "str"},
            },
            "export": {
                "type": "dict",
                "project": {"type": "list", "elements": "str"},
                "template": {
                    "type": "list",
                    "elements": "dict",
                    "project_name": {"type": "str"},
                    "template_name": {"type": "str"},
                },
            },
            "import": {
                "type": "dict",
                "project": {
                    "type": "dict",
                    "do_version": {"type": "str", "default": "False"},
                },
                "template": {
                    "type": "dict",
                    "do_version": {"type": "str", "default": "False"},
                    "payload": {
                        "type": "list",
                        "elements": "dict",
                        "tags": {"type": "list"},
                        "author": {"type": "str"},
                        "composite": {"type": "bool"},
                        "containing_templates": {"type": "list"},
                        "create_time": {"type": "int"},
                        "custom_params_order": {"type": "bool"},
                        "description": {"type": "str"},
                        "device_types": {
                            "type": "list",
                            "elements": "dict",
                            "product_family": {"type": "str"},
                            "product_series": {"type": "str"},
                            "product_type": {"type": "str"},
                        },
                        "failure_policy": {"type": "str"},
                        "id": {"type": "str"},
                        "language": {"type": "str"},
                        "last_update_time": {"type": "int"},
                        "latest_version_time": {"type": "int"},
                        "name": {"type": "str"},
                        "parent_template_id": {"type": "str"},
                        "project_id": {"type": "str"},
                        "project_name": {"type": "str"},
                        "project_description": {"type": "str"},
                        "rollback_template_content": {"type": "str"},
                        "rollback_template_params": {"type": "list"},
                        "software_type": {"type": "str"},
                        "software_variant": {"type": "str"},
                        "software_version": {"type": "str"},
                        "template_content": {"type": "str"},
                        "template_params": {"type": "list"},
                        "template_name": {"type": "str"},
                        "validation_errors": {"type": "dict"},
                        "version": {"type": "str"},
                    },
                },
            },
        }
        # Validate template params
        self.config = self.camel_to_snake_case(self.config)
        valid_temp, invalid_params = validate_list_of_dicts(self.config, temp_spec)
        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.validated_config = valid_temp
        self.log(
            "Successfully validated playbook config params: {0}".format(valid_temp),
            "INFO",
        )
        self.msg = "Successfully validated input"
        self.status = "success"
        return self

    def get_project_params(self, params):
        """
        Store project parameters from the playbook for template processing in DNAC.

        Parameters:
            params (dict) - Playbook details containing Project information.

        Returns:
            project_params (dict) - Organized Project parameters.
        """

        project_params = {
            "name": params.get("project_name"),
            "description": params.get("project_description"),
        }
        return project_params

    def get_tags(self, _tags):
        """
        Store tags from the playbook for template processing in DNAC.
        Check using check_return_status()

        Parameters:
            tags (dict) - Tags details containing Template information.

        Returns:
            tags (dict) - Organized tags parameters.
        """

        if _tags is None:
            return None

        tags = []
        i = 0
        for item in _tags:
            tags.append({})
            id = item.get("id")
            if id is not None:
                tags[i].update({"id": id})

            name = item.get("name")
            if name is not None:
                tags[i].update({"name": name})
            else:
                self.msg = "name is mandatory in tags in location " + str(i)
                self.status = "failed"
                return self.check_return_status()

        return tags

    def get_device_types(self, device_types):
        """
        Store device types parameters from the playbook for template processing in DNAC.
        Check using check_return_status()

        Parameters:
            device_types (dict) - Device types details containing Template information.

        Returns:
            deviceTypes (dict) - Organized device types parameters.
        """

        if device_types is None:
            return None

        deviceTypes = []
        i = 0
        for item in device_types:
            deviceTypes.append({})
            product_family = item.get("product_family")
            if product_family is not None:
                deviceTypes[i].update({"productFamily": product_family})
            else:
                self.msg = "product_family is mandatory for deviceTypes"
                self.status = "failed"
                return self.check_return_status()

            product_series = item.get("product_series")
            if product_series is not None:
                deviceTypes[i].update({"productSeries": product_series})
            product_type = item.get("product_type")
            if product_type is not None:
                deviceTypes[i].update({"productType": product_type})
            i = i + 1

        return deviceTypes

    def get_validation_errors(self, validation_errors):
        """
        Store template parameters from the playbook for template processing in DNAC.

        Parameters:
            validation_errors (dict) - Playbook details containing validation errors information.

        Returns:
            validationErrors (dict) - Organized validation errors parameters.
        """

        if validation_errors is None:
            return None

        validationErrors = {}
        rollback_template_errors = validation_errors.get("rollback_template_errors")
        if rollback_template_errors is not None:
            validationErrors.update(
                {"rollbackTemplateErrors": rollback_template_errors}
            )

        template_errors = validation_errors.get("template_errors")
        if template_errors is not None:
            validationErrors.update({"templateErrors": template_errors})

        template_id = validation_errors.get("template_id")
        if template_id is not None:
            validationErrors.update({"templateId": template_id})

        template_version = validation_errors.get("template_version")
        if template_version is not None:
            validationErrors.update({"templateVersion": template_version})

        return validationErrors

    def get_template_info(self, template_params):
        """
        Store template params from the playbook for template processing in DNAC.
        Check using check_return_status()

        Parameters:
            template_params (dict) - Playbook details containing template params information.

        Returns:
            templateParams (dict) - Organized template params parameters.
        """

        if template_params is None:
            return None

        templateParams = []
        i = 0
        self.log("Template params details: {0}".format(template_params), "DEBUG")
        for item in template_params:
            self.log("Template params items: {0}".format(item), "DEBUG")
            templateParams.append({})
            binding = item.get("binding")
            if binding is not None:
                templateParams[i].update({"binding": binding})

            custom_order = item.get("custom_order")
            if custom_order is not None:
                templateParams[i].update({"customOrder": custom_order})

            default_value = item.get("default_value")
            if default_value is not None:
                templateParams[i].update({"defaultValue": default_value})

            description = item.get("description")
            if description is not None:
                templateParams[i].update({"description": description})

            display_name = item.get("display_name")
            if display_name is not None:
                templateParams[i].update({"displayName": display_name})

            group = item.get("group")
            if group is not None:
                templateParams[i].update({"group": group})

            id = item.get("id")
            if id is not None:
                templateParams[i].update({"id": id})

            instruction_text = item.get("instruction_text")
            if instruction_text is not None:
                templateParams[i].update({"instructionText": instruction_text})

            key = item.get("key")
            if key is not None:
                templateParams[i].update({"key": key})

            not_param = item.get("not_param")
            if not_param is not None:
                templateParams[i].update({"notParam": not_param})

            order = item.get("order")
            if order is not None:
                templateParams[i].update({"order": order})

            param_array = item.get("param_array")
            if param_array is not None:
                templateParams[i].update({"paramArray": param_array})

            provider = item.get("provider")
            if provider is not None:
                templateParams[i].update({"provider": provider})

            parameter_name = item.get("parameter_name")
            if parameter_name is not None:
                templateParams[i].update({"parameterName": parameter_name})
            else:
                self.msg = "parameter_name is mandatory for the template_params."
                self.status = "failed"
                return self.check_return_status()

            data_type = item.get("data_type")
            datatypes = [
                "STRING",
                "INTEGER",
                "IPADDRESS",
                "MACADDRESS",
                "SECTIONDIVIDER",
            ]
            if data_type is not None:
                templateParams[i].update({"dataType": data_type})
            else:
                self.msg = "dataType is mandatory for the template_params."
                self.status = "failed"
                return self.check_return_status()
            if data_type not in datatypes:
                self.msg = "data_type under template_params should be in " + str(
                    datatypes
                )
                self.status = "failed"
                return self.check_return_status()

            required = item.get("required")
            if required is not None:
                templateParams[i].update({"required": required})

            range = item.get("range")
            self.log("Template params range list: {0}".format(range), "DEBUG")
            if range is not None:
                templateParams[i].update({"range": []})
                _range = templateParams[i].get("range")
                self.log("Template params range: {0}".format(_range), "DEBUG")
                j = 0
                for value in range:
                    _range.append({})
                    id = value.get("id")
                    if id is not None:
                        _range[j].update({"id": id})
                    max_value = value.get("max_value")
                    if max_value is not None:
                        _range[j].update({"maxValue": max_value})
                    else:
                        self.msg = (
                            "max_value is mandatory for range under template_params"
                        )
                        self.status = "failed"
                        return self.check_return_status()
                    min_value = value.get("min_value")
                    if min_value is not None:
                        _range[j].update({"maxValue": min_value})
                    else:
                        self.msg = (
                            "min_value is mandatory for range under template_params"
                        )
                        self.status = "failed"
                        return self.check_return_status()
                    j = j + 1

            self.log("Template params details: {0}".format(templateParams), "DEBUG")
            selection = item.get("selection")
            self.log("Template params selection: {0}".format(selection), "DEBUG")
            if selection is not None:
                templateParams[i].update({"selection": {}})
                _selection = templateParams[i].get("selection")
                id = selection.get("id")
                if id is not None:
                    _selection.update({"id": id})
                default_selected_values = selection.get("default_selected_values")
                if default_selected_values is not None:
                    _selection.update(
                        {"defaultSelectedValues": default_selected_values}
                    )
                selection_values = selection.get("selection_values")
                if selection_values is not None:
                    _selection.update({"selectionValues": selection_values})
                selection_type = selection.get("selection_type")
                if selection_type is not None:
                    _selection.update({"selectionType": selection_type})
            i = i + 1

        return templateParams

    def get_containing_templates(self, containing_templates):
        """
        Store tags from the playbook for template processing in DNAC.
        Check using check_return_status()

        Parameters:
            containing_templates (dict) - Containing tempaltes details
            containing Template information.

        Returns:
            containingTemplates (dict) - Organized containing templates parameters.
        """

        if containing_templates is None:
            return None

        containingTemplates = []
        i = 0
        for item in containing_templates:
            containingTemplates.append({})
            _tags = item.get("tags")
            if _tags is not None:
                containingTemplates[i].update({"tags": self.get_tags(_tags)})

            composite = item.get("composite")
            if composite is not None:
                containingTemplates[i].update({"composite": composite})

            description = item.get("description")
            if description is not None:
                containingTemplates[i].update({"description": description})

            device_types = item.get("device_types")
            if device_types is not None:
                containingTemplates[i].update(
                    {"deviceTypes": self.get_device_types(device_types)}
                )

            id = item.get("id")
            if id is not None:
                containingTemplates[i].update({"id": id})

            name = item.get("name")
            if name is None:
                self.msg = "name is mandatory under containing templates"
                self.status = "failed"
                return self.check_return_status()

            containingTemplates[i].update({"name": name})

            language = item.get("language")
            if language is None:
                self.msg = "language is mandatory under containing templates"
                self.status = "failed"
                return self.check_return_status()

            language_list = ["JINJA", "VELOCITY"]
            if language not in language_list:
                self.msg = "language under containing templates should be in " + str(
                    language_list
                )
                self.status = "failed"
                return self.check_return_status()

            containingTemplates[i].update({"language": language})

            project_name = item.get("project_name")
            if project_name is not None:
                containingTemplates[i].update({"projectName": project_name})
            else:
                self.msg = "project_name is mandatory under containing templates"
                self.status = "failed"
                return self.check_return_status()

            rollback_template_params = item.get("rollback_template_params")
            if rollback_template_params is not None:
                containingTemplates[i].update(
                    {
                        "rollbackTemplateParams": self.get_template_info(
                            rollback_template_params
                        )
                    }
                )

            template_content = item.get("template_content")
            if template_content is not None:
                containingTemplates[i].update({"templateContent": template_content})

            template_params = item.get("template_params")
            if template_params is not None:
                containingTemplates[i].update(
                    {"templateParams": self.get_template_info(template_params)}
                )

            version = item.get("version")
            if version is not None:
                containingTemplates[i].update({"version": version})

        return containingTemplates

    def get_template_params(self, params):
        """
        Store template parameters from the playbook for template processing in DNAC.

        Parameters:
            params (dict) - Playbook details containing Template information.

        Returns:
            temp_params (dict) - Organized template parameters.
        """

        self.log("Template params playbook details: {0}".format(params), "DEBUG")
        temp_params = {
            "tags": self.get_tags(params.get("template_tag")),
            "author": params.get("author"),
            "composite": params.get("composite"),
            "containingTemplates": self.get_containing_templates(
                params.get("containing_templates")
            ),
            "createTime": params.get("create_time"),
            "customParamsOrder": params.get("custom_params_order"),
            "description": params.get("template_description"),
            "deviceTypes": self.get_device_types(params.get("device_types")),
            "failurePolicy": params.get("failure_policy"),
            "id": params.get("id"),
            "language": params.get("language").upper(),
            "lastUpdateTime": params.get("last_update_time"),
            "latestVersionTime": params.get("latest_version_time"),
            "name": params.get("template_name"),
            "parentTemplateId": params.get("parent_template_id"),
            "projectId": params.get("project_id"),
            "projectName": params.get("project_name"),
            "rollbackTemplateContent": params.get("rollback_template_content"),
            "rollbackTemplateParams": self.get_template_info(
                params.get("rollback_template_params")
            ),
            "softwareType": params.get("software_type"),
            "softwareVariant": params.get("software_variant"),
            "softwareVersion": params.get("software_version"),
            "templateContent": params.get("template_content"),
            "templateParams": self.get_template_info(params.get("template_params")),
            "validationErrors": self.get_validation_errors(
                params.get("validation_errors")
            ),
            "version": params.get("version"),
            "project_id": params.get("project_id"),
        }
        self.log("Formatted template params details: {0}".format(temp_params), "DEBUG")
        copy_temp_params = copy.deepcopy(temp_params)
        for item in copy_temp_params:
            if temp_params[item] is None:
                del temp_params[item]
        self.log("Formatted template params details: {0}".format(temp_params), "DEBUG")
        return temp_params

    def get_template(self, config):
        """
        Get the template needed for updation or creation.

        Parameters:
            config (dict) - Playbook details containing Template information.

        Returns:
            result (dict) - Template details for the given template ID.
        """

        result = None
        items = self.dnac_apply["exec"](
            family="configuration_templates",
            function="get_template_details",
            op_modifies=True,
            params={"template_id": config.get("templateId")},
        )
        if items:
            result = items

        self.log(
            "Received API response from 'get_template_details': {0}".format(items),
            "DEBUG",
        )
        self.result["response"] = items
        return result

    def get_have_project(self, config):
        """
        Get the current project related information from DNAC.

        Parameters:
            config (dict) - Playbook details containing Project information.

        Returns:
            template_available (list) - Current project information.
        """

        have_project = {}
        given_projectName = config.get("configuration_templates").get("project_name")
        template_available = None

        # Check if project exists.
        project_details = self.get_project_details(given_projectName)
        # DNAC returns project details even if the substring matches.
        # Hence check the projectName retrieved from DNAC.
        if not (project_details and isinstance(project_details, list)):
            self.log(
                "Project: {0} not found, need to create new project in DNAC".format(
                    given_projectName
                ),
                "INFO",
            )
            return None

        fetched_projectName = project_details[0].get("name")
        if fetched_projectName != given_projectName:
            self.log(
                "Project {0} provided is not exact match in DNAC DB".format(
                    given_projectName
                ),
                "INFO",
            )
            return None

        template_available = project_details[0].get("templates")
        have_project["project_found"] = True
        have_project["id"] = project_details[0].get("id")
        have_project["isDeletable"] = project_details[0].get("isDeletable")

        self.have_project = have_project
        return template_available

    def get_have_template(self, config, template_available):
        """
        Get the current template related information from DNAC.

        Parameters:
            config (dict) - Playbook details containing Template information.
            template_available (list) -  Current project information.

        Returns:
            self
        """

        projectName = config.get("configuration_templates").get("project_name")
        templateName = config.get("configuration_templates").get("template_name")
        template = None
        have_template = {}

        have_template["isCommitPending"] = False
        have_template["template_found"] = False

        template_details = get_dict_result(template_available, "name", templateName)
        # Check if specified template in playbook is available
        if not template_details:
            self.log(
                "Template {0} not found in project {1}".format(
                    templateName, projectName
                ),
                "INFO",
            )
            self.msg = "Template : {0} missing, new template to be created".format(
                templateName
            )
            self.status = "success"
            return self

        config["templateId"] = template_details.get("id")
        have_template["id"] = template_details.get("id")
        # Get available templates which are committed under the project
        template_list = self.dnac_apply["exec"](
            family="configuration_templates",
            function="gets_the_templates_available",
            op_modifies=True,
            params={"projectNames": config.get("projectName")},
        )
        have_template["isCommitPending"] = True
        # This check will fail if specified template is there not committed in dnac
        if template_list and isinstance(template_list, list):
            template_info = get_dict_result(template_list, "name", templateName)
            if template_info:
                template = self.get_template(config)
                have_template["template"] = template
                have_template["isCommitPending"] = False
                have_template["template_found"] = template is not None and isinstance(
                    template, dict
                )
                self.log(
                    "Template {0} is found and template "
                    "details are :{1}".format(templateName, str(template)),
                    "INFO",
                )

        # There are committed templates in the project but the
        # one specified in the playbook may not be committed
        self.log(
            "Commit pending for template name {0}"
            " is {1}".format(templateName, have_template.get("isCommitPending")),
            "INFO",
        )

        self.have_template = have_template
        self.msg = (
            "Successfully collected all template parameters from dnac for comparison"
        )
        self.status = "success"
        return self

    def get_have(self, config):
        """
        Get the current project and template details from DNAC.

        Parameters:
            config (dict) - Playbook details containing Project/Template information.

        Returns:
            self
        """
        configuration_templates = config.get("configuration_templates")
        if configuration_templates:
            if not configuration_templates.get("project_name"):
                self.msg = "Mandatory Parameter project_name not available"
                self.status = "failed"
                return self
            template_available = self.get_have_project(config)
            if template_available:
                self.get_have_template(config, template_available)

        self.msg = "Successfully collected all project and template \
                    parameters from dnac for comparison"
        self.status = "success"
        return self

    def get_project_details(self, projectName):
        """
        Get the details of specific project name provided.

        Parameters:
            projectName (str) - Project Name

        Returns:
            items (dict) - Project details with given project name.
        """

        items = self.dnac_apply["exec"](
            family="configuration_templates",
            function="get_projects",
            op_modifies=True,
            params={"name": projectName},
        )
        return items

    def get_want(self, config):
        """
        Get all the template and project related information from playbook
        that is needed to be created in DNAC.

        Parameters:
            config (dict) - Playbook details.

        Returns:
            self
        """

        want = {}
        configuration_templates = config.get("configuration_templates")
        self.log("Playbook details: {0}".format(config), "INFO")
        if configuration_templates:
            template_params = self.get_template_params(configuration_templates)
            project_params = self.get_project_params(configuration_templates)
            version_comments = configuration_templates.get("version_description")

            if self.params.get("state") == "merged":
                self.update_mandatory_parameters(template_params)

            want["template_params"] = template_params
            want["project_params"] = project_params
            want["comments"] = version_comments

        self.want = want
        self.msg = (
            "Successfully collected all parameters from playbook " + "for comparison"
        )
        self.status = "success"
        return self

    def create_project_or_template(self, is_create_project=False):
        """
        Call DNAC API to create project or template based on the input provided.

        Parameters:
            is_create_project (bool) - Default value is False.

        Returns:
            creation_id (str) - Project Id.
            created (str) - True if Project created, else False.
        """

        creation_id = None
        created = False
        self.log("Desired State (want): {0}".format(self.want), "INFO")
        template_params = self.want.get("template_params")
        project_params = self.want.get("project_params")

        if is_create_project:
            params_key = project_params
            name = "project: {0}".format(project_params.get("name"))
            validation_string = "Successfully created project"
            creation_value = "create_project"
        else:
            params_key = template_params
            name = "template: {0}".format(template_params.get("name"))
            validation_string = "Successfully created template"
            creation_value = "create_template"

        response = self.dnac_apply["exec"](
            family="configuration_templates",
            function=creation_value,
            op_modifies=True,
            params=params_key,
        )
        if not isinstance(response, dict):
            self.log(
                "Response of '{0}' is not in dictionary format.".format(creation_value),
                "CRITICAL",
            )
            return creation_id, created

        task_id = response.get("response").get("taskId")
        if not task_id:
            self.log(
                "Task id {0} not found for '{1}'.".format(task_id, creation_value),
                "CRITICAL",
            )
            return creation_id, created

        while not created:
            task_details = self.get_task_details(task_id)
            if not task_details:
                self.log(
                    "Failed to get task details of '{0}' for taskid: {1}".format(
                        creation_value, task_id
                    ),
                    "CRITICAL",
                )
                return creation_id, created

            self.log(
                "Task details for {0}: {1}".format(creation_value, task_details),
                "DEBUG",
            )
            if task_details.get("isError"):
                self.log(
                    "Error occurred for '{0}' with taskid: {1}".format(
                        creation_value, task_id
                    ),
                    "ERROR",
                )
                return creation_id, created

            if validation_string not in task_details.get("progress"):
                self.log(
                    "'{0}' progress set to {1} for taskid: {2}".format(
                        creation_value, task_details.get("progress"), task_id
                    ),
                    "DEBUG",
                )
                continue

            task_details_data = task_details.get("data")
            value = self.check_string_dictionary(task_details_data)
            if value is None:
                creation_id = task_details.get("data")
            else:
                creation_id = value.get("templateId")
            if not creation_id:
                self.log(
                    "Export data is not found for '{0}' with taskid : {1}".format(
                        creation_value, task_id
                    ),
                    "DEBUG",
                )
                continue

            created = True
            if is_create_project:
                # ProjectId is required for creating a new template.
                # Store it with other template parameters.
                template_params["projectId"] = creation_id
                template_params["project_id"] = creation_id

        self.log("New {0} created with id {1}".format(name, creation_id), "DEBUG")
        return creation_id, created

    def requires_update(self):
        """
        Check if the template config given requires update.

        Parameters:
            self - Current object.

        Returns:
            bool - True if any parameter specified in obj_params differs between
            current_obj and requested_obj, indicating that an update is required.
            False if all specified parameters are equal.
        """

        if self.have_template.get("isCommitPending"):
            self.log(
                "Template '{0}' is in saved state and needs to be updated and committed.".format(
                    self.have_template.get("template").get("name")
                ),
                "DEBUG",
            )
            return True

        current_obj = self.have_template.get("template")
        requested_obj = self.want.get("template_params")
        self.log("Current State (have): {0}".format(current_obj), "INFO")
        self.log("Desired State (want): {0}".format(requested_obj), "INFO")
        obj_params = [
            ("tags", "tags", ""),
            ("author", "author", ""),
            ("composite", "composite", False),
            ("containingTemplates", "containingTemplates", []),
            ("createTime", "createTime", ""),
            ("customParamsOrder", "customParamsOrder", False),
            ("description", "description", ""),
            ("deviceTypes", "deviceTypes", []),
            ("failurePolicy", "failurePolicy", ""),
            ("id", "id", ""),
            ("language", "language", "VELOCITY"),
            ("lastUpdateTime", "lastUpdateTime", ""),
            ("latestVersionTime", "latestVersionTime", ""),
            ("name", "name", ""),
            ("parentTemplateId", "parentTemplateId", ""),
            ("projectId", "projectId", ""),
            ("projectName", "projectName", ""),
            ("rollbackTemplateContent", "rollbackTemplateContent", ""),
            ("rollbackTemplateParams", "rollbackTemplateParams", []),
            ("softwareType", "softwareType", ""),
            ("softwareVariant", "softwareVariant", ""),
            ("softwareVersion", "softwareVersion", ""),
            ("templateContent", "templateContent", ""),
            ("templateParams", "templateParams", []),
            ("validationErrors", "validationErrors", {}),
            ("version", "version", ""),
        ]

        return any(
            not dnac_compare_equality(
                current_obj.get(dnac_param, default), requested_obj.get(ansible_param)
            )
            for (dnac_param, ansible_param, default) in obj_params
        )

    def update_mandatory_parameters(self, template_params):
        """
        Update parameters which are mandatory for creating a template.

        Parameters:
            template_params (dict) - Template information.

        Returns:
            None
        """

        # Mandate fields required for creating a new template.
        # Store it with other template parameters.
        template_params["projectId"] = self.have_project.get("id")
        template_params["project_id"] = self.have_project.get("id")
        # Update language,deviceTypes and softwareType if not provided for existing template.
        if not template_params.get("language"):
            template_params["language"] = self.have_template.get("template").get(
                "language"
            )
        if not template_params.get("deviceTypes"):
            template_params["deviceTypes"] = self.have_template.get("template").get(
                "deviceTypes"
            )
        if not template_params.get("softwareType"):
            template_params["softwareType"] = self.have_template.get("template").get(
                "softwareType"
            )

    def validate_input_merge(self, template_exists):
        """
        Validate input after getting all the parameters from DNAC.
        "If mandate like deviceTypes, softwareType and language "
        "already present in DNAC for a template."
        "It is not required to be provided in playbook, "
        "but if it is new creation error will be thrown to provide these fields.

        Parameters:
            template_exists (bool) - True if template exists, else False.

        Returns:
            None
        """

        template_params = self.want.get("template_params")
        language = template_params.get("language").upper()
        if language:
            if language not in self.accepted_languages:
                self.msg = (
                    "Invalid value language {0} ."
                    "Accepted language values are {1}".format(
                        self.accepted_languages, language
                    )
                )
                self.status = "failed"
                return self
        else:
            template_params["language"] = "JINJA"

        if not template_exists:
            if not template_params.get("deviceTypes") or not template_params.get(
                "softwareType"
            ):
                self.msg = "DeviceTypes and SoftwareType are required arguments to create Templates"
                self.status = "failed"
                return self

        self.msg = "Input validated for merging"
        self.status = "success"
        return self

    def get_export_template_values(self, export_values):
        """
        Get the export template values from the details provided by the playbook.

        Parameters:
            export_values (bool) - All the template available under the project.

        Returns:
            self
        """

        template_details = self.dnac._exec(
            family="configuration_templates", function="get_projects_details"
        )
        for values in export_values:
            project_name = values.get("project_name")
            self.log(
                "Project name for export template: {0}".format(project_name), "DEBUG"
            )
            template_details = template_details.get("response")
            self.log("Template details: {0}".format(template_details), "DEBUG")
            all_template_details = get_dict_result(
                template_details, "name", project_name
            )
            self.log(
                "Template details under the project name {0}: {1}".format(
                    project_name, all_template_details
                ),
                "DEBUG",
            )
            all_template_details = all_template_details.get("templates")
            self.log(
                "Template details under the project name {0}: {1}".format(
                    project_name, all_template_details
                ),
                "DEBUG",
            )
            template_name = values.get("template_name")
            template_detail = get_dict_result(
                all_template_details, "name", template_name
            )
            self.log(
                "Template details with template name {0}: {1}".format(
                    template_name, template_detail
                ),
                "DEBUG",
            )
            if template_detail is None:
                self.msg = "Invalid project_name and template_name in export"
                self.status = "failed"
                return self
            self.export_template.append(template_detail.get("id"))

        self.msg = "Successfully collected the export template IDs"
        self.status = "success"
        return self

    def update_configuration_templates(self, config):
        """
        Update/Create templates and projects in DNAC with fields provided in DNAC.

        Parameters:
            config (dict) - Playbook details containing template information.

        Returns:
            self
        """

        configuration_templates = config.get("configuration_templates")
        if configuration_templates:
            is_project_found = self.have_project.get("project_found")
            if not is_project_found:
                project_id, project_created = self.create_project_or_template(
                    is_create_project=True
                )
                if project_created:
                    self.log(
                        "project created with projectId: {0}".format(project_id),
                        "DEBUG",
                    )
                else:
                    self.status = "failed"
                    self.msg = "Project creation failed"
                    return self

            is_template_found = self.have_template.get("template_found")
            template_params = self.want.get("template_params")
            self.log("Desired template details: {0}".format(template_params), "DEBUG")
            self.log(
                "Current template details: {0}".format(self.have_template), "DEBUG"
            )
            template_id = None
            template_updated = False
            self.validate_input_merge(is_template_found).check_return_status()
            if is_template_found:
                if self.requires_update():
                    template_id = self.have_template.get("id")
                    template_params.update({"id": template_id})
                    self.log(
                        "Current State (have): {0}".format(self.have_template), "INFO"
                    )
                    self.log("Desired State (want): {0}".format(self.want), "INFO")
                    response = self.dnac_apply["exec"](
                        family="configuration_templates",
                        function="update_template",
                        op_modifies=True,
                        params=template_params,
                    )
                    template_updated = True
                    self.log(
                        "Updating existing template '{0}'.".format(
                            self.have_template.get("template").get("name")
                        ),
                        "INFO",
                    )
                else:
                    # Template does not need update
                    self.result.update(
                        {
                            "response": self.have_template.get("template"),
                            "msg": "Template does not need update",
                        }
                    )
                    self.status = "exited"
                    return self
            else:
                if template_params.get("name"):
                    template_id, template_updated = self.create_project_or_template()
                else:
                    self.msg = "missing required arguments: template_name"
                    self.status = "failed"
                    return self

            if template_updated:
                # Template needs to be versioned
                version_params = {
                    "comments": self.want.get("comments"),
                    "templateId": template_id,
                }
                response = self.dnac_apply["exec"](
                    family="configuration_templates",
                    function="version_template",
                    op_modifies=True,
                    params=version_params,
                )
                task_id = response.get("response").get("taskId")
                if not task_id:
                    self.msg = "Task id: {0} not found".format(task_id)
                    self.status = "failed"
                    return self
                task_details = self.get_task_details(task_id)
                self.result["changed"] = True
                self.result["msg"] = task_details.get("progress")
                self.result["diff"] = config.get("configuration_templates")
                self.log(
                    "Task details for 'version_template': {0}".format(task_details),
                    "DEBUG",
                )
                self.result["response"] = task_details if task_details else response

                if not self.result.get("msg"):
                    self.msg = "Error while versioning the template"
                    self.status = "failed"
                    return self

    def handle_export(self, config):
        """
        Export templates and projects in DNAC with fields provided in DNAC.

        Parameters:
            config (dict) - Playbook details containing template information.

        Returns:
            self
        """

        export = config.get("export")
        if export:
            export_project = export.get("project")
            self.log(
                "Export project playbook details: {0}".format(export_project), "DEBUG"
            )
            if export_project:
                response = self.dnac._exec(
                    family="configuration_templates",
                    function="export_projects",
                    op_modifies=True,
                    params={"payload": export_project},
                )
                validation_string = "successfully exported project"
                self.check_task_response_status(
                    response, validation_string, True
                ).check_return_status()
                self.result["response"][0].update({"exportProject": self.msg})

            export_values = export.get("template")
            if export_values:
                self.get_export_template_values(export_values).check_return_status()
                self.log(
                    "Exporting template playbook details: {0}".format(
                        self.export_template
                    ),
                    "DEBUG",
                )
                response = self.dnac._exec(
                    family="configuration_templates",
                    function="export_templates",
                    op_modifies=True,
                    params={"payload": self.export_template},
                )
                validation_string = "successfully exported template"
                self.check_task_response_status(
                    response, validation_string, True
                ).check_return_status()
                self.result["response"][0].update({"exportTemplate": self.msg})

        return self

    def handle_import(self, config):
        """
        Import templates and projects in DNAC with fields provided in DNAC.

        Parameters:
            config (dict) - Playbook details containing template information.

        Returns:
            self
        """

        _import = config.get("import")
        if _import:
            # _import_project = _import.get("project")
            do_version = _import.get("project").get("do_version")
            payload = None
            if _import.get("project").get("payload"):
                payload = _import.get("project").get("payload")
            else:
                self.msg = (
                    "Mandatory parameter payload is not found under import project"
                )
                self.status = "failed"
                return self
            _import_project = {
                "doVersion": do_version,
                # "payload": "{0}".format(payload)
                "payload": payload,
            }
            self.log(
                "Importing project details from the playbook: {0}".format(
                    _import_project
                ),
                "DEBUG",
            )
            if _import_project:
                response = self.dnac._exec(
                    family="configuration_templates",
                    function="imports_the_projects_provided",
                    op_modifies=True,
                    params=_import_project,
                )
                validation_string = "successfully imported project"
                self.check_task_response_status(
                    response, validation_string
                ).check_return_status()
                self.result["response"][0].update({"importProject": validation_string})

            _import_template = _import.get("template")
            if _import_template.get("project_name"):
                self.msg = (
                    "Mandatory paramter project_name is not found under import template"
                )
                self.status = "failed"
                return self
            if _import_template.get("payload"):
                self.msg = (
                    "Mandatory paramter payload is not found under import template"
                )
                self.status = "failed"
                return self

            payload = _import_template.get("project_name")
            import_template = {
                "doVersion": _import_template.get("do_version"),
                "projectName": _import_template.get("project_name"),
                "payload": self.get_template_params(payload),
            }
            self.log(
                "Import template details from the playbook: {0}".format(
                    _import_template
                ),
                "DEBUG",
            )
            if _import_template:
                response = self.dnac._exec(
                    family="configuration_templates",
                    function="imports_the_templates_provided",
                    op_modifies=True,
                    params=import_template,
                )
                validation_string = "successfully imported template"
                self.check_task_response_status(
                    response, validation_string
                ).check_return_status()
                self.result["response"][0].update({"importTemplate": validation_string})

        return self

    def get_diff_merged(self, config):
        """
        Update/Create templates and projects in DNAC with fields provided in DNAC.
        Export the tempaltes and projects.
        Import the templates and projects.
        Check using check_return_status().

        Parameters:
            config (dict) - Playbook details containing template information.

        Returns:
            self
        """

        self.update_configuration_templates(config)
        if self.status == "failed":
            return self

        self.handle_export(config)
        if self.status == "failed":
            return self

        self.handle_import(config)
        if self.status == "failed":
            return self

        self.msg = "Successfully completed merged state execution"
        self.status = "success"
        return self

    def delete_project_or_template(self, config, is_delete_project=False):
        """
        Call DNAC API to delete project or template with provided inputs.

        Parameters:
            config (dict) - Playbook details containing template information.
            is_delete_project (bool) - True if we need to delete project, else False.

        Returns:
            self
        """

        if is_delete_project:
            params_key = {"project_id": self.have_project.get("id")}
            deletion_value = "deletes_the_project"
            name = "project: {0}".format(
                config.get("configuration_templates").get("project_name")
            )
        else:
            template_params = self.want.get("template_params")
            params_key = {"template_id": self.have_template.get("id")}
            deletion_value = "deletes_the_template"
            name = "templateName: {0}".format(template_params.get("templateName"))

        response = self.dnac_apply["exec"](
            family="configuration_templates",
            function=deletion_value,
            op_modifies=True,
            params=params_key,
        )
        task_id = response.get("response").get("taskId")
        if task_id:
            task_details = self.get_task_details(task_id)
            self.result["changed"] = True
            self.result["msg"] = task_details.get("progress")
            self.result["diff"] = config.get("configuration_templates")

            self.log(
                "Task details for '{0}': {1}".format(deletion_value, task_details),
                "DEBUG",
            )
            self.result["response"] = task_details if task_details else response
            if not self.result["msg"]:
                self.result["msg"] = "Error while deleting {name} : "
                self.status = "failed"
                return self

        self.msg = "Successfully deleted {0} ".format(name)
        self.status = "success"
        return self

    def get_diff_deleted(self, config):
        """
        Delete projects or templates in DNAC with fields provided in playbook.

        Parameters:
            config (dict) - Playbook details containing template information.

        Returns:
            self
        """

        configuration_templates = config.get("configuration_templates")
        if configuration_templates:
            is_project_found = self.have_project.get("project_found")
            projectName = config.get("configuration_templates").get("project_name")

            if not is_project_found:
                self.msg = "Project {0} is not found".format(projectName)
                self.status = "failed"
                return self

            is_template_found = self.have_template.get("template_found")
            template_params = self.want.get("template_params")
            templateName = config.get("configuration_templates").get("template_name")
            if template_params.get("name"):
                if is_template_found:
                    self.delete_project_or_template(config)
                else:
                    self.msg = "Invalid template {0} under project".format(templateName)
                    self.status = "failed"
                    return self
            else:
                self.log(
                    "Template name is empty, deleting the project '{0}' and "
                    "associated templates".format(
                        config.get("configuration_templates").get("project_name")
                    ),
                    "INFO",
                )
                is_project_deletable = self.have_project.get("isDeletable")
                if is_project_deletable:
                    self.delete_project_or_template(config, is_delete_project=True)
                else:
                    self.msg = "Project is not deletable"
                    self.status = "failed"
                    return self

        self.msg = "Successfully completed delete state execution"
        self.status = "success"
        return self

    def verify_diff_merged(self, config):
        """
        Validating the DNAC configuration with the playbook details
        when state is merged (Create/Update).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self
        """

        if config.get("configuration_templates") is not None:
            is_template_available = self.get_have_project(config)
            self.log("Template availability: {0}".format(is_template_available), "INFO")
            if not is_template_available:
                self.msg = "Configuration Template config is not applied to the DNAC."
                self.status = "failed"
                return self

            self.get_have_template(config, is_template_available)
            self.log(
                "Current State (have): {0}".format(self.want.get("template_params")),
                "INFO",
            )
            self.log(
                "Desired State (want): {0}".format(self.have_template.get("template")),
                "INFO",
            )
            template_params = [
                "language",
                "name",
                "projectName",
                "softwareType",
                "softwareVariant",
                "templateContent",
            ]
            for item in template_params:
                if self.have_template.get("template").get(item) != self.want.get(
                    "template_params"
                ).get(item):
                    self.msg = (
                        " Configuration Template config is not applied to the DNAC."
                    )
                    self.status = "failed"
                    return self
            self.log(
                "Successfully validated the Template in the Catalyst Center.", "INFO"
            )
            self.result.get("response").update({"Validation": "Success"})

        self.msg = "Successfully validated the Configuration Templates."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the DNAC configuration with the playbook details
        when state is deleted (delete).

        Parameters:
            config (dict) - Playbook details containing Global Pool,
            Reserved Pool, and Network Management configuration.

        Returns:
            self
        """

        if config.get("configuration_templates") is not None:
            self.log("Current State (have): {0}".format(self.have), "INFO")
            self.log("Desired State (want): {0}".format(self.want), "INFO")
            template_list = self.dnac_apply["exec"](
                family="configuration_templates",
                function="gets_the_templates_available",
                op_modifies=True,
                params={"projectNames": config.get("projectName")},
            )
            if template_list and isinstance(template_list, list):
                templateName = config.get("configuration_templates").get(
                    "template_name"
                )
                template_info = get_dict_result(template_list, "name", templateName)
                if template_info:
                    self.msg = (
                        "Configuration Template config is not applied to the DNAC."
                    )
                    self.status = "failed"
                    return self

            self.log(
                "Successfully validated absence of template in the Catalyst Center.",
                "INFO",
            )
            self.result.get("response").update({"Validation": "Success"})

        self.msg = "Successfully validated the absence of Template in the DNAC."
        self.status = "success"
        return self

    def reset_values(self):
        """
        Reset all neccessary attributes to default values.

        Parameters:
            self - The current object.

        Returns:
            None
        """

        self.have_project.clear()
        self.have_template.clear()
        self.want.clear()


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
        "dnac_log": {"type": "bool", "default": False},
        "dnac_log_level": {"type": "str", "default": "WARNING"},
        "dnac_log_file_path": {"type": "str", "default": "dnac.log"},
        "dnac_log_append": {"type": "bool", "default": True},
        "validate_response_schema": {"type": "bool", "default": True},
        "config_verify": {"type": "bool", "default": False},
        "dnac_api_task_timeout": {"type": "int", "default": 1200},
        "dnac_task_poll_interval": {"type": "int", "default": 2},
        "config": {"required": True, "type": "list", "elements": "dict"},
        "state": {"default": "merged", "choices": ["merged", "deleted"]},
    }
    module = AnsibleModule(argument_spec=element_spec, supports_check_mode=False)
    dnac_template = DnacTemplate(module)
    dnac_template.validate_input().check_return_status()
    state = dnac_template.params.get("state")
    config_verify = dnac_template.params.get("config_verify")
    if state not in dnac_template.supported_states:
        dnac_template.status = "invalid"
        dnac_template.msg = "State {0} is invalid".format(state)
        dnac_template.check_return_status()

    for config in dnac_template.validated_config:
        dnac_template.reset_values()
        dnac_template.get_have(config).check_return_status()
        dnac_template.get_want(config).check_return_status()
        dnac_template.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            dnac_template.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**dnac_template.result)


if __name__ == "__main__":
    main()
