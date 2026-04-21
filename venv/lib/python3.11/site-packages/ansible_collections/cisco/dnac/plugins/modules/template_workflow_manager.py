#!/usr/bin/python
# -*- coding: utf-8 -*-
# Copyright (c) 2024, Cisco Systems
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)
"""Ansible module to perform operations on projects and templates in Cisco Catalyst Center."""

from __future__ import absolute_import, division, print_function

__metaclass__ = type

__author__ = ['Madhan Sankaranarayanan, Rishita Chowdhary, Akash Bhaskaran, Muthu Rakesh, Abhishek Maheshwari, Archit Soni, A Mohamed Rafeek']

DOCUMENTATION = r"""
---
module: template_workflow_manager
short_description: Resource module for Template functions
description:
  - Manages operations for creating, updating, and deleting
    configuration templates.
  - Creates templates by project and template names.
  - Updates templates by project and template names.
  - Deletes templates by project and template names.
  - Exports projects and templates based on specified
    parameters.
  - Handles the creation of resources for importing
    configuration templates and projects.
version_added: '6.33.0'
extends_documentation_fragment:
  - cisco.dnac.workflow_manager_params
author: Madhan Sankaranarayanan (@madhansansel)
        Rishita Chowdhary (@rishitachowdhary)
        Akash Bhaskaran (@akabhask)
        Muthu Rakesh (@MUTHU-RAKESH-27)
        Abhishek Maheshwari (@abmahesh)
        Archit Soni (@koderchit)
        A Mohamed Rafeek (@mabdulk2)
options:
  config_verify:
    description: |
      If set to True, verifies the Cisco Catalyst Center
      configuration after applying the playbook.

    type: bool
    default: false
  state:
    description: Desired state of the Cisco Catalyst
      Center after module execution.
    type: str
    choices: [merged, deleted]
    default: merged
  config:
    description: Details of templates to manage.
    type: list
    elements: dict
    required: true
    suboptions:
      projects:
        description: |
          Create, update, or delete projects with associated details such as name,
          and description.
        type: list
        elements: dict
        required: false
        suboptions:
          name:
            description: |
              The name of the project. This is used to identify the project for creation,
              update, or deletion.
            type: str
            required: true
          new_name:
            description: |
              Specify a new name for the project when updating an existing project.
            type: str
            required: false
          description:
            description: A brief description of the project.
            type: str
            required: false

      configuration_templates:
        description: Operations for Create/Update/Delete
          on a template.
        type: dict
        suboptions:
          author:
            description: Creator of the template.
            type: str
          composite:
            description: Specifies if the template is
              composite.
            type: bool
          containing_templates:
            description:
              - Set of templates within the main template
                to define more complex or modular configurations.
              - This is particularly useful in systems
                that support hierarchical or nested
                templates.
              - Here parent templates may contain child
                templates to form a complete configuration.
            suboptions:
              composite:
                description: Specifies if the template
                  is composite.
                type: bool
              template_description:
                description: Provides a description
                  of the template.
                type: str
              device_types:
                description: List of dictionaries details
                  the types of devices that the templates
                  can be applied to.
                type: list
                elements: dict
                required: true
                suboptions:
                  product_family:
                    description: Denotes the family
                      to which the device belongs.
                    choices:
                      - Cisco Cloud Services Platform
                      - Cisco Interfaces and Modules
                      - Content Networking
                      - Network Management
                      - NFV-ThirdParty Devices
                      - NFVIS
                      - Routers
                      - Security and VPN
                      - Storage Networking
                      - Switches and Hubs
                      - Voice and Telephony
                      - Wireless Controller
                    type: str
                    required: true
                  product_series:
                    description: Specifies the series
                      classification of the device.
                    type: str
                  product_type:
                    description: Describes the exact
                      type of the device.
                    type: str
              id:
                description: Unique identifier for the
                  template, represented as a UUID.
                type: str
              language:
                description: Programming language used
                  for templating. Options are 'JINJA'
                  for Jinja templating or 'VELOCITY'
                  for Apache Velocity.
                choices:
                  - JINJA
                  - VELOCITY
                type: str
              name:
                description: Designation of the template,
                  serving as its unique name.
                type: str
              project_name:
                description: Title of the project within
                  which the template is categorized
                  and managed.
                type: str
              project_description:
                description: Narrative that elaborates
                  on the purpose and scope of the project.
                type: str
              profile_names:
                description: |
                    - List of profile names to be associated with the Configuration Template during creation or update operations.
                    - Enables assignment of one or more network profiles to CLI templates for enhanced device configuration management.
                    - Profile names must correspond to existing network profiles in Cisco Catalyst Center for the specified device types.
                    - Supports assignment of multiple profiles simultaneously for comprehensive device configuration coverage.
                    - Profiles are validated against the device types specified in the template configuration to ensure compatibility.
                    - When combined with existing profile assignments, new profiles are added while preserving existing assignments.
                    - Profile assignment operations are idempotent - re-assigning existing profiles will not cause errors or duplicate assignments.
                    - Requires Cisco Catalyst Center version 3.1.3.0 or later for profile assignment functionality.
                    - Profile names are case-sensitive and must match exactly as configured in Cisco Catalyst Center.
                    - Each profile in the list must be a valid string representing an existing network profile name.
                    - If no profiles are specified, the template will not be associated with any profiles by default.
                    - Profile names can be detached from the template based on deleted state operations.
                    - C(examples):
                    - ["Enterprise_Security_Profile", "QoS_Voice_Profile"]
                    - ["Campus_Switching_Profile"]
                    - ["WAN_Edge_Profile", "Security_Baseline_Profile", "Monitoring_Profile"]
                type: list
                elements: str
                required: false
              tags:
                description: A list of dictionaries
                  representing tags associated with
                  the Configuration Template during
                  creation.
                suboptions:
                  id:
                    description: The unique identifier
                      for each tag, presented as a UUID.
                    type: str
                  name:
                    description: The descriptive label
                      or name assigned to the tag.
                    type: str
                type: list
                elements: dict
              template_content:
                description: The actual script or code
                  constituting the body of the template.
                type: str
              template_params:
                description: The customization of the
                  contents within the template.
                elements: dict
                suboptions:
                  binding:
                    description: Associates the parameter
                      with its source.
                    type: str
                  custom_order:
                    description: Specifies a user-defined
                      ordering for the parameter.
                    type: int
                  data_type:
                    description: Identifies the data
                      type of the parameter (e.g., string,
                      integer, boolean).
                    type: str
                  default_value:
                    description: Establishes a default
                      value for the parameter, used
                      if no other value is provided.
                    type: str
                  description:
                    description: Provides a descriptive
                      explanation of the parameter's
                      purpose.
                    type: str
                  display_name:
                    description: The name of the parameter
                      as displayed to users.
                    type: str
                  group:
                    description: Categorizes the parameter
                      into a named group for organizational
                      purposes.
                    type: str
                  id:
                    description: A unique identifier
                      for the parameter, formatted as
                      a UUID.
                    type: str
                  instruction_text:
                    description: Gives guidance or instructions
                      regarding the parameter's use.
                    type: str
                  key:
                    description: A unique key that identifies
                      the parameter within the template.
                    type: str
                  not_param:
                    description: Indicates whether the
                      entry is not to be treated as
                      a parameter.
                    type: bool
                  order:
                    description: Determines the sequence
                      in which the parameter appears
                      relative to others.
                    type: int
                  param_array:
                    description: Specifies if the parameter
                      should be treated as an array.
                    type: bool
                  parameter_name:
                    description: The name of the parameter.
                    type: str
                  provider:
                    description: Denotes the provider
                      associated with the parameter.
                    type: str
                  range:
                    description: Defines the permissible
                      range for the parameter's value.
                    suboptions:
                      id:
                        description: Unique identifier
                          for the range, represented
                          as a UUID.
                        type: str
                      max_value:
                        description: Specifies the maximum
                          allowable value for the parameter.
                        type: int
                      min_value:
                        description: Specifies the minimum
                          allowable value for the parameter.
                        type: int
                    type: list
                    elements: dict
                  required:
                    description: Dictates whether the
                      parameter is required for template
                      operations.
                    type: bool
                  selection:
                    description: Contains options for
                      parameter selection when a choice
                      is available.
                    suboptions:
                      default_selected_values:
                        description: Lists the default
                          values that are preselected.
                        elements: str
                        type: list
                      id:
                        description: A unique identifier
                          for the selection entity,
                          represented as a UUID.
                        type: str
                      selection_type:
                        description: Specifies the type
                          of selection, such as 'SINGLE_SELECT'
                          or 'MULTI_SELECT'.
                        type: str
                      selection_values:
                        description: A dictionary of
                          available values for selection.
                        type: dict
                    type: dict
                type: list
              version:
                description: The current version of
                  template.
                type: str
            type: list
            elements: dict
          custom_params_order:
            description: Specifies the sequence in which
              custom parameters or variables should
              be arranged within the template.
            type: bool
          template_description:
            description: Provides a overview  of the
              template.
            type: str
          commit:
            description:
              - Indicates whether the template should be committed after configuration changes.
              - If set to 'false', the changes are not committed immediately, allowing for additional
                modifications before an explicit commit.
            type: bool
            default: true
          device_types:
            description: List of dictionaries details
              the types of devices that the templates
              can be applied to.
            type: list
            elements: dict
            suboptions:
              product_family:
                description: Denotes the family to which
                  the device belongs.
                choices:
                  - Cisco Cloud Services Platform
                  - Cisco Interfaces and Modules
                  - Content Networking
                  - Network Management
                  - NFV-ThirdParty Devices
                  - NFVIS
                  - Routers
                  - Security and VPN
                  - Storage Networking
                  - Switches and Hubs
                  - Voice and Telephony
                  - Wireless Controller
                type: str
              product_series:
                description: Specifies the series classification
                  of the device.
                type: str
              product_type:
                description: Describes the exact type
                  of the device.
                type: str
          failure_policy:
            description:
              - Define failure policy if template provisioning
                fails.
              - failure_policy will be enabled only
                when the composite is set to True.
            choices:
              - ABORT_TARGET_ON_ERROR
            type: str
          id:
            description: A unique identifier, represented
              as a UUID.
            type: str
          language:
            description: Programming language used for
              templating. Options are 'JINJA' for Jinja
              templating or 'VELOCITY' for Apache Velocity.
            choices:
              - JINJA
              - VELOCITY
            type: str
          template_name:
            description: Name of template. This field
              is required to create a new template.
            type: str
          new_template_name:
            description:
              - New name of the template.
              - Use this field to update the name of
                the existing template.
            type: str
          project_name:
            description: Title of the project within
              which the template is categorized and
              managed.
            type: str
          project_description:
            description: Narrative that elaborates on
              the purpose and scope of the project.
            type: str
          software_type:
            description: Applicable device software
              type. This field is required to create
              a new template.
            choices:
              - IOS
              - IOS-XE
              - IOS-XR
              - NX-OS
              - Cisco Controller
              - Wide Area Application Services
              - Adaptive Security Appliance
              - NFV-OS
              - Others
            type: str
          software_version:
            description: Applicable device software
              version.
            type: str
          template_tag:
            description: Refers to a keyword, label,
              or metadata assigned to a template.
            suboptions:
              id:
                description: A unique identifier for
                  the tag, represented as a UUID.
                type: str
              name:
                description: The name of the tag.
                type: str
            type: list
            elements: dict
          template_content:
            description: The actual script or code constituting
              the body of the template.
            type: str
          template_params:
            description: The customization of the contents
              within the template.
            suboptions:
              binding:
                description: Associates the parameter
                  with its source.
                type: str
              custom_order:
                description: Specifies a user-defined
                  ordering for the parameter.
                type: int
              data_type:
                description: Identifies the data type
                  of the parameter (e.g., string, integer,
                  boolean).
                type: str
              default_value:
                description: Establishes a default value
                  for the parameter, used if no other
                  value is provided.
                type: str
              description:
                description: Provides a descriptive
                  explanation of the parameter's purpose.
                type: str
              display_name:
                description: The name of the parameter
                  as displayed to users.
                type: str
              group:
                description: Categorizes the parameter
                  into a named group for organizational
                  purposes.
                type: str
              id:
                description: A unique identifier for
                  the parameter, formatted as a UUID.
                type: str
              instruction_text:
                description: Gives guidance or instructions
                  regarding the parameter's use.
                type: str
              key:
                description: A unique key that identifies
                  the parameter within the template.
                type: str
              not_param:
                description: Indicates whether the entry
                  is not to be treated as a parameter.
                type: bool
              order:
                description: Determines the sequence
                  in which the parameter appears relative
                  to others.
                type: int
              param_array:
                description: Specifies if the parameter
                  should be treated as an array.
                type: bool
              parameter_name:
                description: The name of the parameter.
                type: str
              provider:
                description: Denotes the provider associated
                  with the parameter.
                type: str
              range:
                description: Defines the permissible
                  range for the parameter's value.
                suboptions:
                  id:
                    description: Unique identifier for
                      the range, represented as a UUID.
                    type: str
                  max_value:
                    description: Specifies the maximum
                      allowable value for the parameter.
                    type: int
                  min_value:
                    description: Specifies the minimum
                      allowable value for the parameter.
                    type: int
                type: list
                elements: dict
              required:
                description: Dictates whether the parameter
                  is required for template operations.
                type: bool
              selection:
                description: Contains options for parameter
                  selection when a choice is available.
                suboptions:
                  default_selected_values:
                    description: Lists the default values
                      that are preselected.
                    elements: str
                    type: list
                  id:
                    description: A unique identifier
                      for the selection entity, represented
                      as a UUID.
                    type: str
                  selection_type:
                    description: Specifies the type
                      of selection, such as 'SINGLE_SELECT'
                      or 'MULTI_SELECT'.
                    type: str
                  selection_values:
                    description: A dictionary of available
                      values for selection.
                    type: dict
                type: dict
            type: list
            elements: dict
          version:
            description: The current version of template.
            type: str
          version_description:
            description: Template version comments.
            type: str
      export:
        description: Perform export on the projects
          and templates.
        type: dict
        suboptions:
          project:
            description: Export the project(s) details.
            type: list
            elements: str
          template:
            description: Export the template(s) details.
            type: list
            elements: dict
            suboptions:
              project_name:
                description: Name of the project under
                  the template available.
                type: str
              template_name:
                description: Name of the template which
                  we need to be exported.
                type: str
      import:
        description: Perform import on the projects
          and templates.
        type: dict
        suboptions:
          project:
            description: Import the projects.
            type: dict
            suboptions:
              do_version:
                description:
                  - Determines whether to create a new
                    version of the project with the
                    imported contents.
                  - If set to true and the project already
                    exists, a new version will be created.
                  - If false, the operation will fail
                    with a 'Project already exists'
                    error if the project already exists.
                type: bool
              project_file:
                description:
                  - Specifies the path to a JSON file
                    that contains the import project
                    configuration.
                  - If both 'project_file' and 'payload'
                    are provided, the 'project_file'
                    will be given priority.
                type: str
                version_added: 6.17.0
              payload:
                description:
                  - Directly imports configuration data
                    into the system using the provided
                    payload.
                  - Offers an alternative to 'project_file'
                    for importing configurations without
                    referencing an external file.
                  - Ignored if 'project_file' is also
                    provided.
                type: list
                elements: dict
                suboptions:
                  name:
                    description: Name of the project
                      to be imported.
                    type: str
          template:
            description: Import the templates.
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
              template_file:
                description:
                  - Specifies the path to a JSON file
                    that contains an import template.
                  - If both 'template_file' and 'payload'
                    are provided, the 'template_file'
                    will be given priority.
                type: str
              payload:
                description:
                  - The payload parameter is used to
                    directly import configuration data
                    into the system.
                  - The payload provides an alternative
                    way to import configurations without
                    the need to reference an external
                    file.
                  - If both 'template_file' and 'payload'
                    are provided, the 'template_file'
                    will be given priority.
                type: list
                elements: dict
                suboptions:
                  author:
                    description: Identifies the creator
                      of the template.
                    type: str
                  composite:
                    description: Specifies if the template
                      is composite.
                    type: bool
                  containing_templates:
                    description:
                      - Refer to a set of templates
                        within the main template to
                        define more complex or modular
                        configurations.
                      - This is particularly useful
                        in systems that support hierarchical
                        or nested templates.
                      - Here parent templates may contain
                        child templates to form a complete
                        configuration.
                    suboptions:
                      composite:
                        description: Specifies if the
                          template is composite.
                        type: bool
                      description:
                        description: Provides a description
                          of the template.
                        type: str
                      device_types:
                        description: List of dictionaries
                          details the types of devices
                          that the templates can be
                          applied to.
                        type: list
                        elements: dict
                        suboptions:
                          product_family:
                            description: Denotes the
                              family to which the device
                              belongs.
                            choices:
                              - Cisco Cloud Services
                                Platform
                              - Cisco Interfaces and
                                Modules
                              - Content Networking
                              - Network Management
                              - NFV-ThirdParty Devices
                              - NFVIS
                              - Routers
                              - Security and VPN
                              - Storage Networking
                              - Switches and Hubs
                              - Voice and Telephony
                              - Wireless Controller
                            type: str
                          product_series:
                            description: Specifies the
                              series classification
                              of the device.
                            type: str
                          product_type:
                            description: Describes the
                              exact type of the device.
                            type: str
                      id:
                        description: Unique identifier
                          for the template, represented
                          as a UUID.
                        type: str
                      language:
                        description: Programming language
                          used for templating. Options
                          are 'JINJA' for Jinja templating
                          or 'VELOCITY' for Apache Velocity.
                        choices:
                          - JINJA
                          - VELOCITY
                        type: str
                      name:
                        description: Designation of
                          the template, serving as its
                          unique name.
                        type: str
                      project_name:
                        description: Title of the project
                          within which the template
                          is categorized and managed.
                        type: str
                      tags:
                        description: A list of dictionaries
                          representing tags associated
                          with the Configuration Template
                          during creation.
                        suboptions:
                          id:
                            description: The unique
                              identifier for each tag,
                              presented as a UUID.
                            type: str
                          name:
                            description: The descriptive
                              label or name assigned
                              to the tag.
                            type: str
                        type: list
                        elements: dict
                      template_content:
                        description: The actual script
                          or code constituting the body
                          of the template.
                        type: str
                      template_params:
                        description: The customization
                          of the contents within the
                          template.
                        elements: dict
                        suboptions:
                          binding:
                            description: Associates
                              the parameter with its
                              source.
                            type: str
                          custom_order:
                            description: Specifies a
                              user-defined ordering
                              for the parameter.
                            type: int
                          data_type:
                            description: Identifies
                              the data type of the parameter
                              (e.g., string, integer,
                              boolean).
                            type: str
                          default_value:
                            description: Establishes
                              a default value for the
                              parameter, used if no
                              other value is provided.
                            type: str
                          description:
                            description: Provides a
                              descriptive explanation
                              of the parameter's purpose.
                            type: str
                          display_name:
                            description: The name of
                              the parameter as displayed
                              to users.
                            type: str
                          group:
                            description: Categorizes
                              the parameter into a named
                              group for organizational
                              purposes.
                            type: str
                          id:
                            description: A unique identifier
                              for the parameter, formatted
                              as a UUID.
                            type: str
                          instruction_text:
                            description: Gives guidance
                              or instructions regarding
                              the parameter's use.
                            type: str
                          key:
                            description: A unique key
                              that identifies the parameter
                              within the template.
                            type: str
                          not_param:
                            description: Indicates whether
                              the entry is not to be
                              treated as a parameter.
                            type: bool
                          order:
                            description: Determines
                              the sequence in which
                              the parameter appears
                              relative to others.
                            type: int
                          param_array:
                            description: Specifies if
                              the parameter should be
                              treated as an array.
                            type: bool
                          parameter_name:
                            description: The name of
                              the parameter.
                            type: str
                          provider:
                            description: Denotes the
                              provider associated with
                              the parameter.
                            type: str
                          range:
                            description: Defines the
                              permissible range for
                              the parameter's value.
                            suboptions:
                              id:
                                description: Unique
                                  identifier for the
                                  range, represented
                                  as a UUID.
                                type: str
                              max_value:
                                description: Specifies
                                  the maximum allowable
                                  value for the parameter.
                                type: int
                              min_value:
                                description: Specifies
                                  the minimum allowable
                                  value for the parameter.
                                type: int
                            type: list
                            elements: dict
                          required:
                            description: Dictates whether
                              the parameter is required
                              for template operations.
                            type: bool
                          selection:
                            description: Contains options
                              for parameter selection
                              when a choice is available.
                            suboptions:
                              default_selected_values:
                                description: Lists the
                                  default values that
                                  are preselected.
                                elements: str
                                type: list
                              id:
                                description: A unique
                                  identifier for the
                                  selection entity,
                                  represented as a UUID.
                                type: str
                              selection_type:
                                description: Specifies
                                  the type of selection,
                                  such as 'SINGLE_SELECT'
                                  or 'MULTI_SELECT'.
                                type: str
                              selection_values:
                                description: A dictionary
                                  of available values
                                  for selection.
                                type: dict
                            type: dict
                        type: list
                      version:
                        description: The current version
                          of template.
                        type: str
                    type: list
                    elements: dict
                  custom_params_order:
                    description: Specifies the sequence
                      in which custom parameters or
                      variables should be arranged within
                      the template.
                    type: bool
                  template_description:
                    description: Provides a overview  of
                      the template.
                    type: str
                  device_types:
                    description: List of dictionaries
                      details the types of devices that
                      the templates can be applied to.
                    type: list
                    elements: dict
                    suboptions:
                      product_family:
                        description: Denotes the family
                          to which the device belongs.
                        choices:
                          - Cisco Cloud Services Platform
                          - Cisco Interfaces and Modules
                          - Content Networking
                          - Network Management
                          - NFV-ThirdParty Devices
                          - NFVIS
                          - Routers
                          - Security and VPN
                          - Storage Networking
                          - Switches and Hubs
                          - Voice and Telephony
                          - Wireless Controller
                        type: str
                      product_series:
                        description: Specifies the series
                          classification of the device.
                        type: str
                      product_type:
                        description: Describes the exact
                          type of the device.
                        type: str
                  failure_policy:
                    description:
                      - Define failure policy if template
                        provisioning fails.
                      - failure_policy will be enabled
                        only when the composite is set
                        to True.
                    choices:
                      - ABORT_TARGET_ON_ERROR
                    type: str
                  id:
                    description: A unique identifier,
                      represented as a UUID.
                    type: str
                  language:
                    description: Programming language
                      used for templating. Options are
                      'JINJA' for Jinja templating or
                      'VELOCITY' for Apache Velocity.
                    choices:
                      - JINJA
                      - VELOCITY
                    type: str
                  template_name:
                    description: Name of template. This
                      field is required to create a
                      new template.
                    type: str
                  project_name:
                    description: Title of the project
                      within which the template is categorized
                      and managed.
                    type: str
                  project_description:
                    description: Narrative that elaborates
                      on the purpose and scope of the
                      project.
                    type: str
                  software_type:
                    description: Applicable device software
                      type. This field is required to
                      create a new template.
                    choices:
                      - IOS
                      - IOS-XE
                      - IOS-XR
                      - NX-OS
                      - Cisco Controller
                      - Wide Area Application Services
                      - Adaptive Security Appliance
                      - NFV-OS
                      - Others
                    type: str
                  software_version:
                    description: Applicable device software
                      version.
                    type: str
                  template_tag:
                    description: Refers to a keyword,
                      label, or metadata assigned to
                      a template.
                    suboptions:
                      id:
                        description: A unique identifier
                          for the tag, represented as
                          a UUID.
                        type: str
                      name:
                        description: The name of the
                          tag.
                        type: str
                    type: list
                    elements: dict
                  template_content:
                    description: The actual script or
                      code constituting the body of
                      the template.
                    type: str
                  template_params:
                    description: The customization of
                      the contents within the template.
                    suboptions:
                      binding:
                        description: Associates the
                          parameter with its source.
                        type: str
                      custom_order:
                        description: Specifies a user-defined
                          ordering for the parameter.
                        type: int
                      data_type:
                        description: Identifies the
                          data type of the parameter
                          (e.g., string, integer, boolean).
                        type: str
                      default_value:
                        description: Establishes a default
                          value for the parameter, used
                          if no other value is provided.
                        type: str
                      description:
                        description: Provides a descriptive
                          explanation of the parameter's
                          purpose.
                        type: str
                      display_name:
                        description: The name of the
                          parameter as displayed to
                          users.
                        type: str
                      group:
                        description: Categorizes the
                          parameter into a named group
                          for organizational purposes.
                        type: str
                      id:
                        description: A unique identifier
                          for the parameter, formatted
                          as a UUID.
                        type: str
                      instruction_text:
                        description: Gives guidance
                          or instructions regarding
                          the parameter's use.
                        type: str
                      key:
                        description: A unique key that
                          identifies the parameter within
                          the template.
                        type: str
                      not_param:
                        description: Indicates whether
                          the entry is not to be treated
                          as a parameter.
                        type: bool
                      order:
                        description: Determines the
                          sequence in which the parameter
                          appears relative to others.
                        type: int
                      param_array:
                        description: Specifies if the
                          parameter should be treated
                          as an array.
                        type: bool
                      parameter_name:
                        description: The name of the
                          parameter.
                        type: str
                      provider:
                        description: Denotes the provider
                          associated with the parameter.
                        type: str
                      range:
                        description: Defines the permissible
                          range for the parameter's
                          value.
                        suboptions:
                          id:
                            description: Unique identifier
                              for the range, represented
                              as a UUID.
                            type: str
                          max_value:
                            description: Specifies the
                              maximum allowable value
                              for the parameter.
                            type: int
                          min_value:
                            description: Specifies the
                              minimum allowable value
                              for the parameter.
                            type: int
                        type: list
                        elements: dict
                      required:
                        description: Dictates whether
                          the parameter is required
                          for template operations.
                        type: bool
                      selection:
                        description: Contains options
                          for parameter selection when
                          a choice is available.
                        suboptions:
                          default_selected_values:
                            description: Lists the default
                              values that are preselected.
                            elements: str
                            type: list
                          id:
                            description: A unique identifier
                              for the selection entity,
                              represented as a UUID.
                            type: str
                          selection_type:
                            description: Specifies the
                              type of selection, such
                              as 'SINGLE_SELECT' or
                              'MULTI_SELECT'.
                            type: str
                          selection_values:
                            description: A dictionary
                              of available values for
                              selection.
                            type: dict
                        type: dict
                    type: list
                    elements: dict
                  version:
                    description: The current version
                      of template.
                    type: str
              project_name:
                description: ProjectName path parameter.
                  Project name to create template under
                  the project.
                type: str
      deploy_template:
        description: To deploy the template to the devices
          based on either list of site provisionig details
          with further filtering criteria like device
          family, device role, device tag or by providing
          the device specific details which includes
          device_ips, device_hostnames, serial_numbers
          or mac_addresses.
        type: dict
        suboptions:
          project_name:
            description: Provide the name of project
              under which the template is available.
            type: str
          template_name:
            description: Name of the template to be
              deployed.
            type: str
          force_push:
            description: Boolean flag to indicate whether
              the template should be forcefully pushed
              to the devices, overriding any existing
              configuration.
            type: bool
          is_composite:
            description: Boolean flag indicating whether
              the template is composite, which means
              the template is built using multiple smaller
              templates.
            type: bool
          copy_config:
            description:
              - A boolean flag that specifies whether
                the device's running configuration should
                be copied to the startup configuration
                after applying the template.
              - If set to 'true', the updated configuration
                will be saved to the startup configuration.
                be copied to the start up config from
                the device before applying the template.
            type: bool
            default: true
          version:
            description: This is useful for targeting specific template versions, such as rolling back
              to a tested version.
            type: int
          template_parameters:
            description: A list of parameter name-value
              pairs used for customizing the template
              with specific values for each device.
            type: list
            elements: dict
            suboptions:
              param_name:
                description: Name of the parameter in
                  the template that needs to be replaced
                  with a specific value.
                type: str
              param_value:
                description: Value assigned to the parameter
                  for deployment to devices.
                type: str
          resource_parameters:
            description: A list of configuration parameters
              required for provisioning resources in
              the system. These parameters define specific
              settings or details that must be supplied
              when deploying templates. If the template
              uses system variables (variables prefixed
              with __, (e.g., __device), the corresponding
              resource parameters must be provided to
              ensure successful deployment.
            type: list
            elements: dict
            suboptions:
              resource_type:
                description: The type of the resource param that is to be provisioned during template deployment
                  - Specifies the type of the resource parameter to be provisioned during template deployment.
                  - Possible enum values are -
                    - MANAGED_DEVICE_UUID - Used when the parameter value is the UUID of the device.
                    - MANAGED_DEVICE_IP - Used when the parameter value is the device's IP address.
                    - MANAGED_DEVICE_HOSTNAME - Used when the parameter value is the device's hostname.
                    - SITE_UUID - Used when the parameter value is the UUID of a site.
                    - MANAGED_AP_LOCATIONS - Used when the parameter value is the locations of managed access points within the network.
                    - SECONDARY_MANAGED_AP_LOCATIONS - Used when the parameter value is the locations of secondary or backup managed access points.
                    - SSID_NAME - Used when the parameter value is the name of a wireless network.
                    - POLICY_PROFILE - Used when the parameter value is a set of policies that can be applied to network devices or users.
                    - From the above enum values, the following resource types support value provisioning at runtime
                      - MANAGED_DEVICE_UUID
                      - MANAGED_DEVICE_IP
                      - MANAGED_DEVICE_HOSTNAME
                      - SITE_UUID
                    - For all other resource types, the values must be provided at design time in the playbook.
                type: str
              resource_scope:
                description:
                  - Specifies the scope in which the
                    resource parameter is to be provisioned.
                  - Possible enum values are - - RUNTIME
                    - A parameter with a runtime scope
                    is provided at the time of deployment.
                    These values are dynamic and may
                    change with each deployment, as
                    they are based on the specific context
                    of the deployment. - DESIGN - A
                    parameter with a design scope is
                    defined during the design phase
                    of the template. These values are
                    static after template creation and
                    remain consistent across deployments.
                type: str
              resource_value:
                description: The actual value of the
                  resource param to be provisioned.
                type: str
          device_details:
            description: Details specific to devices
              where the template will be deployed, including
              lists of device IPs, hostnames, serial
              numbers, or MAC addresses.
            type: dict
            suboptions:
              device_ips:
                description: A list of IP addresses
                  of the devices where the template
                  will be deployed.
                type: list
                elements: str
              device_hostnames:
                description: A list of hostnames of
                  the devices where the template will
                  be deployed.
                type: list
                elements: str
              serial_numbers:
                description: A list of serial numbers
                  of the devices where the template
                  will be deployed.
                type: list
                elements: str
              mac_addresses:
                description: A list of MAC addresses
                  of the devices where the template
                  will be deployed.
                type: list
                elements: str
          site_provisioning_details:
            description: Parameters related to site-based
              provisioning, allowing the deployment
              of templates to devices associated with
              specific sites, with optional filtering
              by device family, role, or tag.
            type: list
            elements: dict
            suboptions:
              site_name:
                description: Name of the site where
                  the devices are associated for provisioning.
                type: list
                elements: str
              device_family:
                description: Family of the devices (e.g.,
                  switches, routers) used to filter
                  devices for template deployment.
                type: str
              device_role:
                description: Role of the devices (e.g.,
                  access, core, edge) used to filter
                  devices for template deployment.
                type: str
              device_tag:
                description: Specific device tag used
                  to filter devices for template deployment.
                type: str

requirements:
  - dnacentersdk >= 2.8.6
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
  - While deploying the template to devices, the value for the following resource types can be filled in the resource parameters at
    RUNTIME- MANAGED_DEVICE_UUID, MANAGED_DEVICE_IP, MANAGED_DEVICE_HOSTNAME, and SITE_UUID. For all other resource types, the value
    must be provided at DESIGN time in the playbook.
"""

EXAMPLES = r"""
---
- name: Create a new template.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      - configuration_templates:
          author: string
          composite: true
          custom_params_order: true
          template_description: string
          device_types:
            - product_family: string
              product_series: string
              product_type: string
          failure_policy: string
          id: string
          language: string
          template_name: string
          project_name: string
          project_description: string
          profile_names:
            - string
          software_type: string
          software_version: string
          tags:
            - id: string
              name: string
          template_content: string
          version: string

- name: Update a template.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      - configuration_templates:
          author: string
          composite: true
          custom_params_order: true
          template_description: string
          device_types:
            - product_family: string
              product_series: string
              product_type: string
          failure_policy: string
          id: string
          language: string
          template_name: string
          new_template_name: string
          project_name: string
          project_description: string
          profile_names:
            - string
          software_type: string
          software_version: string
          tags:
            - id: string
              name: string
          template_content: string

- name: Export the projects.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      export:
        project:
          - string
          - string

- name: Export the templates.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      export:
        template:
          - project_name: string
            template_name: string
          - project_name: string
            template_name: string

- name: Import the Projects.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      import:
        project:
          do_version: false
          payload:
            - name: string
            - name: string

- name: Import the Templates.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      import:
        template:
          do_version: false
          project_name: string
          template_file: string

- name: Creating a JINJA-based template to configure
    access VLAN and interfaces on Catalyst 9300
  cisco.dnac.template_workflow_manager:
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
          author: Test_User
          composite: false
          custom_params_order: true
          template_description: Template to configure access
            VLAN and access interfaces
          device_types:
            - product_family: Switches and Hubs
              product_series: Cisco Catalyst 9300 Series
                Switches
          failure_policy: ABORT_TARGET_ON_ERROR
          language: JINJA
          template_name: PnP-Upstream-SW1
          project_name: access_vlan_template_9300_switches
          project_description: This project contains
            all the templates for Access Switches
          software_type: IOS-XE
          template_content: |
            {% raw %}
            vlan {{ vlan }}
            interface {{ interface }}
            no shutdown
            switchport access vlan {{ vlan }}
            switchport mode access
            description {{ interface_description }}
            {% endraw %}
          version: "1.0"

- name: Creating a VELOCITY-based Fusion Router template
    for Catalyst 3850 switches
  cisco.dnac.template_workflow_manager:
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
          template_name: "Fusion Router Config"
          template_description: "VELOCITY template to configure
            L3 handoff and loopback on Catalyst 3850"
          project_name: "Network Configuration Templates"
          tags: []
          author: admin
          device_types:
            - product_family: "Switches and Hubs"
              product_series: "Cisco Catalyst 3850 Series
                Ethernet Stackable Switch"
          software_type: IOS-XE
          language: VELOCITY
          failure_policy: ABORT_TARGET_ON_ERROR
          template_content: |
            ! L3handoff Vlan
            vlan $VLANID
            hostname  Old$__device.hostname
            interface Loopback0
            ip address $LOOPBACKIP 255.255.255.255
            ipv6 address $LOOPBACKIPV6
            ipv6 enable
            ipv6 nd other-config-flag
            ipv6 dhcp server EMPPool
            ! L3handdoff interface for provider VN
            interface Vlan$VLANID
            description L3handoff $VLANID
            ip address $interfaceIP 255.255.255.252
            ip route-cache same-interface
            ipv6 address $interfaceIPV6
            ipv6 enable
            ipv6 tcp adjust-mss 1400

- name: Deploy the given template to the devices based
    on site specific details and other filtering mode
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      deploy_template:
        project_name: "Sample_Project"
        template_name: "Sample Template"
        force_push: true
        template_parameters:
          - param_name: "vlan_id"
            param_value: "1431"
          - param_name: "vlan_name"
            param_value: "testvlan31"
        site_provisioning_details:
          - site_name: "Global/Bangalore/Building14/Floor1"
            device_family: "Switches and Hubs"

- name: Deploy the given template to the devices based
    on device specific details
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      deploy_template:
        project_name: "Sample_Project"
        template_name: "Sample Template"
        force_push: true
        template_parameters:
          - param_name: "vlan_id"
            param_value: "1431"
          - param_name: "vlan_name"
            param_value: "testvlan31"
        device_details:
          device_ips: ["10.1.2.1", "10.2.3.4"]

- name: Deploy template to the devices using resource
    parameters and copying config
  cisco.dnac.template_workflow_manager:
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
      deploy_template:
        project_name: "Sample_Project"
        template_name: "Sample Template"
        force_push: true
        template_parameters:
          - param_name: "vlan_id"
            param_value: "1431"
          - param_name: "vlan_name"
            param_value: "testvlan31"
        resource_parameters:
          - resource_type: "MANAGED_DEVICE_IP"
            resource_scope: "RUNTIME"
        device_details:
          device_ips: ["10.1.2.1", "10.2.3.4"]
        copy_config: true

- name: Delete the given project or template from the
    Cisco Catalyst Center
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: deleted
    config:
      configuration_templates:
        project_name: "Sample_Project"
        template_name: "Sample Template"
        language: "velocity"
        software_type: "IOS-XE"
        device_types:
          - product_family: "Switches and Hubs"

- name: Create a New Project
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      - projects:
          - name: Wireless_Controller
            description: Centralized repository for managing templates and configurations for wireless controllers (WLCs).

- name: Update project name and details.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: merged
    config:
      - projects:
          - name: Wireless_Controller
            new_name: Wireless_Template_Management
            description: Centralized repository for managing templates and configurations for wireless controllers (WLCs).

- name: Delete project based on the name.
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: deleted
    config:
      - projects:
          - name: Wireless_Template_Management

- name: Creating complete configuration template with profiles
    response in Case_9
  cisco.dnac.template_workflow_manager:
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
          author: Test_User
          composite: false
          custom_params_order: true
          template_description: Template to configure access
            VLAN and access interfaces
          device_types:
            - product_family: Switches and Hubs
              product_series: Cisco Catalyst 9300 Series
                Switches
          failure_policy: ABORT_TARGET_ON_ERROR
          language: JINJA
          template_name: PnP-Upstream-SW1
          profile_names:
            - TestProfile
            - PNP_Onboarding_Template
          project_name: access_vlan_template_9300_switches
          project_description: This project contains
            all the templates for Access Switches
          software_type: IOS-XE
          template_content: |
            {% raw %}
            vlan {{ vlan }}
            interface {{ interface }}
            no shutdown
            switchport access vlan {{ vlan }}
            switchport mode access
            description {{ interface_description }}
            {% endraw %}
          version: "1.0"

- name: Update configuration template with additional profile
    response in Case_10
  cisco.dnac.template_workflow_manager:
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
          author: Test_User
          composite: false
          custom_params_order: true
          template_description: Template to configure access
            VLAN and access interfaces
          device_types:
            - product_family: Switches and Hubs
              product_series: Cisco Catalyst 9300 Series
                Switches
          failure_policy: ABORT_TARGET_ON_ERROR
          language: JINJA
          template_name: PnP-Upstream-SW1
          profile_names:
            - TestProfile
            - PNP_Onboarding_Template
          project_name: access_vlan_template_9300_switches
          project_description: This project contains
            all the templates for Access Switches
          software_type: IOS-XE
          template_content: |
            {% raw %}
            vlan {{ vlan }}
            interface {{ interface }}
            no shutdown
            switchport access vlan {{ vlan }}
            switchport mode access
            description {{ interface_description }}
            {% endraw %}
          version: "1.0"

- name: Detach a profile from the configuration template on deleted state
    response in Case_11
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: deleted
    config:
      configuration_templates:
        project_name: "access_vlan_template_9300_switches"
        template_name: "AA_PnP-Upstream-SW1"
        language: "JINJA"
        software_type: "IOS-XE"
        profile_names:
          - TestProfile
        device_types:
          - product_family: "Switches and Hubs"

- name: Deleting configuration template no need to attach profiles
    it will unassign profiles and delete the template without impacting profiles
    response in Case_12
  cisco.dnac.template_workflow_manager:
    dnac_host: "{{ dnac_host }}"
    dnac_port: "{{ dnac_port }}"
    dnac_username: "{{ dnac_username }}"
    dnac_password: "{{ dnac_password }}"
    dnac_verify: "{{ dnac_verify }}"
    dnac_version: "{{ dnac_version }}"
    dnac_debug: "{{ dnac_debug }}"
    dnac_log_level: "{{ dnac_log_level }}"
    dnac_log: true
    config_verify: true
    state: deleted
    config:
      configuration_templates:
        project_name: "access_vlan_template_9300_switches"
        template_name: "AA_PnP-Upstream-SW1"
        language: "JINJA"
        software_type: "IOS-XE"
        device_types:
          - product_family: "Switches and Hubs"
"""

RETURN = r"""
# Case_1: Successful creation/updation/deletion of template/project
response_1:
  description: A dictionary with versioning details of the template as returned by the Cisco Catalyst Center Python SDK
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
  description: A list with the response returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: list
  sample: >
    {
      "response": [],
      "msg": String
    }

# Case_3: Given template already exists and requires no update
response_3:
  description: A dictionary with the exisiting template deatails as returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "msg": String
    }

# Case_4: Given template list that needs to be exported
response_4:
  description: Details of the templates in the list as returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "msg": String
    }

# Case_5: Given project list that needs to be exported
response_5:
  description: Details of the projects in the list as returned by the Cisco Catalyst Center Python SDK
  returned: always
  type: dict
  sample: >
    {
      "response": {},
      "msg": String
    }

# Case_6: Response for Creating a Project with a Name
response_6:
  description: Response when a project is created successfully
  returned: always
  type: dict
  sample: >
    {
        "msg": "project Wireless_Controller created succesfully",
        "response": "project Wireless_Controller created succesfully",
        "status": "success"
    }

# Case_7: Response for Updating a Project with a Name
response_7:
  description: Provides details of the response when a project is successfully updated using the Cisco Catalyst Center Python SDK.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Project 'Wireless_Template_Management' updated successfully.",
        "response": Project 'Wireless_Template_Management' updated successfully.",
        "status": "success"
    }

# Case_8: Response for Deleting a Project by Name
response_8:
  description: Response when a project is Deleted successfully.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Project(s) are deleted and verified successfully. ['Wireless_Template_Management']",
        "response": [
            {
                "name": "Wireless_Template_Management"
            }
        ],
        "status": "success"
    }

# Case_9: Response for Creating a Complete Configuration Template with profiles
response_9:
  description: Response when a complete configuration template is created successfully with profiles.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Template '['AA_PnP-Upstream-SW1']' created successfully in the Cisco Catalyst Center.
                Template '['AA_PnP-Upstream-SW1']' committed successfully in the Cisco Catalyst Center.
                Profile(s) '['TestProfile', 'PNP_Onboarding_Template']' assigned successfully to the template.",
        "response": "Template '['AA_PnP-Upstream-SW1']' created successfully in the Cisco Catalyst Center.
                    Template '['AA_PnP-Upstream-SW1']' committed successfully in the Cisco Catalyst Center.
                    Profile(s) '['TestProfile', 'PNP_Onboarding_Template']' assigned successfully to the template.",
        "status": "success"
    }

# Case_10: Response for Updating a Configuration Template with Additional Profile
response_10:
  description: Response when a configuration template is updated successfully with an additional profile.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Template '['AA_PnP-Upstream-SW1']' updated successfully in the Cisco Catalyst Center.
                Template '['AA_PnP-Upstream-SW1']' committed successfully in the Cisco Catalyst Center.
                Profile(s) '['PNP_Onboarding_Template']' assigned successfully to the template.
                Profile(s) '['TestProfile']' already exist and cannot be assigned to the template.",
        "response": "Template '['AA_PnP-Upstream-SW1']' updated successfully in the Cisco Catalyst Center.
                    Template '['AA_PnP-Upstream-SW1']' committed successfully in the Cisco Catalyst Center.
                    Profile(s) '['PNP_Onboarding_Template']' assigned successfully to the template.
                    Profile(s) '['TestProfile']' already exist and cannot be assigned to the template.",
        "status": "success"
    }

# Case_11: Response for Detach a profile from the configuration template on deleted state
response_11:
  description: Response when a profile is detached from the configuration template on deleted state.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Profile(s) '['TestProfile']' detached successfully from the template.",
        "response": "Profile(s) '['TestProfile']' detached successfully from the template.",
        "status": "success"
    }

# Case_12: Response for Deleting a configuration template without affecting profiles
response_12:
  description: Response when a configuration template is deleted without affecting profiles.
  returned: always
  type: dict
  sample: >
    {
        "msg": "Task: deletes_the_template is successful for parameters:
                {'template_id': '9a68dfa3-86ac-442b-bc92-957bfbd76ca7', 'active_validation': False}",
        "response": "Task: deletes_the_template is successful for parameters:
                    {'template_id': '9a68dfa3-86ac-442b-bc92-957bfbd76ca7', 'active_validation': False}",
        "status": "success"
    }
"""

import copy
import json
import time
import re
from ansible.module_utils.basic import AnsibleModule
from ansible_collections.cisco.dnac.plugins.module_utils.dnac import (
    validate_list_of_dicts,
    get_dict_result,
    dnac_compare_equality,
    validate_str
)
from ansible_collections.cisco.dnac.plugins.module_utils.network_profiles import (
    NetworkProfileFunctions,
)


class Template(NetworkProfileFunctions):
    """Class containing member attributes for template_workflow_manager module"""

    def __init__(self, module):
        super().__init__(module)
        self.have_project = {}
        self.have_template = {}
        self.supported_states = ["merged", "deleted"]
        self.accepted_languages = ["JINJA", "VELOCITY"]
        self.export_template = []
        self.max_timeout = self.params.get('dnac_api_task_timeout')
        self.template_created, self.no_update_template, self.template_updated = [], [], []
        self.project_created, self.template_committed = [], []
        self.profile_assigned, self.no_profile_assigned, self.profile_exists = [], [], []
        self.profile_detached, self.profile_not_detached, self.profile_already_detached = [], [], []
        self.result['response'] = [
            {"configurationTemplate": {"response": {}, "msg": {}}},
            {"export": {"response": {}}},
            {"import": {"response": {}}},
        ]

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
                "custom_params_order": {"type": "bool"},
                "template_description": {"type": "str"},
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
                "name": {"type": "str"},
                "project_name": {"type": "str"},
                "project_description": {"type": "str"},
                "profile_names": {"type": "list", "elements": "str"},
                "software_type": {"type": "str"},
                "software_version": {"type": "str"},
                "template_content": {"type": "str"},
                "template_params": {"type": "list"},
                "template_name": {"type": "str"},
                "new_template_name": {"type": "str"},
                "version": {"type": "str"},
            },
            "deploy_template": {
                "type": "dict",
                "project_name": {"type": "str"},
                "template_name": {"type": "str"},
                "force_push": {"type": "bool"},
                "is_composite": {"type": "bool"},
                "copy_config": {"type": "bool", "default": True},
                "template_parameters": {
                    "type": "list",
                    "elements": "dict",
                    "param_name": {"type": "str"},
                    "param_value": {"type": "str"},
                },
                "resource_parameters": {
                    "type": "list",
                    "elements": "dict",
                    "resource_type": {"type": "str"},
                    "resource_scope": {"type": "str"},
                    "resource_value": {"type": "str"},
                },
                "device_details": {
                    "type": "dict",
                    "device_ips": {"type": "list", "elements": "str"},
                    "device_hostnames": {"type": "list", "elements": "str"},
                    "serial_numbers": {"type": "list", "elements": "str"},
                    "mac_addresses": {"type": "list", "elements": "str"},
                },
                "site_provisioning_details": {
                    "type": "list",
                    "elements": "dict",
                    "site_name": {"type": "str"},
                    "device_family": {"type": "str"},
                    "device_role": {"type": "str"},
                    "device_tag": {"type": "str"},
                },
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
                    "project_file": {"type": "str"},
                    "do_version": {"type": "str", "default": "False"},
                },
                "template": {
                    "type": "dict",
                    "do_version": {"type": "str", "default": "False"},
                    "template_file": {"type": "str"},
                    "payload": {
                        "type": "list",
                        "elements": "dict",
                        "tags": {"type": "list"},
                        "author": {"type": "str"},
                        "composite": {"type": "bool"},
                        "containing_templates": {"type": "list"},
                        "custom_params_order": {"type": "bool"},
                        "template_description": {"type": "str"},
                        "device_types": {
                            "type": "list",
                            "elements": "dict",
                            "product_family": {"type": "str"},
                            "product_series": {"type": "str"},
                            "product_type": {"type": "str"},
                        },
                        'failure_policy': {'type': 'str'},
                        'id': {'type': 'str'},
                        'language': {'type': 'str'},
                        'name': {'type': 'str'},
                        'project_name': {'type': 'str'},
                        'project_description': {'type': 'str'},
                        'software_type': {'type': 'str'},
                        'software_version': {'type': 'str'},
                        'template_content': {'type': 'str'},
                        'template_params': {'type': 'list'},
                        'template_name': {'type': 'str'},
                        'version': {'type': 'str'}
                    }
                }
            },
            "projects": {
                "type": "list",
                "elements": "dict",
                "options": {
                    "name": {"type": "str", "required": True},
                    "new_name": {"type": "str"},
                    "description": {"type": "str"}
                }
            }
        }

        # Validate template params
        self.config = self.camel_to_snake_case(self.config)

        valid_temp, invalid_params = validate_list_of_dicts(
            self.config, temp_spec
        )

        if invalid_params:
            self.msg = "Invalid parameters in playbook: {0}".format(
                "\n".join(invalid_params)
            )
            self.status = "failed"
            return self

        self.input_data_validation(valid_temp).check_return_status()

        self.validated_config = valid_temp
        self.log(
            "Successfully validated playbook config params: {0}".format(self.pprint(valid_temp)),
            "INFO",
        )
        self.msg = "Successfully validated input"
        self.status = "success"
        return self

    def input_data_validation(self, config):
        """
        Validates the input configuration structure for template workflow operations in Cisco Catalyst Center.

        Args:
            self (object): Instance of the class interacting with Cisco Catalyst Center.
            config (list[dict]): List of dictionaries containing project definitions data.

        Returns:
            object: Returns self if validation passes; otherwise, logs an error and exits the module.

        Description:
            This method performs structural and type validation on the 'projects' list within the config.
            It checks for the presence and string type of required fields like 'name', and optionally
            validates fields such as 'new_name' and 'description'.

            If the module state is set to 'deleted', only minimal validation is performed.
            If any validation errors are detected, the method logs an error and terminates the module run.
        """

        self.log("Starting input data validation.", "INFO")
        errormsg = []
        param_spec_str = dict(type="str")

        projects = config[0].get("projects")
        if projects and isinstance(projects, list):
            for each_project in projects:
                project_name = each_project.get("name")
                if project_name and isinstance(project_name, str):
                    validate_str(project_name, param_spec_str, "name", errormsg)
                else:
                    errormsg.append("Missing or invalid 'name' field in project.")

                if self.payload.get("state") == "deleted":
                    continue

                project_new_name = each_project.get("new_name")
                if project_new_name and isinstance(project_new_name, str):
                    validate_str(project_new_name, param_spec_str, "new_name", errormsg)

                description = each_project.get("description")
                if description and isinstance(description, str):
                    validate_str(description, param_spec_str, "description", errormsg)

        self.log("Initiating profile assignment validation for CLI templates", "DEBUG")
        configuration_templates = config[0].get("configuration_templates")
        if configuration_templates and isinstance(configuration_templates, dict):
            profile_names = configuration_templates.get("profile_names")
            ccc_version = self.get_ccc_version()
            self.log("Processing profile assignment configuration - profiles: {0}".format(
                profile_names), "DEBUG")

            if profile_names and isinstance(profile_names, list):
                if self.compare_dnac_versions(ccc_version, "3.1.3.0") < 0:
                    msg = (
                        "Profile assignment feature is not supported in Cisco Catalyst Center version '{0}'. "
                        "Supported versions start from '3.1.3.0' onwards. Current configuration includes "
                        "profiles: {1}".format(ccc_version, bool(profile_names))
                    )
                    errormsg.append(msg)
                else:
                    self.log("Validating profiles configuration for template profile assignment", "DEBUG")
                    for each_profile in profile_names:
                        if each_profile and isinstance(each_profile, str):
                            validate_str(each_profile, param_spec_str, "profile_names", errormsg)

        if errormsg:
            msg = "Invalid parameters in playbook config: '{0}' ".format(errormsg)
            self.log(msg, "ERROR")
            self.fail_and_exit(msg)

        msg = "Successfully validated config params: {0}".format(str(config))
        self.log(msg, "INFO")
        return self

    def get_project_params(self, params):
        """
        Store project parameters from the playbook for template processing in Cisco Catalyst Center.

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
        Store tags from the playbook for template processing in Cisco Catalyst Center.
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
                self.msg = "name is required in tags in location " + str(i)
                self.status = "failed"
                return self.check_return_status()

        return tags

    def get_device_types(self, device_types):
        """
        Store device types parameters from the playbook for template processing in Cisco Catalyst Center.
        Check using check_return_status()

        Parameters:
            device_types (dict) - Device types details containing Template information.

        Returns:
            deviceTypes (dict) - Organized device types parameters.
        """

        if device_types is None:
            self.msg = "The parameter 'device_types' is required but not provided."
            self.status = "failed"
            return self.check_return_status()

        deviceTypes = []
        i = 0
        for item in device_types:
            deviceTypes.append({})
            product_family = item.get("product_family")
            if product_family is not None:
                deviceTypes[i].update({"productFamily": product_family})
            else:
                self.msg = "The parameter 'product_family' is required for 'device_types' but not provided."
                self.status = "failed"
                return self.check_return_status()

            product_families_list = [
                "Cisco Cloud Services Platform",
                "Cisco Interfaces and Modules",
                "Content Networking",
                "Network Management",
                "NFV-ThirdParty Devices",
                "NFVIS",
                "Routers",
                "Security and VPN",
                "Storage Networking",
                "Switches and Hubs",
                "Voice and Telephony",
                "Wireless Controller",
            ]
            if product_family not in product_families_list:
                self.msg = (
                    "The 'product_family should be in the following list {0}.".format(
                        product_families_list
                    )
                )
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

    def get_template_info(self, template_params):
        """
        Store template params from the playbook for template processing in Cisco Catalyst Center.
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
                self.msg = "The parameter 'parameter_name' is required for 'template_params' but not provided."
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
                self.msg = "dataType is required for the template_params."
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
                        self.msg = "The parameter 'max_value' is required for range under 'template_params' but not provided."
                        self.status = "failed"
                        return self.check_return_status()
                    min_value = value.get("min_value")
                    if min_value is not None:
                        _range[j].update({"minValue": min_value})
                    else:
                        self.msg = "The parameter 'min_value' is required for range under 'template_params' but not provided."
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

    def get_project_defined_template_details(self, project_name, template_name):
        """
        Get the template details from the template name provided in the playbook.
        Parameters:
            project_name (str) - Name of the project under which templates are associated.
            template_name (str) - Name of the template provided in the playbook.
        Returns:
            template_details (dict) - Template details for the given template name.
        """

        self.log(
            "Starting to retrieve template details for project '{0}' and template '{1}'.".format(
                project_name, template_name
            ),
            "INFO",
        )
        template_details = None
        try:
            items = self.dnac_apply["exec"](
                family="configuration_templates",
                function="get_templates_details",
                op_modifies=True,
                params={"project_name": project_name, "name": template_name},
            )
            if items:
                template_details = items
                self.log(
                    "Received template details for '{0}': {1}".format(
                        template_name, template_details
                    ),
                    "DEBUG",
                )
            else:
                self.log(
                    "No template details found for project '{0}' and template '{1}'.".format(
                        project_name, template_name
                    ),
                    "WARNING",
                )

            self.log(
                "Received API response from 'get_templates_details': {0}".format(
                    template_details
                ),
                "DEBUG",
            )
        except Exception as e:
            self.log(
                "Exception occurred while retrieving template details for '{0}': {1}".format(
                    template_name, str(e)
                ),
                "ERROR",
            )

        return template_details

    def get_containing_templates(self, containing_templates):
        """
        Store tags from the playbook for template processing in Cisco Catalyst Center.
        Check using check_return_status()

        Parameters:
            containing_templates (dict) - Containing templates details.
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

            name = item.get("name")
            if name is None:
                self.msg = "The parameter 'name' is required under 'containing_templates' but not provided."
                self.status = "failed"
                return self.check_return_status()

            containingTemplates[i].update({"name": name})

            project_name = item.get("project_name")
            if project_name is None:
                self.msg = "The parameter 'project_name' is required under 'containing_templates' but not provided."
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            template_details = self.get_project_defined_template_details(
                project_name, name
            ).get("response")
            if not template_details:
                self.msg = "No template with the template name '{0}' or it is not versioned".format(
                    name
                )
                self.status = "failed"
                return self.check_return_status()

            id = template_details[0].get("id")
            if id is not None:
                containingTemplates[i].update({"id": id})

            language = item.get("language")
            if language is None:
                self.msg = "The parameter 'language' is required under 'containing_templates' but not provided."
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

            containingTemplates[i].update({"projectName": project_name})
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

            i += 1

        return containingTemplates

    def get_template_params(self, params):
        """
        Store template parameters from the playbook for template processing in Cisco Catalyst Center.

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
            "customParamsOrder": params.get("custom_params_order"),
            "description": params.get("template_description"),
            "deviceTypes": self.get_device_types(params.get("device_types")),
            "id": params.get("id"),
            "softwareVersion": params.get("software_version"),
            "templateContent": params.get("template_content"),
            "templateParams": self.get_template_info(params.get("template_params")),
            "version": params.get("version"),
        }
        language = params.get("language")
        if not language:
            self.msg = "The parameter 'language' is required but not provided."
            self.status = "failed"
            return self.check_return_status()

        language = language.upper()
        language_list = ["JINJA", "VELOCITY"]
        if language not in language_list:
            self.msg = "language should be in '{0}'".format(language_list)
            self.status = "failed"
            return self.check_return_status()

        temp_params.update({"language": language})

        name = params.get("template_name")
        if not name:
            self.msg = "The parameter 'template_name' is required but not provided."
            self.status = "failed"
            return self.check_return_status()

        temp_params.update({"name": name})

        projectName = params.get("project_name")
        if not projectName:
            self.msg = "The parameter 'project_name' is required but not provided."
            self.status = "failed"
            return self.check_return_status()

        temp_params.update({"projectName": projectName})

        softwareType = params.get("software_type")
        if not softwareType:
            self.msg = "The parameter 'software_type' is required but not provided."
            self.status = "failed"
            return self.check_return_status()

        software_types_list = [
            "IOS",
            "IOS-XE",
            "IOS-XR",
            "NX-OS",
            "Cisco Controller",
            "Wide Area Application Services",
            "Adaptive Security Appliance",
            "NFV-OS",
            "Others",
        ]
        if softwareType not in software_types_list:
            self.msg = (
                "The 'software_type' should be in the following list {0}.".format(
                    software_types_list
                )
            )
            self.status = "failed"
            return self.check_return_status()

        temp_params.update({"softwareType": softwareType})

        if temp_params.get("composite") is True:
            failure_policy = params.get("failure_policy")
            failure_policy_list = ["ABORT_TARGET_ON_ERROR", None]
            if failure_policy not in failure_policy_list:
                self.msg = (
                    "The 'failure_policy' should be in the following list {0}.".format(
                        failure_policy
                    )
                )
                self.status = "failed"
                return self

            temp_params.update({"failurePolicy": failure_policy})

        self.log("Formatted template params details: {0}".format(temp_params), "DEBUG")
        copy_temp_params = copy.deepcopy(temp_params)
        for item in copy_temp_params:
            if temp_params[item] is None:
                del temp_params[item]
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

        return result

    def get_uncommitted_template_id(self, project_name, template_name):
        """
        Retrieves the ID of an uncommitted template from a specified project in the Cisco Catalyst Center.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            project_name (str): The name of the project under which the template is located.
            template_name (str): The name of the template whose uncommitted ID is to be retrieved.
        Returns:
            str or None: The template ID if found, otherwise `None` if the template is not available or uncommitted.
        Description:
            This function queries the Cisco Catalyst Center for uncommitted templates within a specified project.
            It checks if the template list contains the specified `template_name` and if found, returns the associated
            `templateId`. If the template is not found, the function logs a warning message and returns `None`.
            The function is useful for identifying templates that are not yet committed, which can then be versioned
            or deployed. If the template is unavailable, an appropriate log message is recorded and the function
            exits early with `None`.
        """
        self.log(
            "Retrieving uncommitted template ID for project '{0}' and template "
            "'{1}'.".format(project_name, template_name),
            "INFO",
        )
        template_id = None
        try:
            template_list = self.dnac_apply["exec"](
                family="configuration_templates",
                function="gets_the_templates_available",
                op_modifies=False,
                params={"projectNames": project_name, "un_committed": True},
            )
            self.log(
                "Received Response from 'gets_the_templates_available' for 'project_name': '{0}' is {1}".format(
                    project_name, template_list
                ),
                "DEBUG",
            )

            if not template_list:
                msg = (
                    "No uncommitted templates available under the project '{0}'. "
                    "Cannot commit or deploy the template '{1}' in device(s)."
                ).format(project_name, template_name)
                self.log(msg, "WARNING")
                return template_id

            for template in template_list:
                if template.get("name") == template_name:
                    template_id = template.get("templateId")
                    self.log(
                        "Found uncommitted template '{0}' with ID: '{1}'.".format(
                            template_name, template_id
                        ),
                        "INFO",
                    )
                    return template_id
            self.log(
                "Template '{0}' not found in the uncommitted templates for project '{1}'.".format(
                    template_name, project_name
                ),
                "WARNING",
            )
        except Exception as e:
            error_msg = (
                "Exception occurred while retrieving uncommitted template ID for project '{0}' and "
                "template '{1}': {2}."
            ).format(project_name, template_name, str(e))
            self.log(error_msg, "ERROR")
            self.msg = error_msg

        return template_id

    def versioned_given_template(self, project_name, template_name, template_id):
        """
        Versions (commits) a specified template in the Cisco Catalyst Center.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            project_name (str): The name of the project under which the template resides.
            template_name (str): The name of the template to be versioned.
            template_id (str): The unique identifier of the template to be versioned.
        Returns:
            self (object): The instance of the class itself, with the operation result (success/failure) set accordingly.
        Description:
            This function handles the process of versioning or committing a template in the Cisco Catalyst Center.
            It constructs a request payload with versioning comments and template ID, and then calls the API to
            initiate the versioning task.
            The function returns the class instance for further chaining of operations.
        """

        self.log(
            "Starting the versioning process for template '{0}' in project '{1}'.".format(
                template_name, project_name
            ),
            "INFO",
        )
        try:
            comments = (
                "Given template '{0}' under the project '{1}' versioned successfully."
            ).format(template_name, project_name)

            version_params = {"comments": comments, "templateId": template_id}
            self.log(
                "Preparing to version template with parameters: {0}".format(
                    version_params
                ),
                "DEBUG",
            )
            task_name = "version_template"
            task_id = self.get_taskid_post_api_call(
                "configuration_templates", task_name, version_params
            )

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Given template '{0}' versioned/committed successfully in the Cisco Catalyst Center.".format(
                template_name
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        except Exception as e:
            self.msg = (
                "An exception occured while versioning the template '{0}' in the Cisco Catalyst "
                "Center: {1}"
            ).format(template_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_have_project(self, config):
        """
        Get the current project related information from Cisco Catalyst Center.

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
        # Cisco Catalyst Center returns project details even if the substring matches.
        # Hence check the projectName retrieved from Cisco Catalyst Center.
        if not (project_details and isinstance(project_details, list)):
            self.log(
                "Project: {0} not found, need to create new project in Cisco Catalyst Center".format(
                    given_projectName
                ),
                "INFO",
            )
            return None

        fetched_projectName = project_details[0].get("name")
        if fetched_projectName != given_projectName:
            self.log(
                "Project {0} provided is not exact match in Cisco Catalyst Center DB".format(
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
        Get the current template related information from Cisco Catalyst Center.

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
        project_name = config.get("configuration_templates").get("project_name")
        # Get available templates which are committed under the project
        template_list = self.dnac_apply["exec"](
            family="configuration_templates",
            function="gets_the_templates_available",
            op_modifies=True,
            params={
                "projectNames": projectName,
                "un_committed": True
            },
        )
        self.log(
            "Received response from 'gets_the_templates_available' for project_name: '{0}' is {1}".format(
                project_name, template_list
            ),
            "DEBUG",
        )

        have_template["isCommitPending"] = True
        # This check will fail if specified template is there not committed in Cisco Catalyst Center
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
        self.msg = "Successfully collected all template parameters from Cisco Catalyst Center for comparison"
        self.status = "success"
        return self

    def _retrieve_all_profiles_with_pagination(self, device_type):
        """
        Retrieves all profiles for the specified device type using pagination.

        Parameters:
            device_type (str): The type of device for which to retrieve profiles.
        """

        self.log("Starting profile retrieval with pagination for device type: '{0}'".format(
            device_type), "DEBUG")

        offset = 1
        limit = 500
        api_timeout = int(self.payload.get("dnac_api_task_timeout", 1200))
        poll_interval = int(self.payload.get("dnac_task_poll_interval", 2))

        start_time = time.time()

        while True:
            # Check timeout
            elapsed_time = time.time() - start_time
            if elapsed_time >= api_timeout:
                self.msg = "Timeout exceeded ({0}s) while retrieving profiles for device type '{1}'".format(
                    api_timeout, device_type)
                self.log(self.msg, "ERROR")
                self.fail_and_exit(self.msg)

            self.log("Retrieving profiles with offset={0}, limit={1} for device type '{2}'".format(
                offset, limit, device_type), "DEBUG")

            profiles = self._get_profiles_by_device_type(device_type, offset, limit)

            if not profiles:
                self.log("No more profiles received from API (offset={0}). Pagination complete.".format(offset), "DEBUG")
                break

            self.log("Retrieved {0} profile(s) from API (offset={1})".format(len(profiles), offset), "DEBUG")
            self.have["profile_list"].extend(profiles)

            # Check if we've received all available profiles
            if len(profiles) < limit:
                self.log("Received fewer profiles than limit ({0} < {1}). Last page reached.".format(
                    len(profiles), limit), "DEBUG")
                break

            # Prepare for next iteration
            offset += limit
            self.log("Incrementing offset to {0} for next API request".format(offset), "DEBUG")

            # Rate limiting
            self.log("Applying rate limiting delay of {0} seconds before next API call".format(poll_interval), "DEBUG")
            time.sleep(poll_interval)

    def _get_profiles_by_device_type(self, device_type, offset, limit):
        """
        Maps device type to appropriate network profile category and retrieves profiles.

        Parameters:
            device_type (str): The type of device.
            offset (int): Pagination offset.
            limit (int): Pagination limit.

        Returns:
            list: List of profiles for the specified device type.
        """

        # Device type to profile category mapping
        device_type_mapping = {
            "Switches and Hubs": "Switching",
            "Wireless Controller": "Wireless",
            "Routers": "Routing",
            "Security and VPN": "Firewall"
        }

        profile_category = device_type_mapping.get(device_type, "Assurance")

        self.log("Mapping device type '{0}' to profile category '{1}'".format(
            device_type, profile_category), "DEBUG")

        try:
            profiles = self.get_network_profile(profile_category, offset, limit)
            self.log("Successfully retrieved profiles for category '{0}'".format(
                profile_category), "DEBUG")
            return profiles

        except Exception as e:
            self.log("Error retrieving profiles for category '{0}': {1}".format(
                profile_category, str(e)), "ERROR")
            return []

    def _process_individual_profile(self, profile_name, template_name):
        """
        Processes an individual profile to determine its assignment status.

        Parameters:
            profile_name (str): Name of the profile to process.
            template_name (str): Name of the template to check assignment against.

        Returns:
            dict: Profile information including assignment status.
        """
        self.log("Processing individual profile: '{0}' for template: '{1}'".format(
            profile_name, template_name), "DEBUG")

        profile_info = {
            "profile_name": profile_name,
            "template_name": template_name
        }

        # Validate profile existence
        if not self.value_exists(self.have["profile_list"], "name", profile_name):
            self.msg = "Profile '{0}' does not exist in Cisco Catalyst Center".format(profile_name)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        # Get profile ID
        profile_index = next(
            (index for index, profile in enumerate(self.have["profile_list"])
             if profile.get("name") == profile_name), -1
        )

        if profile_index == -1:
            self.msg = "Failed to locate profile '{0}' in retrieved profile list".format(profile_name)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        profile_id = self.have["profile_list"][profile_index]["id"]
        profile_info["profile_id"] = profile_id

        self.log("Successfully resolved profile '{0}' to ID: '{1}'".format(
            profile_name, profile_id), "DEBUG")

        # Check template assignment
        assignment_status = self._check_profile_template_assignment(
            profile_name, profile_id, template_name)
        profile_info["profile_status"] = assignment_status

        if assignment_status == "already assigned":
            self.profile_exists.append(profile_name)
            self.log("Profile '{0}' marked as existing (already assigned)".format(
                profile_name), "DEBUG")

        self.log("Profile processing completed for '{0}': status='{1}'".format(
            profile_name, assignment_status), "DEBUG")
        return profile_info

    def _check_profile_template_assignment(self, profile_name, profile_id, template_name):
        """
        Checks if a profile is assigned to the specified template.

        Parameters:
            profile_name (str): Name of the profile.
            profile_id (str): ID of the profile.
            template_name (str): Name of the template.

        Returns:
            str: Assignment status ('Not Assigned' or 'already assigned').
        """

        self.log("Checking template assignment for profile '{0}' (ID: {1}) against template '{2}'".format(
            profile_name, profile_id, template_name), "DEBUG")

        try:
            template_details = self.get_templates_for_profile(profile_id)

            if not template_details:
                self.log("No templates found assigned to profile '{0}'".format(
                    profile_name), "INFO")
                return "Not Assigned"

            self.log("Found {0} template(s) assigned to profile '{1}'".format(
                len(template_details), profile_name), "DEBUG")

            # Check if the specific template is assigned
            if self.value_exists(template_details, "name", template_name):
                self.log("Profile '{0}' is already assigned to template '{1}'".format(
                    profile_name, template_name), "INFO")
                return "already assigned"
            else:
                self.log("Profile '{0}' is not assigned to template '{1}' (assigned to other templates)".format(
                    profile_name, template_name), "INFO")
                return "Not Assigned"

        except Exception as e:
            self.log("Error checking template assignment for profile '{0}': {1}".format(
                profile_name, str(e)), "ERROR")
            return "Not Assigned"

    def get_profile_details(self, device_type, input_profiles, template_name):
        """
        Retrieves profile details and assignment status for given profile names from Cisco Catalyst Center.

        Parameters:
            device_type (str) - The type of device for which to retrieve profile details.
            input_profiles (list) - List of profile names to retrieve details for.
            template_name (str) - The name of the template for which to retrieve profile details.

        Returns:
            list: A list of dictionaries containing profile information including:
                - profile_name (str): Name of the profile
                - profile_id (str): UUID of the profile
                - profile_status (str): Assignment status ('Not Assigned' or 'already assigned')
                - template_name (str): Name of the template

        Description:
            This function retrieves comprehensive profile information from Cisco Catalyst Center and determines
            the assignment status of each profile to the specified template. It handles pagination for large
            profile datasets, validates profile existence, and checks current template assignments. The function
            supports multiple device types and maps them to appropriate network profile categories for API calls.
        """
        self.log("Initiating profile details collection for device type '{0}' with profiles: {1} and template '{2}'".format(
            device_type, input_profiles, template_name), "DEBUG")

        # Input validation
        if not device_type:
            self.msg = "Device type is required but not provided for profile details collection"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        if not input_profiles or not isinstance(input_profiles, list):
            self.msg = "Input profiles must be provided as a non-empty list for profile details collection"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        if not template_name:
            self.msg = "Template name is required but not provided for profile details collection"
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        self.log("Collecting profile information for device type '{0}', profiles: {1}, template: '{2}'".format(
            device_type, input_profiles, template_name), "INFO")

        # Initialize profile storage
        self.have["profile"] = []
        self.have["profile_list"] = []

        # Retrieve all profiles with pagination
        self._retrieve_all_profiles_with_pagination(device_type)

        if not self.have["profile_list"]:
            self.msg = "No profiles found for device type '{0}' in Cisco Catalyst Center".format(device_type)
            self.log(self.msg, "ERROR")
            self.fail_and_exit(self.msg)

        self.log("Successfully retrieved {0} total profile(s) for device type '{1}'".format(
            len(self.have["profile_list"]), device_type), "INFO")

        # Process each input profile
        processed_profiles = []
        for profile_name in input_profiles:
            profile_info = self._process_individual_profile(profile_name, template_name)
            processed_profiles.append(profile_info)

        self.log("Profile details collection completed successfully. Processed {0} profile(s): {1}".format(
            len(processed_profiles), self.pprint(processed_profiles)), "INFO")

        return processed_profiles

    def get_have(self, config):
        """
        Get the current project and template details from Cisco Catalyst Center.

        Parameters:
            config (dict) - Playbook details containing Project/Template information.

        Returns:
            self
        """
        have = {}
        configuration_templates = config.get("configuration_templates")
        if configuration_templates:
            profile_names = configuration_templates.get("profile_names")
            template_name = configuration_templates.get("template_name")
            device_types = configuration_templates.get("device_types")
            project_name = configuration_templates.get("project_name")

            if not project_name:
                self.msg = "The parameter 'project_name' is required but not provided."
                self.status = "failed"
                return self
            template_available = self.get_have_project(config)
            if template_available:
                self.get_have_template(config, template_available)

            if profile_names and template_name and device_types:
                self.log("Initiating profile assignment collection for template profile management", "DEBUG")

                if device_types:
                    parsed_current_profile = []
                    for each_type in device_types:
                        each_family = each_type.get("product_family")
                        parsed_current_profile.extend(
                            self.get_profile_details(each_family,
                                                     profile_names,
                                                     template_name)
                        )

                have["current_profile"] = self.deduplicate_list_of_dict(parsed_current_profile)

        project_config = config.get("projects", [])
        if project_config and isinstance(project_config, list):
            have["projects"] = []
            for project in project_config:
                project_name = project.get("name")

                if not project_name:
                    self.log("Skipping project: Missing 'name' field.", "WARNING")
                    continue

                # Fetch existing project details based on the name
                existing = self.get_project_details(project_name)
                if existing:
                    proj_status, unmatched = self.compare_projects(project, existing[0])
                    existing[0]["project_status"] = proj_status
                    existing[0]["unmatched"] = unmatched
                    have["projects"].append(existing[0] or {})
                else:
                    self.log("No existing project found for name: {0}".format(
                        project_name), "INFO")

        deploy_temp_details = config.get("deploy_template")
        if deploy_temp_details:
            template_name = deploy_temp_details.get("template_name")
            project_name = deploy_temp_details.get("project_name")
            self.log(
                "Fetching template details for '{0}' under project '{1}'.".format(
                    template_name, project_name
                ),
                "INFO",
            )
            temp_details = self.get_project_defined_template_details(
                project_name, template_name
            ).get("response")

            if temp_details:
                self.log(
                    "Given template '{0}' is already committed in the Catalyst Center.".format(
                        template_name
                    ),
                    "INFO",
                )
                have["temp_id"] = temp_details[0].get("id")

                self.log(
                    "Successfully collected the details for the template '{0}' from the "
                    "Cisco Catalyst Center.".format(template_name),
                    "INFO",
                )
            else:
                self.log(
                    "No details found for template '{0}' under project '{1}'.".format(
                        template_name, project_name
                    ),
                    "WARNING",
                )

        self.have = have

        self.msg = "Successfully collected all project and template \
                    parameters from Cisco Catalyst Center for comparison"
        self.status = "success"
        self.log("Current State (have): {0}".format(self.pprint(self.have)), "INFO")
        return self

    def get_project_details(self, project_name):
        """
        Get the details of specific project name provided.

        Parameters:
            project_name (str) - Project Name

        Returns:
            items (dict) - Project details with given project name.
        """

        self.log(
            "Initializing retrival of project details for project: {0}".format(
                project_name
            ),
            "DEBUG",
        )
        ccc_version = self.get_ccc_version()

        if self.compare_dnac_versions(ccc_version, "2.3.7.9") < 0:
            self.log(
                "Retrieving project details for project: {0} when catalyst version is less than 2.3.7.9".format(
                    project_name
                ),
                "DEBUG",
            )

            items = self.dnac_apply["exec"](
                family="configuration_templates",
                function="get_projects",
                op_modifies=True,
                params={"name": project_name},
            )

            self.log(
                "Received Response from get_projects for project: {0} when catalyst version is less than 2.3.7.9: {1}".format(
                    project_name, items
                ),
                "DEBUG",
            )
        else:
            self.log(
                "Retrieving project details for project: {0} when catalyst version is greater than or equal to 2.3.7.9".format(
                    project_name
                ),
                "DEBUG",
            )
            items = self.dnac_apply["exec"](
                family="configuration_templates",
                function="get_projects_details",
                op_modifies=True,
                params={"name": project_name},
            )

            self.log(
                "Received Response from get_projects for project: {0} when catalyst version is greater than or equal to 2.3.7.9: {1}".format(
                    project_name, items
                ),
                "DEBUG",
            )
            items = items["response"]

        self.log(
            "Retrieved project details for project '{0}' are {1}".format(
                project_name, items
            ),
            "DEBUG",
        )
        return items

    def get_want(self, config):
        """
        Get all the template and project related information from playbook
        that is needed to be created in Cisco Catalyst Center.

        Parameters:
            config (dict) - Playbook details.

        Returns:
            self
        """

        want = {}

        project_details = config.get("projects", [])
        if project_details:
            want["projects"] = project_details

        configuration_templates = config.get("configuration_templates")
        self.log("Playbook details: {0}".format(config), "INFO")
        if configuration_templates:
            template_params = self.get_template_params(configuration_templates)
            project_params = self.get_project_params(configuration_templates)
            version_comments = configuration_templates.get("version_description")

            if self.params.get("state") == "merged":
                self.update_mandatory_parameters(template_params)

            ccc_version = self.get_ccc_version()
            if (
                self.compare_dnac_versions(ccc_version, "3.1.3.0") >= 0
                and configuration_templates.get("profile_names")
            ):
                want["profile_names"] = configuration_templates.get("profile_names")

            want["template_params"] = template_params
            want["project_params"] = project_params
            want["comments"] = version_comments

        deploy_temp_details = config.get("deploy_template")
        if deploy_temp_details:
            project_name = deploy_temp_details.get("project_name")
            if not project_name:
                self.msg = (
                    "To Deploy the template in the devices, parameter 'project_name' "
                    "must be given in the playboook."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Project name '{0}' found in the playbook.".format(project_name), "INFO"
            )
            template_name = deploy_temp_details.get("template_name")
            if not template_name:
                self.msg = (
                    "To Deploy the template in the devices, parameter 'template_name' "
                    "must be given in the playboook."
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Template name '{0}' found in the playbook.".format(template_name),
                "INFO",
            )
            device_details = deploy_temp_details.get("device_details")
            site_provisioning_details = deploy_temp_details.get(
                "site_provisioning_details"
            )

            if not (device_details or site_provisioning_details):
                self.msg = (
                    "Either give the parameter 'device_details' or 'site_provisioning_details' "
                    "in the playbook to fetch the device ids and proceed for the deployment of template {0}."
                ).format(template_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log(
                "Proceeding with deployment details for template '{0}'.".format(
                    template_name
                ),
                "INFO",
            )
            want["deploy_tempate"] = deploy_temp_details

        self.want = want
        self.msg = (
            "Successfully collected all parameters from playbook " + "for comparison"
        )
        self.status = "success"
        self.log("Desired State (want): {0}".format(self.pprint(self.want)), "INFO")
        return self

    def compare_projects(self, input_config, current_proj):
        """
        Compares an input project configuration with the current project configuration in
        Cisco Catalyst Center.

        Args:
            self (object): Instance of the class used for interacting with Cisco Catalyst Center.
            input_config (dict): The new project configuration intended to be applied.
            current_proj (dict): The existing project configuration retrieved from the system.

        Returns:
            tuple:
                - bool: True if the configurations match (excluding tags), False otherwise.
                - list: List of values from the input configuration that differ from
                the current configuration.

        Description:
            This method performs a key-by-key comparison between the input and existing project configurations,
            excluding the "tags" field. It logs the comparison process and results. If mismatches are found,
            the differing input values are collected and returned for further processing or reporting.
        """
        self.log("Comparing input project config with current config.", "INFO")
        self.log("Input project config: {0}".format(self.pprint(input_config)), "DEBUG")
        self.log("Current project config: {0}".format(self.pprint(current_proj)), "DEBUG")

        unmatched_keys = []

        if input_config and current_proj:
            for key, value in input_config.items():
                # Compare values of the current key
                if current_proj.get(key) != value:
                    unmatched_keys.append(key)
                    self.log("Mismatch found for key: {0}. Input value: {1}, Current value: {2}".format(
                        key, value, current_proj.get(key)), "DEBUG")

            # If no mismatches are found, configurations match
            if not unmatched_keys:
                self.log("Input project config matches current project config.", "INFO")
                return True, None

        self.log("Configurations do not match. Mismatched keys: {0}".format(
            unmatched_keys), "DEBUG")

        return False, unmatched_keys

    def delete_project(self, project_name):
        """
        Deletes a project from Cisco Catalyst Center by its name.

        Args:
          self (object): An instance of the class used to interact with Cisco Catalyst Center.
          project_name (str): The name of the project to delete.

        Returns:
          object: The current instance of the class with updated status and result attributes.

        Description:
          This method attempts to locate a project by its name and delete it using the appropriate API call.
          If the project is found and deleted successfully, the method updates the status, result, and logs
          the outcome. In cases of failure (e.g., missing name, project not found, or API error), it sets the
          operation result to failed and logs the issue accordingly.
        """
        self.log("Attempting to delete project with name: {0}".format(project_name), "DEBUG")

        if not project_name:
            self.msg = "No project name provided for deletion."
            self.log(self.msg, "WARNING")
            return self

        # Fetch the project ID using the project name
        project_id = None
        for each_project in self.have.get("projects"):
            if each_project.get("name") == project_name:
                project_id = each_project.get("id")
                break

        if not project_id:
            self.msg = "Could not find a project with the name: {0}".format(project_name)
            self.log(self.msg, "ERROR")
            self.status = "failed"
            return self

        # If a valid project ID is found, proceed to delete the project
        self.log("Found project ID: {0} for project name: {1}".format(
            project_id, project_name), "INFO")

        try:
            function_name = "delete_template_project"
            params = {"project_id": project_id}
            task_id = self.get_taskid_post_api_call("configuration_templates",
                                                    function_name, params)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    function_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            self.log("Successfully deleted project with ID: {0}".format(project_name), "INFO")
            self.result['changed'] = True  # Indicate that the project was deleted
            self.status = "success"
            self.msg = "Successfully deleted project: {0}".format(project_name)
            return self

        except Exception as e:
            self.msg = "An error occurred while deleting project {0} (ID: {1}). ".format(
                project_name, project_id)
            self.log(self.msg + str(e), "ERROR")
            self.status = "failed"

        return self

    def apply_project_config(self, config):
        """
        Create or update projects based on the presence of a 'new_name' key in each project config.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            config (list[dict]): A list of dictionaries, each containing project details.

        Returns:
            self: The current instance with updated project configuration.
        """
        self.log("Starting to apply project configurations. Total projects: {0}".format(
            len(config)), "INFO")

        for project in config:
            project_name = project.get("name", "Unnamed Project")
            self.log("Processing project: {0}".format(project_name), "DEBUG")
            if project.get("new_name"):
                self.log("Updating project: {0} with new name: {1}".format(
                    project_name, project.get("new_name")), "INFO")
                self.update_project(project)
            else:
                self.log("Creating project: {0}".format(project_name), "INFO")
                self.create_project(project)

        self.log("Finished applying project configurations.", "INFO")
        return self

    def create_project(self, project_detail):
        """
        Create a new project in Cisco Catalyst Center with the provided details.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            project_detail (dict): Dictionary containing project details.

        Returns:
            self: The current instance with created project configuration.
        """

        self.log("Processing Project creation with input details: {0}".format(
            self.pprint(project_detail)), "DEBUG")

        if not project_detail:
            self.msg = "No project details provided for creation."
            self.log(self.msg, "WARNING")
            return self

        try:
            create_project_params = {
                "name": project_detail.get("name"),
                "description": project_detail.get("description"),
                "createTime": int(time.time()),
                "lastUpdateTime": int(time.time())
            }

            self.log("Creating project with parameters: {0}".format(
                self.pprint(create_project_params)), "INFO")

            task_name = "create_project"
            task_id = self.get_taskid_post_api_call("configuration_templates",
                                                    task_name, create_project_params)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "project(s) {0} created succesfully".format(project_detail.get("name"))
            self.log("Task ID '{0}' received. Checking task status.".format(task_id), "DEBUG")
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.log("project(s) {0} created succesfully".format(
                project_detail.get("name")), "INFO")
            return self

        except Exception as e:
            self.msg = "Failed to create the project - ({0}) from Cisco Catalyst Center due to - {1}".format(
                project_detail.get("name"), str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

    def update_project(self, project_detail):
        """
        Identify an existing project in Cisco Catalyst Center by its current name and description,
        and update it with the new name and project details.

        Parameters:
            self (object): An instance of a class for interacting with Cisco Catalyst Center.
            project_detail (dict): Dictionary containing the project config details.

        Returns:
            self: The current instance with updated project configuration.
        """

        self.log("Processing Project update with input details: {0}".format(
            self.pprint(project_detail)), "DEBUG")

        if not project_detail:
            self.msg = "No project details provided for update."
            self.log(self.msg, "WARNING")
            return self

        try:
            old_name = project_detail.get("name")
            new_name = project_detail.get("new_name")

            if not old_name or not new_name:
                self.msg = "Both 'name' (old name) and 'new_name' (new name) are required for the update."
                self.log(self.msg, "ERROR")
                return self

            # Get the existing project info
            existing_projects = self.get_project_details(old_name)
            if not existing_projects:
                self.msg = "Project with name '{0}' not found.".format(old_name)
                self.log(self.msg, "ERROR")
                return self

            existing_project = existing_projects[0]
            # Prepare update parameters
            update_project_params = {
                "id": existing_project.get("id"),
                "name": new_name,
                "description": project_detail.get("description", existing_project.get("description")),
                "createTime": existing_project.get("createTime"),
                "lastUpdateTime": int(time.time()),
                "templates": project_detail.get("templates", existing_project.get("templates", []))
            }

            # Log the update parameters
            self.log("Updating project with parameters: {0}".format(
                self.pprint(update_project_params)), "DEBUG")

            task_name = "update_project"
            task_id = self.get_taskid_post_api_call("configuration_templates",
                                                    task_name, update_project_params)

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(task_name)
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            success_msg = "Project(s) '{0}' updated successfully.".format(new_name)
            self.log("Task ID '{0}' received. Checking task status.".format(task_id), "DEBUG")
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

            self.log("Project(s) '{0}' updated successfully.".format(new_name), "INFO")
            return self

        except Exception as e:
            self.msg = "Failed to update the project '{0}' due to error: {1}".format(
                project_detail.get("name"), str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")
            return self

    def create_project_or_template(self, is_create_project=False):
        """
        Call Cisco Catalyst Center API to create project or template based on the input provided.

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
            self.project_created.append(project_params.get('name'))
            name = "project: {0}".format(project_params.get('name'))
            validation_string = "Successfully created project"
            creation_value = "create_project"
        else:
            params_key = template_params
            self.template_created.append(template_params.get('name'))
            name = "template: {0}".format(template_params.get('name'))
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
                return task_id, created

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

        self.result['changed'] = True
        self.msg = "{0} created successfully with id {1}".format(name, creation_id)
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
            ("customParamsOrder", "customParamsOrder", False),
            ("description", "description", ""),
            ("deviceTypes", "deviceTypes", []),
            ("failurePolicy", "failurePolicy", ""),
            ("id", "id", ""),
            ("language", "language", "VELOCITY"),
            ("name", "name", ""),
            ("projectName", "projectName", ""),
            ("softwareType", "softwareType", ""),
            ("softwareVersion", "softwareVersion", ""),
            ("templateContent", "templateContent", ""),
            ("templateParams", "templateParams", []),
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
        Update parameters which are required for creating a template.

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
        Validate input after getting all the parameters from Cisco Catalyst Center.
        "If mandate like deviceTypes, softwareType and language "
        "already present in Cisco Catalyst Center for a template."
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

        all_project_details = self.dnac._exec(
            family="configuration_templates", function="get_projects_details"
        )
        self.log(
            "Received response from 'get_projects_details' is {0}".format(
                all_project_details
            ),
            "DEBUG",
        )
        all_project_details = all_project_details.get("response")
        for values in export_values:
            project_name = values.get("project_name")
            self.log(
                "Project name for export template: {0}".format(project_name), "DEBUG"
            )
            self.log("Template details: {0}".format(all_project_details), "DEBUG")
            project_details = get_dict_result(all_project_details, "name", project_name)
            if not project_details:
                self.msg = "There are no projects with the given project name '{project_name}'.".format(
                    project_name=project_name
                )
                self.status = "failed"
                return self

            all_template_details = project_details.get("templates")
            if not all_template_details:
                self.msg = "There are no templates associated with the given project name '{project_name}'.".format(
                    project_name=project_name
                )
                self.status = "failed"
                return self

            self.log(
                "Template details under the project name {0}: {1}".format(
                    project_name, all_template_details
                ),
                "DEBUG",
            )
            template_name = values.get("template_name")
            template_details = get_dict_result(
                all_template_details, "name", template_name
            )
            self.log(
                "Template details with template name {0}: {1}".format(
                    template_name, template_details
                ),
                "DEBUG",
            )
            if template_details is None:
                self.msg = (
                    "Invalid 'project_name' and 'template_name' in export templates."
                )
                self.status = "failed"
                return self
            self.export_template.append(template_details.get("id"))

        self.msg = "Successfully collected the export template IDs"
        self.status = "success"
        return self

    def commit_the_template(self, template_id, template_name):
        """
        Commits (versions) a given configuration template in Cisco Catalyst Center.

        Args:
            template_id (str): The UUID of the configuration template to be committed.
            template_name (str): The human-readable name of the template (used for logging and messaging).

        Returns:
            object: Returns the current instance (`self`) with updated result and status fields.

        Description:
            This method commits a configuration template by versioning it through the
            `version_template` API call. It uses optional comments from `self.want` as versioning metadata.
            Upon successful API execution, it retrieves the associated task ID and fetches detailed
            task information. The method updates the `self.result` dictionary with the response and a
            commit confirmation message. Logging is performed at key steps for traceability,
            and proper error handling ensures robustness in case of missing task IDs or API failures.
        """

        try:
            self.log("Starting the commit process for template '{0}' with ID '{1}'.".format(template_name, template_id), "INFO")
            version_params = {
                "comments": self.want.get("comments"),
                "templateId": template_id
            }
            self.log("Versioning parameters for template '{0}': {1}".format(template_name, version_params), "DEBUG")
            response = self.dnac_apply['exec'](
                family="configuration_templates",
                function="version_template",
                op_modifies=True,
                params=version_params
            )
            self.log("Received response from API 'version_template' for 'tempate': '{0}' is {1}".format(template_name, response), "DEBUG")
            if not response or not isinstance(response, dict):
                self.msg = "Invalid response received from 'version_template' API for template '{0}'.".format(template_name)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()
                return self

            task_id = response.get("response").get("taskId")
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the template '{0}'.".format(template_name)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.log("Task ID '{0}' retrieved successfully for template '{1}'.".format(task_id, template_name), "INFO")
            task_details = self.get_task_details(task_id)
            self.log("Task details retrieved for task ID '{0}': {1}".format(task_id, task_details), "DEBUG")
            self.msg = "Template '{0}' committed successfully in Cisco Catalyst Center.".format(template_name)
            # Ensure the response structure in self.result is initialized properly
            self.log("Initializing response structure in self.result for template '{0}'.".format(template_name), "DEBUG")
            if not self.result.get('response'):
                self.result['response'] = [{}]  # Initialize as a list with one empty dictionary

            self.log("Updated self.result structure for template '{0}': {1}".format(template_name, self.result), "DEBUG")
            # Add the template name to the committed list
            self.template_committed.append(template_name)
            self.log("Template '{0}' added to the committed list.".format(template_name), "INFO")
            self.result['changed'] = True
            self.log("Successfully committed template '{0}'.".format(template_name), "INFO")
        except Exception as e:
            self.msg = "Error while executing 'version_template' API for template '{0}': {1}".format(template_name, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        return self

    def get_template_commit_status(self, template_id, name):
        """
        Checks whether a given configuration template is committed in Cisco Catalyst Center.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            template_id (str): The UUID of the configuration template to check.
            name (str): The name of the configuration template (used for logging purposes).

        Returns:
            bool: Returns True if the template is not committed (uncommitted),
                  and False if it is already committed.

        Description:
            This method verifies the commit status of a configuration template by calling the
            'gets_the_templates_available' API with the `un_committed` parameter set to True.
            If the template is not found in the uncommitted list, it is considered committed.
            Logs are generated for debugging and audit purposes. Any exceptions are caught and
            logged without halting execution.
        """

        self.log("Checking commit status for template '{0}' with ID '{1}'.".format(name, template_id), "INFO")
        is_template_uncommitted = True
        try:
            response = self.dnac_apply['exec'](
                family="configuration_templates",
                function="gets_the_templates_available",
                op_modifies=False,
                params={
                    "id": template_id,
                    "un_committed": True
                },
            )
            self.log("Received Response from 'gets_the_templates_available' for 'tempate': '{0}' is {1}".format(name, response), "DEBUG")
            if not response or not isinstance(response, dict):
                self.log("The response for template '{0}' is invalid or empty. Assuming it is already committed.".format(name), "INFO")
                is_template_uncommitted = False
                return is_template_uncommitted

            self.log("Given template '{0}' is not committed in the Cisco Catalyst Center.".format(name), "INFO")
        except Exception as e:
            self.msg = (
                "An exception occurred while retrieving the commit status for template '{0}': {1}"
                .format(name, str(e))
            )
            self.set_operation_result("failed", False, self.msg, "ERROR")
        self.log("Commit status for template '{0}': {1}".format(name, is_template_uncommitted), "DEBUG")

        return is_template_uncommitted

    def update_configuration_templates(self, config, configuration_templates):
        """
        Update/Create templates and projects in CCC with fields provided in Cisco Catalyst Center.

        Parameters:
            config (dict) - Playbook details containing the template, export, import and deploy templates details
            configuration_templates (dict) - Playbook details containing template information.

        Returns:
            self
        """

        is_project_found = self.have_project.get("project_found")
        if not is_project_found:
            project_id, project_created = self.create_project_or_template(
                is_create_project=True
            )
            if not project_created:
                self.status = "failed"
                self.msg = "Project creation failed"
                return self

            self.log("project created with projectId: {0}".format(project_id), "DEBUG")

        is_template_found = self.have_template.get("template_found")
        template_params = self.want.get("template_params")
        self.log("Desired template details: {0}".format(template_params), "DEBUG")
        self.log("Current template details: {0}".format(self.have_template), "DEBUG")
        template_id = None
        self.validate_input_merge(is_template_found).check_return_status()
        if is_template_found:
            current_template_name = self.want.get("template_params").get("name")
            new_template_name = configuration_templates.get("new_template_name")
            template_id = self.have_template.get("id")
            if new_template_name:
                self.log(
                    "User provided 'new_template_name' field. Attempting to change the template name "
                    "from '{template_name}' to '{new_template_name}'.".format(
                        template_name=current_template_name,
                        new_template_name=new_template_name,
                    ),
                    "INFO",
                )
                project_name = configuration_templates.get("project_name")
                self.log(
                    "Checking if template '{new_template_name}' already exists in project '{project_name}'.".format(
                        new_template_name=new_template_name, project_name=project_name
                    ),
                    "DEBUG",
                )
                template_response = self.get_project_defined_template_details(
                    project_name, new_template_name
                )
                if template_response is None:
                    self.msg = "The response of the API 'get_templates_details' for checking template existence is None."
                    self.log(str(self.msg), "WARNING")
                    self.status = "failed"
                    return self
                else:
                    template_response = template_response.get("response")

                if template_response:
                    self.msg = (
                        "Cannot update template name from '{current_template_name}' to '{new_template_name}' "
                        "in project '{project_name}', as a template with the new name already exists in Cisco Catalyst Center.".format(
                            current_template_name=current_template_name,
                            new_template_name=new_template_name,
                            project_name=project_name,
                        )
                    )
                    self.log(str(self.msg), "ERROR")
                    self.status = "failed"
                    return self

                self.log(
                    "Updating template name from '{current_template_name}' to '{new_template_name}'.".format(
                        current_template_name=current_template_name,
                        new_template_name=new_template_name,
                    ),
                    "INFO",
                )
                template_params.update({"name": new_template_name})
                self.want.get("template_params").update({"name": new_template_name})
                config.get("configuration_templates").update(
                    {"template_name": new_template_name}
                )

            if not self.requires_update():
                # Template does not need update
                self.no_update_template.append(current_template_name)
                is_template_un_committed = self.get_template_commit_status(template_id, current_template_name)
                self.log("Template '{0}' uncommitted status: {1}".format(current_template_name, is_template_un_committed), "DEBUG")
                # Check whether the above template is committed or not
                is_commit = configuration_templates.get("commit", True)
                self.log("Commit flag for template '{0}': {1}".format(current_template_name, is_commit), "DEBUG")
                if is_commit and is_template_un_committed:
                    self.commit_the_template(template_id, current_template_name).check_return_status()
                    self.log("Template '{0}' committed successfully in the Cisco Catalyst Center.".format(current_template_name), "INFO")

                return self

            template_id = self.have_template.get("id")
            template_params.update({"id": template_id})
            self.log("Current State (have): {0}".format(self.have_template), "INFO")
            self.log("Desired State (want): {0}".format(self.want), "INFO")
            task_name = "update_template"
            parameters = template_params
            current_response = copy.deepcopy(self.result["response"])
            task_id = self.get_taskid_post_api_call(
                "configuration_templates", task_name, parameters
            )
            template_name = self.want.get("template_params").get("name")
            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}' for the template: '{1}'.".format(
                    task_name, template_name
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            success_msg = "Successfully updated the configuration template '{0}' in Cisco Catalyst Center".format(template_name)
            self.template_updated.append(template_name)
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)
            self.result['response'] = copy.deepcopy(current_response)
            self.log("Updating existing template '{0}'."
                     .format(self.have_template.get("template").get("name")), "INFO")

        else:
            if not template_params.get("name"):
                self.msg = "missing required arguments: template_name"
                self.status = "failed"
                return self
            template_id, template_updated = self.create_project_or_template()

        is_commit = configuration_templates.get("commit", True)
        if is_commit:
            name = self.want.get("template_params").get("name")
            self.log("Attempting to commit template '{0}' with ID '{1}'.".format(name, template_id), "INFO")

            self.commit_the_template(template_id, name).check_return_status()
            self.log("Template '{0}' committed successfully in the Cisco Catalyst Center.".format(name), "INFO")

            self.log("Initiating profile assignment and detachment processing for template '{0}'".format(
                name), "DEBUG")
            current_profiles = self.have.get("current_profile", [])
            self.log("Processing {0} profile(s) for template '{1}'.".format(
                len(current_profiles), name), "INFO")

            for profile_index, each_profile in enumerate(current_profiles):
                # Extract profile information once per iteration
                each_profile_name = each_profile.get("profile_name")
                each_profile_id = each_profile.get("profile_id")
                profile_template_name = each_profile.get("template_name")
                profile_status = each_profile.get("profile_status")

                # Skip profiles not associated with the current template
                if profile_template_name != name:
                    self.log("Skipping profile '{0}' - not associated with template '{1}' (associated with '{2}')".format(
                        each_profile_name, name, profile_template_name), "DEBUG")
                    continue

                self.log("Processing profile '{0}' (index {1}) with status '{2}' for template '{3}'".format(
                    each_profile_name, profile_index, profile_status, name), "DEBUG")

                # Case 1: Assign profile to template
                if profile_status == "Not Assigned":
                    self.log("Assigning profile '{0}' to template '{1}' - profile not currently assigned".format(
                        each_profile_name, name), "INFO")

                    try:
                        template_status = self.attach_networkprofile_cli_template(
                            each_profile_name, each_profile_id, name, template_id)
                        self.log("Received response from profile attachment API for profile '{0}': {1}".format(
                            each_profile_name, template_status), "DEBUG")

                        if template_status and template_status.get("progress"):
                            success_msg = "Profile '{0}' successfully attached to template '{1}'".format(
                                each_profile_name, name)
                            self.log(success_msg, "INFO")
                            self.profile_assigned.append(each_profile_name)
                        else:
                            error_msg = "Failed to attach profile '{0}' to template '{1}' - API response indicates failure".format(
                                each_profile_name, name)
                            self.log(error_msg, "ERROR")
                            self.no_profile_assigned.append(each_profile_name)

                    except Exception as e:
                        error_msg = "Exception occurred while attaching profile '{0}' to template '{1}': {2}".format(
                            each_profile_name, name, str(e))
                        self.log(error_msg, "ERROR")
                        self.no_profile_assigned.append(each_profile_name)

                # Case 2: Profile already assigned (idempotent case)
                elif profile_status == "already assigned":
                    self.log("Profile '{0}' already assigned to template '{1}' - no action required".format(
                        each_profile_name, name), "DEBUG")

                # Case 3: Unexpected scenario
                else:
                    self.log("Unexpected scenario for profile '{0}' on template '{1}': status='{2}'".format(
                        each_profile_name, name, profile_status), "WARNING")

            # Log summary of operations
            total_assigned = len(getattr(self, 'profile_assigned', []))
            total_assignment_failures = len(getattr(self, 'no_profile_assigned', []))

            self.log("Profile operation summary for template '{0}':".format(name), "INFO")
            self.log("  - Profiles assigned: {0} {1}".format(total_assigned,
                                                             getattr(self, 'profile_assigned', [])), "INFO")
            self.log("  - Assignment failures: {0} {1}".format(total_assignment_failures,
                                                               getattr(self, 'no_profile_assigned', [])), "INFO")

            self.log("Completed profile assignment and processing for template '{0}'".format(name), "INFO")

        return self

    def handle_export(self, export):
        """
        Export templates and projects in CCC with fields provided in Cisco Catalyst Center.

        Parameters:
            export (dict) - Playbook details containing export project/template information.

        Returns:
            self
        """

        export_project = export.get("project")
        self.log("Export project playbook details: {0}".format(export_project), "DEBUG")
        if export_project:
            self.log("Found export project details: {0}".format(export_project), "DEBUG")
            response = self.dnac._exec(
                family="configuration_templates",
                function="export_projects",
                op_modifies=True,
                params={
                    "payload": export_project,
                },
            )

            validation_string = "successfully exported project"
            self.check_task_response_status(
                response, validation_string, "export_projects", True
            ).check_return_status()
            self.result["response"][1].get("export").get("response").update(
                {"exportProject": self.msg}
            )

        export_values = export.get("template")
        if export_values:
            self.get_export_template_values(export_values).check_return_status()
            self.log(
                "Exporting template playbook details: {0}".format(self.export_template),
                "DEBUG",
            )
            response = self.dnac._exec(
                family="configuration_templates",
                function="export_templates",
                op_modifies=True,
                params={
                    "payload": self.export_template,
                },
            )
            validation_string = "successfully exported template"
            self.check_task_response_status(
                response, validation_string, "export_templates", True
            ).check_return_status()
            self.result["response"][1].get("export").get("response").update(
                {"exportTemplate": self.msg}
            )

        return self

    def handle_import(self, _import):
        """
        Import templates and projects in CCC with fields provided in Cisco Catalyst Center.

        Parameters:
            _import (dict) - Playbook details containing import project/template information.

        Returns:
            self
        """

        _import_project = _import.get("project")
        if _import_project:
            do_version = _import_project.get("do_version")
            if not do_version:
                do_version = False

            payload = _import.get("project").get("payload")
            project_file = _import.get("project").get("project_file")
            if not (payload or project_file):
                self.msg = "Required parameter 'payload' or 'project_file' is not found under import project"
                self.status = "failed"
                return self

            final_payload = []
            if project_file:
                is_path_exists = self.is_path_exists(project_file)
                if not is_path_exists:
                    self.msg = "Import project file path '{0}' does not exist.".format(
                        project_file
                    )
                    self.status = "failed"
                    return self

                is_json = self.is_json(project_file)
                if not is_json:
                    self.msg = "Import project file '{0}' is not in JSON format".format(
                        project_file
                    )
                    self.status = "failed"
                    return self
                try:
                    with open(project_file, "r") as file:
                        json_data = file.read()
                    json_project = json.loads(json_data)
                    final_payload = json_project
                except Exception as msg:
                    self.msg = "An unexpected error occurred while processing the file '{0}': {1}".format(
                        project_file, msg
                    )
                    self.status = "failed"
                    return self
            elif payload:
                for item in payload:
                    response = self.get_project_details(item.get("name"))
                    if response == []:
                        final_payload.append(item)

            if final_payload != []:
                _import_project = {
                    "do_version": do_version,
                    "payload": final_payload,
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
                        response, validation_string, "imports_the_projects_provided"
                    ).check_return_status()
                    self.result["response"][2].get("import").get("response").update(
                        {"importProject": "Successfully imported the project(s)."}
                    )
            else:
                self.msg = "Projects '{0}' already available.".format(payload)
                self.result["response"][2].get("import").get("response").update(
                    {
                        "importProject": "Projects '{0}' already available.".format(
                            payload
                        )
                    }
                )

        _import_template = _import.get("template")
        if _import_template:
            do_version = _import_template.get("do_version")
            if not do_version:
                do_version = False

            project_name = _import_template.get("project_name")
            if not _import_template.get("project_name"):
                self.msg = (
                    "Required parameter project_name is not found under import template"
                )
                self.status = "failed"
                return self

            is_project_exists = self.get_project_details(project_name)
            if not is_project_exists:
                self.msg = "Project '{0}' is not found.".format(project_name)
                self.status = "failed"
                return self

            payload = _import_template.get("payload")
            template_file = _import_template.get("template_file")
            if not (payload or template_file):
                self.msg = "Required parameter 'payload' or 'template_file' is not found under import template"
                self.status = "failed"
                return self

            final_payload = None
            if template_file:
                is_path_exists = self.is_path_exists(template_file)
                if not is_path_exists:
                    self.msg = "Import template file path '{0}' does not exist.".format(
                        template_file
                    )
                    self.status = "failed"
                    return self

                is_json = self.is_json(template_file)
                if not is_json:
                    self.msg = (
                        "Import template file '{0}' is not in JSON format".format(
                            template_file
                        )
                    )
                    self.status = "failed"
                    return self
                try:
                    with open(template_file, "r") as file:
                        json_data = file.read()
                    json_template = json.loads(json_data)
                    final_payload = json_template
                except Exception as msg:
                    self.msg = "An unexpected error occurred while processing the file '{0}': {1}".format(
                        template_file, msg
                    )
                    self.status = "failed"
                    return self

            elif payload:
                final_payload = []
                for item in payload:
                    final_payload.append(self.get_template_params(item))
            import_template = {
                "do_version": do_version,
                "project_name": project_name,
                "payload": final_payload,
            }
            self.log(
                "Import template details from the playbook: {0}".format(
                    import_template
                ),
                "DEBUG",
            )
            global_project_name = import_template.get("project_name")
            for item in import_template.get("payload"):
                template_project_name = item.get("projectName")
                if (
                    template_project_name is not None
                    and global_project_name != template_project_name
                ):
                    self.msg = "Template '{0}' under the the 'Import Template' should have project_name as {1}".format(
                        item.get("name"), global_project_name
                    )
                    self.log(str(self.msg), "ERROR")
                    self.status = "failed"
                    return self

            if _import_template:
                response = self.dnac._exec(
                    family="configuration_templates",
                    function="imports_the_templates_provided",
                    op_modifies=True,
                    params=import_template,
                )
                validation_string = "successfully imported template"
                self.check_task_response_status(
                    response, validation_string, "imports_the_templates_provided"
                ).check_return_status()
                self.result["response"][2].get("import").get("response").update(
                    {"importTemplate": "Successfully imported the templates"}
                )

        return self

    def filter_devices_with_family_role(
        self, site_assign_device_ids, device_family=None, device_role=None
    ):
        """
        Filters devices based on their family and role from a list of site-assigned device IDs.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center.
            site_assign_device_ids (list): A list of device IDs (strings) assigned to a site that need to be filtered.
            device_family (str, optional): The family of devices to filter by (e.g., 'Switches and Hubs'). If None,
                this filter is not applied. Defaults to None.
            device_role (str, optional): The role of the devices to filter by (e.g., 'ACCESS', 'CORE'). If None,
                this filter is not applied. Defaults to None.
        Returns:
            list (str): A list of filtered device IDs (strings) that belong to the specified device family and role.
            If no matching devices are found, the list will be empty.
        Description:
            This function filters a list of device IDs based on the specified `device_family` and `device_role` by querying
            the Cisco Catalyst Center API. It iterates over each device ID, checking if the device belongs to the specified
            family and has the desired role. Devices that match the criteria are added to the `filtered_device_list`.
            If a device does not match the criteria or no response is received from the API, the function logs an
            informational message and skips that device. In the event of an error during the API call, it logs the error
            message and continues processing the remaining devices.
            The function returns the list of devices that meet the filtering criteria.
        """

        filtered_device_list = []
        self.log(
            "Filtering devices from the provided site-assigned device IDs: {0},  device_family='{1}', "
            "and device_role='{2}'".format(
                site_assign_device_ids, device_family, device_role
            ),
            "DEBUG",
        )

        for device_id in site_assign_device_ids:
            try:
                self.log("Processing device ID: {0}".format(device_id), "DEBUG")
                response = self.dnac._exec(
                    family="devices",
                    function="get_device_list",
                    op_modifies=True,
                    params={
                        "family": device_family,
                        "id": device_id,
                        "role": device_role,
                    },
                )
                self.log(
                    "Received response from get_device_list for device_family: {0}, device_id: {1}, device_role: {2} is {3}".format(
                        device_family, device_id, device_role, response
                    ),
                    "DEBUG",
                )
                if response and "response" in response:
                    response_data = response.get("response")
                else:
                    self.log(
                        "No valid response for device with ID '{0}'.".format(device_id),
                        "INFO",
                    )
                    continue

                if not response_data:
                    self.log(
                        "Device with ID '{0}' does not match family '{1}' or role '{2}'.".format(
                            device_id, device_family, device_role
                        ),
                        "INFO",
                    )
                    continue

                self.log(
                    "Device with ID '{0}' matches the criteria.".format(device_id),
                    "DEBUG",
                )
                filtered_device_list.append(device_id)

            except Exception as e:
                error_message = "Error while getting the response of device from Cisco Catalyst Center: {0}".format(
                    str(e)
                )
                self.log(error_message, "CRITICAL")
                continue
        self.log(
            "Completed filtering. Filtered devices: {0}".format(filtered_device_list),
            "DEBUG",
        )

        return filtered_device_list

    def get_latest_template_version_id(self, template_id, template_name):
        """
        Fetches the latest version ID of a specified template from the Cisco Catalyst Center.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center.
            template_id (str): The unique identifier of the template to retrieve its versions.
            template_name (str): The name of the template for logging and reference purposes.
        Returns:
            str: The ID of the latest version of the template if available; otherwise, returns None.
        Description:
            This method calls the Cisco Catalyst Center API to fetch all versions of the specified template.
            It selects the version with the most recent timestamp and retrieves its version ID.
            If no versions are available or an error occurs during the API call, appropriate logs are generated.
        """
        version_temp_id = None
        self.log(
            "Fetching the latest version ID for template '{0}' using template_id '{1}'.".format(
                template_name, template_id
            ),
            "DEBUG",
        )

        try:
            response = self.dnac._exec(
                family="configuration_templates",
                function="get_template_versions",
                op_modifies=True,
                params={
                    "template_id": template_id,
                },
            )
            self.log(
                "Received Response for 'get_template_versions' for template_name: {0} is {1}".format(
                    template_name, response
                ),
                "DEBUG",
            )
            self.log("Received Response for 'get_template_versions' for template_name: {0} is {1}".format(template_name, response), "DEBUG")
            response = response.get("response")

            if not response or not isinstance(response, list):
                self.log(
                    "No version information found for template '{0}' in Cisco Catalyst Center.".format(
                        template_name
                    ),
                    "INFO",
                )
                return version_temp_id

            self.log(
                "Successfully retrieved version information for template '{0}'.".format(
                    template_name
                ),
                "DEBUG",
            )

            version_temp_id = response[0].get("versionId")
            if not version_temp_id:
                self.log(
                    "Failed to identify the latest version for template '{0}'. 'versionId' key is missing in the response.".format(
                        template_name
                    ), "ERROR"
                )
                self.msg = "Missing 'versionId' in the response for the template '{0}'.".format(template_name)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            self.log(
                "Identified the latest version for template '{0}'. Version ID: {1}".format(
                    template_name, version_temp_id), "DEBUG"
            )
            return version_temp_id

        except Exception as e:
            error_message = "Error while getting the latest version id for the template '{0}': '{1}'".format(
                template_name, str(e)
            )
            self.log(error_message, "CRITICAL")

        self.log(
            "Returning latest version ID '{0}' for template '{1}'.".format(
                version_temp_id, template_name
            ),
            "DEBUG",
        )

        return version_temp_id

    def get_device_hostname_from_device_id(self, device_id):
        """
        Retrieves the hostname of a network device using its device UUID.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center.
            device_id (str): UUID of the network device for which the hostname is to be fetched.

        Returns:
            str or None: The hostname of the device if found; otherwise, returns None.

        Description:
            This method fetches the hostname of a specific network device by invoking the
            `get_device_list` API function with the device UUID as a parameter. It parses the
            response to extract the hostname. Logs are maintained for traceability, and exceptions
            are properly handled to avoid runtime failures in case of API errors or invalid inputs.
        """

        device_hostname = None
        self.log("Fetching device hostname for device_id: {0}".format(device_id), "INFO")
        try:
            response = self.dnac._exec(
                family="devices",
                function='get_device_list',
                op_modifies=True,
                params={"id": device_id}
            )
            self.log("Received API response for 'get_device_list' for device {0}: {1}".format(device_id, str(response)), "DEBUG")
            response = response.get("response")
            if not response:
                self.log("No device found with ID: {0}".format(device_id), "WARNING")
                return None

            if "hostname" not in response[0]:
                self.log("Hostname key missing in the API response for device_id: {0}".format(device_id), "ERROR")
                return None

            device_hostname = response[0].get("hostname")
        except Exception as e:
            self.msg = "Exception occurred while fetching device hostname for device_id '{0}': {1}".format(device_id, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

        self.log("Device hostname for device_id '{0}' is '{1}'.".format(device_id, device_hostname), "INFO")

        return device_hostname

    def get_site_uuid_from_device_id(self, device_id):
        """
        Fetches the Site UUID associated with a given network device UUID.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center.
            device_id (str): UUID of the network device for which the site assignment is to be retrieved.
        Returns:
            str or None: Returns the UUID of the assigned site if found; otherwise, returns None.
        Description:
            This method checks the site assignment for a given network device by making an API call
            using the `get_site_assigned_network_device` function. If the device is assigned to a site,
            the corresponding site UUID is extracted and returned. Logs are generated at each step for
            traceability, and proper exception handling ensures that any issues are logged and reported
            without breaking execution flow.
        """

        self.log("Checking site assignment for device with UUID: {0}".format(device_id), "INFO")
        site_uuid = None
        try:
            response = self.dnac_apply['exec'](
                family="site_design",
                function='get_site_assigned_network_device',
                params={"id": device_id}
            )

            self.log("API response received for 'get_site_assigned_network_device': {0}".format(response), "DEBUG")
            if not response or not isinstance(response, dict):
                self.log("No site assignment found for device with UUID: {0}".format(device_id), "WARNING")
                return site_uuid

            response = response.get("response")
            if not isinstance(response, dict):
                self.log("Unexpected 'response' format for device with UUID: {0}".format(device_id), "WARNING")
                return None

            # Extract site details
            site_uuid = response.get("siteId")
            site_name = response.get("siteNameHierarchy")

            if not site_uuid:
                self.log("No site assignment found for device with UUID: {0}".format(device_id), "WARNING")
                return None

            self.log(
                "Device with UUID {0} is assigned to site: {1} (siteId: {2})".format(device_id, site_name, site_uuid), "INFO"
            )
            return site_uuid

        except Exception as e:
            self.msg = "Exception occurred while fetching site assignment for device with UUID '{0}': {1}".format(device_id, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

    def create_payload_for_template_deploy(self, deploy_temp_details, device_ids):
        """
        Creates a payload for deploying a template to specified devices in the Cisco Catalyst Center.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center.
            deploy_temp_details (dict): A dictionary containing details about the template to be deployed.
            device_ids (list): A list of device UUIDs to which the template should be deployed.
        Returns:
            dict: A dictionary representing the payload required to deploy the template.
        Description:
            This function generates the necessary payload for deploying a template to devices in the Cisco Catalyst Center.
            It first checks if the given template is already committed. If not, it fetches its uncommitted version, commits it,
            and uses its template ID for deployment. The payload includes information about target devices and their respective
            template parameters.
            The function logs appropriate messages during the process, including if a template is already committed, if
            parameters are updated, and when the payload is successfully collected.
        """

        project_name = deploy_temp_details.get("project_name")
        template_name = deploy_temp_details.get("template_name")
        self.log(
            "Starting to create deployment payload for template '{0}' in project '{1}'.".format(
                template_name, project_name
            ),
            "DEBUG",
        )
        # Check if the template is available but not yet committed
        if self.have.get("temp_id"):
            self.log(
                "Template '{0}' is already committed in Cisco Catalyst Center. Using the committed template ID.".format(
                    template_name
                ),
                "INFO",
            )
            template_id = self.have.get("temp_id")
        else:
            self.log(
                "Fetching uncommitted template ID for template '{0}' in project '{1}'.".format(
                    template_name, project_name
                ),
                "DEBUG",
            )
            template_id = self.get_uncommitted_template_id(project_name, template_name)

            if not template_id:
                self.msg = (
                    "Unable to fetch the details for the template '{0}' from the Cisco "
                    "Catalyst Center."
                ).format(template_name)
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()

            self.log(
                "Template '{0}' is available but not committed yet. Committing template...".format(
                    template_name
                ),
                "INFO",
            )

            # Commit or versioned the given template in the Catalyst Center
            self.versioned_given_template(
                project_name, template_name, template_id
            ).check_return_status()

        deploy_payload = {
            "forcePushTemplate": deploy_temp_details.get("force_push", False),
            "isComposite": deploy_temp_details.get("is_composite", False),
            "templateId": template_id,
            "copyingConfig": deploy_temp_details.get("copy_config", True),
        }
        self.log(
            "Handling template parameters for the deployment of template '{0}'.".format(
                template_name
            ),
            "DEBUG",
        )
        target_info_list = []
        template_dict = {}
        template_parameters = deploy_temp_details.get("template_parameters")
        if not template_parameters:
            self.msg = (
                "It appears that no template parameters were provided in the playbook. Unfortunately, this "
                "means we cannot proceed with deploying template '{0}' to the devices."
            ).format(template_name)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        for param in template_parameters:
            name = param["param_name"]
            value = param["param_value"]
            self.log(
                "Update the template placeholder for the name '{0}' with value {1}".format(
                    name, value
                ),
                "DEBUG",
            )
            template_dict[name] = value

        # Get the latest version template ID
        version_template_id = self.get_latest_template_version_id(template_id, template_name)
        if not version_template_id:
            self.log(
                "No versioning found for the template: {0}".format(template_name),
                "INFO",
            )
            version_template_id = template_id

        self.log("Preparing to deploy template '{0}' to the following device IDs: '{1}'".format(template_name, device_ids), "DEBUG")
        for device_id in device_ids:
            self.log(
                "Adding device '{0}' to the deployment payload.".format(device_id),
                "DEBUG",
            )
            target_device_dict = {
                "id": device_id,
                "type": "MANAGED_DEVICE_UUID",
                "versionedTemplateId": version_template_id,
                "params": template_dict,
            }
            resource_params = deploy_temp_details.get("resource_parameters")
            self.log("Handling resource parameters for the deployment of template '{0}'.".format(template_name), "DEBUG")
            resource_params_list = []
            runtime_scopes_available = ["MANAGED_DEVICE_UUID", "MANAGED_DEVICE_IP", "MANAGED_DEVICE_HOSTNAME", "SITE_UUID"]
            self.log("Available runtime scopes for resource parameters: {0}".format(runtime_scopes_available), "DEBUG")
            if resource_params:
                for resource_param in resource_params:
                    r_type = resource_param.get("resource_type")
                    scope = resource_param.get("resource_scope", "RUNTIME")
                    resource_params_dict = {
                        'type': r_type,
                        'scope': scope
                    }
                    if scope == "RUNTIME":
                        # Validate runtime scope type
                        if r_type not in runtime_scopes_available:
                            self.msg = (
                                "The resource type '{0}' with scope '{1}' is not supported for runtime provisioning. "
                                "Supported types are: {2}."
                            ).format(r_type, scope, ", ".join(runtime_scopes_available))
                            self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                        self.log(
                            "Processing resource parameter with type '{0}' and scope '{1}' for runtime"
                            " provisioning.".format(r_type, scope), "DEBUG"
                        )
                        if r_type == "SITE_UUID":
                            value = self.get_site_uuid_from_device_id(device_id)
                        elif r_type == "MANAGED_DEVICE_UUID":
                            value = device_id
                        elif r_type == "MANAGED_DEVICE_IP":
                            device_ip_id_map = self.get_device_ips_from_device_ids([device_id])
                            value = device_ip_id_map[device_id]
                        elif r_type == "MANAGED_DEVICE_HOSTNAME":
                            value = self.get_device_hostname_from_device_id(device_id)

                        resource_params_dict['value'] = value
                        self.log("Update the resource placeholder for the type '{0}' with scope {1}".format(r_type, scope), "DEBUG")
                        resource_params_list.append(resource_params_dict)
                        continue

                    # If the scope is not RUNTIME, we take the value directly from the resource_param dictionary
                    self.log("Processing resource parameter with type '{0}' and scope '{1}'.".format(r_type, scope), "DEBUG")
                    value = resource_param.get("resource_value")
                    if not value:
                        self.msg = (
                            "The resource type '{0}' with scope '{1}' requires a value to be provided. "
                            "Please specify a value for this resource parameter."
                        ).format(r_type, scope)
                        self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

                    resource_params_dict['value'] = value
                    self.log("Update the resource placeholder for the type '{0}' with scope {1}".format(r_type, scope), "DEBUG")
                    resource_params_list.append(resource_params_dict)

            if resource_params_list:
                self.log(
                    "Adding resource parameters to the target device dictionary for template '{0}'.".format(
                        template_name
                    ),
                    "DEBUG",
                )
                target_device_dict["resourceParams"] = resource_params_list

            target_info_list.append(target_device_dict)
            del target_device_dict

        deploy_payload["targetInfo"] = target_info_list
        self.log(
            "Successfully generated deployment payload for template '{0}'.".format(
                template_name
            ),
            "INFO",
        )

        return deploy_payload

    def monitor_template_deployment_status(
        self, template_name, deployment_id, device_ips
    ):
        """
        Monitors the status of a template deployment in Cisco Catalyst Center until it completes
        successfully, fails, or times out.

        Args:
            self (object): An instance of the class interacting with Cisco Catalyst Center.
            template_name (str): Name of the configuration template being deployed.
            deployment_id (str): Unique identifier for the deployment task.
            device_ips (list): List of IP addresses of devices to which the template is being deployed.
        Description:
            This method continuously polls the deployment status of a configuration template applied
            to one or more devices using the Cisco Catalyst Center API. It logs status updates, handles
            failures, and manages timeout conditions. Upon successful deployment, it marks the
            operation as successful; otherwise, it collects and logs failure reasons and exits
            accordingly.
        """

        loop_start_time = time.time()
        self.log(
            "Starting template deployment monitoring for '{0}' with deployment ID '{1}', targeting"
            " devices: {2}.".format(template_name, deployment_id, device_ips),
            "DEBUG",
        )
        self.log(
            "Starting template deployment monitoring for '{0}' with deployment ID '{1}'.".format(
                template_name, deployment_id
            ),
            "DEBUG",
        )

        while True:
            try:
                task_name = "get_template_deployment_status"
                response = self.dnac._exec(
                    family="configuration_templates",
                    function=task_name,
                    params={"deployment_id": deployment_id},
                    op_modifies=True,
                )
                self.log(
                    "API response received for task '{0}'. Deployment ID: '{1}', Response: {2}".format(
                        task_name, deployment_id, response
                    ),
                    "DEBUG",
                )

                if not isinstance(response, dict):
                    self.log(
                        "Error: Received invalid response type for deployment ID: '{0}'. Expected a dictionary but got: {1}".format(
                            deployment_id, type(response).__name__
                        ),
                        "ERROR",
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                deployment_status = response.get("status")
                self.log(
                    "Deployment status for template '{0}': {1}".format(
                        template_name, deployment_status
                    ),
                    "DEBUG",
                )
                if deployment_status == "SUCCESS":
                    self.msg = (
                        "Given template '{0}' deployed successfully to all the device(s) '{1}' "
                        " in the Cisco Catalyst Center."
                    ).format(template_name, device_ips)
                    self.set_operation_result("success", True, self.msg, "INFO")
                    return self

                if deployment_status == "FAILURE":
                    self.log(
                        "Deployment of template '{0}' failed. Retrieving detailed failure messages...".format(
                            template_name
                        ),
                        "ERROR",
                    )
                    devices = response.get("devices", [])
                    failure_msg = []
                    for device in devices:
                        status_msg = device.get(
                            "detailedStatusMessage", "No detailed status available."
                        )
                        self.log(
                            "Device deployment failure: {0}".format(status_msg), "ERROR"
                        )
                        failure_msg.append(status_msg)

                    failure_reason = "Deployment of the template '{0}' failed on devices {1} with the following reason(s): {2}".format(
                        template_name, device_ips, ", ".join(failure_msg)
                    )
                    self.msg = failure_reason
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                # Check if the elapsed time exceeds the timeout
                elapsed_time = time.time() - loop_start_time
                if self.check_timeout_and_exit(
                    loop_start_time, deployment_id, task_name
                ):
                    self.log(
                        "Timeout exceeded after {0:.2f} seconds while monitoring deployment task '{1}'. Deployment ID: '{2}'.".format(
                            elapsed_time, task_name, deployment_id
                        ),
                        "DEBUG",
                    )
                    self.check_return_status()

                # Wait for the specified poll interval before the next check
                poll_interval = self.params.get("dnac_task_poll_interval")
                self.log(
                    "Waiting for the next poll interval of {0} seconds before checking deployment status again.".format(
                        poll_interval
                    ),
                    "DEBUG",
                )
                time.sleep(poll_interval)

            except Exception as e:
                self.msg = (
                    "An unexpected error occurred during API call for task '{0}'. Deployment ID: '{1}'. "
                    "Exception: {2}".format(task_name, deployment_id, str(e))
                )
                self.fail_and_exit(self.msg)

    def deploy_template_to_devices(
        self, deploy_temp_payload, template_name, device_ips
    ):
        """
        Deploys a specified template to devices associated with a site in the Cisco Catalyst Center.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            deploy_temp_payload (dict): The payload containing the details required to deploy the template.
                This includes the template ID, device details, and template parameters.
            template_name (str): The name of the template to be deployed.
            device_ips (list): The management ip address of the devices to which template will be deployed.
        Returns:
            self (object): The instance of the class itself, with the operation result (success or failure)
            set accordingly.
        Description:
            This function handles the deployment of a template to a set of devices managed in the Cisco Catalyst Center.
            It sends a POST request with the deployment payload and retrieves the task ID associated with the deployment task.
            It then monitors the status of the task using the task ID and logs the result.
            If the task ID is not retrieved or an exception occurs during deployment, the function logs an error message,
            sets the operation result to "failed," and returns the instance.
            The success message indicates that the template has been successfully deployed to all the devices in the specified
            site, while any exceptions are caught and logged with appropriate details.
        """

        try:
            self.log(
                "Deploying the given template {0} to the device(s) {1}.".format(
                    template_name, device_ips
                )
            )
            payload = {"payload": deploy_temp_payload}
            task_name = "deploy_template_v2"
            task_id = self.get_taskid_post_api_call(
                "configuration_templates", task_name, payload
            )

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0}'.".format(
                    task_name
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            loop_start_time = time.time()
            sleep_duration = self.params.get("dnac_task_poll_interval")
            self.log(
                "Starting task monitoring for '{0}' with task ID '{1}'.".format(
                    task_name, task_id
                ),
                "DEBUG",
            )

            while True:
                task_details = self.get_task_details_by_id(task_id)
                if not task_details:
                    self.msg = "Error retrieving task status for '{0}' with task ID '{1}'".format(
                        task_name, task_id
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                # Check if the elapsed time exceeds the timeout
                elapsed_time = time.time() - loop_start_time
                if self.check_timeout_and_exit(loop_start_time, task_id, task_name):
                    self.log(
                        "Timeout exceeded after {0:.2f} seconds while monitoring task '{1}' with task ID '{2}'.".format(
                            elapsed_time, task_name, task_id
                        ),
                        "DEBUG",
                    )
                    return self

                progress = task_details.get("progress")
                self.log(
                    "Task ID '{0}' progress details retrieved from API '{1}'. Progress: '{2}'.".format(
                        task_id, task_name, progress
                    ),
                    "DEBUG",
                )
                # Get the deployment id of the template if it get deployed successfully on the devices
                self.log(
                    "Searching for the Deployment ID in the task progress message using regex...",
                    "DEBUG",
                )
                match = re.search(
                    r"Template\s+Deployemnt\s+Id:\s+([a-f0-9\-]+)",
                    progress,
                    re.IGNORECASE,
                )
                deployment_id = None
                if match:
                    deployment_id = match.group(1)
                    if deployment_id:
                        self.log(
                            "Deployment ID found in the progress message. Template Deployment ID: '{0}'.".format(
                                deployment_id
                            ),
                            "DEBUG",
                        )
                        self.log(
                            "Proceeding to monitor the deployment with Deployment ID: '{0}'.".format(
                                deployment_id
                            ),
                            "DEBUG",
                        )
                        self.monitor_template_deployment_status(
                            template_name, deployment_id, device_ips
                        ).check_return_status()
                    else:
                        self.log(
                            "Regex matched the progress message, but no Deployment ID was captured. "
                            "This could indicate an issue with the progress message or the regex pattern. Progress: '{0}'.".format(
                                progress
                            ),
                            "ERROR",
                        )
                else:
                    self.log(
                        "Deployment ID not found in the progress message. This could indicate that the template '{0}' is already deployed with"
                        " same parameters, Hence not deploying on devices. Progress message: '{1}'.".format(
                            template_name, progress
                        ),
                        "WARNING",
                    )

                if "already deployed with same params" in progress:
                    self.msg = "Template '{0}' is already deployed with the same parameters. No deployment actions will be performed.".format(
                        template_name
                    )
                    self.log(self.msg, "INFO")
                    self.set_operation_result("success", False, self.msg, "INFO")
                    return self

                failure_reason = task_details.get("failureReason")
                if failure_reason:
                    self.log(
                        "Deployment of the template '{0}' failed. Failure reason: '{1}'. No further actions will be taken.".format(
                            template_name, failure_reason
                        ),
                        "ERROR",
                    )
                    self.msg = failure_reason
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                if "not deploying" in progress:
                    self.log(
                        "Deployment of the template {0} gets failed because of: {1}".format(
                            template_name, progress
                        ),
                        "WARNING",
                    )
                    self.msg = progress
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                if "ApplicableTargets" in progress:
                    self.msg = (
                        "Given template '{0}' deployed successfully to all the device(s) '{1}' "
                        " in the Cisco Catalyst Center."
                    ).format(template_name, device_ips)
                    self.set_operation_result("success", True, self.msg, "INFO")
                    return self

                self.log(
                    "Waiting for {0} seconds before checking the task status again.".format(
                        sleep_duration
                    ),
                    "DEBUG",
                )
                time.sleep(sleep_duration)

        except Exception as e:
            self.msg = (
                "An exception occured while deploying the template '{0}' to the device(s) {1} "
                " in the Cisco Catalyst Center: {2}."
            ).format(template_name, device_ips, str(e))
            self.set_operation_result("failed", False, self.msg, "ERROR")

        return self

    def get_device_ips_from_config_priority(self, device_details):
        """
        Retrieve device IPs based on the configuration.
        Parameters:
            -  self (object): An instance of a class used for interacting with Cisco Cisco Catalyst Center.
        Returns:
            list: A list containing device IPs.
        Description:
            This method retrieves device IPs based on the priority order specified in the configuration.
            It first checks if device IPs are available. If not, it checks hostnames, serial numbers,
            and MAC addresses in order and retrieves IPs based on availability.
            If none of the information is available, an empty list is returned.
        """
        # Retrieve device IPs from the configuration
        self.log(
            "Retrieving device IPs based on the configuration priority with details: {0}".format(
                device_details
            ),
            "INFO",
        )
        try:
            device_ips = device_details.get("device_ips")
            if device_ips and not isinstance(device_ips, list):
                self.msg = "Device IPs should be a list, but got: {0}".format(type(device_ips).__name__)
                self.set_operation_result("failed", False, self.msg, "ERROR").check_return_status()

            if device_ips:
                self.log("Found device IPs: {0}".format(device_ips), "INFO")
                return device_ips

            # If device IPs are not available, check hostnames
            device_hostnames = device_details.get("device_hostnames")
            if device_hostnames:
                self.log(
                    "No device IPs found. Checking hostnames: {0}".format(
                        device_hostnames
                    ),
                    "INFO",
                )
                device_ip_dict = self.get_device_ips_from_hostnames(device_hostnames)
                return self.get_list_from_dict_values(device_ip_dict)

            # If hostnames are not available, check serial numbers
            device_serial_numbers = device_details.get("serial_numbers")
            if device_serial_numbers:
                self.log(
                    "No device IPs or hostnames found. Checking serial numbers: {0}".format(
                        device_serial_numbers
                    ),
                    "INFO",
                )
                device_ip_dict = self.get_device_ips_from_serial_numbers(
                    device_serial_numbers
                )
                return self.get_list_from_dict_values(device_ip_dict)

            # If serial numbers are not available, check MAC addresses
            device_mac_addresses = device_details.get("mac_addresses")
            if device_mac_addresses:
                self.log(
                    "No device IPs, hostnames, or serial numbers found. Checking MAC addresses: {0}".format(
                        device_mac_addresses
                    ),
                    "INFO",
                )
                device_ip_dict = self.get_device_ips_from_mac_addresses(
                    device_mac_addresses
                )
                return self.get_list_from_dict_values(device_ip_dict)

            # If no information is available, return an empty list
            self.log("No device information available to retrieve IPs.", "WARNING")
            return []

        except Exception as e:
            self.log("No device information available to retrieve IPs.", "WARNING")
            return []

    def get_device_ids_from_tag(self, tag_name, tag_id):
        """
        Retrieves the device IDs associated with a specific tag from the Cisco Catalyst Center.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.
            tag_name (str): The name of the tag, used for logging purposes.
            tag_id (str): The unique identifier of the tag from which to retrieve associated device IDs.
        Returns:
            list (str): A list of device IDs (strings) associated with the specified tag. If no devices are found or
            an error occurs, the function returns an empty list.
        Description:
            This function queries the Cisco Catalyst Center API to retrieve a list of devices associated with a given tag.
            It calls the `get_tag_members_by_id` function using the tag's ID, specifying that the tag members should be of
            type "networkdevice". If the API response contains device data, the function extracts and returns the device IDs.
            The function logs whether the tag has associated devices and details about the API response. In the event of an
            exception, it logs an error message, sets the operation result to "failed," and returns an empty list.
        """

        device_ids = []
        self.log(
            "Fetching device IDs associated with the tag '{0}' (ID: {1}).".format(
                tag_name, tag_id
            ),
            "INFO",
        )

        try:
            response = self.dnac._exec(
                family="tag",
                function="get_tag_members_by_id",
                op_modifies=False,
                params={
                    "id": tag_id,
                    "member_type": "networkdevice",
                },
            )
            if response and "response" in response:
                response_data = response.get("response")
            else:
                self.log(
                    "No valid response for device with tag ID '{0}'.".format(tag_id),
                    "INFO",
                )
                return device_ids

            if not response_data:
                self.log(
                    "No device(s) are associated with the tag '{0}'.".format(tag_name),
                    "WARNING",
                )
                return device_ids

            self.log(
                "Received API response from 'get_tag_members_by_id' for the tag {0}: {1}".format(
                    tag_name, response_data
                ),
                "DEBUG",
            )
            for tag in response_data:
                device_id = tag.get("id")
                self.log(
                    "Device ID '{0}' found for tag '{1}'.".format(device_id, tag_name),
                    "DEBUG",
                )
                device_ids.append(device_id)

        except Exception as e:
            self.msg = (
                "Exception occurred while fetching tag id for the tag '{0} 'from "
                "Cisco Catalyst Center: {1}"
            ).format(tag_name, str(e))
            self.set_operation_result(
                "failed", False, self.msg, "INFO"
            ).check_return_status()

        return device_ids

    def update_template_projects_message(self):
        """
        Updates the result message and change status based on the outcomes of project and template operations.

        Args:
            self (object): An instance of the class used for interacting with Cisco Catalyst Center.

        Returns:
            object: Returns the current instance (`self`) with updated `result` and `msg` fields.

        Description:
            This method checks various internal flags (such as whether a project or template was created, updated,
            or committed) and builds a descriptive message accordingly. It updates the result dictionary with a
            `changed` flag and constructs a human-readable summary message about the performed operations.
            The message is stored in `self.msg`, and the result is logged via `set_operation_result`.
        """

        self.result["changed"] = False
        result_msg_list = []
        if self.project_created:
            create_project_msg = "Project '{0}' created successfully in the Cisco Catalyst Center.".format(self.project_created)
            result_msg_list.append(create_project_msg)

        if self.template_created:
            create_template_msg = "Template '{0}' created successfully in the Cisco Catalyst Center.".format(self.template_created)
            result_msg_list.append(create_template_msg)

        if self.template_updated:
            update_template_msg = "Template '{0}' updated successfully in the Cisco Catalyst Center.".format(self.template_updated)
            result_msg_list.append(update_template_msg)

        if self.no_update_template:
            no_update_template_msg = (
                "No changes detected in the template '{0}' so not updating it in the Cisco Catalyst Center."
            ).format(self.no_update_template)
            result_msg_list.append(no_update_template_msg)

        if self.template_committed:
            commit_template_msg = "Template '{0}' committed successfully in the Cisco Catalyst Center.".format(self.template_committed)
            result_msg_list.append(commit_template_msg)

        if self.profile_assigned:
            profile_assign_msg = "Profile(s) '{0}' assigned successfully to the template.".format(str(
                self.profile_assigned))
            result_msg_list.append(profile_assign_msg)

        if self.no_profile_assigned:
            no_profile_assign_msg = "Unable to assign the profile(s) '{0}' to the template.".format(str(
                self.no_profile_assigned))
            result_msg_list.append(no_profile_assign_msg)

        if (self.profile_exists and not self.profile_detached
           and not self.profile_not_detached and not self.profile_already_detached):
            profile_exists_msg = "Profile(s) '{0}' already exist and cannot be assigned to the template.".format(str(
                self.profile_exists))
            result_msg_list.append(profile_exists_msg)

        if self.profile_detached:
            profile_detach_msg = "Profile(s) '{0}' detached successfully from the template.".format(str(
                self.profile_detached))
            result_msg_list.append(profile_detach_msg)

        if self.profile_not_detached:
            profile_not_detach_msg = "Profile(s) '{0}' could not be detached from the template.".format(str(
                self.profile_not_detached))
            result_msg_list.append(profile_not_detach_msg)

        if self.profile_already_detached:
            profile_already_detach_msg = "Profile(s) '{0}' were already detached from the template.".format(str(
                self.profile_already_detached))
            result_msg_list.append(profile_already_detach_msg)

        if (
            self.project_created or self.template_created or self.template_updated
            or self.template_committed or self.profile_assigned or self.profile_detached
        ):
            self.result["changed"] = True

        self.msg = " ".join(result_msg_list)
        self.set_operation_result("success", self.result["changed"], self.msg, "INFO")

        return self

    def get_diff_merged(self, config):
        """
        Update/Create templates and projects in CCC with fields provided in Cisco Catalyst Center.
        Export the tempaltes and projects.
        Import the templates and projects.
        Deploy the template to the devices based on device specific details or by fetching the device
        details from site using other filtering parameters like device tag, device family, device role.
        Check using check_return_status().

        Parameters:
            config (dict) - Playbook details containing template information.

        Returns:
            self
        """

        project_details = config.get("projects")
        if project_details:
            if len(self.have.get("projects")) == len(project_details):
                project_unmatch = any(not project.get("project_status") and
                                      not project.get("new_name")
                                      for project in self.have.get("projects"))
                if not project_unmatch:
                    self.msg = "No changes required, project(s) already exist"
                    self.log(self.msg, "INFO")
                    self.set_operation_result("success", False, self.msg, "INFO").check_return_status()
                    return self
            self.apply_project_config(project_details).check_return_status()
            return self

        configuration_templates = config.get("configuration_templates")
        if configuration_templates:
            self.update_configuration_templates(config, configuration_templates).check_return_status()
            self.update_template_projects_message().check_return_status()

        _import = config.get("import")
        if _import:
            self.handle_import(_import).check_return_status()

        export = config.get("export")
        if export:
            self.log("Found export configuration: {0}".format(export), "DEBUG")
            self.handle_export(export).check_return_status()

        deploy_temp_details = config.get("deploy_template")
        if deploy_temp_details:
            template_name = deploy_temp_details.get("template_name")
            device_details = deploy_temp_details.get("device_details")
            site_specific_details = deploy_temp_details.get("site_provisioning_details")
            self.log(
                "Deploy template details found for template '{0}'".format(
                    template_name
                ),
                "DEBUG",
            )
            self.log("Device specific details: {0}".format(device_details), "DEBUG")
            self.log(
                "Site associated provisioning details: {0}".format(
                    site_specific_details
                ),
                "DEBUG",
            )

            if device_details:
                self.log(
                    "Attempting to retrieve device IPs based on priority from device specific details.",
                    "DEBUG",
                )
                device_ips = self.get_device_ips_from_config_priority(device_details)
                if not device_ips:
                    self.msg = (
                        "No matching device management IP addresses found for the "
                        "deployment of template '{0}'."
                    ).format(template_name)
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                self.log(
                    "Successfully retrieved device IPs for template '{0}': '{1}'".format(
                        template_name, device_ips
                    ),
                    "INFO",
                )
                device_id_dict = self.get_device_ids_from_device_ips(device_ips)
                device_ids = self.get_list_from_dict_values(device_id_dict)

                device_missing_msg = (
                    "There are no device id found for the device(s) '{0}' in the "
                    "Cisco Catalyst Center so cannot deploy the given template '{1}'."
                ).format(device_ips, template_name)
            elif site_specific_details:
                device_ids, site_name_list = [], []

                for site in site_specific_details:
                    site_name = site.get("site_name")
                    site_exists, site_id = self.get_site_id(site_name)
                    self.log(
                        "Checking if the site '{0}' exists in Cisco Catalyst Center.".format(
                            site_name
                        ),
                        "DEBUG",
                    )
                    if not site_exists:
                        self.msg = (
                            "To Deploy the template in the devices, given site '{0}' must be "
                            "present in the Cisco Catalyst Center and it's not there currently."
                        ).format(site_name)
                        self.set_operation_result("failed", False, self.msg, "ERROR")
                        return self

                    self.log(
                        "Retrieving devices associated with site ID '{0}' for site '{1}'.".format(
                            site_id, site_name
                        ),
                        "DEBUG",
                    )
                    site_response, site_assign_device_ids = (
                        self.get_device_ids_from_site(site_name, site_id)
                    )
                    site_name_list.append(site_name)

                    if not site_assign_device_ids:
                        device_missing_msg = (
                            "There is no device currently associated with the site '{0}' in the "
                            "Cisco Catalyst Center so cannot deploy the given template '{1}'."
                        ).format(site_name, template_name)
                        self.msg = device_missing_msg
                        self.log(device_missing_msg, "WARNING")
                        continue

                    device_family = site.get("device_family")
                    device_role = site.get("device_role")

                    # Filter devices based on the device family or device role
                    if device_family or device_role:
                        self.log(
                            "Filtering devices based on the device family '{0}' or role '{1}' for the site '{2}'.".format(
                                device_family, device_role, site_name
                            ),
                            "DEBUG",
                        )
                        self.log(
                            "Filtering devices based on the given family/role for the site {0}.".format(
                                site_name
                            ),
                            "INFO",
                        )
                        site_assign_device_ids = self.filter_devices_with_family_role(
                            site_assign_device_ids, device_family, device_role
                        )

                    # Filter devices based on the device tag given to the devices
                    tag_name = site.get("device_tag")
                    tag_device_ids = None
                    if tag_name:
                        self.log(
                            "Filtering out the devices based on the given device tag: '{0}'".format(
                                tag_name
                            ),
                            "INFO",
                        )
                        tag_id = self.get_network_device_tag_id(tag_name)
                        self.log(
                            "Successfully collected the tag id '{0}' for the tag '{1}'".format(
                                tag_id, tag_name
                            ),
                            "INFO",
                        )
                        # Get the device ids associated with the given tag for given site
                        tag_device_ids = self.get_device_ids_from_tag(tag_name, tag_id)
                        self.log(
                            "Successfully collected the device ids {0} associated with the tag {1}".format(
                                tag_device_ids, tag_name
                            ),
                            "INFO",
                        )

                    self.log(
                        "Getting the device ids based on device assoicated with tag or site or both.",
                        "DEBUG",
                    )

                    if tag_device_ids and site_assign_device_ids:
                        self.log(
                            "Determining device IDs from site and tag criteria.",
                            "DEBUG",
                        )
                        common_device_ids = list(
                            set(tag_device_ids).intersection(
                                set(site_assign_device_ids)
                            )
                        )
                        device_ids.extend(common_device_ids)
                    elif site_assign_device_ids and not tag_device_ids:
                        self.log(
                            "Getting the device ids based on devices fetched from site.",
                            "DEBUG",
                        )
                        device_ids.extend(site_assign_device_ids)
                    elif tag_device_ids and not site_assign_device_ids:
                        self.log(
                            "Getting the device ids based on devices fetched with the tag {0}.".format(
                                tag_name
                            ),
                            "DEBUG",
                        )
                        device_ids.extend(tag_device_ids)
                    else:
                        self.log(
                            "There is no matching device ids found for the deployment of template {0} "
                            "for the given site {1}".format(template_name, site_name),
                            "WARNING",
                        )
                        continue

                device_missing_msg = (
                    "There is no device id found for the given site(s) '{0}' in the "
                    "Cisco Catalyst Center so cannot deploy the template '{1}'."
                ).format(site_name_list, template_name)
            else:
                self.msg = (
                    "Unable to provision the template '{0}' as device related details are "
                    "not given in the playboook. Please provide it either via the parameter "
                    "device_details or with site_provisioning_details."
                ).format(self.msg)
                self.set_operation_result(
                    "failed", False, self.msg, "INFO"
                ).check_return_status()

            if not device_ids:
                self.msg = device_missing_msg
                self.set_operation_result("failed", False, self.msg, "INFO")
                return self

            device_ip_dict = self.get_device_ips_from_device_ids(device_ids)
            device_ips = self.get_list_from_dict_values(device_ip_dict)
            self.log(
                "Successfully collect the device ips {0} for the device ids {1}.".format(
                    device_ips, device_ids
                ),
                "INFO",
            )
            deploy_temp_payload = self.create_payload_for_template_deploy(
                deploy_temp_details, device_ids
            )
            self.log(
                "Deployment payload created successfully for template '{0}'.".format(
                    template_name
                ),
                "INFO",
            )
            self.deploy_template_to_devices(
                deploy_temp_payload, template_name, device_ips
            ).check_return_status()
            self.log(
                "Successfully deployed template '{0}'.".format(template_name), "INFO"
            )

        self.msg = "Successfully completed merged state execution"
        self.status = "success"

        return self

    def delete_project_or_template(self, config, is_delete_project=False):
        """
        Call Cisco Catalyst Center API to delete project or template with provided inputs.

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
            name = "templateName: {0}".format(template_params.get("name"))
        ccc_version = self.get_ccc_version()
        if self.compare_dnac_versions(ccc_version, "2.3.5.3") <= 0:
            self.log(
                "Deleting '{0}' using function '{1}' with parameters: {2} on Catalyst version: {3} (≤ 2.3.5.3)".format(
                    name, deletion_value, params_key, ccc_version
                ),
                "DEBUG",
            )
            response = self.dnac_apply["exec"](
                family="configuration_templates",
                function=deletion_value,
                op_modifies=True,
                params=params_key,
            )
            task_id = response.get("response").get("taskId")
            if not task_id:
                self.msg = "Unable to retrieve the task ID for the task '{0}'.".format(
                    deletion_value
                )
                self.set_operation_result("failed", False, self.msg, "ERROR")
                return self

            sleep_duration = self.params.get("dnac_task_poll_interval")
            while True:
                task_details = self.get_task_details(task_id)
                self.log("Printing task details: {0}".format(task_details), "DEBUG")
                if not task_details:
                    self.msg = "Unable to delete {0} as task details is empty.".format(
                        deletion_value
                    )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    return self

                progress = task_details.get("progress")
                self.log(
                    "Task details for the API {0}: {1}".format(
                        deletion_value, progress
                    ),
                    "DEBUG",
                )

                if "deleted" in progress:
                    self.log(
                        "Successfully performed the operation of '{0}' for '{1}'".format(
                            deletion_value, name
                        ),
                        "INFO",
                    )
                    self.msg = "Successfully deleted {0} ".format(name)
                    self.set_operation_result("success", True, self.msg, "INFO")
                    break

                if task_details.get("isError"):
                    failure_reason = task_details.get("failureReason")
                    if failure_reason:
                        self.msg = (
                            "Failed to perform the operation of {0} for {1} because of: {2}"
                        ).format(deletion_value, name, failure_reason)
                    else:
                        self.msg = (
                            "Failed to perform the operation of {0} for {1}.".format(
                                deletion_value, name
                            )
                        )
                    self.set_operation_result("failed", False, self.msg, "ERROR")
                    break

                self.log(
                    "Waiting for {0} seconds before checking the task status again.".format(
                        sleep_duration
                    ),
                    "DEBUG",
                )
                time.sleep(sleep_duration)
        else:
            current_profiles = self.have.get("current_profile", [])
            if current_profiles and self.compare_dnac_versions(ccc_version, "3.1.3.0") >= 0:
                template_name = self.want.get("template_params").get("name")
                self.log("Detaching profile from template", "DEBUG")
                detach_status = self.detach_profiles_from_template(template_name, current_profiles)
                if detach_status:
                    self.log("Received response from detach profile.", "DEBUG")
                    self.update_template_projects_message().check_return_status()
                    return self

            self.log(
                "Deleting '{0}' using function '{1}' with parameters: '{2}' on Catalyst version: {3} (> 2.3.5.3)".format(
                    name, deletion_value, params_key, ccc_version
                ),
                "DEBUG",
            )

            task_name = deletion_value
            parameters = params_key
            task_id = self.get_taskid_post_api_call(
                "configuration_templates", task_name, parameters
            )

            if not task_id:
                self.msg = "Unable to retrieve the task_id for the task '{0} for the parameters {1}'.".format(
                    task_name, parameters
                )
                self.set_operation_result(
                    "failed", False, self.msg, "ERROR"
                ).check_return_status()
                return self

            success_msg = "Task: {0} is successful for parameters: {1}".format(
                task_name, parameters
            )
            self.get_task_status_from_tasks_by_id(task_id, task_name, success_msg)

        return self

    def detach_profiles_from_template(self, name, current_profiles):
        """
        Detach profiles from a specific template in Cisco Catalyst Center.

        Args:
            name (str): The name of the template.
            current_profiles (list): A list of profile names to detach.

        Returns:
            bool: Returns True if the detachment was successful execution.
        """
        self.log("Detaching profiles from template '{0}': {1}".format(name, current_profiles), "INFO")

        for profile_index, each_profile in enumerate(current_profiles):
            # Extract profile information once per iteration
            each_profile_name = each_profile.get("profile_name")
            each_profile_id = each_profile.get("profile_id")
            profile_template_name = each_profile.get("template_name")
            profile_status = each_profile.get("profile_status")
            template_id = self.have_template.get("id")

            # Skip profiles not associated with the current template
            if profile_template_name != name:
                self.log("Skipping profile '{0}' - not associated with template '{1}' (associated with '{2}')".format(
                    each_profile_name, name, profile_template_name), "DEBUG")
                continue

            self.log("Processing profile '{0}' (index {1}) with status '{2}' for template '{3}'".format(
                each_profile_name, profile_index, profile_status, name), "DEBUG")

            # Case 1: Detach profile from template
            if profile_status == "already assigned":
                self.log("Detaching profile '{0}' from template '{1}' - profile currently assigned and detach requested".format(
                    each_profile_name, name), "INFO")

                try:
                    template_status = self.detach_networkprofile_cli_template(
                        each_profile_name, each_profile_id, name, template_id)
                    self.log("Received response from profile detachment API for profile '{0}': {1}".format(
                        each_profile_name, template_status), "DEBUG")

                    if template_status and template_status.get("progress"):
                        success_msg = "Profile '{0}' successfully detached from template '{1}'".format(
                            each_profile_name, name)
                        self.log(success_msg, "INFO")
                        self.profile_detached.append(each_profile_name)
                    else:
                        error_msg = "Failed to detach profile '{0}' from template '{1}' - API response indicates failure".format(
                            each_profile_name, name)
                        self.log(error_msg, "ERROR")
                        self.profile_not_detached.append(each_profile_name)

                except Exception as e:
                    error_msg = "Exception occurred while detaching profile '{0}' from template '{1}': {2}".format(
                        each_profile_name, name, str(e))
                    self.log(error_msg, "ERROR")
                    self.profile_not_detached.append(each_profile_name)

            # Case 2: Profile already detached (idempotent case)
            elif profile_status == "Not Assigned":
                self.log("Profile '{0}' already detached from template '{1}' - no action required".format(
                    each_profile_name, name), "INFO")
                self.profile_already_detached.append(each_profile_name)

            # Case 3: Unexpected scenario
            else:
                self.log("Unexpected scenario for profile '{0}' on template '{1}': status='{2}'".format(
                    each_profile_name, name, profile_status), "WARNING")

        # Log summary of operations
        total_detached = len(getattr(self, 'profile_detached', []))
        total_detachment_failures = len(getattr(self, 'profile_not_detached', []))
        total_already_detached = len(getattr(self, 'profile_already_detached', []))

        self.log("Profile operation summary for template '{0}':".format(name), "INFO")
        self.log("  - Profiles detached: {0} {1}".format(total_detached,
                                                         getattr(self, 'profile_detached', [])), "INFO")
        self.log("  - Detachment failures: {0} {1}".format(total_detachment_failures,
                                                           getattr(self, 'profile_not_detached', [])), "INFO")
        self.log("  - Already detached: {0} {1}".format(total_already_detached,
                                                        getattr(self, 'profile_already_detached', [])), "INFO")

        self.log("Completed profile detachment processing for template '{0}'".format(name), "INFO")

        return True

    def get_diff_deleted(self, config):
        """
        Delete projects or templates in Cisco Catalyst Center with fields provided in playbook.

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
                    self.result["response"][0].get("configurationTemplate").update(
                        {
                            "msg": "Template with template_name '{0}' already deleted".format(
                                templateName
                            )
                        }
                    )
                    self.msg = "Invalid template {0} under project".format(templateName)
                    self.status = "success"
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
            self.log(
                "Successfully completed the delete operation for the template {0}".format(
                    templateName
                ),
                "DEBUG",
            )

        deploy_temp_details = config.get("deploy_template")
        if deploy_temp_details:
            template_name = deploy_temp_details.get("template_name")
            self.msg = (
                "Deleting or removing the device configuration using deployment of template is not supported "
                "for the template {0} in the Cisco Catalyst Center."
            ).format(template_name)
            self.set_operation_result(
                "failed", False, self.msg, "ERROR"
            ).check_return_status()

        project_details = config.get("projects")
        if project_details and isinstance(project_details, list):
            self.processed_project = []
            if not self.have.get("projects"):
                self.log("No existing projects found. Nothing to delete.", "INFO")
                return self

            for each_project in project_details:
                project_name = each_project.get("name")
                if not project_name:
                    self.log("Skipping project with missing 'name' field.", "WARNING")
                    continue

                if self.delete_project(project_name):
                    self.processed_project.append(project_name)
                    self.log("Successfully deleted project: {0}".format(project_name), "INFO")

        return self

    def verify_diff_merged(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
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
                self.msg = "Configuration Template config is not applied to the Cisco Catalyst Center."
                self.status = "failed"
                return self

            self.get_have_template(config, is_template_available)
            self.log(
                "Desired State (want): {0}".format(self.want.get("template_params")),
                "INFO",
            )
            self.log(
                "Current State (have): {0}".format(self.have_template.get("template")),
                "INFO",
            )
            if not self.have_template.get("template"):
                self.msg = "No template created with the name '{0}'".format(
                    self.want.get("template_params").get("name")
                )
                self.status = "failed"
                return self

            template_params = [
                "language",
                "name",
                "projectName",
                "softwareType",
                "templateContent",
            ]
            have_template = self.have_template.get("template")
            want_template = self.want.get("template_params")
            for item in template_params:
                if have_template.get(item) != want_template.get(item):
                    self.msg = "Configuration Template config with template_name {0}'s '{1}' is not applied to the Cisco Catalyst Center.".format(
                        want_template.get("name"), item
                    )
                    self.status = "failed"
                    return self

            want_template_containing_template = want_template.get("containingTemplates")
            if want_template_containing_template:
                for item in want_template_containing_template:
                    name = item.get("name")
                    response = get_dict_result(
                        have_template.get("containingTemplates"), "name", name
                    )
                    if response is None:
                        self.msg = (
                            "Configuration Template config with template_name '{0}' under ".format(
                                name
                            )
                            + "'containing_templates' is not available in the Cisco Catalyst Center."
                        )
                        self.status = "failed"
                        return self
                    for value in item:
                        if item.get(value) != response.get(value):
                            self.msg = (
                                "Configuration Template config with template_name "
                                + "{0}'s '{1}' is not applied to the Cisco Catalyst Center.".format(
                                    name, value
                                )
                            )
                            self.status = "failed"
                            return self

            self.log(
                "Successfully validated the Template in the Catalyst Center.", "INFO"
            )

        self.msg = "Successfully validated the Configuration Templates."
        self.status = "success"
        return self

    def verify_diff_deleted(self, config):
        """
        Validating the Cisco Catalyst Center configuration with the playbook details
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
                params={
                    "projectNames": config.get("configuration_templates").get(
                        "project_name"
                    )
                },
            )
            self.log(
                "Received response from 'gets_the_templates_available' for 'project_name': '{0}' is {1}".format(
                    config.get("configuration_templates").get("project_name"),
                    template_list,
                ),
                "DEBUG",
            )
            if template_list and isinstance(template_list, list):
                templateName = config.get("configuration_templates").get(
                    "template_name"
                )
                template_info = get_dict_result(template_list, "name", templateName)
                if template_info:
                    self.log(
                        "Configuration Template config is not applied to the Cisco Catalyst Center.",
                        "WARNING",
                    )
                    return self

                self.log(
                    "Successfully validated the absence of Template {0} in the Cisco Catalyst Center.".format(
                        templateName
                    ),
                    "INFO",
                )

        if config.get("projects"):
            if not self.processed_project:
                self.msg = "No changes required, project(s) are already deleted"
                self.log(self.msg, "INFO")
                self.set_operation_result("success", False, self.msg,
                                          "INFO").check_return_status()
                return self

            self.get_have(config)
            self.log("Current State (have): {0}".format(self.have), "INFO")
            self.log("Desired State (want): {0}".format(self.want), "INFO")
            if not self.have.get("projects"):
                self.msg = "Project(s) are deleted and verified successfully. {0}".format(
                    self.processed_project)
                self.log(self.msg, "INFO")
                self.set_operation_result("success", True, self.msg, "INFO",
                                          config.get("projects")).check_return_status()
                return self

            self.msg = "Unable to delete the following project(s): {0}".format(
                [project.get("name") for project in self.have.get("projects", [])])
            self.log(self.msg, "ERROR")
            self.set_operation_result("failed", False, self.msg, "INFO",
                                      self.have.get("projects")).check_return_status()
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
    ccc_template = Template(module)

    ccc_version = ccc_template.get_ccc_version()
    if ccc_template.compare_dnac_versions(ccc_version, "2.3.7.6") < 0:
        ccc_template.msg = (
            "Template module is not supported in Cisco Catalyst Center version '{0}'. Supported versions start "
            "from '2.3.7.6' onwards.".format(ccc_version)
        )
        ccc_template.set_operation_result(
            "failed", False, ccc_template.msg, "ERROR"
        ).check_return_status()

    ccc_template.validate_input().check_return_status()
    state = ccc_template.params.get("state")
    config_verify = ccc_template.params.get("config_verify")
    if state not in ccc_template.supported_states:
        ccc_template.status = "invalid"
        ccc_template.msg = "State {0} is invalid".format(state)
        ccc_template.check_return_status()

    for config in ccc_template.validated_config:
        ccc_template.reset_values()
        ccc_template.get_have(config).check_return_status()
        ccc_template.get_want(config).check_return_status()
        ccc_template.get_diff_state_apply[state](config).check_return_status()
        if config_verify:
            ccc_template.verify_diff_state_apply[state](config).check_return_status()

    module.exit_json(**ccc_template.result)


if __name__ == "__main__":
    main()
