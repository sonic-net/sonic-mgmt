#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_pssession_configuration
short_description: Manage PSSession Configurations
description:
  - Register, unregister, and modify PSSession Configurations for PowerShell remoting.
options:
  name:
    description:
      - The name of the session configuration to manage.
    type: str
    required: yes
  state:
    description:
      - The desired state of the configuration.
    type: str
    choices:
      - present
      - absent
    default: present
  guid:
    description:
      - The GUID (UUID) of the session configuration file.
      - This value is metadata, so it only matters if you use it externally.
      - If not set, a value will be generated automatically.
      - Acceptable GUID formats are flexible. Any string of 32 hexadecimal digits will be accepted, with all hyphens C(-) and opening/closing C({}) ignored.
      - See also I(lenient_config_fields).
    type: raw
  schema_version:
    description:
      - The schema version of the session configuration file.
      - If not set, a value will be generated automatically.
      - Must be a valid .Net System.Version string.
    type: raw
  author:
    description:
      - The author of the session configuration.
      - This value is metadata and does not affect the functionality of the session configuration.
      - If not set, a value may be generated automatically.
      - See also I(lenient_config_fields).
    type: str
  description:
    description:
      - The description of the session configuration.
      - This value is metadata and does not affect the functionality of the session configuration.
      - See also I(lenient_config_fields).
    type: str
  company_name:
    description:
      - The company that authored the session configuration.
      - This value is metadata and does not affect the functionality of the session configuration.
      - If not set, a value may be generated automatically.
      - See also I(lenient_config_fields).
    type: str
  copyright:
    description:
      - The copyright statement of the session configuration.
      - This value is metadata and does not affect the functionality of the session configuration.
      - If not set, a value may be generated automatically.
      - See also I(lenient_config_fields).
    type: str
  session_type:
    description:
      - Controls what type of session this is.
    type: str
    choices:
      - default
      - empty
      - restricted_remote_server
  transcript_directory:
    description:
      - Automatic session transcripts will be written to this directory.
    type: path
  run_as_virtual_account:
    description:
      - If C(yes) the session runs as a virtual account.
      - Do not use I(run_as_credential_username) and I(run_as_credential_password) to specify a virtual account.
    type: bool
  run_as_virtual_account_groups:
    description:
      - If I(run_as_virtual_account=yes) this is a list of groups to add the virtual account to.
    type: list
    elements: str
  mount_user_drive:
      description:
        - If C(yes) the session creates and mounts a user-specific PSDrive for use with file transfers.
      type: bool
  user_drive_maximum_size:
    description:
      - The maximum size of the user drive in bytes.
      - Must fit into an Int64.
    type: raw
  group_managed_service_account:
    description:
      - If the session will run as a group managed service account (gMSA) then this is the name.
      - Do not use I(run_as_credential_username) and I(run_as_credential_password) to specify a gMSA.
    type: str
  scripts_to_process:
    description:
      - A list of paths to script files ending in C(.ps1) that should be applied to the session.
    type: list
    elements: str
  role_definitions:
    description:
      - A dict defining the roles for JEA sessions.
      - For more information see U(https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/session-configurations#role-definitions).
    type: dict
  required_groups:
    description:
      - For JEA sessions, defines conditional access rules about which groups a connecting user must belong to.
      - For more information see U(https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/session-configurations#conditional-access-rules).
    type: dict
  language_mode:
    description:
      - Determines the language mode of the PowerShell session.
    type: str
    choices:
      - no_language
      - restricted_language
      - constrained_language
      - full_language
  execution_policy:
    description:
      - The execution policy controlling script execution in the PowerShell session.
    type: str
    choices:
      - default
      - remote_signed
      - restricted
      - undefined
      - unrestricted
  powershell_version:
    description:
      - The minimum required PowerShell version for this session.
      - Must be a valid .Net System.Version string.
    type: raw
  modules_to_import:
    description:
      - A list of modules that should be imported into the session.
      - Any valid PowerShell module spec can be used here, so simple str names or dicts can be used.
      - If a dict is used, no snake_case conversion is done, so the original PowerShell names must be used.
    type: list
    elements: raw
  visible_aliases:
    description:
      - The aliases that can be used in the session.
      - For more information see U(https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/role-capabilities).
    type: list
    elements: str
  visible_cmdlets:
    description:
      - The cmdlets that can be used in the session.
      - The elements can be simple names or complex command specifications.
      - For more information see U(https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/role-capabilities).
    type: list
    elements: raw
  visible_functions:
    description:
      - The functions that can be used in the session.
      - The elements can be simple names or complex command specifications.
      - For more information see U(https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/role-capabilities).
    type: list
    elements: raw
  visible_external_commands:
    description:
      - The external commands and scripts that can be used in the session.
      - For more information see U(https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/role-capabilities).
    type: list
    elements: str
  alias_definitions:
    description:
      - A dict that defines aliases for each session.
    type: dict
  function_definitions:
    description:
      - A dict that defines functions for each session.
    type: dict
  variable_definitions:
    description:
      - A list of dicts where each elements defines a variable for each session.
    type: list
    elements: dict
  environment_variables:
    description:
      - A dict that defines environment variables for each session.
    type: dict
  types_to_process:
    description:
      - Paths to type definition files to process for each session.
    type: list
    elements: path
  formats_to_process:
    description:
      - Paths to format definition files to process for each session.
    type: list
    elements: path
  assemblies_to_load:
    description:
      - The assemblies that should be loaded into each session.
    type: list
    elements: str
  processor_architecure:
    description:
      - The processor architecture of the session (32 bit vs. 64 bit).
    type: str
    choices:
      - amd64
      - x86
  access_mode:
    description:
      - Controls whether the session configuration allows connection from the C(local) machine only, both local and C(remote), or none (C(disabled)).
    type: str
    choices:
      - disabled
      - local
      - remote
  use_shared_process:
    description:
      - If C(yes) then the session shares a process for each session.
    type: bool
  thread_apartment_state:
    description:
      - The apartment state for the PowerShell session.
    type: str
    choices:
      - mta
      - sta
  thread_options:
    description:
      - Sets thread options for the session.
    type: str
    choices:
      - default
      - reuse_thread
      - use_current_thread
      - use_new_thread
  startup_script:
    description:
      - A script that gets run on session startup.
    type: path
  maximum_received_data_size_per_command_mb:
    description:
      - Sets the maximum received data size per command in MB.
      - Must fit into a double precision floating point value.
    type: raw
  maximum_received_object_size_mb:
    description:
      - Sets the maximum object size in MB.
      - Must fit into a double precision floating point value.
    type: raw
  security_descriptor_sddl:
    description:
      - An SDDL string that controls which users and groups can connect to the session.
      - If I(role_definitions) is specified the security descriptor will be set based on that.
      - If this option is not specified the default security descriptor will be applied.
    type: str
  run_as_credential_username:
    description:
      - Used to set a RunAs account for the session. All commands executed in the session will be run as this user.
      - To use a gMSA, see I(group_managed_service_account).
      - To use a virtual account, see I(run_as_virtual_account) and I(run_as_virtual_account_groups).
      - Status will always be C(changed) when a RunAs credential is set because the password cannot be retrieved for comparison.
    type: str
  run_as_credential_password:
    description:
      - The password for I(run_as_credential_username).
    type: str
  lenient_config_fields:
    description:
      - Some fields used in the session configuration do not affect its function, and are sometimes auto-generated when not specified.
      - To avoid unnecessarily changing the configuration on each run, the values of these options will only be enforced when they are explicitly specified.
    type: list
    elements: str
    default:
      - guid
      - author
      - company_name
      - copyright
      - description
  async_timeout:
    description:
      - Sets a timeout for how long in seconds to wait for asynchronous module execution and waiting for the connection to recover.
      - Replicates the functionality of the C(async) keyword.
      - Has no effect in check mode.
    type: int
    default: 300
  async_poll:
    description:
      - Sets a delay in seconds between each check of the asynchronous execution status.
      - Replicates the functionality of the C(poll) keyword.
      - Has no effect in check mode.
      - I(async_poll=0) is not supported.
    type: int
    default: 1
notes:
  - This module will restart the WinRM service on any change. This will terminate all WinRM connections including those by other Ansible runs.
  - Internally this module uses C(async) when not in check mode to ensure things go smoothly when restarting the WinRM service.
  - The standard C(async) and C(poll) keywords cannot be used; instead use the I(async_timeout) and I(async_poll) options to control asynchronous execution.
  - Options that don't list a default value here will use the defaults of C(New-PSSessionConfigurationFile) and C(Register-PSSessionConfiguration).
  - If a value can be specified in both a session config file and directly in the session options, this module will prefer the setting be in the config file.
seealso:
  - name: C(New-PSSessionConfigurationFile) Reference
    description: Details and defaults for options that end up in the session configuration file.
    link: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/new-pssessionconfigurationfile
  - name: C(Register-PSSessionConfiguration) Reference
    description: Details and defaults for options that are not specified in the session config file.
    link: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/register-pssessionconfiguration
  - name: PowerShell Just Enough Administration (JEA)
    description: Refer to the JEA documentation for advanced usage of some options
    link: https://docs.microsoft.com/en-us/powershell/scripting/learn/remoting/jea/overview
  - name: About Session Configurations
    description: General information about session configurations.
    link: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_session_configurations
  - name: About Session Configuration Files
    description: General information about session configuration files.
    link: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_session_configuration_files
author:
  - Brian Scholer (@briantist)
'''

EXAMPLES = r'''
- name: Register a session configuration that loads modules automatically
  community.windows.win_pssession_configuration:
    name: WebAdmin
    modules_to_import:
      - WebAdministration
      - IISAdministration
    description: This endpoint has IIS modules pre-loaded

- name: Set up an admin endpoint with a restricted execution policy
  community.windows.win_pssession_configuration:
    name: GloboCorp.Admin
    company_name: Globo Corp
    description: Admin Endpoint
    execution_policy: restricted

- name: Create a complex JEA endpoint
  community.windows.win_pssession_configuration:
    name: RBAC.Endpoint
    session_type: restricted_remote_server
    run_as_virtual_account: true
    transcript_directory: '\\server\share\Transcripts'
    language_mode: no_language
    execution_policy: restricted
    role_definitions:
      'CORP\IT Support':
        RoleCapabilities:
          - PasswordResetter
          - EmployeeOffboarder
      'CORP\Webhosts':
        RoleCapabilities: IISAdmin
    visible_functions:
      - tabexpansion2
      - help
    visible_cmdlets:
      - Get-Help
      - Name: Get-Service
        Parameters:
          - Name: DependentServices
          - Name: RequiredServices
          - Name: Name
            ValidateSet:
              - WinRM
              - W3SVC
              - WAS
    visible_aliases:
      - gsv
    state: present

- name: Remove a session configuration
  community.windows.win_pssession_configuration:
    name: UnusedEndpoint
    state: absent

- name: Set a sessions configuration with tweaked async values
  community.windows.win_pssession_configuration:
    name: MySession
    description: A sample session
    async_timeout: 500
    async_poll: 5
'''

RETURN = r'''
'''
