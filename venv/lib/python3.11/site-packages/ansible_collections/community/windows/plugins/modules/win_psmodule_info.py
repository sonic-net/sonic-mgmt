#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_psmodule_info
short_description: Gather information about PowerShell Modules
description:
  - Gather information about PowerShell Modules including information from PowerShellGet.
options:
  name:
    description:
      - The name of the module to retrieve.
      - Supports any wildcard pattern supported by C(Get-Module).
      - If omitted then all modules will returned.
    type: str
    default: '*'
  repository:
    description:
      - The name of the PSRepository the modules were installed from.
      - This acts as a filter against the modules that would be returned based on the I(name) option.
      - Modules that were not installed from a repository will not be returned if this option is set.
      - Only modules installed from a registered repository will be returned.
      - If the repository was re-registered after module installation with a new C(SourceLocation), this will not match.
    type: str
requirements:
  - C(PowerShellGet) module
seealso:
  - module: community.windows.win_psrepository_info
  - module: community.windows.win_psscript_info
author:
  - Brian Scholer (@briantist)
'''

EXAMPLES = r'''
- name: Get info about all modules on the system
  community.windows.win_psmodule_info:

- name: Get info about the ScheduledTasks module
  community.windows.win_psmodule_info:
    name: ScheduledTasks

- name: Get info about networking modules
  community.windows.win_psmodule_info:
    name: Net*

- name: Get info about all modules installed from the PSGallery repository
  community.windows.win_psmodule_info:
    repository: PSGallery
  register: gallery_modules

- name: Update all modules retrieved from above example
  community.windows.win_psmodule:
    name: "{{ item }}"
    state: latest
  loop: "{{ gallery_modules.modules | map(attribute=name) }}"

- name: Get info about all modules on the system
  community.windows.win_psmodule_info:
  register: all_modules

- name: Find modules installed from a repository that isn't registered now
  set_fact:
    missing_repository_modules: "{{
      all_modules
      | json_query('modules[?repository!=null && repository==repository_source_location].{name: name, version: version, repository: repository}')
      | list
    }}"

- debug:
    var: missing_repository_modules
'''

RETURN = r'''
modules:
  description:
    - A list of modules (or an empty list is there are none).
  returned: always
  type: list
  elements: dict
  contains:
    name:
      description:
        - The name of the module.
      type: str
      sample: PSReadLine
    version:
      description:
        - The module version.
      type: str
      sample: 1.2.3
    guid:
      description:
        - The GUID of the module.
      type: str
      sample: 74c9fd30-734b-4c89-a8ae-7727ad21d1d5
    path:
      description:
        - The path to the module.
      type: str
      sample: 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\PKI\PKI.psd1'
    module_base:
      description:
        - The path that contains the module's files.
      type: str
      sample: 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\PKI'
    installed_location:
      description:
        - The path where the module is installed.
        - This should have the same value as C(module_base) but only has a value when the module was installed via PowerShellGet.
      type: str
      sample: 'C:\Program Files\WindowsPowerShell\Modules\posh-git\0.7.1'
    exported_aliases:
      description:
        - The aliases exported from the module.
      type: list
      elements: str
      sample:
        - glu
        - slu
    exported_cmdlets:
      description:
        - The cmdlets exported from the module.
      type: list
      elements: str
      sample:
        - Get-Certificate
        - Get-PfxData
    exported_commands:
      description:
        - All of the commands exported from the module. Includes functions, cmdlets, and aliases.
      type: list
      elements: str
      sample:
        - glu
        - Get-LocalUser
    exported_dsc_resources:
      description:
        - The DSC resources exported from the module.
      type: list
      elements: str
      sample:
        - xWebAppPool
        - xWebSite
    exported_format_files:
      description:
        - The format files exported from the module.
      type: list
      elements: path
      sample:
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsCmdlets.Format.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsConfig.Format.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsClientPSProvider.Format.ps1xml'
    exported_functions:
      description:
        - The functions exported from the module.
      type: list
      elements: str
      sample:
        - New-VirtualDisk
        - New-Volume
    exported_type_files:
      description:
        - The type files exported from the module.
      type: list
      elements: path
      sample:
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsCmdlets.Types.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsConfig.Types.ps1xml'
        - 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsClientPSProvider.Types.ps1xml'
    exported_variables:
      description:
        - The variables exported from the module.
      type: list
      elements: str
      sample:
        - GitPromptScriptBlock
    exported_workflows:
      description:
        - The workflows exported from the module.
      type: list
      elements: str
    access_mode:
      description:
        - The module's access mode. See U(https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.moduleaccessmode)
      type: str
      sample: ReadWrite
    module_type:
      description:
        - The module's type. See U(https://docs.microsoft.com/en-us/dotnet/api/system.management.automation.moduletype)
      type: str
      sample: Script
    procoessor_architecture:
      description:
        - The module's processor architecture. See U(https://docs.microsoft.com/en-us/dotnet/api/system.reflection.processorarchitecture)
      type: str
      sample: Amd64
    author:
      description:
        - The author of the module.
      type: str
      sample: Warren Frame
    copyright:
      description:
        - The copyright of the module.
      type: str
      sample: '(c) 2016 Warren F. All rights reserved.'
    company_name:
      description:
        - The company name of the module.
      type: str
      sample: Microsoft Corporation
    description:
      description:
        - The description of the module.
      type: str
      sample: Provides cmdlets to work with local users and local groups
    clr_version:
      description:
        - The CLR version of the module.
      type: str
      sample: '4.0'
    compatible_ps_editions:
      description:
        - The PS Editions the module is compatible with.
      type: list
      elements: str
      sample:
        - Desktop
    dependencies:
      description:
        - The modules required by this module.
      type: list
      elements: str
    dot_net_framework_version:
      description:
        - The .Net Framework version of the module.
      type: str
      sample: '4.6.1'
    file_list:
      description:
        - The files included in the module.
      type: list
      elements: path
      sample:
        - 'C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.6.0\PSModule.psm1'
        - 'C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.6.0\PSGet.Format.ps1xml'
        - 'C:\Program Files\WindowsPowerShell\Modules\PowerShellGet\1.6.0\PSGet.Resource.psd1'
    help_info_uri:
      description:
        - The help info address of the module.
      type: str
      sample: 'https://go.microsoft.com/fwlink/?linkid=390823'
    icon_uri:
      description:
        - The address of the icon of the module.
      type: str
      sample: 'https://raw.githubusercontent.com/powershell/psscriptanalyzer/master/logo.png'
    license_uri:
      description:
        - The address of the license for the module.
      type: str
      sample: 'https://github.com/PowerShell/xPendingReboot/blob/master/LICENSE'
    project_uri:
      description:
        - The address of the module's project.
      type: str
      sample: 'https://github.com/psake/psake'
    repository_source_location:
      description:
        - The source location of the repository where the module was installed from.
      type: str
      sample: 'https://www.powershellgallery.com/api/v2'
    repository:
      description:
        - The PSRepository where the module was installed from.
        - This value is not historical. It depends on the PSRepositories that are registered now for the current user.
        - The C(repository_source_location) must match the current source location of a registered repository to get a repository name.
        - If there is no match, then this value will match C(repository_source_location).
      type: str
      sample: PSGallery
    release_notes:
      description:
        - The module's release notes. This is a free text field and no specific format should be assumed.
      type: str
      sample: |
        ## 1.4.6
        - Update `HelpInfoUri` to point to the latest content

        ## 1.4.5
        - Bug fix for deadlock when getting parameters in an event

        ## 1.4.4
        - Bug fix when installing modules from private feeds
    installed_date:
      description:
        - The date the module was installed.
      type: str
      sample: '2018-02-14T17:55:34.9620740-05:00'
    published_date:
      description:
        - The date the module was published.
      type: str
      sample: '2017-03-15T04:18:09.0000000'
    updated_date:
      description:
        - The date the module was last updated.
      type: str
      sample: '2019-12-31T09:20:02.0000000'
    log_pipeline_execution_details:
      description:
        - Determines whether pipeline execution detail events should be logged.
      type: bool
    module_list:
      description:
        - A list of modules packaged with this module.
        - This value is not often returned and the modules are not automatically processed.
      type: list
      elements: dict
      contains:
        name:
          description:
            - The name of the module.
            - This may also be a path to the module file.
          type: str
          sample: '.\WindowsUpdateLog.psm1'
        guid:
          description:
            - The GUID of the module.
          type: str
          sample: 82fdb72c-ecc5-4dfd-b9d5-83cf6eb9067f
        version:
          description:
            - The minimum version of the module.
          type: str
          sample: '2.0'
        maximum_version:
          description:
            - The maximum version of the module.
          type: str
          sample: '2.9'
        required_version:
          description:
            - The exact version of the module required.
          type: str
          sample: '3.1.4'
    nested_modules:
      description:
        - A list of modules nested with and loaded into the scope of this module.
        - This list contains full module objects, so each item can have all of the properties listed here, including C(nested_modules).
      type: list
      elements: dict
    required_modules:
      description:
        - A list of modules required by this module.
        - This list contains full module objects, so each item can have all of the properties listed here, including C(required_modules).
        - These module objects may not contain full information however, so you may see different results than if you had directly queried the module.
      type: list
      elements: dict
    required_assemblies:
      description:
        - A list of assemblies that the module requires.
        - The values may be a simple name or a full path.
      type: str
      sample:
        - Microsoft.Management.Infrastructure.CimCmdlets.dll
        - Microsoft.Management.Infrastructure.Dll
    package_management_provider:
      description:
        - If the module was installed from PowerShellGet, this is the package management provider used.
      type: str
      sample: NuGet
    power_shell_host_name:
      description:
        - The name of the PowerShell host that the module requires.
      type: str
      sample: Windows PowerShell ISE Host
    power_shell_host_version:
      description:
        - The version of the PowerShell host that the module requires.
      type: str
      sample: '1.1'
    power_shell_version:
      description:
        - The minimum version of PowerShell that the module requires.
      type: str
      sample: '5.1'
    prefix:
      description:
        - The default prefix applied to C(Verb-Noun) commands exported from the module, resulting in C(Verb-PrefixNoun) names.
      type: str
    private_data:
      description:
        - Arbitrary private data used by the module. This is typically defined in the module manifest.
        - This module limits the depth of the data returned for module types other than C(Script) and C(Manifest).
        - The C(PSData) is commonly supplied and provides metadata for PowerShellGet but those fields are surfaced in top-level properties as well.
      type: dict
      sample:
        PSData:
          LicenseUri: https://example.com/module/LICENSE
          ProjectUri: https://example.com/module/
          ReleaseNotes: |
            v2 - Fixed some bugs
            v1 - First release
          Tags:
            - networking
            - serialization
    root_module:
      description:
        - The root module as defined in the manifest.
        - This may be a module name, filename, or full path.
      type: str
      sample: WindowsErrorReporting.psm1
    scripts:
      description:
        - A list of scripts (C(.ps1) files) that run in the caller's session state when the module is imported.
        - This value comes from the C(ScriptsToProcess) field in the module's manifest.
      type: list
      sample:
        - PrepareEnvironment.ps1
        - InitializeData.ps1
    tags:
      description:
        - The tags defined in the module's C(PSData) metadata.
      type: list
      elements: str
      sample:
        - networking
        - serialization
        - git
        - dsc
'''
