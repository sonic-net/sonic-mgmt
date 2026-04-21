#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2020, Brian Scholer <@briantist>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

DOCUMENTATION = r'''
---
module: win_psrepository_copy
short_description: Copies registered PSRepositories to other user profiles
version_added: '1.3.0'
description:
  - Copies specified registered PSRepositories to other user profiles on the system.
  - Can include the C(Default) profile so that new users start with the selected repositories.
  - Can include special service accounts like the local SYSTEM user, LocalService, NetworkService.
options:
  source:
    description:
      - The full path to the source repositories XML file.
      - Defaults to the repositories registered to the current user.
    type: path
    default: '%LOCALAPPDATA%\Microsoft\Windows\PowerShell\PowerShellGet\PSRepositories.xml'
  name:
    description:
      - The names of repositories to copy.
      - Names are interpreted as wildcards.
    type: list
    elements: str
    default: ['*']
  exclude:
    description:
      - The names of repositories to exclude.
      - Names are interpreted as wildcards.
      - If a name matches both an include (I(name)) and I(exclude), it will be excluded.
    type: list
    elements: str
  profiles:
    description:
      - The names of user profiles to populate with repositories.
      - Names are interpreted as wildcards.
      - The C(Default) profile can also be matched.
      - The C(Public) and C(All Users) profiles cannot be targeted, as PSRepositories are not loaded from them.
    type: list
    elements: str
    default: ['*']
  exclude_profiles:
    description:
      - The names of user profiles to exclude.
      - If a profile matches both an include (I(profiles)) and I(exclude_profiles), it will be excluded.
      - By default, the service account profiles are excluded.
      - To explcitly exclude nothing, set I(exclude_profiles=[]).
    type: list
    elements: str
    default:
      - systemprofile
      - LocalService
      - NetworkService
  force:
    description:
      - If C(True), this deletes repositories that are not present in the source.
    type: bool
    default: False
    version_added: 2.4.0
notes:
  - Does not require the C(PowerShellGet) module or any other external dependencies.
  - User profiles are loaded from the registry. If a given path does not exist (like if the profile directory was deleted), it is silently skipped.
  - If setting service account profiles, you may need C(become=yes). See examples.
  - "When PowerShellGet first sets up a repositories file, it always adds C(PSGallery), however if this module creates a new repos file and your selected
    repositories don't include C(PSGallery), it won't be in your destination."
  - "The values searched in I(profiles) (and I(exclude_profiles)) are profile names, not necessarily user names. This can happen when the profile path is
    deliberately changed or when domain user names conflict with users from the local computer or another domain. In this case the second+ user may have the
    domain name or local computer name appended, like C(JoeUser.Contoso) vs. C(JoeUser).
    If you intend to filter user profiles, ensure your filters catch the right names."
  - "In the case of the service accounts, the specific profiles are C(systemprofile) (for the C(SYSTEM) user), and C(LocalService) or C(NetworkService)
    for those accounts respectively."
  - "Repositories with credentials (requiring authentication) or proxy information will copy, but the credentials and proxy details will not as that
    information is not stored with repository."
seealso:
  - module: community.windows.win_psrepository
  - module: community.windows.win_psrepository_info
author:
  - Brian Scholer (@briantist)
'''

EXAMPLES = r'''
- name: Copy the current user's PSRepositories to all non-service account profiles and Default profile
  community.windows.win_psrepository_copy:

- name: Copy the current user's PSRepositories to all profiles and Default profile
  community.windows.win_psrepository_copy:
    exclude_profiles: []

- name: Copy the current user's PSRepositories to all profiles beginning with A, B, or C
  community.windows.win_psrepository_copy:
    profiles:
      - 'A*'
      - 'B*'
      - 'C*'

- name: Copy the current user's PSRepositories to all profiles beginning B except Brian and Brianna
  community.windows.win_psrepository_copy:
    profiles: 'B*'
    exclude_profiles:
      - Brian
      - Brianna

- name: Copy a specific set of repositories to profiles beginning with 'svc' with exceptions
  community.windows.win_psrepository_copy:
    name:
      - CompanyRepo1
      - CompanyRepo2
      - PSGallery
    profiles: 'svc*'
    exclude_profiles: 'svc-restricted'

- name: Copy repos matching a pattern with exceptions
  community.windows.win_psrepository_copy:
    name: 'CompanyRepo*'
    exclude: 'CompanyRepo*-Beta'

- name: Copy repositories from a custom XML file on the target host
  community.windows.win_psrepository_copy:
    source: 'C:\data\CustomRepostories.xml'

### A sample workflow of seeding a system with a custom repository

# A playbook that does initial host setup or builds system images

- name: Register custom respository
  community.windows.win_psrepository:
    name: PrivateRepo
    source_location: https://example.com/nuget/feed/etc
    installation_policy: trusted

- name: Ensure all current and new users have this repository registered
  community.windows.win_psrepository_copy:
    name: PrivateRepo

# In another playbook, run by other users (who may have been created later)

- name: Install a module
  community.windows.win_psmodule:
    name: CompanyModule
    repository: PrivateRepo
    state: present
'''

RETURN = r'''
'''
