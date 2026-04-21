#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2014, Trond Hindenes <trond@hindenes.com>
# Copyright: (c) 2018, Ansible Project
# Copyright: (c) 2020, Chocolatey Software
# GNU General Public License v3.0+ (see LICENSE or https://www.gnu.org/licenses/gpl-3.0.txt)

# this is a windows documentation stub.  actual code lives in the .ps1
# file of the same name

ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = r'''
---
module: win_chocolatey
version_added: '0.1.9'
short_description: Manage packages using chocolatey
description:
- Manage packages using Chocolatey.
- If Chocolatey is missing from the system, the module will install it.
- If there are multiple installations of choco.exe in env:PATH, it will use the first found one
requirements:
- chocolatey >= 0.10.5 (will be upgraded if older)
options:
  allow_empty_checksums:
    description:
    - Allow empty checksums to be used for downloaded resource from non-secure
      locations.
    - Use M(chocolatey.chocolatey.win_chocolatey_feature) with the name C(allowEmptyChecksums) to
      control this option globally.
    type: bool
    default: false
    version_added: '0.2.2'
  allow_multiple:
    description:
    - This option is deprecated and will be removed in v2.0.0 of this collection.
      Chocolatey CLI has L(deprecated side-by-side installations, https://github.com/chocolatey/choco/issues/2787)
      as of its v1.2.0 release and plans to remove them in its v2.0.0 release.
    - Chocolatey CLI (choco) v2.0.0 and higher do not support this option.
      This module will return an error if this option is enabled and the
      installed version of Chocolatey CLI on the client is v2.0.0 or higher.
    - Allow the installation of multiple packages when I(version) is specified.
    - Having multiple packages at different versions can cause issues if the
      package doesn't support this. Use at your own risk.
    - The value of this parameter is ignored if I(state) is C(absent). Instead,
      this parameter is automatically configured to remove all versions if
      I(version) is not specified, and the specific version only if I(version)
      is specified.
    type: bool
    default: false
    version_added: '0.2.8'
  allow_prerelease:
    description:
    - Allow the installation of pre-release packages.
    - If I(state) is C(latest), the latest pre-release package will be
      installed.
    type: bool
    default: false
    version_added: '0.2.6'
  architecture:
    description:
    - Force Chocolatey to install the package of a specific process
      architecture.
    - When setting C(x86), will ensure Chocolatey installs the x86 package
      even when on an x64 bit OS.
    type: str
    choices: [ default, x86 ]
    default: default
    version_added: '0.2.7'
  bootstrap_script:
    description:
    - Specify the bootstrap script URL that can be used to install Chocolatey
      if it is not already present on the system.
    - Use this parameter when I(name) is C(chocolatey) to ensure that a
      custom bootstrap script is used.
    - If neither this parameter nor I(source) is set, the bootstrap script
      url will be C(https://community.chocolatey.org/install.ps1)
    - If this parameter is not set, and I(source) is set to a url, the
      bootstrap script url will be determined from that url instead.
    - This parameter only defines which bootstrap script is used to download
      and install Chocolatey. To define the URL to a specific Chocolatey
      nupkg to install, note that many bootstrap scripts respect the value
      of the C(chocolateyDownloadUrl) environment variable, which can be set
      for the task as well.
    type: str
    version_added: '1.3.0'
    aliases: [ install_ps1, bootstrap_ps1 ]
  bootstrap_tls_version:
    description:
    - Specify the TLS versions used when retrieving and invoking the I(bootstrap_script) to install
      Chocolatey if it is not already installed on the system.
    - Does not change the TLS versions used by Chocolatey itself after it has already been installed.
    - Specified TLS versions may be ignored or unused if the target TLS version is not available on
      the client.
    type: list
    elements: str
    choices: [ tls11, tls12, tls13 ]
    default: [ tls12, tls13 ]
    version_added: '1.4.0'
    aliases: [ bootstrap_tls_versions, tls_version, tls_versions ]
  checksum:
    description:
    - Override a package's checksums for files downloaded during installation.
    - If the checksum is not MD5, you will need to specify the I(checksum_type) as well.
    type: str
    version_added: '1.5.0'
  checksum_type:
    description:
    - Override a package's checksum type for files downloaded during install. Use in conjunction with I(checksum).
    type: str
    choices: [ md5, sha1, sha256, sha512 ]
    version_added: '1.5.0'
  checksum64:
    description:
    - Override a package's checksums for 64-bit files downloaded during installation.
    - If the checksum is not MD5, you will need to specify the I(checksum_type64) as well.
    type: str
    version_added: '1.5.0'
  checksum_type64:
    description:
    - Override a package's checksum type for files downloaded during install. Use in conjunction with I(checksum64).
    choices: [ md5, sha1, sha256, sha512 ]
    type: str
    version_added: '1.5.0'
  force:
    description:
    - Forces the install of a package, even if it already is installed.
    - Using I(force) will cause Ansible to always report that a change was
      made.
    type: bool
    default: false
  ignore_checksums:
    description:
    - Ignore the checksums provided by the package.
    - Use M(chocolatey.chocolatey.win_chocolatey_feature) with the name C(checksumFiles) to control
      this option globally.
    type: bool
    default: false
    version_added: '0.2.2'
  ignore_dependencies:
    description:
    - Ignore dependencies, only install/upgrade the package itself.
    type: bool
    default: false
    version_added: '0.2.1'
  remove_dependencies:
    description:
    - Remove a package's dependencies on uninstall.
    type: bool
    default: false
    version_added: '1.1.0'
  install_args:
    description:
    - These are arguments that are passed directly to the installer run by
      the Chocolatey package, for example MSI properties or command-line
      arguments for the specific native installer used by the package.
    - For parameters that need to be passed to the chocolateyInstall script
      for the Chocolatey package itself, use I(package_params).
    type: str
    version_added: '0.2.1'
  name:
    description:
    - Name of the package(s) to be installed.
    - Set to C(all) to run the action on all the installed packages.
    type: list
    elements: str
    required: true
  override_args:
    description:
    - Override arguments of native installer with arguments provided by user.
    - Should install arguments be used exclusively without appending
      to current package passed arguments.
    type: bool
    default: false
    version_added: '0.2.10'
  package_params:
    description:
    - Parameters to pass to the package's chocolateyInstall script.
    - These are parameters specific to the Chocolatey package and are generally
      documented by the package itself.
    - For parameters that should be passed directly to the underlying installer
      (for example, MSI installer properties and arguments), use I(install_args)
      instead.
    type: str
    version_added: '0.2.1'
    aliases: [ params ]
  choco_args:
    description:
    - Additional parameters to pass to choco.exe
    - These may be any additional parameters to pass through directly to
      Chocolatey, in addition to the arguments already specified via other
      parameters.
    - This may be used to pass licensed options to Chocolatey, for example
      C(--package-parameters-sensitive) or C(--install-directory).
    - Passing licensed options may result in them being ignored or causing
      errors if the targeted node is unlicensed or missing the
      chocolatey.extension package.
    type: list
    elements: str
    version_added: '1.2.0'
    aliases: [ licensed_args ]
  pinned:
    description:
    - Whether to pin the Chocolatey package or not.
    - If omitted then no checks on package pins are done.
    - Will pin/unpin the specific version if I(version) is set.
    - Will pin the latest version of a package if C(true), I(version) is not set
      and and no pin already exists.
    - Will unpin all versions of a package if C(no) and I(version) is not set.
    - This is ignored when C(state=absent).
    type: bool
    version_added: '0.2.8'
  proxy_url:
    description:
    - Proxy URL used to install chocolatey and the package.
    - Use M(chocolatey.chocolatey.win_chocolatey_config) with the name C(proxy) to control this
      option globally.
    type: str
    version_added: '0.2.4'
  proxy_username:
    description:
    - Proxy username used to install Chocolatey and the package.
    - Before Ansible 2.7, users with double quote characters C(") would need to
      be escaped with C(\) beforehand. This is no longer necessary.
    - Use M(chocolatey.chocolatey.win_chocolatey_config) with the name C(proxyUser) to control this
      option globally.
    type: str
    version_added: '0.2.4'
  proxy_password:
    description:
    - Proxy password used to install Chocolatey and the package.
    - This value is exposed as a command argument and any privileged account
      can see this value when the module is running Chocolatey, define the
      password on the global config level with M(chocolatey.chocolatey.win_chocolatey_config) with
      name C(proxyPassword) to avoid this.
    type: str
    version_added: '0.2.4'
  skip_scripts:
    description:
    - Do not run I(chocolateyInstall.ps1) or I(chocolateyUninstall.ps1) scripts
      when installing a package.
    type: bool
    default: false
    version_added: '0.2.4'
  source:
    description:
    - Specify the source to retrieve the package from.
    - Use M(chocolatey.chocolatey.win_chocolatey_source) to manage global sources.
    - This value can either be the URL to a Chocolatey feed, a path to a folder
      containing C(.nupkg) packages or the name of a source defined by
      M(chocolatey.chocolatey.win_chocolatey_source).
    - When Chocolatey is not yet installed, prefer using I(bootstrap_script)
      instead to determine where to pull the bootstrap script from.
    - This value may also be used when Chocolatey is not installed as the
      location of the install.ps1 script if I(bootstrap_script) is not set, and
      only supports URLs for this case.
      In this case, if the URL ends in ".ps1", it is used as-is. Otherwise,
      if the URL appears to contain a "/repository/" fragment, the module
      will attempt to append "/install.ps1" to find an install script. If
      neither of these checks pass, the module will strip off the URL path and
      try to find an "/install.ps1" from the root of the server.
    type: str
  source_username:
    description:
    - A username to use with I(source) when accessing a feed that requires
      authentication.
    - It is recommended you define the credentials on a source with
      M(chocolatey.chocolatey.win_chocolatey_source) instead of passing it per task.
    type: str
    version_added: '0.2.7'
  source_password:
    description:
    - The password for I(source_username).
    - This value is exposed as a command argument and any privileged account
      can see this value when the module is running Chocolatey, define the
      credentials with a source with M(chocolatey.chocolatey.win_chocolatey_source) to avoid this.
    type: str
    version_added: '0.2.7'
  state:
    description:
    - State of the package on the system.
    - When C(absent), will ensure the package is not installed.
    - When C(present), will ensure the package is installed.
    - When C(downgrade), will allow Chocolatey to downgrade a package if
      I(version) is older than the installed version.
    - When C(latest) or C(upgrade), will ensure the package is installed to the latest
      available version.
    - When C(reinstalled), will uninstall and reinstall the package.
    type: str
    choices: [ absent, downgrade, upgrade, latest, present, reinstalled ]
    default: present
  timeout:
    description:
    - The time (in seconds) to allow chocolatey to finish before timing out.
    type: int
    default: 2700
    version_added: '0.2.3'
    aliases: [ execution_timeout ]
  validate_certs:
    description:
    - Used when downloading the Chocolatey install script if Chocolatey is not
      already installed, this does not affect the Chocolatey package install
      process.
    - When C(no), no SSL certificates will be validated.
    - This should only be used on personally controlled sites using self-signed
      certificate.
    type: bool
    default: true
    version_added: '0.2.7'
  version:
    description:
    - Specific version of the package to be installed.
    - When I(state) is set to C(absent), will uninstall the specific version
      otherwise all versions of that package will be removed.
    - When I(state) is set to C(present) and the package is already installed
      at a version that does not match, this task fails.
    - If a different version of package is already installed, I(state) must be
      C(latest), C(upgrade), or C(downgrade), or I(force) must be set to C(true) to install
      the desired version.
    - Provide as a string (e.g. C('6.1')), otherwise it is considered to be
      a floating-point number and depending on the locale could become C(6,1),
      which will cause a failure.
    - If I(name) is set to C(chocolatey) and Chocolatey is not installed on the
      host, this will be the version of Chocolatey that is installed. You can
      also set the C(chocolateyVersion) environment var.
    type: str
notes:
- This module will install or upgrade Chocolatey when needed.
- When using verbosity 2 or less (C(-vv)) the C(stdout) output will be restricted.
  When using verbosity 4 (C(-vvvv)) the C(stdout) output will be more verbose.
  When using verbosity 5 (C(-vvvvv)) the C(stdout) output will include debug output.
- Some packages, like hotfixes or updates need an interactive user logon in
  order to install. You can use C(become) to achieve this, see
  :ref:`become_windows`.
  Even if you are connecting as local Administrator, using C(become) to
  become Administrator will give you an interactive user logon, see examples
  below.
- If C(become) is unavailable, use M(ansible.windows.win_hotfix) to install hotfixes instead
  of M(chocolatey.chocolatey.win_chocolatey) as M(ansible.windows.win_hotfix) avoids using C(wusa.exe) which cannot
  be run without C(become).
- From Chocolatey CLI 2.0.0 and above, the minimum .NET Framework version required
  was changed to .NET Framework 4.8.
  If this requirement is not met, and a 1.x version of Chocolatey CLI is not specified,
  then M(chocolatey.chocolatey.win_chocolatey) will not attempt to install Chocolatey CLI.
  See the examples section below for one method of meeting the .NET Framework 4.8
  requirement and also refer to the L(Chocolatey documentation,https://docs.chocolatey.org/en-us/guides/upgrading-to-chocolatey-v2-v6)
  for more information about Chocolatey CLI 2.0.0.
seealso:
- module: chocolatey.chocolatey.win_chocolatey_config
- module: chocolatey.chocolatey.win_chocolatey_facts
- module: chocolatey.chocolatey.win_chocolatey_feature
- module: chocolatey.chocolatey.win_chocolatey_source
- module: ansible.windows.win_feature
- module: ansible.windows.win_hotfix
  description: Use when C(become) is unavailable, to avoid using C(wusa.exe).
- module: ansible.windows.win_package
- module: ansible.windows.win_updates
- name: Chocolatey website
  description: More information about the Chocolatey tool.
  link: http://chocolatey.org/
- name: Chocolatey packages
  description: An overview of the available Chocolatey packages.
  link: http://chocolatey.org/packages
- ref: become_windows
  description: Some packages, like hotfixes or updates need an interactive user logon
    in order to install. You can use C(become) to achieve this.
author:
- Trond Hindenes (@trondhindenes)
- Peter Mounce (@petemounce)
- Pepe Barbe (@elventear)
- Adam Keech (@smadam813)
- Pierre Templier (@ptemplier)
- Jordan Borean (@jborean93)
- Rain Sallow (@vexx32)
- Josh King (@windos)
'''

# TODO:
# * Better parsing when a package has dependencies - currently fails
# * Time each item that is run
# * Support 'changed' with gems - would require shelling out to `gem list` first and parsing, kinda defeating the point of using chocolatey.
# * Version provided not as string might be translated to 6,6 depending on Locale (results in errors)

EXAMPLES = r'''
- name: Install git
  win_chocolatey:
    name: git
    state: present

- name: Upgrade installed packages
  win_chocolatey:
    name: all
    state: latest

- name: Install notepadplusplus version 6.6
  win_chocolatey:
    name: notepadplusplus
    version: '6.6'

- name: Install notepadplusplus 32 bit version
  win_chocolatey:
    name: notepadplusplus
    architecture: x86

- name: Install git from specified repository
  win_chocolatey:
    name: git
    source: https://someserver/api/v2/

- name: Install git from a pre configured source (win_chocolatey_source)
  win_chocolatey:
    name: git
    source: internal_repo

- name: Ensure Chocolatey itself is installed, using community repo for the bootstrap
  win_chocolatey:
    name: chocolatey

- name: Ensure Chocolatey itself is installed, bootstrapping with a specific nupkg url
  win_chocolatey:
    name: chocolatey
  environment:
    chocolateyDownloadUrl: "https://internal-web-server/files/chocolatey.1.1.0.nupkg"

- name: Ensure Chocolatey itself is installed and use internal repo as source for bootstrap script
  win_chocolatey:
    name: chocolatey
    source: http://someserver/chocolatey

- name: Ensure Chocolatey itself is installed, using a specific bootstrap script
  win_chocolatey:
    name: chocolatey
    bootstrap_script: https://internal-web-server/files/custom-chocolatey-install.ps1

- name: Ensure Chocolatey itself is installed, using a specific bootstrap script and target nupkg
  win_chocolatey:
    name: chocolatey
    bootstrap_script: https://internal-web-server/files/custom-chocolatey-install.ps1
  environment:
    chocolateyDownloadUrl: "https://internal-web-server/files/chocolatey.1.1.0.nupkg"

- name: Uninstall git
  win_chocolatey:
    name: git
    state: absent

- name: Install multiple packages
  win_chocolatey:
    name:
    - procexp
    - putty
    - windirstat
    state: present

- name: Install multiple packages sequentially
  win_chocolatey:
    name: '{{ item }}'
    state: present
  loop:
  - procexp
  - putty
  - windirstat

- name: Uninstall multiple packages
  win_chocolatey:
    name:
    - procexp
    - putty
    - windirstat
    state: absent

- name: Uninstall a package and dependencies
  win_chocolatey:
    name: audacity-lame
    remove_dependencies: true
    state: absent

- name: Install curl using proxy
  win_chocolatey:
    name: curl
    proxy_url: http://proxy-server:8080/
    proxy_username: joe
    proxy_password: p@ssw0rd

- name: Install a package that requires 'become'
  win_chocolatey:
    name: officepro2013
  become: true
  become_user: Administrator
  become_method: runas

- name: install and pin Notepad++ at 7.6.3
  win_chocolatey:
    name: notepadplusplus
    version: 7.6.3
    pinned: true
    state: present

- name: remove all pins for Notepad++ on all versions
  win_chocolatey:
    name: notepadplusplus
    pinned: false
    state: present

- name: install a package with options that require licensed edition
  win_chocolatey:
    name: foo
    state: present
    choco_args:
    - --skip-download-cache
    - --package-parameters-sensitive
    - '/Password=SecretPassword'

- name: ensure .NET Framework 4.8 requirement is satisfied for Chocolatey CLI v2.0.0+
  block:
  - name: install Chocolatey CLI v1.4.0
    win_chocolatey:
      name: 'chocolatey'
      state: present
      version: '1.4.0'

  - name: install Microsoft .NET Framework 4.8
    win_chocolatey:
      name: 'netfx-4.8'
      state: present

  - name: Reboot the host to complete .NET Framework 4.8 install
    ansible.windows.win_reboot:

  - name: install Chocolatey CLI v2.0.0+ when .NET Framework 4.8 dependency is met
    win_chocolatey:
      name: 'chocolatey'
      state: latest
'''

RETURN = r'''
command:
  description: The full command used in the chocolatey task.
  returned: changed
  type: str
  sample: choco.exe install -r --no-progress -y sysinternals --timeout 2700 --failonunfound
rc:
  description: The return code from the chocolatey task.
  returned: always
  type: int
  sample: 0
stdout:
  description: The stdout from the chocolatey task. The verbosity level of the
    messages are affected by Ansible verbosity setting, see notes for more
    details.
  returned: changed
  type: str
  sample: Chocolatey upgraded 1/1 packages.
'''
