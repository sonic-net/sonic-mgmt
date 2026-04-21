#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2016, Eric D Helms <ericdhelms@gmail.com>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = '''
---
module: repository
version_added: 1.0.0
short_description: Manage Repositories
description:
  - Create and manage repositories
author: "Eric D Helms (@ehelms)"
notes:
  - You can configure certain aspects of existing Red Hat Repositories (like I(download_policy)) using this module,
    but you can't create (enable) or delete (disable) them.
  - If you want to enable or disable Red Hat Repositories available through your subscription,
    please use the M(theforeman.foreman.repository_set) module instead.
options:
  name:
    description:
      - Name of the repository
    required: true
    type: str
  description:
    description:
      - Description of the repository
    required: false
    type: str
  product:
    description:
      - Product to which the repository lives in
    required: true
    type: str
  label:
    description:
      - label of the repository
    type: str
  content_type:
    description:
      - The content type of the repository
    required: true
    choices:
      - deb
      - docker
      - file
      - ostree
      - puppet
      - yum
      - ansible_collection
      - python
    type: str
  url:
    description:
      - Repository URL to sync from
    required: false
    type: str
  ignore_global_proxy:
    description:
      - Whether content sync should use or ignore the global http proxy setting
      - This is deprecated with Katello 3.13
      - It has been superseeded by I(http_proxy_policy)
    required: false
    type: bool
  http_proxy_policy:
    description:
      - Which proxy to use for content synching
    choices:
      - global_default_http_proxy
      - none
      - use_selected_http_proxy
    required: false
    type: str
  http_proxy:
    description:
      - Name of the http proxy to use for content synching
      - Should be combined with I(http_proxy_policy='use_selected_http_proxy')
    required: false
    type: str
  gpg_key:
    description:
    - Repository GPG key
    required: false
    type: str
  ssl_ca_cert:
    description:
    - Repository SSL CA certificate
    required: false
    type: str
  ssl_client_cert:
    description:
    - Repository SSL client certificate
    required: false
    type: str
  ssl_client_key:
    description:
    - Repository SSL client private key
    required: false
    type: str
  download_concurrency:
    description:
      - download concurrency for sync from upstream
      - as the API does not return this value, this will break idempotence for this module
    required: false
    type: int
    version_added: 3.0.0
  download_policy:
    description:
      - The download policy for sync from upstream.
      - The download policy C(background) is deprecated and not available since Katello 4.3.
    choices:
      - background
      - immediate
      - on_demand
    required: false
    type: str
  mirror_on_sync:
    description:
      - toggle "mirror on sync" where the state of the repository mirrors that of the upstream repository at sync time
      - This is deprecated with Katello 4.3
      - It has been superseeded by I(mirroring_policy=mirror_content_only)
    type: bool
    required: false
  mirroring_policy:
    description:
      - Policy to set for mirroring content
      - Supported since Katello 4.3
    type: str
    choices:
      - additive
      - mirror_content_only
      - mirror_complete
  verify_ssl_on_sync:
    description:
      - verify the upstream certifcates are signed by a trusted CA
    type: bool
    required: false
  upstream_username:
    description:
      - username to access upstream repository
    type: str
  upstream_password:
    description:
      - Password to access upstream repository.
      - When this parameter is set, the module will not be idempotent.
    type: str
  docker_upstream_name:
    description:
      - name of the upstream docker repository
      - only available for I(content_type=docker)
    type: str
  docker_tags_whitelist:
    description:
      - list of tags to sync for Container Image repository
      - only available for I(content_type=docker)
      - Deprecated since Katello 4.4
    type: list
    elements: str
  deb_releases:
    description:
      - comma separated list of releases to be synced from deb-archive
      - only available for I(content_type=deb)
    type: str
  deb_components:
    description:
      - comma separated list of repo components to be synced from deb-archive
      - only available for I(content_type=deb)
    type: str
  deb_architectures:
    description:
      - comma separated list of architectures to be synced from deb-archive
      - only available for I(content_type=deb)
    type: str
  deb_errata_url:
    description:
      - URL to sync Debian or Ubuntu errata information from
      - only available on Orcharhino
      - only available for I(content_type=deb)
    type: str
    required: false
  unprotected:
    description:
      - publish the repository via HTTP
    type: bool
    required: false
  checksum_type:
    description:
      - Checksum of the repository
    type: str
    required: false
    choices:
      - sha1
      - sha256
  ignorable_content:
    description:
      - List of content units to ignore while syncing a yum repository.
      - Must be subset of rpm,drpm,srpm,distribution,erratum.
    type: list
    elements: str
    required: false
  ansible_collection_requirements:
    description:
      - Contents of requirement yaml file to sync from URL
    type: str
    required: false
  auto_enabled:
    description:
      - repositories will be automatically enabled on a registered host subscribed to this product
    type: bool
    required: false
  os_versions:
    description:
      - Identifies whether the repository should be disabled on a client with a non-matching OS version.
      - A maximum of one OS version can be selected.
      - Set to C([]) to disable filtering again.
    type: list
    elements: str
    required: false
    choices:
      - rhel-6
      - rhel-7
      - rhel-8
      - rhel-9
      - rhel-10
  arch:
    description:
      - Architecture of content in the repository
      - Set to C(noarch) to disable the architecture restriction again.
    type: str
    required: false
  include_tags:
    description:
      - List of tags to sync for a container image repository.
    type: list
    elements: str
    required: false
    version_added: 3.7.0
  exclude_tags:
    description:
      - List of tags to exclude when syncing a container image repository.
    type: list
    elements: str
    required: false
    version_added: 3.7.0
  retain_package_versions_count:
    description:
      - The maximum number of versions of each package to keep.
    type: int
    required: false
    version_added: 5.4.0
  metadata_expire:
    description:
      - Set the metadata expiration time (in seconds) for a yum repository.
    type: int
    required: false
    version_added: 5.4.0
  ansible_collection_auth_token:
    description:
      - The token key to use for authentication.
    type: str
    required: false
    version_added: 5.5.0
  ansible_collection_auth_url:
    description:
      - The URL to receive a session token from, e.g. used with Automation Hub.
    type: str
    required: false
    version_added: 5.5.0
  depth:
    description:
      - An option to specify how many ostree commits to traverse.
    type: int
    required: false
    version_added: 5.5.0
  exclude_refs:
    description:
      - List of tags to exclude during an ostree sync.
      - The wildcards C(*), C(?) are recognized.
      - C(exclude_refs) is evaluated after C(include_refs).
    type: list
    elements: str
    required: false
    version_added: 5.5.0
  excludes:
    description:
      - Python packages to exclude from the upstream URL.
      - "You may also specify versions, for example: C(django~=2.0)."
    type: list
    elements: str
    required: false
    version_added: 5.5.0
  include_refs:
    description:
      - List of refs to include during an ostree sync.
      - The wildcards C(*), C(?) are recognized.
    type: list
    elements: str
    required: false
    version_added: 5.5.0
  includes:
    description:
      - Python packages to include from the upstream URL,
      - "You may also specify versions, for example: C(django~=2.0)."
      - Leave empty to include every package.
    type: list
    elements: str
    required: false
    version_added: 5.5.0
  keep_latest_packages:
    description:
      - The amount of latest versions of a package to keep on sync, includes pre-releases if synced.
      - Defaults to keep all versions.
    type: int
    required: false
    version_added: 5.5.0
  package_types:
    description:
      - Package types to sync for Python content, separated by comma. FIXME
      - Leave empty to get every package type.
    choices:
      - bdist_dmg
      - bdist_dumb
      - bdist_egg
      - bdist_msi
      - bdist_rpm
      - bdist_wheel
      - bdist_wininst
      - sdist
    type: list
    elements: str
    required: false
    version_added: 5.5.0
  upstream_authentication_token:
    description:
      - Upstream authentication token string for yum repositories.
    type: str
    required: false
    version_added: 5.5.0

extends_documentation_fragment:
  - theforeman.foreman.foreman
  - theforeman.foreman.foreman.entity_state_with_defaults
  - theforeman.foreman.foreman.organization
'''

EXAMPLES = '''
- name: "Create repository"
  theforeman.foreman.repository:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "My repository"
    state: present
    content_type: "yum"
    product: "My Product"
    organization: "Default Organization"
    url: "http://yum.theforeman.org/plugins/latest/el7/x86_64/"
    mirror_on_sync: true
    download_policy: immediate

- name: "Create repository with content credentials"
  theforeman.foreman.repository:
    username: "admin"
    password: "changeme"
    server_url: "https://foreman.example.com"
    name: "My repository 2"
    state: present
    content_type: "yum"
    product: "My Product"
    organization: "Default Organization"
    url: "http://yum.theforeman.org/releases/latest/el7/x86_64/"
    download_policy: on_demand
    mirror_on_sync: true
    gpg_key: RPM-GPG-KEY-my-product2
'''

RETURN = '''
entity:
  description: Final state of the affected entities grouped by their type.
  returned: success
  type: dict
  contains:
    repositories:
      description: List of repositories.
      type: list
      elements: dict
'''


from ansible_collections.theforeman.foreman.plugins.module_utils.foreman_helper import KatelloEntityAnsibleModule


class KatelloRepositoryModule(KatelloEntityAnsibleModule):
    pass


def main():
    module = KatelloRepositoryModule(
        foreman_spec=dict(
            product=dict(type='entity', scope=['organization'], required=True),
            label=dict(),
            name=dict(required=True),
            content_type=dict(required=True, choices=['docker', 'ostree', 'yum', 'puppet', 'file', 'deb', 'ansible_collection', 'python']),
            url=dict(),
            ignore_global_proxy=dict(type='bool'),
            http_proxy_policy=dict(choices=['global_default_http_proxy', 'none', 'use_selected_http_proxy']),
            http_proxy=dict(type='entity'),
            gpg_key=dict(type='entity', resource_type='content_credentials', scope=['organization'], no_log=False),
            ssl_ca_cert=dict(type='entity', resource_type='content_credentials', scope=['organization']),
            ssl_client_cert=dict(type='entity', resource_type='content_credentials', scope=['organization']),
            ssl_client_key=dict(type='entity', resource_type='content_credentials', scope=['organization'], no_log=False),
            download_policy=dict(choices=['background', 'immediate', 'on_demand']),
            download_concurrency=dict(type='int'),
            mirror_on_sync=dict(type='bool'),
            mirroring_policy=dict(type='str', choices=['additive', 'mirror_content_only', 'mirror_complete']),
            verify_ssl_on_sync=dict(type='bool'),
            upstream_username=dict(),
            upstream_password=dict(no_log=True),
            docker_upstream_name=dict(),
            docker_tags_whitelist=dict(type='list', elements='str'),
            deb_errata_url=dict(),
            deb_releases=dict(),
            deb_components=dict(),
            deb_architectures=dict(),
            description=dict(),
            unprotected=dict(type='bool'),
            checksum_type=dict(choices=['sha1', 'sha256']),
            ignorable_content=dict(type='list', elements='str'),
            ansible_collection_requirements=dict(),
            auto_enabled=dict(type='bool'),
            os_versions=dict(type='list', elements='str', choices=['rhel-6', 'rhel-7', 'rhel-8', 'rhel-9', 'rhel-10']),
            arch=dict(),
            include_tags=dict(type='list', elements='str'),
            exclude_tags=dict(type='list', elements='str'),
            retain_package_versions_count=dict(type='int'),
            metadata_expire=dict(type="int"),
            ansible_collection_auth_token=dict(no_log=True),
            ansible_collection_auth_url=dict(),
            depth=dict(type='int'),
            exclude_refs=dict(type='list', elements='str'),
            excludes=dict(type='list', elements='str'),
            include_refs=dict(type='list', elements='str'),
            includes=dict(type='list', elements='str'),
            keep_latest_packages=dict(type='int'),
            package_types=dict(type='list', elements='str',
                               choices=['bdist_dmg', 'bdist_dumb', 'bdist_egg', 'bdist_msi', 'bdist_rpm', 'bdist_wheel', 'bdist_wininst', 'sdist']),
            upstream_authentication_token=dict(no_log=True),
        ),
        mutually_exclusive=[
            ['mirror_on_sync', 'mirroring_policy']
        ],
        argument_spec=dict(
            state=dict(default='present', choices=['present_with_defaults', 'present', 'absent']),
        ),
        entity_opts={'scope': ['product']},
    )

    # KatelloEntityAnsibleModule automatically adds organization to the entity scope
    # but repositories are scoped by product (and these are org scoped)
    module.foreman_spec['entity']['scope'].remove('organization')

    if module.foreman_params['content_type'] != 'docker':
        invalid_list = [key for key in ['docker_upstream_name', 'docker_tags_whitelist', 'include_tags', 'exclude_tags'] if key in module.foreman_params]
        if invalid_list:
            module.fail_json(msg="({0}) can only be used with content_type 'docker'".format(",".join(invalid_list)))

    if module.foreman_params['content_type'] != 'deb':
        invalid_list = [key for key in ['deb_errata_url', 'deb_releases', 'deb_components', 'deb_architectures'] if key in module.foreman_params]
        if invalid_list:
            module.fail_json(msg="({0}) can only be used with content_type 'deb'".format(",".join(invalid_list)))

    if module.foreman_params['content_type'] != 'ansible_collection':
        invalid_list = [
            key for key in ['ansible_collection_requirements', 'ansible_collection_auth_token', 'ansible_collection_auth_url'] if key in module.foreman_params
        ]
        if invalid_list:
            module.fail_json(msg="({0}) can only be used with content_type 'ansible_collection'".format(",".join(invalid_list)))

    if module.foreman_params['content_type'] != 'yum':
        invalid_list = [key for key in ['ignorable_content', 'os_versions', 'metadata_expire', 'upstream_authentication_token'] if key in module.foreman_params]
        if invalid_list:
            module.fail_json(msg="({0}) can only be used with content_type 'yum'".format(",".join(invalid_list)))

    if module.foreman_params['content_type'] != 'ostree':
        invalid_list = [key for key in ['depth', 'exclude_refs', 'include_refs'] if key in module.foreman_params]
        if invalid_list:
            module.fail_json(msg="({0}) can only be used with content_type 'ostree'".format(",".join(invalid_list)))

    if module.foreman_params['content_type'] != 'python':
        invalid_list = [key for key in ['excludes', 'includes', 'package_types', 'keep_latest_packages'] if key in module.foreman_params]
        if invalid_list:
            module.fail_json(msg="({0}) can only be used with content_type 'python'".format(",".join(invalid_list)))

    if 'ignore_global_proxy' in module.foreman_params and 'http_proxy_policy' not in module.foreman_params:
        module.foreman_params['http_proxy_policy'] = 'none' if module.foreman_params['ignore_global_proxy'] else 'global_default_http_proxy'

    with module.api_connection():
        if not module.desired_absent:
            module.auto_lookup_entities()
            module.foreman_params.pop('organization')
        module.run()


if __name__ == '__main__':
    main()
