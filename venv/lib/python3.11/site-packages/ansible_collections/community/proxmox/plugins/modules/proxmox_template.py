#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright Ansible Project
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import absolute_import, division, print_function
__metaclass__ = type


DOCUMENTATION = r"""
module: proxmox_template
short_description: Management of OS templates in Proxmox VE cluster
description:
  - Allows you to upload/delete templates in Proxmox VE cluster.
attributes:
  check_mode:
    support: none
  diff_mode:
    support: none
options:
  node:
    description:
      - Proxmox VE node on which to operate.
    type: str
  src:
    description:
      - Path to uploaded file.
      - Exactly one of O(src) or O(url) is required for O(state=present).
    type: path
  url:
    description:
      - URL to file to download.
      - Exactly one of O(src) or O(url) is required for O(state=present).
    type: str
  template:
    description:
      - The template name.
      - Required for O(state=absent) to delete a template.
      - Required for O(state=present) to download an appliance container template (pveam).
    type: str
  content_type:
    description:
      - Content type of the template.
      - Valid values are V(vztmpl) for LXC container templates, V(iso) for ISO disc images, and V(import) for harddisk images and Open Virtual Appliances (OVA).
    type: str
    default: 'vztmpl'
    choices: ['vztmpl', 'import', 'iso']
  storage:
    description:
      - Target storage.
    type: str
    default: 'local'
  timeout:
    description:
      - Timeout for operations.
    type: int
    default: 30
  force:
    description:
      - It can only be used with O(state=present), existing template will be overwritten.
    type: bool
    default: false
  state:
    description:
      - Indicate desired state of the template.
    type: str
    choices: ['present', 'absent']
    default: present
  checksum_algorithm:
    description:
      - Algorithm used to verify the checksum.
      - If specified, O(checksum) must also be specified.
    type: str
    choices: ['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']
  checksum:
    description:
      - The checksum to validate against.
      - Checksums are often provided by software distributors to verify that a download is not corrupted.
      - Checksums can usually be found on the distributors download page in the form of a file or string.
      - If specified, O(checksum_algorithm) must also be specified.
    type: str
notes:
  - Requires C(proxmoxer) and C(requests) modules on host. Those modules can be installed with M(ansible.builtin.pip).
  - Requires C(requests_toolbelt) to upload files larger than 256 MB.
author: Sergei Antipov (@UnderGreen)
extends_documentation_fragment:
  - community.proxmox.proxmox.actiongroup_proxmox
  - community.proxmox.proxmox.documentation
  - community.proxmox.attributes
"""

EXAMPLES = r"""
---
- name: Upload new openvz template with minimal options
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    src: ~/ubuntu-14.04-x86_64.tar.gz

- name: Pull new openvz template with minimal options
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    url: https://ubuntu-mirror/ubuntu-14.04-x86_64.tar.gz

- name: >
    Upload new openvz template with minimal options use environment
    PROXMOX_PASSWORD variable(you should export it before)
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_host: node1
    src: ~/ubuntu-14.04-x86_64.tar.gz

- name: Upload new openvz template with all options and force overwrite
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    storage: local
    content_type: vztmpl
    src: ~/ubuntu-14.04-x86_64.tar.gz
    force: true

- name: Pull new openvz template with all options and force overwrite
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    storage: local
    content_type: vztmpl
    url: https://ubuntu-mirror/ubuntu-14.04-x86_64.tar.gz
    force: true

- name: Delete template with minimal options
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    template: ubuntu-14.04-x86_64.tar.gz
    state: absent

- name: Download proxmox appliance container template
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    storage: local
    content_type: vztmpl
    template: ubuntu-20.04-standard_20.04-1_amd64.tar.gz

- name: Download and verify a template's checksum
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    url: ubuntu-20.04-standard_20.04-1_amd64.tar.gz
    checksum_algorithm: sha256
    checksum: 65d860160bdc9b98abf72407e14ca40b609417de7939897d3b58d55787aaef69

- name: Upload new disk image template with minimal options
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    content_type: import
    src: debian-13-genericcloud-amd64.qcow2

- name: Upload new ISO with minimal options
  community.proxmox.proxmox_template:
    node: uk-mc02
    api_user: root@pam
    api_password: 1q2w3e
    api_host: node1
    content_type: iso
    src: proxmox.iso
"""

import os
import time
import traceback
from urllib.parse import urlparse, urlencode

from ansible.module_utils.basic import AnsibleModule, missing_required_lib
from ansible_collections.community.proxmox.plugins.module_utils.proxmox import proxmox_auth_argument_spec, ProxmoxAnsible

REQUESTS_TOOLBELT_ERR = None
try:
    # requests_toolbelt is used internally by proxmoxer module
    import requests_toolbelt  # noqa: F401, pylint: disable=unused-import
    HAS_REQUESTS_TOOLBELT = True
except ImportError:
    HAS_REQUESTS_TOOLBELT = False
    REQUESTS_TOOLBELT_ERR = traceback.format_exc()


class ProxmoxTemplateAnsible(ProxmoxAnsible):
    def has_template(self, node, storage, content_type, template):
        volid = '%s:%s/%s' % (storage, content_type, template)
        try:
            return any(tmpl['volid'] == volid for tmpl in self.proxmox_api.nodes(node).storage(storage).content.get())
        except Exception as e:
            self.module.fail_json(msg="Failed to retrieve template '%s': %s" % (volid, e))

    def task_status(self, node, taskid, timeout):
        """
        Check the task status and wait until the task is completed or the timeout is reached.
        """
        while timeout:
            if self.api_task_ok(node, taskid):
                return True
            elif self.api_task_failed(node, taskid):
                self.module.fail_json(msg="Task error: %s" % self.proxmox_api.nodes(node).tasks(taskid).status.get()['exitstatus'])
            timeout = timeout - 1
            if timeout == 0:
                self.module.fail_json(msg='Reached timeout while waiting for uploading/downloading template. Last line in task before timeout: %s' %
                                      self.proxmox_api.nodes(node).tasks(taskid).log.get()[:1])

            time.sleep(1)
        return False

    def upload_template(self, node, storage, content_type, realpath, timeout):
        stats = os.stat(realpath)
        if stats.st_size > 268435456 and not HAS_REQUESTS_TOOLBELT:
            self.module.fail_json(msg=missing_required_lib('requests_toolbelt', reason='to upload files larger than 256MB'),
                                  exception=REQUESTS_TOOLBELT_ERR)

        try:
            taskid = self.proxmox_api.nodes(node).storage(storage).upload.post(content=content_type, filename=open(realpath, 'rb'))
            return self.task_status(node, taskid, timeout)
        except Exception as e:
            self.module.fail_json(msg="Uploading template %s failed with error: %s" % (realpath, e))

    def fetch_template(self, node, storage, content_type, url, timeout, template):
        """Fetch a template from a web url source using the proxmox download-url endpoint
        """
        try:
            taskid = self.proxmox_api.nodes(node).storage(storage)("download-url").post(
                url=url, content=content_type, filename=template
            )
            return self.task_status(node, taskid, timeout)
        except Exception as e:
            self.module.fail_json(msg="Fetching template from url %s failed with error: %s" % (url, e))

    def download_template(self, node, storage, template, timeout):
        try:
            taskid = self.proxmox_api.nodes(node).aplinfo.post(storage=storage, template=template)
            return self.task_status(node, taskid, timeout)
        except Exception as e:
            self.module.fail_json(msg="Downloading template %s failed with error: %s" % (template, e))

    def delete_template(self, node, storage, content_type, template, timeout):
        volid = '%s:%s/%s' % (storage, content_type, template)
        self.proxmox_api.nodes(node).storage(storage).content.delete(volid)
        while timeout:
            if not self.has_template(node, storage, content_type, template):
                return True
            timeout = timeout - 1
            if timeout == 0:
                self.module.fail_json(msg='Reached timeout while waiting for deleting template.')

            time.sleep(1)
        return False

    def fetch_and_verify(self, node, storage, url, content_type, timeout, checksum, checksum_algorithm, template):
        """ Fetch a template from a web url, then verify it using a checksum.
        """
        data = {
            'url': url,
            'content': content_type,
            'filename': template,
            'checksum': checksum,
            'checksum-algorithm': checksum_algorithm}
        try:
            taskid = self.proxmox_api.nodes(node).storage(storage).post("download-url?{}".format(urlencode(data)))
            return self.task_status(node, taskid, timeout)
        except Exception as e:
            self.module.fail_json(msg="Checksum mismatch: %s" % (e))


def main():
    module_args = proxmox_auth_argument_spec()
    template_args = dict(
        node=dict(),
        src=dict(type='path'),
        url=dict(),
        template=dict(),
        content_type=dict(default='vztmpl', choices=['vztmpl', 'iso', 'import']),
        storage=dict(default='local'),
        timeout=dict(type='int', default=30),
        force=dict(type='bool', default=False),
        state=dict(default='present', choices=['present', 'absent']),
        checksum_algorithm=dict(choices=['md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512']),
        checksum=dict(type='str'),
    )
    module_args.update(template_args)

    module = AnsibleModule(
        argument_spec=module_args,
        required_together=[('api_token_id', 'api_token_secret'), ('checksum', 'checksum_algorithm')],
        required_one_of=[('api_password', 'api_token_id')],
        required_if=[('state', 'absent', ['template'])],
        mutually_exclusive=[("src", "url")],
    )

    proxmox = ProxmoxTemplateAnsible(module)

    state = module.params['state']
    node = module.params['node']
    storage = module.params['storage']
    timeout = module.params['timeout']
    checksum = module.params['checksum']
    checksum_algorithm = module.params['checksum_algorithm']

    if state == 'present':
        content_type = module.params['content_type']
        src = module.params['src']
        url = module.params['url']
        template = module.params['template']

        # download appliance template
        if content_type == 'vztmpl' and not (src or url):
            if not template:
                module.fail_json(msg='template param for downloading appliance template is mandatory')

            if proxmox.has_template(node, storage, content_type, template) and not module.params['force']:
                module.exit_json(changed=False, msg='template with volid=%s:%s/%s already exists' % (storage, content_type, template))

            if proxmox.download_template(node, storage, template, timeout):
                module.exit_json(changed=True, msg='template with volid=%s:%s/%s downloaded' % (storage, content_type, template))

        if not src and not url:
            module.fail_json(msg='src or url param for uploading template file is mandatory')
        elif not url:
            template = os.path.basename(src)
            if proxmox.has_template(node, storage, content_type, template) and not module.params['force']:
                module.exit_json(changed=False, msg='template with volid=%s:%s/%s already exists' % (storage, content_type, template))
            elif not (os.path.exists(src) and os.path.isfile(src)):
                module.fail_json(msg='template file on path %s not exists' % src)

            if proxmox.upload_template(node, storage, content_type, src, timeout):
                module.exit_json(changed=True, msg='template with volid=%s:%s/%s uploaded' % (storage, content_type, template))
        elif not src:
            if not template:
                template = os.path.basename(urlparse(url).path)

            if proxmox.has_template(node, storage, content_type, template):
                if not module.params['force']:
                    module.exit_json(changed=False, msg='template with volid=%s:%s/%s already exists' % (storage, content_type, template))
                elif not proxmox.delete_template(node, storage, content_type, template, timeout):
                    module.fail_json(changed=False, msg='failed to delete template with volid=%s:%s/%s' % (storage, content_type, template))

            if checksum:
                if proxmox.fetch_and_verify(node, storage, url, content_type, timeout, checksum, checksum_algorithm, template):
                    module.exit_json(changed=True, msg="Checksum verified, template with volid=%s:%s/%s uploaded" % (storage, content_type, template))
            if proxmox.fetch_template(node, storage, content_type, url, timeout, template):
                module.exit_json(changed=True, msg='template with volid=%s:%s/%s uploaded' % (storage, content_type, template))

    elif state == 'absent':
        try:
            content_type = module.params['content_type']
            template = module.params['template']

            if not proxmox.has_template(node, storage, content_type, template):
                module.exit_json(changed=False, msg='template with volid=%s:%s/%s is already deleted' % (storage, content_type, template))

            if proxmox.delete_template(node, storage, content_type, template, timeout):
                module.exit_json(changed=True, msg='template with volid=%s:%s/%s deleted' % (storage, content_type, template))
        except Exception as e:
            module.fail_json(msg="deleting of template %s failed with exception: %s" % (template, e))


if __name__ == '__main__':
    main()
