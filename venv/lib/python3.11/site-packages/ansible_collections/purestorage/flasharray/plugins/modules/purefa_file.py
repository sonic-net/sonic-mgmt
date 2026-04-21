#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2020, Simon Dodsley (simon@purestorage.com)
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

ANSIBLE_METADATA = {
    "metadata_version": "1.1",
    "status": ["preview"],
    "supported_by": "community",
}

DOCUMENTATION = r"""
---
module: purefa_file
version_added: '1.22.0'
short_description: Manage FlashArray File Copies
description:
- Copy FlashArray File from one filesystem to another
author:
- Pure Storage Ansible Team (@sdodsley) <pure-ansible-team@purestorage.com>
options:
  source_file:
    description:
    - Name of the file to copy
    - Include full path from the perspective of the source managed directory
    type: str
    required: true
  source_dir:
    description:
    - Name of the source managed directory containing the source file to be copied
    type: str
    required: true
  target_file:
    description:
    - Name of the file to copy to
    - Include full path from the perspective of the target managed directory
    - If not provided the file will be copied to the relative path specified by I(name)
    type: str
  target_dir:
    description:
    - Name of the target managed directory containing the source file to be copied
    - If not provided will use managed directory specified by I(source_dir)
    type: str
  overwrite:
    description:
    - Define whether to overwrite an existing target file
    type: bool
    default: false
extends_documentation_fragment:
- purestorage.flasharray.purestorage.fa
"""

EXAMPLES = r"""
- name: Copy a file from dir foo to dir bar
  purestorage.flasharray.purefa_file:
    source_file: "/directory1/file1"
    source_dir: "fs1:root"
    target_file: "/diff_dir/file1"
    target_dir: "fs1:root"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Copy a file in a direcotry to the same directory with a different name
  purestorage.flasharray.purefa_file:
    source_file: "/directory1/file1"
    source_dir: "fs1:root"
    target_file: "/directory_1/file2"
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592

- name: Copy a file in a direcotry to an existing file with overwrite
  purestorage.flasharray.purefa_file:
    source_file: "/directory1/file1"
    source_dir: "fs1:root"
    target_file: "/diff_dir/file1"
    target_dir: "fs2:root"
    overwrite: true
    fa_url: 10.10.10.2
    api_token: e31060a7-21fc-e277-6240-25983c6c4592
"""

RETURN = r"""
"""

HAS_PURESTORAGE = True
try:
    from pypureclient import flasharray
except ImportError:
    HAS_PURESTORAGE = False

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.purestorage.flasharray.plugins.module_utils.purefa import (
    get_array,
    purefa_argument_spec,
)
from ansible_collections.purestorage.flasharray.plugins.module_utils.version import (
    LooseVersion,
)

MIN_REQUIRED_API_VERSION = "2.26"


def _check_dirs(module, array):
    if array.get_directories(names=[module.params["source_dir"]]).status_code != 200:
        module.fail_json(
            msg="Source directory {0} does not exist".format(
                module.params["source_dir"]
            )
        )
    if array.get_directories(names=[module.params["target_dir"]]).status_code != 200:
        module.fail_json(
            msg="Target directory {0} does not exist".format(
                module.params["target_dir"]
            )
        )


def main():
    argument_spec = purefa_argument_spec()
    argument_spec.update(
        dict(
            overwrite=dict(type="bool", default=False),
            source_file=dict(type="str", required=True),
            source_dir=dict(type="str", required=True),
            target_file=dict(type="str"),
            target_dir=dict(type="str"),
        )
    )

    required_one_of = [["target_file", "target_dir"]]
    module = AnsibleModule(
        argument_spec, required_one_of=required_one_of, supports_check_mode=True
    )

    if not HAS_PURESTORAGE:
        module.fail_json(msg="py-pure-client sdk is required for this module")

    array = get_array(module)
    api_version = array.get_rest_version()

    if LooseVersion(MIN_REQUIRED_API_VERSION) > LooseVersion(api_version):
        module.fail_json(
            msg="FlashArray REST version not supported. "
            "Minimum version required: {0}".format(MIN_REQUIRED_API_VERSION)
        )

    if not module.params["target_file"]:
        module.params["target_file"] = module.params["source_file"]
    if not module.params["target_dir"]:
        module.params["target_dir"] = module.params["source_dir"]
    if ":" not in module.params["target_dir"]:
        module.fail_json(msg="Target Direcotry is not formatted correctly")
    if ":" not in module.params["source_dir"]:
        module.fail_json(msg="Source Direcotry is not formatted correctly")
    _check_dirs(module, array)
    changed = True
    if not module.check_mode:
        res = array.post_files(
            source_file=flasharray.FilePost(
                source=flasharray.ReferenceWithType(
                    name=module.params["source_dir"], resource_type="directories"
                ),
                source_path=module.params["source_file"],
            ),
            overwrite=module.params["overwrite"],
            paths=[module.params["target_file"]],
            directory_names=[module.params["target_dir"]],
        )
        if res.status_code != 200:
            module.fail_json(
                msg="Failed to copy file. Error: {0}".format(res.errors[0].message)
            )

    module.exit_json(changed=changed)


if __name__ == "__main__":
    main()
