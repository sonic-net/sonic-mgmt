#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_import_image

short_description: Import the latest image information from a tag in a container image registry.

version_added: "2.2.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - Image streams allow you to control which images are rolled out to your builds and applications.
  - This module fetches the latest version of an image from a remote repository and updates the image stream tag
    if it does not match the previous value.
  - Running the module multiple times will not create duplicate entries.
  - When importing an image, only the image metadata is copied, not the image contents.
  - Analogous to C(oc import-image).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  namespace:
    description:
    - Use to specify namespace for image stream to create/update.
    type: str
    required: True
  name:
    description:
    - Image stream to import tag into.
    - This can be provided as a list of images streams or a single value.
    type: raw
    required: True
  all:
    description:
    - If set to I(true), import all tags from the provided source on creation or if C(source) is specified.
    type: bool
    default: False
  validate_registry_certs:
    description:
    - If set to I(true), allow importing from registries that have invalid HTTPS certificates.
      or are hosted via HTTP. This parameter will take precedence over the insecure annotation.
    type: bool
  reference_policy:
    description:
    -  Allow to request pullthrough for external image when set to I(local).
    default: source
    choices:
    - source
    - local
    type: str
  scheduled:
    description:
    - Set each imported Docker image to be periodically imported from a remote repository.
    type: bool
    default: False
  source:
    description:
    - A Docker image repository to import images from.
    - Should be provided as 'registry.io/repo/image'
    type: str

requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
  - docker-image-py
"""

EXAMPLES = r"""
# Import tag latest into a new image stream.
- name: Import tag latest into new image stream
  community.okd.openshift_import_image:
    namespace: testing
    name: mystream
    source: registry.io/repo/image:latest

# Update imported data for tag latest in an already existing image stream.
- name: Update imported data for tag latest
  community.okd.openshift_import_image:
    namespace: testing
    name: mystream

# Update imported data for tag 'stable' in an already existing image stream.
- name: Update imported data for tag latest
  community.okd.openshift_import_image:
    namespace: testing
    name: mystream:stable

# Update imported data for all tags in an existing image stream.
- name: Update imported data for all tags
  community.okd.openshift_import_image:
    namespace: testing
    name: mystream
    all: true

# Import all tags into a new image stream.
- name: Import all tags into a new image stream.
  community.okd.openshift_import_image:
    namespace: testing
    name: mystream
    source: registry.io/repo/image:latest
    all: true

# Import all tags into a new image stream for a list of image streams
- name: Import all tags into a new image stream.
  community.okd.openshift_import_image:
    namespace: testing
    name:
      - mystream1
      - mystream2
      - mystream3
    source: registry.io/repo/image:latest
    all: true
"""


RETURN = r"""
result:
  description:
    -  List with all ImageStreamImport that have been created.
  type: list
  returned: success
  elements: dict
  contains:
    api_version:
      description: The versioned schema of this representation of an object.
      returned: success
      type: str
    kind:
      description: Represents the REST resource this object represents.
      returned: success
      type: str
    metadata:
      description: Standard object metadata. Includes name, namespace, annotations, labels, etc.
      returned: success
      type: dict
    spec:
      description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
      returned: success
      type: dict
    status:
      description: Current status details for the object.
      returned: success
      type: dict
"""
# ENDREMOVE (downstream)

import copy

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
)


def argument_spec():
    args = copy.deepcopy(AUTH_ARG_SPEC)
    args.update(
        dict(
            namespace=dict(type="str", required=True),
            name=dict(type="raw", required=True),
            all=dict(type="bool", default=False),
            validate_registry_certs=dict(type="bool"),
            reference_policy=dict(
                type="str", choices=["source", "local"], default="source"
            ),
            scheduled=dict(type="bool", default=False),
            source=dict(type="str"),
        )
    )
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_import_image import (
        OpenShiftImportImage,
    )

    module = OpenShiftImportImage(
        argument_spec=argument_spec(), supports_check_mode=True
    )
    module.run_module()


if __name__ == "__main__":
    main()
