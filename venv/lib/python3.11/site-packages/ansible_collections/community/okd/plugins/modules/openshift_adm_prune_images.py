#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: openshift_adm_prune_images

short_description: Remove unreferenced images

version_added: "2.2.0"

author:
  - Aubin Bikouo (@abikouo)

description:
  - This module allow administrators to remove references images.
  - Note that if the C(namespace) is specified, only references images on Image stream for the corresponding
    namespace will be candidate for prune if only they are not used or references in another Image stream from
    another namespace.
  - Analogous to C(oc adm prune images).

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options

options:
  namespace:
    description:
    - Use to specify namespace for objects.
    type: str
  all_images:
    description:
    - Include images that were imported from external registries as candidates for pruning.
    - If pruned, all the mirrored objects associated with them will also be removed from the integrated registry.
    type: bool
    default: True
  keep_younger_than:
    description:
    - Specify the minimum age (in minutes) of an image and its referrers for it to be considered a candidate for pruning.
    type: int
  prune_over_size_limit:
    description:
    - Specify if images which are exceeding LimitRanges specified in the same namespace,
      should be considered for pruning.
    type: bool
    default: False
  registry_url:
    description:
    - The address to use when contacting the registry, instead of using the default value.
    - This is useful if you can't resolve or reach the default registry but you do have an
      alternative route that works.
    - Particular transport protocol can be enforced using '<scheme>://' prefix.
    type: str
  registry_ca_cert:
    description:
    - Path to a CA certificate used to contact registry. The full certificate chain must be provided to
      avoid certificate validation errors.
    type: path
  registry_validate_certs:
    description:
    - Whether or not to verify the API server's SSL certificates. Can also be specified via K8S_AUTH_VERIFY_SSL
      environment variable.
    type: bool
  prune_registry:
    description:
    - If set to I(False), the prune operation will clean up image API objects, but
      none of the associated content in the registry is removed.
    type: bool
    default: True
  ignore_invalid_refs:
    description:
    - If set to I(True), the pruning process will ignore all errors while parsing image references.
    - This means that the pruning process will ignore the intended connection between the object and the referenced image.
    - As a result an image may be incorrectly deleted as unused.
    type: bool
    default: False
requirements:
  - python >= 3.6
  - kubernetes >= 12.0.0
  - docker-image-py
"""

EXAMPLES = r"""
# Prune if only images and their referrers were more than an hour old
- name: Prune image with referrer been more than an hour old
  community.okd.openshift_adm_prune_images:
    keep_younger_than: 60

# Remove images exceeding currently set limit ranges
- name: Remove images exceeding currently set limit ranges
  community.okd.openshift_adm_prune_images:
    prune_over_size_limit: true

# Force the insecure http protocol with the particular registry host name
- name: Prune images using custom registry
  community.okd.openshift_adm_prune_images:
    registry_url: http://registry.example.org
    registry_validate_certs: false
"""


RETURN = r"""
updated_image_streams:
  description:
  - The images streams updated.
  returned: success
  type: list
  elements: dict
  sample: [
      {
          "apiVersion": "image.openshift.io/v1",
          "kind": "ImageStream",
          "metadata": {
              "annotations": {
                  "openshift.io/image.dockerRepositoryCheck": "2021-12-07T07:55:30Z"
              },
              "creationTimestamp": "2021-12-07T07:55:30Z",
              "generation": 1,
              "name": "python",
              "namespace": "images",
              "resourceVersion": "1139215",
              "uid": "443bad2c-9fd4-4c8f-8a24-3eca4426b07f"
          },
          "spec": {
              "lookupPolicy": {
                  "local": false
              },
              "tags": [
                  {
                      "annotations": null,
                      "from": {
                          "kind": "DockerImage",
                          "name": "python:3.8.12"
                      },
                      "generation": 1,
                      "importPolicy": {
                          "insecure": true
                      },
                      "name": "3.8.12",
                      "referencePolicy": {
                          "type": "Source"
                      }
                  }
              ]
          },
          "status": {
              "dockerImageRepository": "image-registry.openshift-image-registry.svc:5000/images/python",
              "publicDockerImageRepository": "default-route-openshift-image-registry.apps-crc.testing/images/python",
              "tags": []
          }
      },
      ...
  ]
deleted_images:
  description:
  - The images deleted.
  returned: success
  type: list
  elements: dict
  sample: [
      {
          "apiVersion": "image.openshift.io/v1",
          "dockerImageLayers": [
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:5e0b432e8ba9d9029a000e627840b98ffc1ed0c5172075b7d3e869be0df0fe9b",
                  "size": 54932878
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:a84cfd68b5cea612a8343c346bfa5bd6c486769010d12f7ec86b23c74887feb2",
                  "size": 5153424
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:e8b8f2315954535f1e27cd13d777e73da4a787b0aebf4241d225beff3c91cbb1",
                  "size": 10871995
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:0598fa43a7e793a76c198e8d45d8810394e1cfc943b2673d7fcf5a6fdc4f45b3",
                  "size": 54567844
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:83098237b6d3febc7584c1f16076a32ac01def85b0d220ab46b6ebb2d6e7d4d4",
                  "size": 196499409
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:b92c73d4de9a6a8f6b96806a04857ab33cf6674f6411138603471d744f44ef55",
                  "size": 6290769
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:ef9b6ee59783b84a6ec0c8b109c409411ab7c88fa8c53fb3760b5fde4eb0aa07",
                  "size": 16812698
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:c1f6285e64066d36477a81a48d3c4f1dc3c03dddec9e72d97da13ba51bca0d68",
                  "size": 234
              },
              {
                  "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                  "name": "sha256:a0ee7333301245b50eb700f96d9e13220cdc31871ec9d8e7f0ff7f03a17c6fb3",
                  "size": 2349241
              }
          ],
          "dockerImageManifestMediaType": "application/vnd.docker.distribution.manifest.v2+json",
          "dockerImageMetadata": {
              "Architecture": "amd64",
              "Config": {
                  "Cmd": [
                      "python3"
                  ],
                  "Env": [
                      "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                      "LANG=C.UTF-8",
                      "GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568",
                      "PYTHON_VERSION=3.8.12",
                      "PYTHON_PIP_VERSION=21.2.4",
                      "PYTHON_SETUPTOOLS_VERSION=57.5.0",
                      "PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/3cb8888cc2869620f57d5d2da64da38f516078c7/public/get-pip.py",
                      "PYTHON_GET_PIP_SHA256=c518250e91a70d7b20cceb15272209a4ded2a0c263ae5776f129e0d9b5674309"
                  ],
                  "Image": "sha256:cc3a2931749afa7dede97e32edbbe3e627b275c07bf600ac05bc0dc22ef203de"
              },
              "Container": "b43fcf5052feb037f6d204247d51ac8581d45e50f41c6be2410d94b5c3a3453d",
              "ContainerConfig": {
                  "Cmd": [
                      "/bin/sh",
                      "-c",
                      "#(nop) ",
                      "CMD [\"python3\"]"
                  ],
                  "Env": [
                      "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                      "LANG=C.UTF-8",
                      "GPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568",
                      "PYTHON_VERSION=3.8.12",
                      "PYTHON_PIP_VERSION=21.2.4",
                      "PYTHON_SETUPTOOLS_VERSION=57.5.0",
                      "PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/3cb8888cc2869620f57d5d2da64da38f516078c7/public/get-pip.py",
                      "PYTHON_GET_PIP_SHA256=c518250e91a70d7b20cceb15272209a4ded2a0c263ae5776f129e0d9b5674309"
                  ],
                  "Hostname": "b43fcf5052fe",
                  "Image": "sha256:cc3a2931749afa7dede97e32edbbe3e627b275c07bf600ac05bc0dc22ef203de"
              },
              "Created": "2021-12-03T01:53:41Z",
              "DockerVersion": "20.10.7",
              "Id": "sha256:f746089c9d02d7126bbe829f788e093853a11a7f0421049267a650d52bbcac37",
              "Size": 347487141,
              "apiVersion": "image.openshift.io/1.0",
              "kind": "DockerImage"
          },
          "dockerImageMetadataVersion": "1.0",
          "dockerImageReference": "python@sha256:a874dcabc74ca202b92b826521ff79dede61caca00ceab0b65024e895baceb58",
          "kind": "Image",
          "metadata": {
              "annotations": {
                  "image.openshift.io/dockerLayersOrder": "ascending"
              },
              "creationTimestamp": "2021-12-07T07:55:30Z",
              "name": "sha256:a874dcabc74ca202b92b826521ff79dede61caca00ceab0b65024e895baceb58",
              "resourceVersion": "1139214",
              "uid": "33be6ab4-af79-4f44-a0fd-4925bd473c1f"
          }
      },
      ...
  ]
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
            namespace=dict(type="str"),
            all_images=dict(type="bool", default=True),
            keep_younger_than=dict(type="int"),
            prune_over_size_limit=dict(type="bool", default=False),
            registry_url=dict(type="str"),
            registry_validate_certs=dict(type="bool"),
            registry_ca_cert=dict(type="path"),
            prune_registry=dict(type="bool", default=True),
            ignore_invalid_refs=dict(type="bool", default=False),
        )
    )
    return args


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_adm_prune_images import (
        OpenShiftAdmPruneImages,
    )

    module = OpenShiftAdmPruneImages(
        argument_spec=argument_spec(), supports_check_mode=True
    )
    module.run_module()


if __name__ == "__main__":
    main()
