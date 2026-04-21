#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright: (c) 2018, Chris Houseknecht <@chouseknecht>
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)


from __future__ import absolute_import, division, print_function

__metaclass__ = type

# STARTREMOVE (downstream)
DOCUMENTATION = r"""

module: k8s

short_description: Manage OpenShift objects

author:
    - "Chris Houseknecht (@chouseknecht)"
    - "Fabian von Feilitzsch (@fabianvf)"

description:
  - Use the Kubernetes Python client to perform CRUD operations on K8s objects.
  - Pass the object definition from a source file or inline. See examples for reading
    files and using Jinja templates or vault-encrypted files.
  - Access to the full range of K8s APIs.
  - Use the M(kubernetes.core.k8s_info) module to obtain a list of items about an object of type C(kind).
  - Authenticate using either a config file, certificates, password or token.
  - Supports check mode.
  - Optimized for OKD/OpenShift Kubernetes flavors.

extends_documentation_fragment:
  - kubernetes.core.k8s_name_options
  - kubernetes.core.k8s_resource_options
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_wait_options
  - kubernetes.core.k8s_delete_options

options:
  state:
    description:
    - Determines if an object should be created, patched, or deleted. When set to C(present), an object will be
      created, if it does not already exist. If set to C(absent), an existing object will be deleted. If set to
      C(present), an existing object will be patched, if its attributes differ from those specified using
      I(resource_definition) or I(src).
    - C(patched) state is an existing resource that has a given patch applied. If the resource doesn't exist, silently skip it (do not raise an error).
    type: str
    default: present
    choices: [ absent, present, patched ]
  force:
    description:
    - If set to C(yes), and I(state) is C(present), an existing object will be replaced.
    type: bool
    default: no
  merge_type:
    description:
    - Whether to override the default patch merge approach with a specific type. By default, the strategic
      merge will typically be used.
    - For example, Custom Resource Definitions typically aren't updatable by the usual strategic merge. You may
      want to use C(merge) if you see "strategic merge patch format is not supported"
    - See U(https://kubernetes.io/docs/tasks/run-application/update-api-object-kubectl-patch/#use-a-json-merge-patch-to-update-a-deployment)
    - If more than one merge_type is given, the merge_types will be tried in order
    - Defaults to C(['strategic-merge', 'merge']), which is ideal for using the same parameters
      on resource kinds that combine Custom Resources and built-in resources.
    - mutually exclusive with C(apply)
    - I(merge_type=json) has been removed in version 4.0.0. Please use M(kubernetes.core.k8s_json_patch) instead.
    choices:
    - merge
    - strategic-merge
    type: list
    elements: str
  validate:
    description:
      - how (if at all) to validate the resource definition against the kubernetes schema.
        Requires the kubernetes-validate python module
    suboptions:
      fail_on_error:
        description: whether to fail on validation errors.
        type: bool
      version:
        description: version of Kubernetes to validate against. defaults to Kubernetes server version
        type: str
      strict:
        description: whether to fail when passing unexpected properties
        default: True
        type: bool
    type: dict
  append_hash:
    description:
    - Whether to append a hash to a resource name for immutability purposes
    - Applies only to ConfigMap and Secret resources
    - The parameter will be silently ignored for other resource kinds
    - The full definition of an object is needed to generate the hash - this means that deleting an object created with append_hash
      will only work if the same object is passed with state=absent (alternatively, just use state=absent with the name including
      the generated hash and append_hash=no)
    type: bool
    default: false
  apply:
    description:
    - C(apply) compares the desired resource definition with the previously supplied resource definition,
      ignoring properties that are automatically generated
    - C(apply) works better with Services than 'force=yes'
    - mutually exclusive with C(merge_type)
    type: bool
    default: false
  template:
    description:
    - Provide a valid YAML template definition file for an object when creating or updating.
    - Value can be provided as string or dictionary.
    - Mutually exclusive with C(src) and C(resource_definition).
    - Template files needs to be present on the Ansible Controller's file system.
    - Additional parameters can be specified using dictionary.
    - 'Valid additional parameters - '
    - 'C(newline_sequence) (str): Specify the newline sequence to use for templating files.
      valid choices are "\n", "\r", "\r\n". Default value "\n".'
    - 'C(block_start_string) (str): The string marking the beginning of a block.
      Default value "{%".'
    - 'C(block_end_string) (str): The string marking the end of a block.
      Default value "%}".'
    - 'C(variable_start_string) (str): The string marking the beginning of a print statement.
      Default value "{{".'
    - 'C(variable_end_string) (str): The string marking the end of a print statement.
      Default value "}}".'
    - 'C(trim_blocks) (bool): Determine when newlines should be removed from blocks. When set to C(yes) the first newline
       after a block is removed (block, not variable tag!). Default value is true.'
    - 'C(lstrip_blocks) (bool): Determine when leading spaces and tabs should be stripped.
      When set to C(yes) leading spaces and tabs are stripped from the start of a line to a block.
      This functionality requires Jinja 2.7 or newer. Default value is false.'
    type: raw
    version_added: '2.0.0'
  continue_on_error:
    description:
    - Whether to continue on creation/deletion errors when multiple resources are defined.
    - This has no effect on the validation step which is controlled by the C(validate.fail_on_error) parameter.
    type: bool
    default: False
    version_added: 2.0.0

requirements:
  - "python >= 3.6"
  - "kubernetes >= 12.0.0"
  - "PyYAML >= 3.11"
"""

EXAMPLES = r"""
- name: Create an OCP project
  community.okd.k8s:
    state: present
    resource_definition:
      apiVersion: project.openshift.io/v1
      kind: Project
      metadata:
        name: testing

- name: Create a k8s namespace
  community.okd.k8s:
    name: testing
    api_version: v1
    kind: Namespace
    state: present

- name: Create a Service object from an inline definition
  community.okd.k8s:
    state: present
    definition:
      apiVersion: v1
      kind: Service
      metadata:
        name: web
        namespace: testing
        labels:
          app: galaxy
          service: web
      spec:
        selector:
          app: galaxy
          service: web
        ports:
          - protocol: TCP
            targetPort: 8000
            name: port-8000-tcp
            port: 8000

- name: Remove an existing Service object
  community.okd.k8s:
    state: absent
    api_version: v1
    kind: Service
    namespace: testing
    name: web

# Passing the object definition from a file

- name: Create a Deployment by reading the definition from a local file
  community.okd.k8s:
    state: present
    src: /testing/deployment.yml

- name: >-
    Read definition file from the Ansible controller file system.
    If the definition file has been encrypted with Ansible Vault it will automatically be decrypted.
  community.okd.k8s:
    state: present
    definition: "{{ lookup('file', '/testing/deployment.yml') | from_yaml }}"

- name: Read definition file from the Ansible controller file system after Jinja templating
  community.okd.k8s:
    state: present
    definition: "{{ lookup('template', '/testing/deployment.yml') | from_yaml }}"

- name: fail on validation errors
  community.okd.k8s:
    state: present
    definition: "{{ lookup('template', '/testing/deployment.yml') | from_yaml }}"
    validate:
      fail_on_error: true

- name: warn on validation errors, check for unexpected properties
  community.okd.k8s:
    state: present
    definition: "{{ lookup('template', '/testing/deployment.yml') | from_yaml }}"
    validate:
      fail_on_error: false
      strict: true
"""

RETURN = r"""
result:
  description:
  - The created, patched, or otherwise present object. Will be empty in the case of a deletion.
  returned: success
  type: complex
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
       type: complex
     spec:
       description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
       returned: success
       type: complex
     status:
       description: Current status details for the object.
       returned: success
       type: complex
     items:
       description: Returned only when multiple yaml documents are passed to src or resource_definition
       returned: when resource_definition or src contains list of objects
       type: list
     duration:
       description: elapsed time of task in seconds
       returned: when C(wait) is true
       type: int
       sample: 48
     error:
       description: Error while trying to create/delete the object.
       returned: error
       type: complex
"""
# ENDREMOVE (downstream)

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    NAME_ARG_SPEC,
    RESOURCE_ARG_SPEC,
    AUTH_ARG_SPEC,
    WAIT_ARG_SPEC,
    DELETE_OPTS_ARG_SPEC,
)


def validate_spec():
    return dict(
        fail_on_error=dict(type="bool"),
        version=dict(),
        strict=dict(type="bool", default=True),
    )


def argspec():
    argument_spec = {}
    argument_spec.update(NAME_ARG_SPEC)
    argument_spec.update(RESOURCE_ARG_SPEC)
    argument_spec.update(AUTH_ARG_SPEC)
    argument_spec.update(WAIT_ARG_SPEC)
    argument_spec["merge_type"] = dict(
        type="list", elements="str", choices=["merge", "strategic-merge"]
    )
    argument_spec["validate"] = dict(type="dict", default=None, options=validate_spec())
    argument_spec["append_hash"] = dict(type="bool", default=False)
    argument_spec["apply"] = dict(type="bool", default=False)
    argument_spec["template"] = dict(type="raw", default=None)
    argument_spec["delete_options"] = dict(
        type="dict", default=None, options=DELETE_OPTS_ARG_SPEC
    )
    argument_spec["continue_on_error"] = dict(type="bool", default=False)
    argument_spec["state"] = dict(
        default="present", choices=["present", "absent", "patched"]
    )
    argument_spec["force"] = dict(type="bool", default=False)
    return argument_spec


def main():
    mutually_exclusive = [
        ("resource_definition", "src"),
        ("merge_type", "apply"),
        ("template", "resource_definition"),
        ("template", "src"),
    ]

    from ansible_collections.community.okd.plugins.module_utils.k8s import OKDRawModule

    module = OKDRawModule(
        argument_spec=argspec(),
        supports_check_mode=True,
        mutually_exclusive=mutually_exclusive,
    )
    module.run_module()


if __name__ == "__main__":
    main()
