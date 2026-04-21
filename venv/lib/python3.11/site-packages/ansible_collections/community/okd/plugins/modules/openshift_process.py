#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import absolute_import, division, print_function

__metaclass__ = type

# Copyright (c) 2020-2021, Red Hat
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

# STARTREMOVE (downstream)
DOCUMENTATION = r"""
module: openshift_process

short_description: Process an OpenShift template.openshift.io/v1 Template

version_added: "0.3.0"

author: "Fabian von Feilitzsch (@fabianvf)"

description:
  - Processes a specified OpenShift template with the provided template.
  - Templates can be provided inline, from a file, or specified by name and namespace in the cluster.
  - Analogous to `oc process`.
  - For CRUD operations on Template resources themselves, see the community.okd.k8s module.

extends_documentation_fragment:
  - kubernetes.core.k8s_auth_options
  - kubernetes.core.k8s_wait_options
  - kubernetes.core.k8s_resource_options

requirements:
  - "python >= 3.6"
  - "kubernetes >= 12.0.0"
  - "PyYAML >= 3.11"

options:
  name:
    description:
      - The name of the Template to process.
      - The Template must be present in the cluster.
      - When provided, I(namespace) is required.
      - Mutually exclusive with I(resource_definition) or I(src)
    type: str
  namespace:
    description:
      - The namespace that the template can be found in.
    type: str
  namespace_target:
    description:
      - The namespace that resources should be created, updated, or deleted in.
      - Only used when I(state) is present or absent.
    type: str
  parameters:
    description:
      - 'A set of key: value pairs that will be used to set/override values in the Template.'
      - Corresponds to the `--param` argument to oc process.
    type: dict
  parameter_file:
    description:
      - A path to a file containing template parameter values to override/set values in the Template.
      - Corresponds to the `--param-file` argument to oc process.
    type: str
  state:
    description:
    - Determines what to do with the rendered Template.
    - The state I(rendered) will render the Template based on the provided parameters, and return the rendered
        objects in the I(resources) field. These can then be referenced in future tasks.
    - The state I(present) will cause the resources in the rendered Template to be created if they do not
        already exist, and patched if they do.
    - The state I(absent) will delete the resources in the rendered Template.
    type: str
    default: rendered
    choices: [ absent, present, rendered ]
"""

EXAMPLES = r"""
- name: Process a template in the cluster
  community.okd.openshift_process:
    name: nginx-example
    namespace: openshift # only needed if using a template already on the server
    parameters:
      NAMESPACE: openshift
      NAME: test123
    state: rendered
  register: result

- name: Create the rendered resources using apply
  community.okd.k8s:
    namespace: default
    definition: '{{ item }}'
    wait: true
    apply: true
  loop: '{{ result.resources }}'

- name: Process a template with parameters from an env file and create the resources
  community.okd.openshift_process:
    name: nginx-example
    namespace: openshift
    namespace_target: default
    parameter_file: 'files/nginx.env'
    state: present
    wait: true

- name: Process a local template and create the resources
  community.okd.openshift_process:
    src: files/example-template.yaml
    parameter_file: files/example.env
    namespace_target: default
    state: present

- name: Process a local template, delete the resources, and wait for them to terminate
  community.okd.openshift_process:
    src: files/example-template.yaml
    parameter_file: files/example.env
    namespace_target: default
    state: absent
    wait: true
"""

RETURN = r"""
result:
  description:
  - The created, patched, or otherwise present object. Will be empty in the case of a deletion.
  returned: on success when state is present or absent
  type: complex
  contains:
     apiVersion:
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
       contains:
           name:
             description: The name of the resource
             type: str
           namespace:
             description: The namespace of the resource
             type: str
     spec:
       description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
       returned: success
       type: dict
     status:
       description: Current status details for the object.
       returned: success
       type: complex
       contains:
         conditions:
             type: complex
             description: Array of status conditions for the object. Not guaranteed to be present
     items:
       description: Returned only when multiple yaml documents are passed to src or resource_definition
       returned: when resource_definition or src contains list of objects
       type: list
     duration:
       description: elapsed time of task in seconds
       returned: when C(wait) is true
       type: int
       sample: 48
resources:
  type: complex
  description:
  - The rendered resources defined in the Template
  returned: on success when state is rendered
  contains:
     apiVersion:
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
       contains:
           name:
             description: The name of the resource
             type: str
           namespace:
             description: The namespace of the resource
             type: str
     spec:
       description: Specific attributes of the object. Will vary based on the I(api_version) and I(kind).
       returned: success
       type: dict
     status:
       description: Current status details for the object.
       returned: success
       type: dict
       contains:
         conditions:
             type: complex
             description: Array of status conditions for the object. Not guaranteed to be present
"""
# ENDREMOVE (downstream)

from ansible_collections.kubernetes.core.plugins.module_utils.args_common import (
    AUTH_ARG_SPEC,
    RESOURCE_ARG_SPEC,
    WAIT_ARG_SPEC,
)


def argspec():
    argument_spec = {}
    argument_spec.update(AUTH_ARG_SPEC)
    argument_spec.update(WAIT_ARG_SPEC)
    argument_spec.update(RESOURCE_ARG_SPEC)
    argument_spec["state"] = dict(
        type="str", default="rendered", choices=["present", "absent", "rendered"]
    )
    argument_spec["namespace"] = dict(type="str")
    argument_spec["namespace_target"] = dict(type="str")
    argument_spec["parameters"] = dict(type="dict")
    argument_spec["name"] = dict(type="str")
    argument_spec["parameter_file"] = dict(type="str")

    return argument_spec


def main():
    from ansible_collections.community.okd.plugins.module_utils.openshift_process import (
        OpenShiftProcess,
    )

    module = OpenShiftProcess(argument_spec=argspec(), supports_check_mode=True)
    module.run_module()


if __name__ == "__main__":
    main()
