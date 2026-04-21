# Kubernetes Collection for Ansible

This repository hosts the `kubernetes.core` (formerly known as `community.kubernetes`) Ansible Collection.

## Description

The collection includes a variety of Ansible content to help automate the management of applications in Kubernetes and OpenShift clusters, as well as the provisioning and maintenance of clusters themselves.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'kubernetes'](https://forum.ansible.com/tag/kubernetes): subscribe to participate in collection-related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Requirements

<!--start requires_ansible-->
## Ansible version compatibility

This collection has been tested against the following Ansible versions: **>=2.16.0**.

Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

### Python Support

* Collection supports 3.9+

Note: Python2 is deprecated from [1st January 2020](https://www.python.org/doc/sunset-python-2/). Please switch to Python3.

### Kubernetes Version Support

This collection supports Kubernetes versions >= 1.24.

### Included Content

Click on the name of a plugin or module to view that content's documentation:

<!--start collection content-->
### Connection plugins
Name | Description
--- | ---
[kubernetes.core.kubectl](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.kubectl_connection.rst)|Execute tasks in pods running on Kubernetes.

### K8s filter plugins
Name | Description
--- | ---
kubernetes.core.k8s_config_resource_name|Generate resource name for the given resource of type ConfigMap, Secret

### Lookup plugins
Name | Description
--- | ---
[kubernetes.core.k8s](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_lookup.rst)|Query the K8s API
[kubernetes.core.kustomize](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.kustomize_lookup.rst)|Build a set of kubernetes resources using a 'kustomization.yaml' file.

### Modules
Name | Description
--- | ---
[kubernetes.core.helm](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_module.rst)|Manages Kubernetes packages with the Helm package manager
[kubernetes.core.helm_info](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_info_module.rst)|Get information from Helm package deployed inside the cluster
[kubernetes.core.helm_plugin](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_plugin_module.rst)|Manage Helm plugins
[kubernetes.core.helm_plugin_info](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_plugin_info_module.rst)|Gather information about Helm plugins
[kubernetes.core.helm_pull](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_pull_module.rst)|download a chart from a repository and (optionally) unpack it in local directory.
[kubernetes.core.helm_registry_auth](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_registry_auth_module.rst)|Helm registry authentication module
[kubernetes.core.helm_repository](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_repository_module.rst)|Manage Helm repositories.
[kubernetes.core.helm_template](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.helm_template_module.rst)|Render chart templates
[kubernetes.core.k8s](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_module.rst)|Manage Kubernetes (K8s) objects
[kubernetes.core.k8s_cluster_info](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_cluster_info_module.rst)|Describe Kubernetes (K8s) cluster, APIs available and their respective versions
[kubernetes.core.k8s_cp](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_cp_module.rst)|Copy files and directories to and from pod.
[kubernetes.core.k8s_drain](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_drain_module.rst)|Drain, Cordon, or Uncordon node in k8s cluster
[kubernetes.core.k8s_exec](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_exec_module.rst)|Execute command in Pod
[kubernetes.core.k8s_info](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_info_module.rst)|Describe Kubernetes (K8s) objects
[kubernetes.core.k8s_json_patch](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_json_patch_module.rst)|Apply JSON patch operations to existing objects
[kubernetes.core.k8s_log](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_log_module.rst)|Fetch logs from Kubernetes resources
[kubernetes.core.k8s_rollback](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_rollback_module.rst)|Rollback Kubernetes (K8S) Deployments and DaemonSets
[kubernetes.core.k8s_scale](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_scale_module.rst)|Set a new size for a Deployment, ReplicaSet, Replication Controller, or Job.
[kubernetes.core.k8s_service](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_service_module.rst)|Manage Services on Kubernetes
[kubernetes.core.k8s_taint](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/kubernetes.core.k8s_taint_module.rst)|Taint a node in a Kubernetes/OpenShift cluster

<!--end collection content-->

## Installation

Before using the Kubernetes collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install kubernetes.core

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: kubernetes.core
    version: 6.2.0
```

### Installing the Kubernetes Python Library

Content in this collection requires the [Kubernetes Python client](https://pypi.org/project/kubernetes/) to interact with Kubernetes' APIs. You can install it with:

    pip3 install kubernetes

## Use Cases

It's preferable to use content in this collection using their Fully Qualified Collection Namespace (FQCN), for example `kubernetes.core.k8s_info`:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  tasks:
    - name: Ensure the myapp Namespace exists.
      kubernetes.core.k8s:
        api_version: v1
        kind: Namespace
        name: myapp
        state: present

    - name: Ensure the myapp Service exists in the myapp Namespace.
      kubernetes.core.k8s:
        state: present
        definition:
          apiVersion: v1
          kind: Service
          metadata:
            name: myapp
            namespace: myapp
          spec:
            type: LoadBalancer
            ports:
            - port: 8080
              targetPort: 8080
            selector:
              app: myapp

    - name: Get a list of all Services in the myapp namespace.
      kubernetes.core.k8s_info:
        kind: Service
        namespace: myapp
      register: myapp_services

    - name: Display number of Services in the myapp namespace.
      debug:
        var: myapp_services.resources | count
```

If upgrading older playbooks which were built prior to Ansible 2.10 and this collection's existence, you can also define `collections` in your play and refer to this collection's modules as you did in Ansible 2.9 and below, as in this example:

```yaml
---
- hosts: localhost
  gather_facts: false
  connection: local

  collections:
    - kubernetes.core

  tasks:
    - name: Ensure the myapp Namespace exists.
      k8s:
        api_version: v1
        kind: Namespace
        name: myapp
        state: present
```

For documentation on how to use individual modules and other content included in this collection, please see the links in the 'Included content' section earlier in this README.

## Ansible Turbo Mode Tech Preview


The ``kubernetes.core`` collection supports Ansible Turbo mode as a tech preview via the ``cloud.common`` collection. By default, this feature is disabled. To enable Turbo mode for modules, set the environment variable `ENABLE_TURBO_MODE=1` on the managed node. For example:

```yaml
---
- hosts: remote
  environment:
    ENABLE_TURBO_MODE: 1
  tasks:
    ...
```

To enable Turbo mode for k8s lookup plugin, set the environment variable `ENABLE_TURBO_MODE=1` on the managed node. This is not working when
defined in the playbook using `environment` keyword as above, you must set it using `export ENABLE_TURBO_MODE=1`.

Please read more about Ansible Turbo mode - [here](https://github.com/ansible-collections/kubernetes.core/blob/main/docs/ansible_turbo_mode.rst).

## Contributing to this Collection

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

See [Contributing to kubernetes.core](CONTRIBUTING.md).

## Testing

[![Linters](https://img.shields.io/github/actions/workflow/status/ansible-collections/kubernetes.core/linters.yaml?label=linters)](https://github.com/ansible-collections/kubernetes.core/actions/workflows/linters.yaml) [![Integration tests](https://img.shields.io/github/actions/workflow/status/ansible-collections/kubernetes.core/integration-tests.yaml?label=integration%20tests)](https://github.com/ansible-collections/kubernetes.core/actions/workflows/integration-tests.yaml) [![Sanity tests](https://img.shields.io/github/actions/workflow/status/ansible-collections/kubernetes.core/sanity-tests.yaml?label=sanity%20tests)](https://github.com/ansible-collections/kubernetes.core/actions/workflows/sanity-tests.yaml) [![Unit tests](https://img.shields.io/github/actions/workflow/status/ansible-collections/kubernetes.core/unit-tests.yaml?label=unit%20tests)](https://github.com/ansible-collections/kubernetes.core/actions/workflows/unit-tests.yaml) [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/kubernetes.core)](https://app.codecov.io/gh/ansible-collections/kubernetes.core)

### Testing with `ansible-test`

The `tests` directory contains configuration for running sanity and integration tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the collection's test suites with the commands:

    make test-sanity
    make test-integration
    make test-unit

### Testing with `molecule`

There are also integration tests in the `molecule` directory which are meant to be run against a local Kubernetes cluster, e.g. using [KinD](https://kind.sigs.k8s.io) or [Minikube](https://minikube.sigs.k8s.io). To setup a local cluster using KinD and run Molecule:

    kind create cluster
    make test-molecule

## Publishing New Versions

Releases are automatically built and pushed to Ansible Galaxy for any new tag. Before tagging a release, make sure to do the following:

  1. Update the version in the following places:
     1. The `version` in `galaxy.yml`
     2. This README's `requirements.yml` example
     3. The `VERSION` in `Makefile`
  2. Update the CHANGELOG:
     1. Make sure you have [`antsibull-changelog`](https://pypi.org/project/antsibull-changelog/) installed.
     2. Make sure there are fragments for all known changes in `changelogs/fragments`.
     3. Run `antsibull-changelog release`.
  3. Commit the changes and create a PR with the changes. Wait for tests to pass, then merge it once they have.
  4. Tag the version in Git and push to GitHub.

After the version is published, verify it exists on the [Kubernetes Collection Galaxy page](https://galaxy.ansible.com/kubernetes/core).

The process for uploading a supported release to Automation Hub is documented separately.

## Support

<!--List available communication channels. In addition to channels specific to your collection, we also recommend to use the following ones.-->

> **Note:** The `stable-4` branch, which handles all `4.x.y` releases of this collection, is no longer supported. This means that no backports nor releases will be performed on the `stable-4` branch.

We announce releases and important changes through Ansible's [The Bullhorn newsletter](https://github.com/ansible/community/wiki/News#the-bullhorn). Be sure you are [subscribed](https://eepurl.com/gZmiEP).

We take part in the global quarterly [Ansible Contributor Summit](https://github.com/ansible/community/wiki/Contributor-Summit) virtually or in-person. Track [The Bullhorn newsletter](https://eepurl.com/gZmiEP) and join us.

For more information about communication, refer to the [Ansible Communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

For the latest supported versions, refer to the release notes below.

If you encounter issues or have questions, you can submit a support request through the following channels:
 - GitHub Issues: Report bugs, request features, or ask questions by opening an issue in the [GitHub repository]((https://github.com/ansible-collections/kubernetes.core/).

## Release Notes

See the [raw generated changelog](https://github.com/ansible-collections/kubernetes.core/blob/main/CHANGELOG.rst).

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior, please refer to the [policy violations](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html#policy-violations) section of the Code for information on how to raise a complaint.


## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.
