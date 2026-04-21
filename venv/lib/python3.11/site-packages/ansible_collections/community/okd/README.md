# OKD Collection for Ansible

This repo hosts the `community.okd` Ansible Collection.

## Description
The collection includes a variety of Ansible content to help automate the management of applications in OKD clusters, as well as the provisioning and maintenance of clusters themselves.

<!--- STARTREMOVE --->
[![CI](https://github.com/ansible-collections/community.okd/workflows/CI/badge.svg?event=push)](https://github.com/ansible-collections/community.okd/actions) [![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.okd)](https://codecov.io/gh/ansible-collections/community.okd)

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [POSTS TAGGED WITH 'YOUR TAG'](https://forum.ansible.com/tag/YOUR_TAG): subscribe to participate in collection-related conversations.
  * [REFER TO YOUR FORUM GROUP HERE IF EXISTS](https://forum.ansible.com/g/): by joining the team you will automatically get subscribed to the posts tagged with [your group forum tag here](https://forum.ansible.com/tags).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Requirements

<!--start requires_ansible-->
### Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.15.0**.

Please ensure to update the `network_os` to use the fully qualified collection name (for example, `cisco.ios.ios`).
Plugins and modules within a collection may be tested with only specific Ansible versions.
A collection may contain metadata that identifies these versions.
PEP440 is the schema used to describe the versions of Ansible.
<!--end requires_ansible-->

### Python Support

* Collection supports 3.9+

### Kubernetes Version Support

This collection supports Kubernetes versions >=1.24.

### Included content

Click on the name of a plugin or module to view that content's documentation:

<!--start collection content-->
#### Connection plugins
Name | Description
--- | ---
[community.okd.oc](https://github.com/openshift/community.okd/blob/main/docs/community.okd.oc_connection.rst)|Execute tasks in pods running on OpenShift.

#### Inventory plugins
Name | Description
--- | ---
[community.okd.openshift](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_inventory.rst)|OpenShift inventory source

#### Modules
Name | Description
--- | ---
[community.okd.k8s](https://github.com/openshift/community.okd/blob/main/docs/community.okd.k8s_module.rst)|Manage OpenShift objects
[community.okd.openshift_adm_groups_sync](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_adm_groups_sync_module.rst)|Sync OpenShift Groups with records from an external provider.
[community.okd.openshift_adm_migrate_template_instances](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_adm_migrate_template_instances_module.rst)|Update TemplateInstances to point to the latest group-version-kinds
[community.okd.openshift_adm_prune_auth](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_adm_prune_auth_module.rst)|Removes references to the specified roles, clusterroles, users, and groups
[community.okd.openshift_adm_prune_builds](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_adm_prune_builds_module.rst)|Prune old completed and failed builds
[community.okd.openshift_adm_prune_deployments](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_adm_prune_deployments_module.rst)|Remove old completed and failed deployment configs
[community.okd.openshift_adm_prune_images](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_adm_prune_images_module.rst)|Remove unreferenced images
[community.okd.openshift_auth](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_auth_module.rst)|Authenticate to OpenShift clusters which require an explicit login step
[community.okd.openshift_build](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_build_module.rst)|Start a new build or Cancel running, pending, or new builds.
[community.okd.openshift_import_image](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_import_image_module.rst)|Import the latest image information from a tag in a container image registry.
[community.okd.openshift_process](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_process_module.rst)|Process an OpenShift template.openshift.io/v1 Template
[community.okd.openshift_registry_info](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_registry_info_module.rst)|Display information about the integrated registry.
[community.okd.openshift_route](https://github.com/openshift/community.okd/blob/main/docs/community.okd.openshift_route_module.rst)|Expose a Service as an OpenShift Route.

<!--end collection content-->

<!--- ENDREMOVE --->

## Installation

### Installing the Collection from Ansible Galaxy

Before using the OKD collection, you need to install it with the Ansible Galaxy CLI:

    ansible-galaxy collection install community.okd

You can also include it in a `requirements.yml` file and install it via `ansible-galaxy collection install -r requirements.yml`, using the format:

```yaml
---
collections:
  - name: community.okd
    version: 4.0.2
```

### Installing the Kubernetes Python Library

Content in this collection requires the [Kubernetes Python client](https://pypi.org/project/kubernetes/) to interact with Kubernetes' APIs. You can install it with:

    pip3 install kubernetes

## Use Cases

### Using modules from the OKD Collection in your playbooks

It's preferable to use content in this collection using their Fully Qualified Collection Namespace (FQCN), for example `community.okd.openshift`:

```yaml
---
plugin: community.okd.openshift
connections:
  - namespaces:
    - testing
```

For documentation on how to use individual plugins included in this collection, please see the links in the 'Included content' section earlier in this README.

### Ansible Turbo mode Tech Preview

The `community.okd` collection supports Ansible Turbo mode as a tech preview via the `cloud.common` collection. By default, this feature is disabled. To enable Turbo mode, set the environment variable `ENABLE_TURBO_MODE=1` on the managed node. For example:

```yaml
---
- hosts: remote
  environment:
    ENABLE_TURBO_MODE: 1
  tasks:
    ...
```

Please read more about Ansible Turbo mode - [here](https://github.com/ansible-collections/community.okd/blob/main/docs/ansible_turbo_mode.rst).

<!--- STARTREMOVE --->
## Contributing to the collection

If you want to develop new content for this collection or improve what's already here, the easiest way to work on the collection is to clone it into one of the configured [`COLLECTIONS_PATHS`](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths), and work on it there.

See [Contributing to community.okd](CONTRIBUTING.md).

## Testing

The `tests` directory contains configuration for running sanity tests using [`ansible-test`](https://docs.ansible.com/ansible/latest/dev_guide/testing_integration.html).

You can run the `ansible-test` sanity tests with the command:

    make test-sanity

The `molecule` directory contains configuration for running integration tests using [`molecule`](https://molecule.readthedocs.io/).

You can run the `molecule` integration tests with the command:

    make test-integration

These commands will create a directory called `ansible_collections` which should not be committed or added to the `.gitignore` (Tracking issue: https://github.com/ansible/ansible/issues/68499)


### Prow

This repository uses the OpenShift [Prow](https://github.com/kubernetes/test-infra/blob/master/prow/README.md) instance for testing against live OpenShift clusters.
The configuration for the CI jobs that this repository runs can be found in the [`openshift/release repository`](https://github.com/openshift/release/blob/master/ci-operator/config/openshift/community.okd/openshift-community.okd-main.yaml).

The [Prow CI integration test job](https://github.com/openshift/release/blob/master/ci-operator/config/openshift/community.okd/openshift-community.okd-main.yaml#L40-L43)
runs the command:

    make test-integration-incluster

which will create a job that runs the normal `make integration` target. In order to mimic the Prow CI job, you must
first build the test image using the Dockerfile in [`ci/Dockerfile`](ci/Dockerfile). Then, push the image
somewhere that it will be accessible to the cluster, and run

    IMAGE_FORMAT=<your image> make test-integration-incluser

where the `IMAGE_FORMAT` environment variable is the full reference to your container (ie, `IMAGE_FORMAT=quay.io/example/molecule-test-runner`)

## Publishing New Versions

Releases are automatically built and pushed to Ansible Galaxy for any new tag. Before tagging a release, make sure to do the following:

1. Update the version in the following places:
    * a. The `version` in `galaxy.yml`
    * b. This README's `requirements.yml` example
    * c. The `DOWNSTREAM_VERSION` in `ci/downstream.sh`
    * d. The `VERSION` in `Makefile`
    * e. The version in `requirements.yml`
2. Update the CHANGELOG:
    * 1. Make sure you have [`antsibull-changelog`](https://pypi.org/project/antsibull-changelog/) installed.
    * 2. Make sure there are fragments for all known changes in `changelogs/fragments`.
    * 3. Run `antsibull-changelog release`.
3. Commit the changes and create a PR with the changes. Wait for tests to pass, then merge it once they have.
4. Tag the version in Git and push to GitHub.

After the version is published, verify it exists on the [OKD Collection Galaxy page](https://galaxy.ansible.com/community/okd).
<!--- ENDREMOVE --->

## Support

<!--List available communication channels. In addition to channels specific to your collection, we also recommend to use the following ones.-->

We announce releases and important changes through Ansible's [The Bullhorn newsletter](https://github.com/ansible/community/wiki/News#the-bullhorn). Be sure you are [subscribed](https://eepurl.com/gZmiEP).

We take part in the global quarterly [Ansible Contributor Summit](https://github.com/ansible/community/wiki/Contributor-Summit) virtually or in-person. Track [The Bullhorn newsletter](https://eepurl.com/gZmiEP) and join us.

For more information about communication, refer to the [Ansible Communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

For the latest supported versions, refer to the release notes below.

If you encounter issues or have questions, you can submit a support request through the following channels:
 - GitHub Issues: Report bugs, request features, or ask questions by opening an issue in the [GitHub repository](https://github.com/openshift/community.okd/).

## Release notes

See the [raw generated changelog](https://github.com/openshift/community.okd/blob/main/CHANGELOG.rst).

## More Information

For more information about Ansible's Kubernetes and OpenShift integrations, join the `#ansible-kubernetes` channel on [libera.chat](https://libera.chat/) IRC, and browse the resources in the [Kubernetes Working Group](https://github.com/ansible/community/wiki/Kubernetes) Community wiki page.

## Code of Conduct

We follow the [Ansible Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior, please refer to the [policy violations](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html#policy-violations) section of the Code for information on how to raise a complaint.

## License

GNU General Public License v3.0 or later

See LICENCE to see the full text.
