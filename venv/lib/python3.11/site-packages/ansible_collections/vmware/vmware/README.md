# Ansible Collection: vmware.vmware

This repo hosts the `vmware.vmware` Ansible Collection.

The **vmware.vmware** collection is part of the **Red Hat Ansible Certified Content for VMware** offering that brings Ansible automation to VMware. This collection brings forward the possibility to manage vSphere resources and automate operator tasks.

System programmers can enable pipelines to setup, tear down and deploy VMs while system administrators can automate time consuming repetitive tasks inevitably freeing up their time. New VMware users can find comfort in Ansible's familiarity and expedite their proficiency in record time.


## Requirements

The host running the tasks must have the python requirements described in [requirements.txt](https://github.com/ansible-collections/vmware.vmware/blob/main/requirements.txt)
Once the collection is installed, you can install them into a python environment using pip: `pip install -r ~/.ansible/collections/ansible_collections/vmware/vmware/requirements.txt`

### Ansible version compatibility

This collection has been tested against following Ansible versions: **>=2.16.0**.


## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```sh
ansible-galaxy collection install vmware.vmware
```

You can also include it in a requirements.yml file and install it with `ansible-galaxy collection install -r requirements.yml`, using the format:

```sh
collections:
  - name: vmware.vmware
```

Note that if you install the collection from Ansible Galaxy, it will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```sh
ansible-galaxy collection install vmware.vmware --upgrade
```

You can also install a specific version of the collection, for example, if you need to install a different version. Use the following syntax to install version 1.0.0:

```sh
ansible-galaxy collection install vmware.vmware:1.0.0
```


## Use Cases

* Use Case Name: Create and Configure Cluster Services
  * Actors:
    * System Admin
  * Description:
    * A systems administrator can create a new vCenter cluster and ensure services are configured correctly.
  * Flow:
    * `vmware.vmware.cluster` - Create a new cluster if it's missing
    * `vmware.vmware.cluster_drs` - Configure cluster DRS settings to ensure correct state
    * `vmware.vmware.cluster_vcls` - Configure cluster vCLS settings to ensure correct state

* Use Case Name: Gather Information About Resources
  * Actors:
    * System Admin
  * Description:
    * The system administrator can gather detailed information about a variety of resources for reporting.
  * Flow:
    * `vmware.vmware.appliance_info` - Gather details about one or more appliances running
    * `vmware.vmware.guest_info` - Gather details about one or more VMs running
    * `vmware.vmware.license_info` - Gather details about one or more licenses used in vCenter or ESXi
    * `vmware.vmware.vm_list_group_by_clusters_info` - Gather VMs and list them grouped by cluster and folder
    * `vmware.vmware.vm_portgroup_info` - Gather details about networks attached to VMs


## Testing

All releases will meet the following test criteria.

* 100% success for [Integration](https://github.com/ansible-collections/vmware.vmware/blob/main/tests/integration) tests.
* 100% success for [Unit](https://github.com/ansible-collections/vmware.vmware/blob/main/tests/unit) tests.
* 100% success for [Sanity](https://docs.ansible.com/ansible/latest/dev_guide/testing/sanity/index.html#all-sanity-tests) tests as part of [ansible-test](https://docs.ansible.com/ansible/latest/dev_guide/testing.html#run-sanity-tests).
* 100% success for [ansible-lint](https://ansible.readthedocs.io/projects/lint/) allowing only false positives.


## Contributing

This community is currently accepting contributions. We encourage you to open [git issues](https://github.com/ansible-collections/vmware.vmware/issues) for bugs, comments or feature requests. Please feel free to submit a PR to resolve the issue.

Refer to the [Ansible community guide](https://docs.ansible.com/ansible/devel/community/index.html).


## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.
  * [Posts tagged with 'vmware'](https://forum.ansible.com/tag/vmware): subscribe to participate in collection-related conversations.
  * [Ansible VMware Automation Working Group](https://forum.ansible.com/g/ansible-vmware): by joining the team you will automatically get subscribed to the posts tagged with ['vmware'](https://forum.ansible.com/tag/vmware).
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).


## Support

As Red Hat Ansible [Certified Content](https://catalog.redhat.com/software/search?target_platforms=Red%20Hat%20Ansible%20Automation%20Platform), this collection is entitled to [support](https://access.redhat.com/support/) through [Ansible Automation Platform](https://www.redhat.com/en/technologies/management/ansible) (AAP).

If a support case cannot be opened with Red Hat and the collection has been obtained either from [Galaxy](https://galaxy.ansible.com/ui/) or [GitHub](https://github.com/ansible-collections/vmware.vmware), there is community support available at no charge. Community support is limited to the collection; community support does not include any of the Ansible Automation Platform components or [ansible-core](https://github.com/ansible/ansible).


## Release Notes and Roadmap

A list of available releases can be found on the github [release page](https://github.com/ansible-collections/vmware.vmware/releases).
A changelog may be found attached to the release, or in the [CHANGELOG.rst](https://github.com/ansible-collections/vmware.vmware/blob/main/CHANGELOG.rst)

Note, some collections release before an ansible-core version reaches End of Life (EOL), thus the version of ansible-core that is supported must be a version that is currently supported.
For AAP users, to see the supported ansible-core versions, review the [AAP Life Cycle](https://access.redhat.com/support/policy/updates/ansible-automation-platform).
For Galaxy and GitHub users, to see the supported ansible-core versions, review the [ansible-core support matrix](https://docs.ansible.com/ansible/latest/reference_appendices/release_and_maintenance.html#ansible-core-support-matrix).


## Related Information

The `vmware.vmware_rest` collection offers additional REST only functionality. It is also a certified collection.
The `community.vmware` collection offers additional community supported functionality.


## License Information

GNU General Public License v3.0 or later
See [LICENSE](https://github.com/ansible-collections/vmware.vmware/blob/main/LICENSE) to see the full text.
