# Ansible Modules for Meraki

The Meraki-Ansible project provides an Ansible collection for managing and automating your Cisco Meraki environment. It consists of a set of modules and roles for performing tasks related to Meraki.

# Quick Start Guide

## Installation
1. Ansible must be installed just in case needed. Check if your environment does not provide it. Example AAP. ([Install guide](https://docs.ansible.com/ansible/latest/installation_guide/intro_installation.html))
```
pip install ansible-core
```

2. Python Meraki SDK must be installed
```
pip install meraki
```

3. Install the collection ([Galaxy link](https://galaxy.ansible.com/cisco/meraki))
```
ansible-galaxy collection install cisco.meraki -f
```
## Initial Configuration

1. First, your Meraki API key needs to be available for the playbook to use. You can leverage environment variables `export MERAKI_DASHBOARD_API_KEY=6bec40cf957de430a6f1f2baa056b99a4fac9ea0`, or create a `credentials.yml` ([example](https://github.com/meraki/dashboard-api-ansible/blob/main/playbooks/credentials.yml) file.
**Note:** Storing your API key in an unencrypted text file is not recommended for security reasons.
2. Create a `hosts` ([example](https://github.com/meraki/dashboard-api-ansible/blob/main/playbooks/hosts)) file that uses `[meraki_servers]` with your Cisco Meraki Settings:
```
[meraki_servers]
meraki_server
```
3. Running your first "Hello, world" in Ansible
Create a playbook `who_am_i.yml` ([example](https://github.com/meraki/dashboard-api-ansible/blob/main/playbooks/who_am_i.yml)):
```
---
- name: Play Name
  hosts: meraki_servers
  gather_facts: false
  tasks:
    - name: Get my administered identities
      cisco.meraki.administered_identities_me_info:
      register: result

    - name: Show result
      ansible.builtin.debug:
        msg: "{{ result }}"
```
This is a simple playbook that will (1) get the information about the Meraki admin user the API key belongs to and (2) print the information on the screen.

Execute the playbook:
```
ansible-playbook -i hosts who_am_i.yml
```
4. Congratulations! You have just run your first Ansible playbook!

- - -
# Detailed Information

This collection has been tested and supports Cisco Meraki Dashboard API v1.33.0

*Note: This collection is not compatible with versions of Ansible before v2.14.*

Other versions of this collection have support for previous Cisco Meraki versions. The recommended versions are listed below on the [Compatibility matrix](https://github.com/meraki/dashboard-api-ansible#compatibility-matrix).

## Compatibility matrix

| Cisco Meraki version | Ansible "cisco.meraki" version | Python "DashboardAPI" version |
|--------------------------|------------------------------|-------------------------------|
| 1.33.0                    | 2.17.0                      |1.33.0                         |
| 1.44.1                    | 2.18.3                      |1.44.1                         |
| 1.53.0                    | 2.20.8                      |1.53.0                         |
| 1.57.0                    | 2.21.2                      |1.57.0                         |

*Notes*:

1. The "Python `meraki` SDK version" column has the minimum recommended version used when testing the Ansible collection. This means you could use later versions of the Python "meraki" than those listed.
2. The "Cisco Meraki version" column has the value of the `meraki_version` you should use for the Ansible collection.

## Requirements
- Ansible >= 2.9
- [Python Meraki SDK](https://github.com/meraki/dashboard-api-python) v1.33.0 or newer
- Python >= 3.6, as the Meraki SDK doesn't support Python version 2.x

## Attention macOS users

If you're using macOS you may receive this error when running your playbook:

```
objc[34120]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called.
objc[34120]: +[__NSCFConstantString initialize] may have been in progress in another thread when fork() was called. We cannot safely call it or ignore it in the fork() child process. Crashing instead. Set a breakpoint on objc_initializeAfterForkError to debug.
ERROR! A worker was found in a dead state
```

If that's the case try setting this environment variable:
```
export OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES
```

## Additional Resources
1. [Meraki's Ansible Collection Documentation](https://docs.ansible.com/ansible/latest/collections/cisco/meraki/index.html)
2. [Meraki Dashboard API Documentation](https://meraki.io/api)
3. [DevNet Learning Lab](https://developer.cisco.com/learning/labs/meraki-dashboard-ansible/introduction/)
4. [DevNet Sandbox](https://devnetsandbox.cisco.com/RM/Diagram/Index/a9487767-deef-4855-b3e3-880e7f39eadc?diagramType=Topology)

## Contributing to this collection

Ongoing development efforts and contributions to this collection are tracked as issues in this repository.

We welcome community contributions to this collection. If you find problems, need an enhancement or need a new module, please open an issue or create a PR against the [Cisco Meraki Ansible collection repository](https://github.com/meraki/dashboard-api-ansible/issues).

## Code of Conduct
This collection follows the Ansible project's
[Code of Conduct](https://docs.ansible.com/ansible/devel/community/code_of_conduct.html).
Please read and familiarize yourself with this document.

## Releasing, Versioning and Deprecation

This collection follows [Semantic Versioning](https://semver.org/). More details on versioning can be found [in the Ansible docs](https://docs.ansible.com/ansible/latest/dev_guide/developing_collections.html#collection-versions).

New minor and major releases as well as deprecations will follow new releases and deprecations of the Cisco Meraki product, its REST API and the corresponding Python SDK, which this project relies on. 


## New collection modules

The modules that were there before, usually with a `meraki` prefix, are maintained until version 2.x.x, with the same structure used in previous versions. The old modules will disappear in the next major release and only the new modules will remain. Each old module has its deprecation marking, indicating which is the new equivalent.

### Example
- Old module:
```
  - name: Create webhook
    cisco.meraki.meraki_webhook:
      auth_key: abc123
      state: present
      org_name: YourOrg
      net_name: YourNet
      name: Test_Hook
      url: https://webhook.url/
      shared_secret: shhhdonttellanyone
      payload_template_name: 'Slack (included)'
    delegate_to: localhost
```
- New module:
```
  - name: Create webhook
    cisco.meraki.networks_webhooks_http_servers:
      meraki_api_key: "{{ meraki_api_key }}"
      state: present
      name: Test_Hook
      networkId: "{{ network_id }}"
      payloadTemplate:
        name: Slack (included)
        payloadTemplateId: wpt_00001
      sharedSecret: shhhdonttellanyone
      url: https://webhook.url/
```

## License

This project is licensed under the [GNU General Public License](https://github.com/meraki/dashboard-api-ansible/blob/main/LICENSE).
