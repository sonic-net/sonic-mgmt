# powerflex_activemq

Role to manage the installation and uninstallation of Powerflex ActiveMQ.

## Table of contents

* [Requirements](#requirements)
* [Ansible collections](#ansible-collections)
* [Role Variables](#role-variables)
* [Examples](#examples)
* [Notes](#notes)
* [Usage instructions](#usage-instructions)
* [Author Information](#author-information)

## Requirements

```
ansible
python
```

## Ansible collections

Collections required to use the role.

```
dellemc.powerflex
```

## Role Variables

<table>
<thead>
  <tr>
    <th>Name</th>
    <th>Required</th>
    <th>Description</th>
    <th>Choices</th>
    <th>Type</th>
    <th>Default Value</th>
  </tr>
</thead>
<tbody>
  <tr>
    <td>hostname</td>
    <td>true</td>
    <td>IP or FQDN of the PowerFlex host.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>username</td>
    <td>true</td>
    <td>The username of the PowerFlex host.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>password</td>
    <td>true</td>
    <td>The password of the PowerFlex host.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>port</td>
    <td>false</td>
    <td>The port of the PowerFlex host.</td>
    <td></td>
    <td>int</td>
    <td>443</td>
  </tr>
  <tr>
    <td>validate_certs</td>
    <td>false</td>
    <td>If C(false), the SSL certificates will not be validated.<br>Configure C(false) only on personally controlled sites where self-signed certificates are used.</td>
    <td></td>
    <td>bool</td>
    <td>false</td>
  </tr>
  <tr>
    <td>timeout</td>
    <td>false</td>
    <td>Time after which connection will get terminated.</td>
    <td></td>
    <td>int</td>
    <td>120</td>
  </tr>
  <tr>
    <td>powerflex_common_file_install_location</td>
    <td>true</td>
    <td>Location of installation and rpm gpg files to be installed.
    <br>The required, compatible installation software package based on the operating system of the node. The files can be downloaded from the Dell Product support page for PowerFlex software.</td>
    <td></td>
    <td>path</td>
    <td>/var/tmp</td>
  </tr>
  <tr>
    <td>powerflex_activemq_state</td>
    <td>false</td>
    <td>Specify state of ActiveMQ.
    <br>present will install the ActiveMQ and absent will uninstall the ActiveMQ.</td>
    <td>absent, present</td>
    <td>str</td>
    <td>present</td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: Install and configure PowerFlex ActiveMQ
    ansible.builtin.import_role:
      name: powerflex_activemq
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_activemq_state: present

  - name: Uninstall powerflex ActiveMQ
    ansible.builtin.import_role:
      name: powerflex_activemq
    vars:
      powerflex_activemq_state: absent

```
## Notes
- Supported in PowerFlex version 4.x and above

## Usage instructions
----
### To install all dependency packages, including ActiveMQ, on node:
  ```
  ansible-playbook -i inventory site_powerflex45.yml
  ```

### To uninstall ActiveMQ:
  ```
  ansible-playbook -i inventory uninstall_powerflex45.yml
  ```

Sample playbooks and inventory can be found in the playbooks directory.

## Author Information
------------------

Dell Technologies<br>
Pavan Mudunuri (ansible.team@Dell.com)  2023
