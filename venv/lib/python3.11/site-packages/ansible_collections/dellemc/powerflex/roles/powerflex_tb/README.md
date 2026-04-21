# powerflex_tb

Role to manage the installation and uninstallation of Powerflex TB.

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
    <td>IP or FQDN of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>username</td>
    <td>true</td>
    <td>The username of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>password</td>
    <td>true</td>
    <td>The password of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>port</td>
    <td>false</td>
    <td>Port of the PowerFlex gateway.</td>
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
    <td>Timeout.</td>
    <td></td>
    <td>int</td>
    <td>120</td>
  </tr>
  <tr>
    <td>powerflex_common_file_install_location</td>
    <td>false</td>
    <td>Location of installation and rpm gpg files to be installed.
    <br>The required, compatible installation software package based on the operating system of the node.
    <br> The files can be downloaded from the Dell Product support page for PowerFlex software.</td>
    <td></td>
    <td>str</td>
    <td>/var/tmp</td>
  </tr>
  <tr>
    <td>powerflex_tb_state</td>
    <td>false</td>
    <td>Specify state of TB.<br></td>
    <td>absent, present</td>
    <td>str</td>
    <td>present</td>
  </tr>
  <tr>
    <td>powerflex_tb_primary_name</td>
    <td>false</td>
    <td>Name of the primary TB.<br></td>
    <td></td>
    <td>str</td>
    <td>primary_tb</td>
  </tr>
  <tr>
    <td>powerflex_tb_secondary_name</td>
    <td>false</td>
    <td>Name of the secondary TB.<br></td>
    <td></td>
    <td>str</td>
    <td>secondary_tb</td>
  </tr>
  <tr>
    <td>powerflex_tb_cluster_mode</td>
    <td>false</td>
    <td>Mode of the cluster.<br></td>
    <td>ThreeNodes, FiveNodes</td>
    <td>str</td>
    <td>ThreeNodes</td>
  </tr>
  <tr>
    <td>powerflex_tb_cert_password</td>
    <td>false</td>
    <td>The CLI certificate password for login to the primary MDM.<br></td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: Install and configure PowerFlex TB
    ansible.builtin.import_role:
      name: "powerflex_tb"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_tb_primary_name: "primary_tb"
      powerflex_tb_secondary_name: "secondary_tb"
      powerflex_tb_cluster_mode: "ThreeNodes"
      powerflex_common_file_install_location: "/var/tmp"
      powerflex_tb_state: present

  - name: Uninstall powerflex TB
    ansible.builtin.import_role:
      name: "powerflex_tb"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_tb_state: 'absent'

```

## Notes
----

- As a pre-requisite for PowerFlex 3.6, the Gateway must be installed.
- For PowerFlex 4.x, after installing the TB perform initial configuration steps on PowerFlex Manager GUI. These steps can be found in Install and Update of Dell PowerFlex 4.x from Dell Support page.

## Usage instructions
----
### To install all dependency packages, including TB, on node:
- PowerFlex 3.6:
  ```
  ansible-playbook -i inventory site.yml
  ```
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory site_powerflex45.yml
  ```

### To uninstall TB:
- PowerFlex 3.6:
  ```
  ansible-playbook -i inventory uninstall_powerflex.yml
  ```
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory uninstall_powerflex45.yml
  ```

Sample playbooks and inventory can be found in the playbooks directory.

## Author Information
------------------

Dell Technologies <br>
Ananthu S Kuttattu (ansible.team@Dell.com)  2023
