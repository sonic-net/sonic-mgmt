# powerflex_sdt

Role to manage the installation and uninstallation of Powerflex SDT.

## Table of contents

* [Requirements](#requirements)
* [Ansible collections](#ansible-collections)
* [Role Variables](#role-variables)
* [Examples](#examples)
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
    <td>10.1.1.1</td>
  </tr>
  <tr>
    <td>username</td>
    <td>true</td>
    <td>The username of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td>admin</td>
  </tr>
  <tr>
    <td>password</td>
    <td>true</td>
    <td>The password of the PowerFlex gateway.</td>
    <td></td>
    <td>str</td>
    <td>password</td>
  </tr>
  <tr>
    <td>port</td>
    <td>false</td>
    <td>Port</td>
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
    <td>Timeout</td>
    <td></td>
    <td>int</td>
    <td>120</td>
  </tr>
    <tr>
    <td>powerflex_common_file_install_location</td>
    <td>true</td>
    <td>Location of installation and rpm gpg files to be installed.
    <br>The required, compatible installation software package based on the operating system of the node.
    <br>The files can be downloaded from the Dell Product support page for PowerFlex software.</td>
    <td></td>
    <td>str</td>
    <td>/var/tmp</td>
  </tr>
    <tr>
    <td>powerflex_sdt_discovery_port</td>
    <td>false</td>
    <td>Port used by the NVMe hosts for discovery. Set to 1 in order to indicate no use of discovery port.</td>
    <td></td>
    <td>int</td>
    <td>8009</td>
  </tr>
  <tr>
    <td>powerflex_sdt_ip_list</td>
    <td>true</td>
    <td>Target IP list of SDT. Comma separated.</td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sdt_nvme_port</td>
    <td>false</td>
    <td>Port used by the NVMe hosts</td>
    <td></td>
    <td>int</td>
    <td>4420</td>
  </tr>
  <tr>
    <td>powerflex_sdt_protection_domain</td>
    <td>true</td>
    <td>The name of the protection domain to which the SDT will be added.
    </td>
    <td></td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sdt_role_list</td>
    <td>true</td>
    <td>Role list of SDT target IP. Comma separated.</td>
    <td>storage_only, host_only, storage_and_host</td>
    <td>str</td>
    <td></td>
  </tr>
  <tr>
    <td>powerflex_sdt_state</td>
    <td>false</td>
    <td>State of the SDT.</td>
    <td>present, absent</td>
    <td>str</td>
    <td>present</td>
  </tr>
  <tr>
    <td>powerflex_sdt_storage_port</td>
    <td>false</td>
    <td>Port assigned to the SDT.</td>
    <td></td>
    <td>int</td>
    <td>12200</td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: "Install and configure powerflex SDT"
    ansible.builtin.import_role:
      name: "powerflex_sdt"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_sdt_protection_domain: PD1
      powerflex_sdt_storage_port: 12200
      powerflex_sdt_nvme_port: 4420
      powerflex_sdt_discovery_port: 8009
      powerflex_sdt_state: present

  - name: "Uninstall powerflex SDT"
    ansible.builtin.import_role:
      name: "powerflex_sdt"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_sdt_state: 'absent'

```

## Usage instructions
----
### To install all dependency packages, including SDT, on node:
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory site_powerflex45.yml
  ```

### To uninstall SDT:
- PowerFlex 4.5:
  ```
  ansible-playbook -i inventory uninstall_powerflex45.yml
  ```

Sample playbooks and inventory can be found in the playbooks directory.

## Author Information
------------------

Dell Technologies
Yuhao Liu (yuhao_liu@Dell.com)  2024