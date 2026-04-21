# powerflex_webui

Role to manage the installation and uninstallation of Powerflex Web UI.

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
    <td>The port of the PowerFlex gateway.</td>
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
    <td>false</td>
    <td>Location of installation, compatible installation software package based on the operating system of the node.
    <br> The files can be downloaded from the Dell Product support page for PowerFlex software.</td>
    <td></td>
    <td>path</td>
    <td>/var/tmp</td>
  </tr>
  <tr>
    <td>powerflex_webui_skip_java</td>
    <td>false</td>
    <td>Specifies whether to install java or not.<br></td>
    <td></td>
    <td>bool</td>
    <td>false</td>
  </tr>
  <tr>
    <td>powerflex_webui_state</td>
    <td>false</td>
    <td>Specify state of web UI.
    <br>present will install the web UI and absent will uninstall the web UI.</td>
    <td>absent, present</td>
    <td>str</td>
    <td>present</td>
  </tr>
</tbody>
</table>

## Examples
----
```
  - name: Install and configure powerflex web UI
    ansible.builtin.import_role:
      name: "powerflex_webui"
    vars:
      hostname: "{{ hostname }}"
      username: "{{ username }}"
      password: "{{ password }}"
      validate_certs: "{{ validate_certs }}"
      port: "{{ port }}"
      powerflex_common_file_install_location: "/opt/scaleio/rpm"
      powerflex_webui_skip_java: true
      powerflex_webui_state: present

  - name: Uninstall powerflex web UI
    ansible.builtin.import_role:
      name: "powerflex_webui"
    vars:
      powerflex_webui_state: absent

```
## Notes
- Supported only in PowerFlex version 3.6.

## Usage instructions
----
### To install all dependency packages, including web UI, on node:
  ```
  ansible-playbook -i inventory site.yml
  ```

### To uninstall web UI:
  ```
  ansible-playbook -i inventory uninstall_powerflex.yml
  ```

Sample playbooks and inventory can be found in the playbooks directory.

## Author Information
------------------

Dell Technologies <br>
Trisha Datta (ansible.team@Dell.com)  2023
