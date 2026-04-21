<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Community RouterOS Collection
[![Documentation](https://img.shields.io/badge/docs-brightgreen.svg)](https://docs.ansible.com/ansible/devel/collections/community/routeros/)
[![CI](https://github.com/ansible-collections/community.routeros/actions/workflows/nox.yml/badge.svg?branch=main)](https://github.com/ansible-collections/community.routeros/actions)
[![Codecov](https://img.shields.io/codecov/c/github/ansible-collections/community.routeros)](https://codecov.io/gh/ansible-collections/community.routeros)
[![REUSE status](https://api.reuse.software/badge/github.com/ansible-collections/community.routeros)](https://api.reuse.software/info/github.com/ansible-collections/community.routeros)

Provides modules for [Ansible](https://www.ansible.com/community) to manage [MikroTik RouterOS](https://mikrotik.com/software) instances.

You can find [documentation for the modules and plugins in this collection here](https://docs.ansible.com/ansible/devel/collections/community/routeros/).

## Code of Conduct

We follow [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html) in all our interactions within this project.

If you encounter abusive behavior violating the [Ansible Code of Conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html), please refer to the [policy violations](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html#policy-violations) section of the Code of Conduct for information on how to raise a complaint.

## Communication

* Join the Ansible forum:
  * [Get Help](https://forum.ansible.com/c/help/6): get help or help others.Please add appropriate tags if you start new discussions, for example the `routeros` tag.
  * [Posts tagged with 'routeros'](https://forum.ansible.com/tag/routeros): subscribe to participate in RouterOS related conversations.
  * [Social Spaces](https://forum.ansible.com/c/chat/4): gather and interact with fellow enthusiasts.
  * [News & Announcements](https://forum.ansible.com/c/news/5): track project-wide announcements including social events.

* The Ansible [Bullhorn newsletter](https://docs.ansible.com/ansible/devel/community/communication.html#the-bullhorn): used to announce releases and important changes.

For more information about communication, see the [Ansible communication guide](https://docs.ansible.com/ansible/devel/community/communication.html).

## Tested with Ansible

Tested with the current ansible-core 2.15, ansible-core 2.16, ansible-core 2.17, ansible-core 2.18, and ansible-core 2.19 releases and the current development version of ansible-core. Ansible 2.9, ansible-base 2.10, and ansible-core versions before 2.15.0 are not supported.

## External requirements

The exact requirements for every module are listed in the module documentation.

### Supported connections

The collection supports the `network_cli` connection.

### Edge cases

Please note that `community.routeros.api` module does **not** support Windows jump hosts!

## Collection Documentation

Browsing the [**latest** collection documentation](https://docs.ansible.com/ansible/latest/collections/community/routeros) will show docs for the _latest version released in the Ansible package_, not the latest version of the collection released on Galaxy.

Browsing the [**devel** collection documentation](https://docs.ansible.com/ansible/devel/collections/community/routeros) shows docs for the _latest version released on Galaxy_.

We also separately publish [**latest commit** collection documentation](https://ansible-collections.github.io/community.routeros/branch/main/) which shows docs for the _latest commit in the `main` branch_.

If you use the Ansible package and do not update collections independently, use **latest**. If you install or update this collection directly from Galaxy, use **devel**. If you are looking to contribute, use **latest commit**.

## Included content

- `community.routeros.api`
- `community.routeros.api_facts`
- `community.routeros.api_find_and_modify`
- `community.routeros.api_info`
- `community.routeros.api_modify`
- `community.routeros.command`
- `community.routeros.facts`

You can find [documentation for the modules and plugins in this collection here](https://docs.ansible.com/ansible/devel/collections/community/routeros/).

## Using this collection

See [Ansible Using collections](https://docs.ansible.com/ansible/latest/user_guide/collections_using.html) for general detail on using collections.

There are two approaches for using this collection. The `command` and `facts` modules use the `network_cli` connection and connect with SSH. The `api` module connects with the HTTP/HTTPS API.

### Prerequisites

The terminal-based modules in this collection (`community.routeros.command` and `community.routeros.facts`) do not support arbitrary symbols in router's identity. If you are having trouble connecting to your device, please make sure that your MikroTik's identity contains only alphanumeric characters and dashes. Also, the `community.routeros.command` module does not support nesting commands and expects every command to start with a forward slash (`/`). Running the following command will produce an error.

```yaml
- community.routeros.command:
    commands:
      - /ip
      - print
```

### Connecting with `network_cli`

Example inventory `hosts` file:

```.ini
[routers]
router ansible_host=192.168.1.1

[routers:vars]
ansible_connection=ansible.netcommon.network_cli
ansible_network_os=community.routeros.routeros
ansible_user=admin
ansible_ssh_pass=test1234
```

Example playbook:

```.yaml
---
- name: RouterOS test with network_cli connection
  hosts: routers
  gather_facts: false
  tasks:
    - name: Run a command
      community.routeros.command:
        commands:
          - /system resource print
      register: system_resource_print
    - name: Print its output
      ansible.builtin.debug:
        var: system_resource_print.stdout_lines

    - name: Retrieve facts
      community.routeros.facts:
    - ansible.builtin.debug:
        msg: "First IP address: {{ ansible_net_all_ipv4_addresses[0] }}"
```

### Connecting with HTTP/HTTPS API

Example playbook:

```.yaml
---
- name: RouterOS test with API
  hosts: localhost
  gather_facts: false
  vars:
    hostname: 192.168.1.1
    username: admin
    password: test1234
  module_defaults:
    group/community.routeros.api:
      hostname: "{{ hostname }}"
      password: "{{ password }}"
      username: "{{ username }}"
      tls: true
      force_no_cert: false
      validate_certs: true
      validate_cert_hostname: true
      ca_path: /path/to/ca-certificate.pem
  tasks:
    - name: Get "ip address print"
      community.routeros.api:
        path: ip address
      register: print_path
    - name: Print the result
      ansible.builtin.debug:
        var: print_path.msg

    - name: Change IP address to 192.168.1.1 for interface bridge
      community.routeros.api_find_and_modify:
        path: ip address
        find:
          interface: bridge
        values:
          address: "192.168.1.1/24"

    - name: Retrieve facts
      community.routeros.api_facts:
    - ansible.builtin.debug:
        msg: "First IP address: {{ ansible_net_all_ipv4_addresses[0] }}"
```

## Contributing to this collection

We're following the general Ansible contributor guidelines; see [Ansible Community Guide](https://docs.ansible.com/ansible/latest/community/index.html).

If you want to clone this repositority (or a fork of it) to improve it, you can proceed as follows:
1. Create a directory `ansible_collections/community`;
2. In there, checkout this repository (or a fork) as `routeros`;
3. Add the directory containing `ansible_collections` to your [ANSIBLE_COLLECTIONS_PATH](https://docs.ansible.com/ansible/latest/reference_appendices/config.html#collections-paths).

See [Ansible's dev guide](https://docs.ansible.com/ansible/devel/dev_guide/developing_collections.html#contributing-to-collections) for more information.

## Release notes

See the [collection's changelog](https://github.com/ansible-collections/community.routeros/blob/main/CHANGELOG.md).

## Roadmap

We plan to regularly release minor and patch versions, whenever new features are added or bugs fixed. Our collection follows [semantic versioning](https://semver.org/), so breaking changes will only happen in major releases.

## More information

- [Ansible Collection overview](https://github.com/ansible-collections/overview)
- [Ansible User guide](https://docs.ansible.com/ansible/latest/user_guide/index.html)
- [Ansible Developer guide](https://docs.ansible.com/ansible/latest/dev_guide/index.html)
- [Ansible Collections Checklist](https://github.com/ansible-collections/overview/blob/master/collection_requirements.rst)
- [Ansible Community code of conduct](https://docs.ansible.com/ansible/latest/community/code_of_conduct.html)
- [The Bullhorn (the Ansible Contributor newsletter)](https://us19.campaign-archive.com/home/?u=56d874e027110e35dea0e03c1&id=d6635f5420)
- [Changes impacting Contributors](https://github.com/ansible-collections/overview/issues/45)

## Licensing

This collection is primarily licensed and distributed as a whole under the GNU General Public License v3.0 or later.

See [LICENSES/GPL-3.0-or-later.txt](https://github.com/ansible-collections/community.routeros/blob/main/COPYING) for the full text.

Parts of the collection are licensed under the [BSD 2-Clause license](https://github.com/ansible-collections/community.routeros/blob/main/LICENSES/BSD-2-Clause.txt).

All files have a machine readable `SDPX-License-Identifier:` comment denoting its respective license(s) or an equivalent entry in an accompanying `.license` file. Only changelog fragments (which will not be part of a release) are covered by a blanket statement in `REUSE.toml`. This conforms to the [REUSE specification](https://reuse.software/spec/).
