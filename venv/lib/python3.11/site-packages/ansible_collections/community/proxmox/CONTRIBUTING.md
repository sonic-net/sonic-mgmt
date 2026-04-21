<!--
Copyright (c) Ansible Project
GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
SPDX-License-Identifier: GPL-3.0-or-later
-->

# Contributing

Refer to the [Ansible community guide](https://docs.ansible.com/ansible/devel/community/index.html).

# Making changelogs
When you make a change, please add a changelog fragment in [changelogs](changelogs), see below for some examples:

* Minor change, bugfixes or anything else small that does break existing tasks:
```
---
minor_changes:
  - module name - short description of the change, PR title could be fine (https://github.com/ansible-collections/community.proxmox/issues/XXX, https://github.com/ansible-collections/community.proxmox/pull/XXX).
```

* Breaking changes, anything that requires end-users to change something on their end as well:
```
---
breaking_changes:
  - module name - will start eating your dog without ``dont_eat_dog: true`` (https://github.com/ansible-collections/community.proxmox/issues/XXX, https://github.com/ansible-collections/community.proxmox/pull/XXX).
```

* Removed features:
```
---
removed_features:
  - Description of removed feature, module etc (https://github.com/ansible-collections/community.proxmox/issues/XXX, https://github.com/ansible-collections/community.proxmox/pull/XXX).
```

* Changelog entries for new modules and plugins are automatically generated (based on `version_added`), so do not add changelog fragments for them.
