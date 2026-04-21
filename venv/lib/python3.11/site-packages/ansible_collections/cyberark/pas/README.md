# CyberArk Ansible Security Automation Collection

<!-- please note this has to be a absolute URL since otherwise it will not show up on galaxy.ansible.com -->
![cyberark logo|](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/images/full-cyberark-logo.jpg?raw=true)

## Description

This collection is the CyberArk Ansible Security Automation project and can be found on [ansible galaxy](https://galaxy.ansible.com/cyberark/pas). This is aimed to enable the automation of securing privileged access by storing privileged accounts in the Enterprise Password Vault (EPV), controlling user's access to privileged accounts in EPV, and securely retreiving secrets using Application Access Manager (AAM).
The collection includes [support for Event-Driven Ansible](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_eda.md) by providing an event-source plugin for syslog and also guidance on how to use it. 

## Requirements

- Ansible Core 2.13.x or above
- CyberArk Privileged Account Security Web Services SDK
- CyberArk AAM Central Credential Provider (**Only required for cyberark_credential**)

## Installation

Before using this collection, you need to install it with the Ansible Galaxy command-line tool:

```
ansible-galaxy collection install cyberark.pas
```

You can also include it in a requirements.yml file and install it with ansible-galaxy collection install -r requirements.yml, using the format:


```yaml
collections:
  - name: cyberark.pas
```

Note that if you install any collections from Ansible Galaxy, they will not be upgraded automatically when you upgrade the Ansible package.
To upgrade the collection to the latest available version, run the following command:

```
ansible-galaxy collection install cyberark.pas --upgrade
```

You can also install a specific version of the collection, for example, if you need to downgrade when something is broken in the latest version (please report an issue in this repository). Use the following syntax to install version 1.0.0:

```
ansible-galaxy collection install cyberark.pas:==1.0.0
```

See [using Ansible collections](https://docs.ansible.com/ansible/devel/user_guide/collections_using.html) for more details.

## Use Cases

There is a list of different modules to perform different tasks:

- Add, Delete, Update CyberArk Users
- Add, Delete, Update CyberArk Accounts
- Rotate Account Credentials

### Modules

#### cyberark_authentication

- Using the CyberArk Web Services SDK, authenticate and obtain an auth token to be passed as a variable in playbooks
- Logoff of an authenticated REST API session<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_authentication.md)

#### cyberark_user

- Add a CyberArk User
- Delete a CyberArk User
- Update a CyberArk User's account parameters
    - Enable/Disable, change password, mark for change at next login, etc
<br>[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_user.md)<br/>

#### cyberark_account

- Add Privileged Account to the EPV
- Delete account objects
- Modify account properties
- Rotate privileged credentials
- Retrieve account password<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_account.md)

#### cyberark_credential

- Using AAM Central Credential Provider (CCP), to securely retreive secrets and account properties from EPV to be registered for use in playbooks<br>
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/cyberark_credential.md)

### Roles

#### aimprovider

- Install agent-based Credential Provider (AIM) on Linux hosts
[Playbooks and Module Info](https://github.com/cyberark/ansible-security-automation-collection/blob/master/docs/aimprovider.md)

## Contributing

Please see the [contributing guidelines](https://github.com/cyberark/ansible-security-automation-collection/blob/master/CONTRIBUTING.md)

### Author Information
- CyberArk Business Development Technical Team 
    - @enunez-cyberark
    - @cyberark-bizdev

## Support

As Red Hat Ansible Certified Content, this collection is entitled to support through the Ansible Automation Platform (AAP) using the Create issue button on the top right corner. If a support case cannot be opened with Red Hat and the collection has been obtained either from Galaxy or GitHub, there may community help available on the [Ansible Forum](https://forum.ansible.com/).

## License

MIT License

Copyright (c) 2017 CyberArk

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

For the full license text see [LICENSE](https://github.com/cyberark/ansible-security-automation-collection/blob/master/LICENSE)