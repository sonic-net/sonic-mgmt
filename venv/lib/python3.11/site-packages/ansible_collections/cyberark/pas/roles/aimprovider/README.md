cyberark.pas.aimprovider
====================

Role to install/uninstall CyberArk's AIM Credential Provider.

Requirements
------------

- CyberArk Privileged Account Security Web Services SDK.
- `cyberark.pas` Collection from Ansible Galaxy or Automation Hub

Role Variables
--------------
```
# CyberArk's Privileged Account Security Web Services SDK api base URL (example: https://components.cyberark.local)
aimprovider_rest_api_url: ""

# Whether to validate certificates for REST api calls. If false, SSL certificates will not be validated. This should only be used on personally controlled sites using self-signed certificates.
aimprovider_validate_certs: true

# Zip file with distribution of AIM Provider (example: /tmp/binaries/RHELinux x64-Rls-v9.8.zip); this file is located in the Ansible server, and it will be copied to the Ansible nodes. It should point to the current version of AIM distribution to be used when delivering to the nodes in a central folder within the Ansible server.
aimprovider_aimprovider_zip_file_name: ""

# Folder name within the ZIP file that will be used. By default, it's taken from zip file name, for example: "RHELinux x64"
aimprovider_folder_name: '{{aimprovider_zip_file_name.split("/")[-1].split("-Rls")[0]}}'

# CyberArk location for App Provider user to be created
aimprovider_app_provider_user_location: "\\Applications"

# CyberArk Vault Address
aimprovider_vault_address: ""

# Whether to use shared logon authentication. If true, it will use the "Shared Logon Authentication" as described in the CyberArk's document "Privileged Account Security Web Services SDK Implementation Guide"
aimprovider_use_shared_logon_authentication: false

# aimprovider_state - can be "present"/"absent" for install/uninstall.
aimprovider_state: "present"
```


Additionally:
- **app_provider_user_group**: The name of the group the Provider user will be added to.

Dependencies
------------

None.


Example Playbook
----------------

1) Install CyberArk AIM Provider.

```
---
- hosts: all

  roles:

    - role: cyberark.pas.aimprovider
      aimprovider_api_base_url: "https://components.cyberark.local"
      aimprovider_validate_certs: false
      aimprovider_zip_file_name: "/tmp/binaries/RHELinux x64-Rls-v9.8.zip"
      aimprovider_vault_address: "10.0.1.10"
      aimprovider_use_shared_logon_authentication: true
```

2) Uninstall CyberArk AIM Provider.
```
---
- hosts: all

  roles:

    - role: cyberark.pas.aimprovider
      aimprovider_api_base_url: "https://components.cyberark.local"
      aimprovider_use_shared_logon_authentication: true
      aimprovider_state: "absent"
      aimprovider_validate_certs: false
```

License
-------

MIT

Author Information
------------------

- Edward Nunez (edward.nunez@cyberark.com)
