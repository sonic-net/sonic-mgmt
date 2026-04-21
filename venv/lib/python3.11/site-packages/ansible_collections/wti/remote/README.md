WTI Ansible Collection
=========

This [Ansible](https://www.ansible.com/) collection provides a set of platform dependent configuration
 management modules specifically designed for  [WTI OOB and PDU devices](https://wti.com/) .

Requirements
------------

* Python 3.5+
* Ansible 2.9.0 or later
* Supported WTI firmware (DSM/CPM v6.58+, VMR 2.15+)
* Configuration command needs a user with Administrator privileges



Installation
-------


Through Galaxy:

```
ansible-galaxy collection install wti.remote
```


Inventory Variables
--------------

The common variables that should be defined in your inventory for your WTI host are:

* `cpm_url`: IP address or name of device.  
* `cpm_username`: Username for device in `plaintext` format  
* `cpm_password`: Password for device in `plaintext` format  
* `use_https`: Set `True` or `False` depending on if Ansible should use a secure https connection  
* `validate_certs`: Set `True` or `False` depending on if Ansible should attempt to validate certificates  
* `use_proxy`: Set `True` or `False` depending if Ansible should bypass environment proxies to connect to the WTI device   


Playbooks
--------------

Playbooks are available on Github to interact with the WTI Ansible Collection:

[WTI Ansible Collection Playbook Location.](https://github.com/wtinetworkgear/wti-collection-playbooks)


Contribution
-------
At WTI we're dedicated to ensuring the quality of our products, if you find any
issues at all please open an issue on our [Github](https://github.com/wtinetworkgear/wti-collection) and we'll be sure to respond promptly!
Or you can always email us directly at support@wti.com


License
-------

Apache-2.0

Author Information
------------------
 - Ken Partridge (@wtinetworkgear)
