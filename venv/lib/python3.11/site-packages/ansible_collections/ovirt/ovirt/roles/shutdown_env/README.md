oVirt environment shutdown
=========

The `shutdown_env` role iterates through all the entities (vms and hosts) in an oVirt/RHV cluster and performs a clean and ordered shutdown.
It also handles an Hosted-Engine and hyper-converged GlusterFS environment as a special case automatically detecting it.
The role is intended to be run only against the engine machine.
Please note that host shutdown is async and the playbook terminates before HE hosts are really down.

If on an Hosted-Engine environment, global maintenance mode will be set:
the user has to manually exit it in order to get the engine VM automatically powered up once needed.

A startup mode is also available:
in the startup mode the role will bring up all the power management configured hosts and it
will unset the global maintenance mode if on an hosted-engine environment.
The startup mode will be executed only if the 'startup' tag is applied; shutdown mode is the default.
The startup mode requires the engine to be already up:
power on it if it's a dedicated host, power on at least one of HE hosts (2 if on an hyperconverged env) and exit the global maintenance mode or manually start the engine VM with hosted-engine --vm-start

According to host power on order the engine could elect a new SPM host or reconstruct the master storage domain.
The environment can take up to 10 minutes to come back to a stable condition.
Possible improvements are tracked here: https://bugzilla.redhat.com/1609029

Example Playbook
----------------

```yaml
---
- name: oVirt shutdown environment
  hosts: localhost
  connection: local
  gather_facts: false

  vars:
    engine_url: https://ovirt-engine.example.com/ovirt-engine/api
    engine_user: admin@internal
    engine_password: 123456
    engine_cafile: /etc/pki/ovirt-engine/ca.pem

  roles:
    - role: shutdown_env
  collections:
    - ovirt.ovirt
```

Demo
----
 Here a demo showing a clean and ordered shutdown of an hyper-converged hosted-engine environment with 3 hosts, 3 regular VMs plus the HE one.
[![asciicast](https://asciinema.org/a/261501.svg)](https://asciinema.org/a/261501)

License
-------

Apache License 2.0
