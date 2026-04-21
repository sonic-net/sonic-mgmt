# How to build an Ansible Execution Environment

## Prerequisites
This was tested with ansible-builder version 1.1.0.

## Building from Galaxy
Using the files in the ansible_collections/netapp/cloudmanager/execution_environments/from_galaxy directory as a template:
- execution-environment.yml     describes the build environment.
- requirements.yml              defines the collections to add into you execution environment.

Then build with:

```
ansible-builder build
```

For instance, using podman instead of docker, and tagging:
```
ansible-builder build --container-runtime=podman --tag myregistry.io/ansible-ee-netapp-cm:21.20.1 -f execution-environment.yml -v 3
```

In my case, I needed to use sudo.

## Building from GitHub
Alternativaly, the source code can be downloaded from GitHub.  It allows to get code before release (at your own risks) or to use a fork.
See ansible_collections/netapp/cloudmanager/execution_environments/from_github/requirements.yml

## References

https://ansible-builder.readthedocs.io/en/stable/usage/

https://docs.ansible.com/automation-controller/latest/html/userguide/ee_reference.html


