#!/usr/bin/python

"""
Ansible module for reliably removing Docker containers.
"""

import time
from ansible.module_utils.basic import AnsibleModule

DOCUMENTATION = '''
---
module: docker_container_cleanup
short_description: Reliably remove Docker containers with force cleanup
'''

EXAMPLES = '''
- name: Remove container
  docker_container_cleanup:
    name: ceos_vm_t1_VM5301

- name: Remove container with custom timeout
  docker_container_cleanup:
    name: net_vm_t1_VM5301
    timeout: 120
'''


def container_exists(module, container_name):
    """Check if container still exists"""
    ret, stdout, _ = module.run_command(['docker', 'ps', '-a', '--format', '{{.Names}}'])
    if ret != 0:
        return False

    containers = [line.strip() for line in stdout.split('\n') if line.strip()]
    return container_name in containers


def remove_container(module, container_name):
    """
    Remove container using docker rm -f.

    Args:
        module: AnsibleModule instance
        container_name: Name of the container to remove

    Returns:
        tuple: (changed, message)
    """
    # Check if container exists
    if not container_exists(module, container_name):
        return False, f"Container {container_name} does not exist or already removed"

    # Try docker rm -f
    ret, stdout, stderr = module.run_command(['docker', 'rm', '-f', container_name])

    # Verify removal
    time.sleep(1)
    if not container_exists(module, container_name):
        return True, f"Container {container_name} removed successfully"
    else:
        return False, f"Failed to remove container {container_name}: {stderr}"


def main():
    module = AnsibleModule(
        argument_spec=dict(
            name=dict(type='str', required=True),
            timeout=dict(type='int', default=60, required=False),
        ),
        supports_check_mode=False
    )

    container_name = module.params['name']

    try:
        changed, message = remove_container(module, container_name)

        if changed or not container_exists(module, container_name):
            module.exit_json(
                changed=changed,
                msg=message,
                container=container_name
            )
        else:
            module.fail_json(
                msg=f"Failed to remove container {container_name}",
                details=message
            )

    except Exception as e:
        module.fail_json(msg=f"Error removing container {container_name}: {str(e)}")


if __name__ == '__main__':
    main()
