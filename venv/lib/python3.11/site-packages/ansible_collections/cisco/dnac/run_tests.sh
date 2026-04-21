#!/bin/bash -eux

ROLES_TO_EXECUTE=$*
echo "${ROLES_TO_EXECUTE}"

cat <<EOF >>ccc_test_roles.yml
---
- hosts: dnac_servers
  gather_facts: no
  connection: local
  tasks:
  
  vars:
    debug: false

  roles:
EOF

for role in $ROLES_TO_EXECUTE
do
    echo "    - $role" >> ccc_test_roles.yml
done

ansible-playbook -i hosts ccc_test_roles.yml
