#!/bin/sh

namespace=$(grep -w "namespace" galaxy.yml |  awk  '{print $2}')
name=$(grep -w "name" galaxy.yml |  awk  '{print $2}')
version=$(grep -w "version" galaxy.yml |  awk  '{print $2}')
collection_file="$namespace-$name-$version.tar.gz"
#echo "$collection_file"

rm -f /root/ansible_log.log
rm -rf /root/.ansible/collections/ansible_collections/dellemc/enterprise_sonic
rm "$collection_file"
ansible-galaxy collection build

ansible-galaxy collection install "$collection_file" --force #-with-deps

# ansible-playbook -i playbooks/common_examples/hosts playbooks/common_examples/sonic_l3_interfaces.yaml -vvvv
# ansible-playbook -i playbooks/common_examples/hosts playbooks/common_examples/sonic_l3_interfaces_config.yaml -vvvv
# ansible-playbook -i playbooks/common_examples/hosts playbooks/common_examples/sonic_l3_interfaces_test.yaml -vvvv
# ansible-playbook -i playbooks/common_examples/hosts -vvvv playbooks/common_examples/sonic_bgp_extcommunities.yaml -vvvv
# ansible-playbook -i playbooks/common_examples/hosts -vvvv playbooks/common_examples/sonic_bgp_extcommunities_config.yaml -vvv
# ansible-playbook -i playbooks/common_examples/hosts -vvvv playbooks/common_examples/test.yml -vvvv
# ansible-playbook -i playbooks/common_examples/hosts -vvvv playbooks/common_examples/sonic_bgp_as_paths_config.yaml -vvvv
