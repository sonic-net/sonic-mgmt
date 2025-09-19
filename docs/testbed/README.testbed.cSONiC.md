# Transitioning Neighbor Devices to cSONiC in SONiC Testbed
This document outlines how to replace neighbor containers(cEOS, vEOS, vSONIC) in the SONiC community testbed with cSONiC containers, enabling a SONiC-to-SONiC test environment and the required design changes.

# Implementation Plan: Adding cSONiC Support in Testbed
To integrate cSONiC as a supported neighbor device in the SONiC testbed, several scripts and ansible roles must be updated to recognize and handle vm_type="csonic".

1. Update testbed-cli.sh.
Modify the CLI help text to include cSONiC as a valid VM type:

        echo "    -k <vmtype>     : vm type (veos|ceos|vsonic|vcisco|csonic) (default: 'ceos')"

   This ensures users can pass -k csonic when invoking the script.

2. Update testbed_add_vm_topology.yml. Add a new role entry for cSONiC in the roles section:

        roles:
         - { role: csonic, when: topology.VMs is defined and VM_targets is defined and inventory_hostname in VM_targets and (vm_type == "csonic") }`

3. Update roles/eos/tasks/main.yml. Add an include task for cSONiC similar to cEOS:

        - include_tasks: csonic.yml
          when: vm_type == "csonic"
4. Create roles/eos/tasks/csonic.yml
 
    This new task file will:
Include cSONiC-specific variables:

        - include_vars: group_vars/vm_host/csonic.yml
        - include_tasks: csonic_config.yml

5. Create roles/eos/tasks/csonic_config.yml

    Define configuration steps for cSONiC front panel and backplane ports.

6. Update ansible/group_vars/vm_host/main.yml
Add csonic to the list of supported VM types:
        
        supported_vm_types: [ "veos", "ceos", "vsonic", "vcisco", "csonic" ]
7. Create ansible/group_vars/vm_host/csonic.yml
Assign the cSONiC image file and URL:
        
        csonic_image_filename: docker-sonic-vs
        csonic_image: docker-sonic-vs
        csonic_image_url:
            - "http://example.com/docker-sonic-vs"
8. Modify roles/vm_set/tasks/add_topo.yml
Update cEOS network creation logic to also handle cSONiC:
        
        - include_tasks: add_ceos_list.yml
          when: vm_type is defined and (vm_type == "ceos" or vm_type == "csonic")
9. Create ansible/roles/vm_set/library/cnet_network.py
for creating container network interfaces (management, front-panel, backplane) for SONiC VMs and attaching them to host/OVS bridges.
This sets up connectivity between the testbed containers and the virtual network environment.

10. Create a file under ansible/roles/vm_set/tasks/add_cnet.yml for creating a base Debian container (net_*) with networking privileges to act as a network namespace.
Then we use a custom module (ceos_network / cnet_network) to attach cEOS or cSONiC containers to this network with management and front-panel interfaces.

11. Create ansible/roles/vm_set/tasks/add_cnet_list.yml. Here we are creating the VM network using the custom vm_topology module (setting up links/interfaces for all VMs).
Then we include add_cnet.yml to attach each VM from VM_targets to its corresponding container network — same can be done for cnet_list to loop through and add each cnet container.

### Deploying T0 Topology

Run the following commands to deploy the T0 topology:


        cd /data/sonic-mgmt/ansible
        ./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k csonic add-topo vms-kvm-t0 password.txt





