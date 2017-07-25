# FAQ

## How to find IP addresses of VMs and PTF
 - IP address of testbed PTF container could be found in testbed.csv
 - To find some VM IP address:
   - find vm_offset parameter for the VM in your topology file
   - find vm_base parameter in testbed.csv
   - Calculate physical VM name as vm_base + vm_offset
   - Find physical VM entry in veos file

TODO: Create ansible playbook for this


