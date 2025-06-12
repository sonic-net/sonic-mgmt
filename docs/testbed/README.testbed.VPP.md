# Running Sonic-mgmt with Sonic-VPP as DUT
To set up a testbed with a Sonic-VPP DUT follow the [VS testbed setup](README.testbed.VsSetup.md), and use the following commands during bringup. All of the following commands are to be run from the sonic-mgmt container.

### Add topology:
```
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos add-topo vms-kvm-vpp-t1-lag  password.txt
```
### Deploy minigraph:
```
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb deploy-mg vms-kvm-vpp-t1-lag veos_vtb password.txt
```
### Example test run:
```
cd /data/sonic-mgmt/tests
./run_tests.sh -n vms-kvm-vpp-t1-lag -d vlab-vpp-01 -O -u -l debug -e -s -e "--disable_loganalyzer --skip_sanity --mark-conditions-files common/plugins/conditional_mark/tests_mark_conditions.yaml" -e "--mark-conditions-files common/plugins/conditional_mark/tests_mark_conditions_sonic_vpp.yaml" -m individual -f vtestbed.yaml -i ../ansible/veos_vtb -p <log> -c <tests>
```
### Remove topology:
```
cd /data/sonic-mgmt/ansible
./testbed-cli.sh -t vtestbed.yaml -m veos_vtb -k ceos remove-topo vms-kvm-vpp-t1-lag password.txt
```
