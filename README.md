# sonic-test
Repo for sonic-test related activities

# create_sonic_t1_ads.py in sonic-test/infra
This script does a lot of different things to get a sonic based testbed up.
 
    # Creates the t1 topology using vxr.py
    # Create admin user in vEOS vm
    # Create testbed file based on vxr_ports
    # Upload t1 specific files to sonic mgmt container
    # Change DUT password and set mgmt ip address
    # Start docker container, deploy DUT minigraph
    # Replace DUT Mgmt Address
    # Reload DUT config
    # Add vEOS config
    
Kindly run the script in an ads machine.
 
./create_sonic_t1_ads.py -t ./../pyvxr_yaml_files/sonic_t1_topo.yaml -c -p cisco123 -u cisco
 
-c clean a previous sim run.
-p sonic dut password
-u sonic dut username
-t t1 topo file (sample file in pyvxr_yaml_files

If you want to make a change to topology, kindly modify infra/sonic_t1_topo/testbed-sherman-t1.yaml file. This file is used
by ansible to populate device info, creds, etc. 
