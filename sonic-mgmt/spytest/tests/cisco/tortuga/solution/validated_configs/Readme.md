1. Execute the below to create a 2x2 Spine/Leaf Topology with the required Topology (l2vni or l3vni)

                cd sonic-test/infra
                ./create_tortuga_topo.py -f ./../pyvxr_yaml_files/tortuga_spytest_solution_tb.yaml -t sol-tb-l3vni -c
                    -f : specify the yaml file for the topology
                    -t : sol-tb-l2vni or sol-tb-l3vni
                    -c : cleanup sim workspace

       Note: vxr sim will be bought up and based on the sol-tb-l2vni or sol-tb-l3vni, the respective configuration will be applied

2. The applied validated configs for each topology are located at - '/spytest/tests/cisco/tortuga/solution/validated_configs/'

3. Once the topology is up, enable traffic with IXIA for the above topology, use 

                  To get the Ixia ip address for the GUI
                  - telnet to ixia chassis
                  - For e.g: Using the port info from above script execution
                  - Ixia Chassis (ixia-pc/<>) :  SlurmHost: 172.26.228.82   Tlnt Port: 27571
                  - Management IP : 192.168.122.156 <- Chassis IP 

                  For example::
                  telnet 172.26.228.82 27571
                  Trying 172.26.228.82...
                  Connected to 172.26.228.82.
                  Escape character is '^]'.

                  Welcome to Ixia Virtual Chassis
                  CentOS Linux 7
                  Kernel 3.10 on x86_64
                  Management IP: 192.168.122.156. --> use the IP from here
                  IxOS Version: 9.00.1900.10
                  IxNetwork Protocol Version: 9.00.1906.13  

4. We have provided a sample IXIA json file to generate bidirectional traffic in 'validated_configs/base_l2vni/'
    - look for 'L2vni_traffic_check.json' or 'L2vni_traffic_check.ixncfg'

