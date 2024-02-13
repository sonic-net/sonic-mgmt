**Steps to Bring up Tortuga Controller based Sim setup**
1. Add image information to pyvxr_yaml_files/tortuga_controller.yaml
2. Currently it will bring up a topology with 3 Leaf and 1 Spine, 9 Trex host.
3. Specify the fabric name. Fabric name has to be unique for each topology.
4. ./create_tortuga_topo.py --topo_type tortuga-controller -f ./../pyvxr_yaml_files/tortuga_controller.yaml -c --fabric_name lotr-1x3
5. Above command will
    1. Bring up the sim based topology
    2. Gather the ip address and ports based information from sim
    3. Populate test.sh which will invoke controller to configure all the devices
    4. Run a traffic test to confirm that the topology has come up properly
    5. Based on the results, it will either print completed or will fail with error message.

  For e.g.
  In case of a passed test
        
        --- 10.212.2.2 ping statistics ---
        5 packets transmitted, 5 received, 0% packet loss, time 4006ms
        rtt min/avg/max/mdev = 24.495/28.886/31.556/2.771 ms

        PING 10.212.12.2 (10.212.12.2) 56(84) bytes of data.
        64 bytes from 10.212.12.2: icmp_seq=1 ttl=60 time=29.5 ms
        64 bytes from 10.212.12.2: icmp_seq=2 ttl=60 time=25.7 ms
        64 bytes from 10.212.12.2: icmp_seq=3 ttl=60 time=24.4 ms
        64 bytes from 10.212.12.2: icmp_seq=4 ttl=60 time=41.6 ms
        64 bytes from 10.212.12.2: icmp_seq=5 ttl=60 time=29.8 ms

        --- 10.212.12.2 ping statistics ---
        5 packets transmitted, 5 received, 0% packet loss, time 4006ms
        rtt min/avg/max/mdev = 24.449/30.247/41.619/6.064 ms


        Completed in 434s

        Successfully pushed configuration and Traffic Test passed

  In case of a failed test:

      --- 10.212.20.2 ping statistics ---
      4 packets transmitted, 0 received, +4 errors, 100% packet loss, time 2999ms
      pipe 4

      cannot ping host: kindly-1x3-host0 cannot ping 10.212.20.2 from 10.212.0.2
      Test Failed. Something went wrong, Please check the test logs
