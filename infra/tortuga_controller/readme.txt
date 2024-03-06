How to use Tortuga to test fabric configuration.

1) Create a PyVxr setup.
    - Create /nobackup directory. SIM and SONiC images are going to be
       in /nobackup directory. Therefore, ensure that you have enough storage.
    - Create /nobackup/images and copy SONiC and RHEL (TREX) images to it.
       - rhel7_serial.qcow2 (for TREX or hosts).
       - sonic-cisco-8000.bin (for switches)
    - Copy reset_sim.sh to /nobackup directory.
    - Copy get_ports.sh to /nobackup directory.
    - Create /nobackup/cfg directory. Copy sonic-ref-sim.yaml to /nobackup/cfg directory.
    - Create /nobackup/sim directory. This is where SIM gets copied to.

3) Customize /nobackup/cfg/sonic-ref-sim.yaml to match your PyVxr setup
    - Change hostname to your PyVxr hostname.
    - Rename 'tortuga-1x3' to match your PyVxr hostname.
    - DO NOT add cisco.com in the hostname.
    - DO NOT use "tortuga" as hostname. Why? Because we have a number of fabrics
      that use tortuga as prefix. It may confuse UI developers, and they may end
      up deleting or modifying your fabric.

   NOTES:
    Rename hostnames of all nodes (spines and leaves) in the reference YAML from
    tortuga-1x3-leaf[0-3]/spine[0] to <pyvxr hostname>-leaf[0-3]/spine[0]. If you
    are sharing same PyVxr and creating multiple SIMs, then come up with a unique
    prefix for node hostnames. E.g. <cisco-username>-leaf[0-3]/spine[0].

    Prefix of node hostname (E.g. <cisco-username>) must be set as FABRIC_NAME in
    test.sh file.

4) Execute /nobackup/reset_sim.sh to create PyVxr SIM.
    - This may take up to 15m.

5) Execute /nobackup/get_ports.sh to get PyVxr SIM ports.
    - get_ports.sh prints out PyVxr ports for spines, leaves and hosts.

6) Edit ./test.sh and replace variables.
    - Set PyVxr hostname (without cisco.com) or the prefix (E.g. <cisco-username>) you used
      for node hostnames to FABRIC_NAME. This is very important. Otherwise, config-gen will
      not match discovered fabric with your fabric.
    - Set full PyVxr hostname (with cisco.com) to PYVXR_HOST.
    - Set host ports reported by get_ports.sh to HOST_PORTS.
    - Set leaf ports reported by get_ports.sh to LEAF_PORTS.
    - Set the correct spine count to SPINE_COUNT.

7) Execute ./test.sh from your Linux dev machine to run tests.
   - You may execute test.sh as many times as you want.
   - Each run of test.sh will clear out switch configs and re-configure them.
   - Each test.sh may take up to 8m. This includes time to reboot PyVxr nodes.

Notes:
 - You must execute reset_sim.sh when there is a new SONiC image.
 - You must run edit and set HOST_PORTS variable in test.sh each time you run reset_sim.sh
 - You don't have to reset PyVxr to repeat tests with the same SONiC image.
