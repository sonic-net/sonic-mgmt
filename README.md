# godiva-test
Test Scripts and Libraries 

Steps before working/using Godiva based test scripts and libraries
==================================================================
Clone `godiva-test` git repository, and execute `make` to start a `godiva-test` container.

```
git clone git@wwwin-github.cisco.com:gplatforms/godiva-test.git
cd godiva-test && make
```

The `godiva-test` container includes all required packages and configuration to execute a `pytest` test-script.

Steps to run P4 script
========================
1. Modify p4-topo.json to match your testbed.
2. Modify gd_input_file.json to match your test requirements
3. Modify p4-job.sh
4. Execute p4-job.sh

Steps to test BSP
=================
1. /auto/vxr/pyvxr/pyvxr-0.4.5/vxr.py --cmd ports godiva.yaml -- Will launch the spitfire sim and install godiva image
2. ./bsp_job.sh
