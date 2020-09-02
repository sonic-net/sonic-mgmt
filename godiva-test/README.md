# godiva-test - a simple test for subtrees
Test Scripts and Libraries 

Steps before working/using Godiva based test scripts and libraries
==================================================================
Clone `godiva-test` git repository, and execute `make` to start a `godiva-test` container.

```
git clone git@wwwin-github.cisco.com:gplatforms/godiva-test.git
cd godiva-test && make
```

If HTTP proxy is needed:
```
export http_proxy=http://proxy-wsa.esl.cisco.com:80
export https_proxy=http://proxy-wsa.esl.cisco.com:80
export no_proxy=.cisco.com
cd godiva-test && make
```

The `godiva-test` container includes all required packages and configuration to execute a `pytest` test-script.

Note, the following directories from host are mounted inside the container at:
- /opt/home: home directory in host.Eg: /home/$USER in slurm server
- /godiva-test: godiva-test git workspace
- /root/gd-test: docker build directory in godiva-test git workspace

The user credential in host is not set up inside container. Hence, any git 
operation in `/godiva-test` directory will not work in container.

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
