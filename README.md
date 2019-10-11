# godiva-test
Test Scripts and Libraries 

Steps before working/using Godiva based test scripts and libraries
==================================================================
1. Setup a virtual-env called godiva. Use of virtual-env-wrapper is preferred.
2. Clone godiva-test repo
3. Clone cafykit repo

Steps for installing cafyKit libraries on ubuntu:
================================================
1. export GIT_REPO=/home/venkat/cafykit
2. export PYTHONPATH="$GIT_REPO/lib"
3. pip3 install --upgrade pip
4. sudo apt-get install build-essential libssl-dev libffi-dev python-dev
5. sudo apt-get install libxml2-dev libxslt-dev
6. sudo apt-get install libmysqlclient-dev 
7. pip3 install wheel
8. pip3 install setuptools --upgrade
9. sudo apt-get install openssh-server
10. sudo apt-get install python3-dev
11. sudo apt install libssl1.0

4. pip3 install current-req.txt

Steps to run cmal script
========================
1. Modify cmal-topo.json to match your testbed.
2. Modify gd_input_file.json to match your test requirements
3. pytest -rapP -vs cmal_ap.py --mail-to your-email-id@cisco.com --topology-file cmal_topo.json --test-input-file=gd_input_file.json

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
