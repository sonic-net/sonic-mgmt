# godiva-test
Test Scripts and Libraries 

Steps before working/using Godiva based test scripts and libraries
==================================================================
1. Setup a virtual-env called godiva
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
12. pip3 install -r $GIT_REPO/requirements.txt

4. Install Godiva test specific requirements.txt

Steps to run cmal script
========================
1. Modify cmal-topo.json to match your testbed.
2. Modify gd_input_file.json to match your test requirements
3. pytest -rapP -vs cmal_ap.py --mail-to your-email-id@cisco.com --topology-file cmal_topo.json --test-input-file=gd_input_file.json
