# godiva-test
Test Scripts and Libraries 

Steps before working/using Godiva based test scripts and libraries
==================================================================
1. Setup a virtual-env called godiva
2. Clone godiva-test repo
3. Clone cafykit repo

Steps for installing cafyKit libraries on ubuntu:
================================================
export GIT_REPO=/home/venkat/cafykit
export PYTHONPATH="$GIT_REPO/lib"
pip3 install --upgrade pip
sudo apt-get install build-essential libssl-dev libffi-dev python-dev
sudo apt-get install libxml2-dev libxslt-dev
sudo apt-get install libmysqlclient-dev 
pip3 install wheel
pip3 install setuptools --upgrade
sudo apt-get install openssh-server
sudo apt-get install python3-dev
sudo apt install libssl1.0
pip3 install -r $GIT_REPO/requirements.txt

4. Install Godiva test specific requirements.txt

Steps to run cmal script
========================
Modify cmal-topo.json to match your testbed.
Modify gd_input_file.json to match your test requirements
pytest -rapP -vs cmal_ap.py --mail-to your-email-id@cisco.com --topology-file cmal_topo.json --test-input-file=gd_input_file.json
