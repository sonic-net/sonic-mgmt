#!/bin/bash

TMPFILE=$(mktemp)

export SPYTEST_PYTHON=/usr/bin/python3.8

cat << EOF > $TMPFILE.1
pyfiglet
textfsm
pytest-timeout
gitpython
ansible-core
jinja2
psutil
prettytable
tabulate
pycryptodome
natsort
redis
requests
jsonpatch
rpyc
Pyro4
netaddr
# GNMI
crc16
autoflake
pyang
pyangbind
yapf
#yabgp
pexpect
pytz
docker==2.7.0
pdbpp
pylint-pytest
pylint-protobuf
EOF

cat << EOF > $TMPFILE.3
pylint>=2.7.2
netmiko>=3.3.3,<=3.4.0
pytest<=6.2.5
pytest-xdist<=2.5.0
future>=0.16.0
cryptography >= 2.5
scapy>=2.4.4
# GNMI
protobuf>=3.15.6,<=3.20.3
pyopenssl
deepdiff>=5.5.0
grpcio>=1.8.3
grpcio-tools>=1.8.3
black
pyenchant
sys-prctl
openpyxl
# TGEN
scapy>=2.4.5
exabgp>=4.1.0
pyrasite
EOF

cat $TMPFILE.1 $TMPFILE.3 > $TMPFILE.0

#INSTALL_OPTS="--upgrade --force-reinstall"
#INSTALL_OPTS="$INSTALL_OPTS --verbose"
$SPYTEST_PYTHON -m pip install --upgrade pip
$SPYTEST_PYTHON -m pip --no-cache-dir install $INSTALL_OPTS wheel
$SPYTEST_PYTHON -m pip --no-cache-dir install $INSTALL_OPTS sqlite3
$SPYTEST_PYTHON -m pip --no-cache-dir install $INSTALL_OPTS -r $TMPFILE.0

$SPYTEST_PYTHON -m pip install --upgrade git+https://github.com/sachinholla/pyangbind.git@0.8.1+spytest.20220216#egg=pyangbind
$SPYTEST_PYTHON -m pip install --upgrade git+https://github.com/ramakristipatibrcm/pytest-xdist.git@spytest#egg=pytest-xdist
