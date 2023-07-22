#!/bin/bash

#bsub -q sj-slx -m lc-lvn-0291 -Is bash

mkdir -p /tmp/$USER
exec &> >(tee /tmp/$USER/upgrade-$SPYTEST_PYTHON_VERSION-requirements.log)

dir=$(cd $(dirname $0);pwd -P)

# source environment
. $dir/env

export PATH=/tools/bin:$PATH
export GCCVER=5.4.0
export CC=${PREFIX}gcc
export CPP=${PREFIX}cpp
export CXX=${PREFIX}c++
export LIBS=
export LDSHARED="${PREFIX}gcc -pthread -shared"
export PYMSSQL_BUILD_WITH_BUNDLED_FREETDS=1

TMPFILE=$(mktemp)

cat << EOF > $TMPFILE.1
readline
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
pyparsing
pyangbind
yapf
#yabgp
pexpect
pytz
docker==2.7.0
pdbpp
pylint-pytest
pylint-protobuf
ruff
EOF

cat << EOF > $TMPFILE.2
pylint>=1.9.5
paramiko==2.11.0
netmiko==2.4.2
pytest>=4.4.1,<=4.6.5
pytest-xdist==1.28.0
future>=0.16.0
cryptography >= 2.5
scapy==2.4.3rc1
# GNMI
protobuf>=3.15.6,<=3.20.*
deepdiff==3.3.0
grpcio>=1.8.3,<=1.20.1
grpcio-tools>=1.8.3,<=1.20.1
regex<2022.1.18
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
EOF

$SPYTEST_PYTHON -V 2>&1 | grep "Python 3"
if [ $? -eq 0 ]; then
  is_v3=1
else
  is_v3=0
fi

if [ $is_v3 -eq 0 ]; then
  cat $TMPFILE.1 $TMPFILE.2 > $TMPFILE.0
else
  cat $TMPFILE.1 $TMPFILE.3 > $TMPFILE.0
fi

#$SPYTEST_PYTHON -m pip install python-jenkins; exit 0

#INSTALL_OPTS="--upgrade --force-reinstall"
#INSTALL_OPTS="$INSTALL_OPTS --verbose"
$SPYTEST_PYTHON -m pip install --upgrade pip
#$SPYTEST_PYTHON -m pip install --upgrade pyopenssl
#$SPYTEST_PYTHON -m pip uninstall -y regex bitarray pyang pyangbind
$SPYTEST_PYTHON -m pip --no-cache-dir install $INSTALL_OPTS wheel
$SPYTEST_PYTHON -m pip --no-cache-dir install $INSTALL_OPTS sqlite3
$SPYTEST_PYTHON -m pip --no-cache-dir install $INSTALL_OPTS -r $TMPFILE.0

if [ $is_v3 -ne 0 ]; then
  $SPYTEST_PYTHON -m pip install --upgrade git+https://github.com/sachinholla/pyangbind.git@0.8.1+spytest.20220216#egg=pyangbind

  VERSION=$($SPYTEST_PYTHON -V 2>&1 | cut -d\  -f 2)
  VERSION=(${VERSION//./ })
  if [[ ${VERSION[0]} -ge 3 ]] && [[ ${VERSION[1]} -ge 9 ]] ; then
    $SPYTEST_PYTHON -m pip uninstall -y pytest pytest-xdist
    $SPYTEST_PYTHON -m pip install --no-input pytest-xdist==1.28.0 pytest==5.4.3
  else
    $SPYTEST_PYTHON -m pip install --upgrade git+https://github.com/ramakristipatibrcm/pytest-xdist.git@spytest#egg=pytest-xdist
  fi
fi

read -rs -n1 -t30 -p "Press any key or wait to continue ..."

if [ -d $SCID_PYTHON_BIN ]; then
    $SPYTEST_PYTHON -m compileall $SCID_PYTHON_BIN/..
    chmod -R go+r $SCID_PYTHON_BIN/..
fi
