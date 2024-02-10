#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2024 Cisco Systems, Inc., All rights reserved.

vxr=/auto/vxr/pyvxr/latest/vxr.py
config=/nobackup/cfg

pushd "${config}" || exit

$vxr stop
$vxr clean

# start sim
echo "Starting sim, will take some time"
$vxr start sonic-ref-sim.yaml

# get port info
/nobackup/get_ports.sh

popd || exit >& /dev/null
