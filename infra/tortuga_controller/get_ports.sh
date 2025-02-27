#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2024 Cisco Systems, Inc., All rights reserved.

vxr=/auto/vxr/pyvxr/latest/vxr.py
host=$(hostname -s)
config=/nobackup/cfg

pushd "${config}" || exit
ports=$($vxr ports)
popd || exit >& /dev/null

s0=$(echo "${ports}" | jq .S0.xr_redir22)
s1=$(echo "${ports}" | jq .S1.xr_redir22)
l0=$(echo "${ports}" | jq .L0.xr_redir22)
l1=$(echo "${ports}" | jq .L1.xr_redir22)
l2=$(echo "${ports}" | jq .L2.xr_redir22)
l3=$(echo "${ports}" | jq .L3.xr_redir22)
n1=$(echo "${ports}" | jq .N1.xr_redir22)
h1=$(echo "${ports}" | jq .trex1.xr_redir22)
h2=$(echo "${ports}" | jq .trex2.xr_redir22)
h3=$(echo "${ports}" | jq .trex3.xr_redir22)
h4=$(echo "${ports}" | jq .trex4.xr_redir22)
h5=$(echo "${ports}" | jq .trex5.xr_redir22)
h6=$(echo "${ports}" | jq .trex6.xr_redir22)
h7=$(echo "${ports}" | jq .trex7.xr_redir22)
h8=$(echo "${ports}" | jq .trex8.xr_redir22)
h9=$(echo "${ports}" | jq .trex9.xr_redir22)
h10=$(echo "${ports}" | jq .trex10.xr_redir22)
h11=$(echo "${ports}" | jq .trex11.xr_redir22)
h12=$(echo "${ports}" | jq .trex12.xr_redir22)
h13=$(echo "${ports}" | jq .trex13.xr_redir22)
h14=$(echo "${ports}" | jq .trex14.xr_redir22)

hosts="${h1},${h2}"
if [[ "${h3}" != "null" ]]; then
  hosts="${hosts},${h3}"
fi
if [[ "${h4}" != "null" ]]; then
  hosts="${hosts},${h4}"
fi
if [[ "${h5}" != "null" ]]; then
  hosts="${hosts},${h5}"
fi
if [[ "${h6}" != "null" ]]; then
  hosts="${hosts},${h6}"
fi
if [[ "${h7}" != "null" ]]; then
  hosts="${hosts},${h7}"
fi
if [[ "${h8}" != "null" ]]; then
  hosts="${hosts},${h8}"
fi
if [[ "${h9}" != "null" ]]; then
  hosts="${hosts},${h9}"
fi
if [[ "${h10}" != "null" ]]; then
  hosts="${hosts},${h10}"
fi

spines=
if [[ "${s0}" != "null" ]]; then
  spines="${s0}"
fi
if [[ "${s1}" != "null" ]]; then
  spines="${spines},${s1}"
fi

leaves="${l0},${l1}"
if [[ "${l2}" != "null" ]]; then
  leaves="${leaves},${l2}"
fi
if [[ "${l3}" != "null" ]]; then
  leaves="${leaves},${l3}"
fi

if [[ "${n1}" != "null" ]] && [[ "${l0}" != "null" ]]; then
  echo "--pyvxr ${host} --spines ${spines} --leaves ${leaves} --hosts ${hosts}"
  echo "--pyvxr ${host} --spines 0 --leaves ${n1} --hosts ${h11},${h12},${h13},${h14}"
elif [[ "${n1}" != "null" ]]; then
   echo "--pyvxr ${host} --spines 0 --leaves ${n1} --hosts ${hosts}"
else
  echo "--pyvxr ${host} --spines ${spines} --leaves ${leaves} --hosts ${hosts}"
fi
