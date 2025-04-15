#!/bin/bash
#
# PROPRIETARY AND CONFIDENTIAL. Cisco Systems, Inc. considers the contents of this
# file to be highly confidential trade secret information.
#
# COPYRIGHT 2023-2025 Cisco Systems, Inc., All rights reserved.

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
l4=$(echo "${ports}" | jq .L4.xr_redir22)
l5=$(echo "${ports}" | jq .L5.xr_redir22)
l6=$(echo "${ports}" | jq .L6.xr_redir22)
l7=$(echo "${ports}" | jq .L7.xr_redir22)
l8=$(echo "${ports}" | jq .L8.xr_redir22)
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
h15=$(echo "${ports}" | jq .trex15.xr_redir22)
h16=$(echo "${ports}" | jq .trex16.xr_redir22)
h17=$(echo "${ports}" | jq .trex17.xr_redir22)
h18=$(echo "${ports}" | jq .trex18.xr_redir22)
h19=$(echo "${ports}" | jq .trex19.xr_redir22)
h20=$(echo "${ports}" | jq .trex20.xr_redir22)
h21=$(echo "${ports}" | jq .trex21.xr_redir22)
h22=$(echo "${ports}" | jq .trex22.xr_redir22)
h23=$(echo "${ports}" | jq .trex23.xr_redir22)
h24=$(echo "${ports}" | jq .trex24.xr_redir22)
h25=$(echo "${ports}" | jq .trex25.xr_redir22)
h26=$(echo "${ports}" | jq .trex26.xr_redir22)
h27=$(echo "${ports}" | jq .trex27.xr_redir22)
h28=$(echo "${ports}" | jq .trex28.xr_redir22)

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

# Add additional hosts in non-switch mode.
if [[ "${n1}" == "null" ]]; then
  if [[ "${h11}" != "null" ]]; then
    hosts="${hosts},${h11}"
  fi
  if [[ "${h12}" != "null" ]]; then
    hosts="${hosts},${h12}"
  fi
  if [[ "${h13}" != "null" ]]; then
    hosts="${hosts},${h13}"
  fi
  if [[ "${h14}" != "null" ]]; then
    hosts="${hosts},${h14}"
  fi
  if [[ "${h15}" != "null" ]]; then
    hosts="${hosts},${h15}"
  fi
  if [[ "${h16}" != "null" ]]; then
    hosts="${hosts},${h16}"
  fi
  if [[ "${h17}" != "null" ]]; then
    hosts="${hosts},${h17}"
  fi
  if [[ "${h18}" != "null" ]]; then
    hosts="${hosts},${h18}"
  fi
  if [[ "${h19}" != "null" ]]; then
    hosts="${hosts},${h19}"
  fi
  if [[ "${h20}" != "null" ]]; then
    hosts="${hosts},${h20}"
  fi
  if [[ "${h21}" != "null" ]]; then
    hosts="${hosts},${h21}"
  fi
  if [[ "${h22}" != "null" ]]; then
    hosts="${hosts},${h22}"
  fi
  if [[ "${h23}" != "null" ]]; then
    hosts="${hosts},${h23}"
  fi
  if [[ "${h24}" != "null" ]]; then
    hosts="${hosts},${h24}"
  fi
  if [[ "${h25}" != "null" ]]; then
    hosts="${hosts},${h25}"
  fi
  if [[ "${h26}" != "null" ]]; then
    hosts="${hosts},${h26}"
  fi
  if [[ "${h27}" != "null" ]]; then
    hosts="${hosts},${h27}"
  fi
  if [[ "${h28}" != "null" ]]; then
    hosts="${hosts},${h28}"
  fi
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
if [[ "${l4}" != "null" ]]; then
  leaves="${leaves},${l4}"
fi
if [[ "${l5}" != "null" ]]; then
  leaves="${leaves},${l5}"
fi
if [[ "${l6}" != "null" ]]; then
  leaves="${leaves},${l6}"
fi
if [[ "${l7}" != "null" ]]; then
  leaves="${leaves},${l7}"
fi
if [[ "${l8}" != "null" ]]; then
  leaves="${leaves},${l8}"
fi

if [[ "${n1}" != "null" ]] && [[ "${l0}" != "null" ]]; then
  echo "--pyvxr ${host} --spines ${spines} --leaves ${leaves} --hosts ${hosts}"
  echo "--pyvxr ${host} --spines 0 --leaves ${n1} --hosts ${h11},${h12},${h13},${h14}"
elif [[ "${n1}" != "null" ]]; then
   echo "--pyvxr ${host} --spines 0 --leaves ${n1} --hosts ${hosts}"
else
  echo "--pyvxr ${host} --spines ${spines} --leaves ${leaves} --hosts ${hosts}"
fi
