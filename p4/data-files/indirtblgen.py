import os
import sys
import json
import argparse

def util_json_load_file(filename):
    data = None
    if filename[-3:] == '.gz':
        with gzip.open(filename, 'rt', encoding='utf-8') as data_file:
            data = json.loads(data_file.read())
    else:
        with open(filename, encoding="utf-8") as data_file:
            data = json.loads(data_file.read())
    return data

def util_json_save_file(filename, data):
    if filename is not None:
        with open(filename, 'w', encoding="utf-8") as data_file:
            json.dump(data, data_file, indent=4)


tbl_entries = []
octs1 = 100
octd1 = 200
oct2 = 1
oct3 = 1
oct4 = 1
idx = 1
for x in range(50000):
    tbl_entries.append(
    {
      "table": "ingress.l3_fwd.l3_ipv4_vrf_table",
      "entry_oper": "INSERT",
      "match": {
        "local_metadata.vrf_id": 1,
        "hdr.ipv4_base.dst_addr": [str(octs1)+"."+str(oct2)+"."+str(oct3)+"."+str(oct4), 32]
      },
      "action_member": 1,
      "priority": 0
    })

    oct4 = oct4%253 + 1
    if oct4 == 1:
        oct3 = oct3%253 + 1
        if oct3 == 1: 
            oct2 = oct2%253 + 1
            if oct2 == 1:
                octs1 = octs1%253 + 1

mbr_entries = [
        {
            "member_id": 1,
            "entry_oper": "INSERT",
            "action_profile_id": 285212673,
            "action_profile_name": "ingress.l3_fwd.l3_action_profile",
            "action_name": "ingress.l3_fwd.set_nexthop",
            "action_params":
                {
                    "port": 1,
                    "smac": "0e:85:90:95:28:3b",
                    "dmac": "0e:85:90:95:28:4b",
                    "l3_class_id": 10
                }
        }
    ]
tbl_data = {
  "target": "th3",
  "p4info": "build/basic.p4.p4info.txt",
  "th3_json": "build/basic.json",
  "table_name": "ingress.l3_fwd.l3_ipv4_vrf_table",
  "action_profile_name": "ingress.l3_fwd.l3_action_profile",
  "table_entries": tbl_entries,
  "member_entries": mbr_entries
}
util_json_save_file("./ingress-l3fwd-ipv4vrf-scale-table.json", tbl_data)
