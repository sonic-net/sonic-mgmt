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
for x in range(1024):
    tbl_entries.append(
    {
      "table": "ingress.encap.encap_in_ipv4_table",
      "entry_oper": "INSERT",
      "match": {
        "local_metadata.encap_id": idx
      },
      "action_name": "ingress.encap.encap_ip_in_ip",
      "action_params": {
        "src_addr": str(octs1)+"."+str(oct2)+"."+str(oct3)+"."+str(oct4),
        "dst_addr": str(octd1)+"."+str(oct2)+"."+str(oct3)+"."+str(oct4)
      },
      "priority": 0
    })
    idx = idx+1
    oct4 = oct4%253 + 1
    if oct4 == 1:
        oct3 = oct3%253 + 1
        if oct3 == 1: 
            oct2 = oct2%253 + 1
            if oct2 == 1:
                octs1 = octs1%253 + 1
                octd1 = octd1%253 + 1
tbl_data = {
  "target": "th3",
  "p4info": "build/basic.p4.p4info.txt",
  "th3_json": "build/basic.json",
  "table_name": "ingress.encap.encap_in_ipv4_table",
  "table_entries": tbl_entries
}
#util_json_save_file("/tmp/input-test.json", tbl_entries)    
util_json_save_file("./ingress-encapin-ipv4-scale-table.json", tbl_data)
