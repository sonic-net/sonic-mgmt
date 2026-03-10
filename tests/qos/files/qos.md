qos.yml
===

## the reason of split qos.yml

Original requirement come from [issue #7467](https://github.com/sonic-net/sonic-mgmt/issues/7467)

qos.yml has become very big, and has a lot of fields that have to be populated per platform.
And many similar fields in different make it difficult to modify, review and maintain.
So separate.

## detail of spliting

So far, split qos.yml by asic type, as below:
```bash
$ ls -l tests/qos/files/*.yaml
-rw-r--r-- 1 xuchen 536871425 33998 Jul  9 08:39 tests/qos/files/qos_params.gb.yaml
-rw-r--r-- 1 xuchen 536871425 21062 Jul  9 08:40 tests/qos/files/qos_params.j2c.yaml
-rw-r--r-- 1 xuchen 536871425  5504 Jul  9 08:39 tests/qos/files/qos_params.jr2.yaml
-rw-r--r-- 1 xuchen 536871425  4939 Jul  9 08:33 tests/qos/files/qos_params.mellanox.yaml
-rw-r--r-- 1 xuchen 536871425  1265 Jul  9 08:32 tests/qos/files/qos_params.spc3.yaml
-rw-r--r-- 1 xuchen 536871425 16932 Jul  9 08:35 tests/qos/files/qos_params.td2.yaml
-rw-r--r-- 1 xuchen 536871425 30238 Jul  9 08:36 tests/qos/files/qos_params.td3.yaml
-rw-r--r-- 1 xuchen 536871425  8605 Jul  9 08:41 tests/qos/files/qos_params.th.yaml
-rw-r--r-- 1 xuchen 536871425 15703 Jul  9 08:37 tests/qos/files/qos_params.th2.yaml
-rw-r--r-- 1 xuchen 536871425 11077 Jul  9 08:38 tests/qos/files/qos_params.th3.yaml
```


"tests/qos/conftest.py::combine_qos_parameter" can help merge above splited yaml files into single qos.yml.
Since its behaviros is merge instead of concatenation, you can split qos.yml at any layer of hierarchy.

So, you can continue to slit qos_params.gb.yaml by topology or speed and cable length, if you consider gb's qos parameters are still very big after split.

Reminder:
- splited yaml files' extention name **MUST** be ".yaml" instead of ".yml"
- **BETTER** to use heirarchy of splited yaml file as its file name


## existing comments in qos.yml, before split it

TBD for ACS-MSN2700 xon_1, xon_2:
Once the new fw version with the fix is burned, should change the
xon_th_pkts to 10687
xoff_th_pkts to 0
since xon_th and xoff_th are configured to the same value.
The current parameters are according to current fw behavior
ecn:
  Dictate the ECN field in assembling a packet
  0 - not-ECT; 1 - ECT(1); 2 - ECT(0); 3 - CE
ecn_* profile is for ECN limit test, which is removed
Arista-7260CX3-D108C8:
  xoff_1 for 50G
  xoff_2 for 100G
