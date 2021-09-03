# get_ip_in_range

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Get certain number of ips within a prefix

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname, tbinfo):
    duthost = duthosts[rand_one_dut_hostname]

    mg_facts = duthost.get_extended_minigraph_facts(tbinfo)

    vlan_addr = mg_facts['minigraph_vlan_interfaces'][0]['addr']
    vlan_prefix = mg_facts['minigraph_vlan_interfaces'][0]['prefixlen']

    ips_in_range = duthost.get_ip_in_range(num=1, prefix="{}/{}".format(vlan_addr, vlan_prefix))
```


## Arguments
- `num` - Number of ips to be generated
    - Required: `True`
    - Type: `Integer`
- `prefix` - required IP range in prefix format
    - Required: `True`
    - Type: `String`
- `exclude_ips` - List of ips within the `prefix` that should be excluded from generation
    - Required: `False`
    - Type: `List`
        - Element-Type: `String`

## Expected Output
Returns dictionary containing generated ips. The dictionary hierarchy is described below, with each indentation describing a sub-dictionary:

- `ansible_facts`
     - `generated_ips` - list of generated ips

(u'ansible_facts', {u'generated_ips': [u'192.168.0.1/21', u'192.168.0.2/21']})