# show_and_parse

- [Overview](#overview)
- [Examples](#examples)
- [Arguments](#arguments)
- [Expected Output](#expected-output)

## Overview
Runs a show command on the host and parses the input into a computer readable format, usually a list of entries. Works on any show command that has suimilar structure to `show interface status`

## Examples
```
def test_fun(duthosts, rand_one_dut_hostname):
    duthost = duthosts[rand_one_dut_hostname]

    parsed_com = duthost.show_and_parse('show ip {} interface'.format(namespace))
```

## Arguments
- `show_cmd` - show command to be run on the command line
    - Required: `True`
    - Type: `String`

Any kwargs passed in will be also passed into the duthost.shell command.

## Expected output
```
admin@str-msn2700-02:~$ show interface status
Interface         Lanes       Speed    MTU    FEC    Alias       Vlan          Oper    Admin        Type         Asym PFC
----------  ---------------  -------  -----  -----  -------  ---------------  ------  -------  ---------------  ----------
Ethernet0          0,1,2,3      40G   9100    N/A     etp1  PortChannel0002      up       up   QSFP+ or later         off
Ethernet4          4,5,6,7      40G   9100    N/A     etp2  PortChannel0002      up       up   QSFP+ or later         off
Ethernet8        8,9,10,11      40G   9100    N/A     etp3  PortChannel0005      up       up   QSFP+ or later         off
...

The parsed example will be like:
    [{
        "oper": "up",
        "lanes": "0,1,2,3",
        "fec": "N/A",
        "asym pfc": "off",
        "admin": "up",
        "type": "QSFP+ or later",
        "vlan": "PortChannel0002",
        "mtu": "9100",
        "alias": "etp1",
        "interface": "Ethernet0",
        "speed": "40G"
        },
        {
        "oper": "up",
        "lanes": "4,5,6,7",
        "fec": "N/A",
        "asym pfc": "off",
        "admin": "up",                                                                                                                                                                                                                             "type": "QSFP+ or later",                                                                                                                                                                                                                  "vlan": "PortChannel0002",                                                                                                                                                                                                                 "mtu": "9100",                                                                                                                                                                                                                             "alias": "etp2",
        "interface": "Ethernet4",
        "speed": "40G"
        },
        {
        "oper": "up",
        "lanes": "8,9,10,11",
        "fec": "N/A",
        "asym pfc": "off",
        "admin": "up",
        "type": "QSFP+ or later",
        "vlan": "PortChannel0005",
        "mtu": "9100",
        "alias": "etp3",
        "interface": "Ethernet8",
        "speed": "40G"
        },
        ...
    ]
```