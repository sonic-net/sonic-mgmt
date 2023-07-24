## [DRAFT, UNDER DEVELOPMENT]


- [Overview](#overview)
    - [Scope](#scope)
    - [Related DUT CLI commands](#related-dut-cli-commands)
    - [Related DUT configuration files](#related-dut-configuration-files)
- [Test cases](#test-cases)

## Overview
The purpose is to test functionality of the FIPS on SONiC DUT with and without FIPS configured.

### Scope
The test is targeting a running SONIC system with fully functioning configuration. The purpose of the test is not to test specific API, but functional testing of FIPS configuration on SONIC system.

### Related DUT CLI commands
Manual FIPS configuration can be done using the sonic-installer command, see [here](https://github.com/sonic-net/sonic-utilities/blob/72ca48481645edc3437d7899e2fa754d16eff02e/doc/Command-Reference.md?plain=1#L11515).
```
   sonic-installer set-fips [--enable-fips|--disable-fips] [<image_name>]
```

| Command | Comment |
|:-------:|---------------------|
| sonic-installer set-fips | Enable or disable the FIPS feature |
| sonic-installer get-fips | Show the FIPS enabling state |

### Related DUT configuration files
| File | Comment |
|:-------:|---------------------|
| /etc/fips/fips_enabled | The FIPS enabling config |

## Test cases

### Test case #1 – Test to enable the FIPS
1. Setup the dut to disable the FIPS.
1. Enable the FIPS in ConfigDB
1. Verify the FIPS enabled state in STATE_DB is 1, and the enforced state is 0.
1. Verify the FIPS enabled by command: openssl engine -vv, expect the symcrypt loadded.
1. Disable the FIPS in ConfigDB.
1. Verify the FIPS enabled state in STATE_DB is 0.
1. Verify the symcrypt not loaded by command: openssl engine -vv.

### Test case #2 – Test to enforce the FIPS
1. Setup the dut to disable the FIPS.
1. Enable the FIPS in ConfigDB.
1. Reboot the dut.
1. Verify the FIPS enabled state in STATE_DB is 1, and the enforced state is 1.
1. Verify the FIPS enabled by command: openssl engine -vv, expect the symcrypt loadded.
1. Disable the FIPS in ConfigDB.
1. Reboot the dut.
1. Verify the FIPS enforced state in STATE_DB is 0.
1. Verify the symcrypt not loaded by command: openssl engine -vv.

### Test case #3 – Test to enable the FIPS for Python
1. Setup the dut to disable the FIPS
1. Import ssl, and call the ssl function RAND_bytes.
1. Verify the symcrypt engine not loaded in the /proc/<python proccess id>/maps.
1. Setup the dut to enable the FIPS
1. Call the RAND_bytes again, and verify the symcrypt engine loaded

Sample code to verify the symcrypt engine loaded:
```python
import os
import ssl
rand_byte = ssl.RAND_bytes(1)
with open(os.path.join('/proc', str(os.getpid()), 'maps')) as f:
    assert 'libsymcrypt.so' in f.read()
```

### Test case #4 – Test to enable the FIPS for Golang
1. Setup the dut to disable the FIPS
1. Restart the restapi service
1. Verify the symcrypt engine not loaded in the /proc/<restapi proccess id>/maps.
1. Setup the dut to enable the FIPS
1. Call the RAND_bytes again, and verify the symcrypt engine loaded
```
root@sonic:/home/admin# ps -ef | grep  go-server-server
root       70019   69976  0 Jul14 pts/0    00:00:01 /usr/sbin/go-server-server -enablehttp=false -enablehttps=true -servercert=/etc/sonic/credentials/restapiserver.crt -serverkey=/etc/sonic/credentials/restapiserver.key -clientcert=/etc/sonic/credentials/AME_ROOT_CERTIFICATE.pem -clientcertcommonname=client.restapi.sonic.gbl -loglevel=info
root      142330  140758  0 00:15 pts/0    00:00:00 grep go-server-server
root@sonic:/home/admin# grep symcrypt /proc/70019/maps
7fa471991000-7fa47199c000 r--p 00000000 fe:03 919328                     /usr/lib/x86_64-linux-gnu/libsymcrypt.so.103.0.1
7fa471a59000-7fa471a5b000 rw-p 0001b000 fe:03 919258                     /usr/lib/x86_64-linux-gnu/libsymcryptengine.so
```

### Test case #5 – Integrate the FIPS in nightly test
Test the FIPS configuration for aboot/uboot/grub, and make sure it can pass all tests with FIPS enabled.
