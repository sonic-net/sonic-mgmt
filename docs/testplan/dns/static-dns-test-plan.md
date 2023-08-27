# Static DNS Configuration Test Plan

## Related documents

| **Document Name** | **Link** |
|-------------------|----------|
| static_dns | [https://github.com/sonic-net/SONiC/blob/master/doc/static-dns/static_dns.md]|


## Overview

The access to the DNS in SONiC is organized via the resolver configuration file (/etc/resolv.conf). resolv.conf is the plain text file that contains the human-readable configuration. It is used across various subsystems in the SONiC to translate domain names into IP addresses.

With the current implementation dynamic DNS configuration can be received from the DHCP server or static configuration can be set manually by the user. However, SONiC doesn't provide any protection for the static configuration. The configuration that is set by the user can be overwritten with the dynamic configuration at any time.

## Requirements

#### The Ip address for the DNS nameserver should be:
1. Unicast IPv4
2. Unicast IPv6
3. Loopback IP address

#### This feature will support the following commands:

1. config: Add/ Delete the static dns nameserver
2. show: Display the static dns nameservers that added

#### This feature will provide error handling for the next situations:

1. Invalid IP address
2. Add the 4th DNS nameserver
3. Add DNS nameserver that already exist in the config db
4. Delete static DNS nameserver that dose not exist

### Scope

The test is to verify the static DNS nameserver could be configured, and once it is configured the dynamic DNS will not work. And after the reload of the system the DNS nameserver could persistent.

### Scale / Performance

The maxminum count of static DNS nameserver can be configured is 3, it will return error when add the 4th DNS nameserver.

### Related **DUT** CLI commands

#### Config
The following command can be used to configure static DNS nameserver:
```
config dns nameserver add <ip_address>
config dns nameserver del <ip_address>
```

Examples:
```
config dns nameserver add 1.1.1.1
config dns nameserver del 1.1.1.1
config dns nameserver add fe80:1000:2000:3000::1
config dns nameserver del fe80:1000:2000:3000::1
```

#### Show
The following command can be used to show static DNS nameserver:
```
show dns nameserver
```
Example:
```
show dns nameserver
NAMESERVER
-----------------------
1.1.1.1
fe80:1000:2000:3000::1
```
### Related DUT configuration files

```
{
    "DNS_NAMESERVER": {
        "1.1.1.1": {},
        "fe80:1000:2000:3000::1": {}
    },
}
```
### Supported topology
The test will be supported on any topology


## Test cases

### Test cases #1 - basic test to verify the cli command could work, and config reload/reboot also work.

1. Add DNS nameserver
   - Verify the nameserver is added to the config db with show cli command.
   - Verify /etc/resolv.conf file (include the files in all the available containers) is overwriten, and the DNS nameserver are same as config db
2. Modify the /etc/resolv.conf file
   - Restart the resolv-config.service, and then check the /etc/resolv.conf (include the files in all the available containers) content will recover to the origin one that have some content as in the config db
3. Save config, modify the /etc/resolv.conf file, then do config reload/reboot
   - Verify the nameserver is still in the config db with the show cli command
   - Verify the /etc/resolv.conf (include the files in all the available containers) also have same nameserver value as config db
4. Delete the DNS nameserver
   - Verify the nameserver is deleted as expected with the show cli command.
   - Verify /etc/resolv.conf file (include the files in all the available containers) is also updated.

### Test cases #2 - Verify that static DNS configuration is not modified when dhcp renew is triggered. It will be skipped when static ip is configured on the mgmt port.
1. Configure static DNS
2. Verify that /etc/resolv.conf is updated
3. Do dhcp renew
4. Verify that /etc/resolv.conf is not modified (still has static configuration)

### Test cases #3 - Verify the dynamic DNS will not work when static ip is configured on the mgmt port. Only when both static ip configured on the mgmt port and dhcp server are configured, it will benifit from this test.
1. Delete all the nameservers from the config db with cli command
    - Verify /etc/resolv.conf will be cleaned
2. Do dhcp renew
   - Verify resolvconf is disabled to receive dynamic DNS configuration(/etc/resolv.conf remains clean)

### Test cases #4 - Negative test: verify the limitation of the name server count should not excced 3, and the ip address should be correct.

1. Delete a DNS nameserver which not exist in the config db
   - Verify there is Err msg returned
   - Verify the DNS nameserver entries will not change with the show cli command
2. Add a DNS nameserver with ip address that not belong to Unicast ip address or loopback ip address
   - Verify there is Err msg returned
   - Verify the DNS nameserver entries will not change with the show cli command
3. Add a DNS nameserver that already exist in the config db
   - Verify there is Err msg returned
   - Verify the DNS nameserver entries will not change with the show cli command
4. Add the 4th DNS nameserver with cli command
   - Verify there is Err msg returned
   - Verify the DNS nameserver entries will not change with the show cli command
