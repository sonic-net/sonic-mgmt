# Announce routes

Announce routes to the exabgp processes running in the PTF container.

## Overview

This method is automatically run in add-topo period or manually run from localhost. (Related api doc: [announce_routes.md](../api_wiki/ansible_methods/announce_routes.md)).
In this method, we generate routes for different topos by configuration defined in `ansible/vars/topo_*.yml` files.

Get the configuration of all neighbor VMs, and use different rules to generate routes according to the router type of the neighbor. Then send post requests to the exabgp processes running in the PTF container to announce routes to DUT.

|topo type|upstream router type|downstream router type|
|:----:|:----:|:----:|
|t0|leaf|N/A|
|t1|spine|tor|
|t2|core|leaf|
|t0-mclag|leaf|N/A|
|m0|m1|mx|

## M0

### Design

For M0, we have 2 sets of routes that we are going to advertise:
- 1st set routes are advertised by the upstream VMs (M1 devices).
- 2nd set routes are advertised by the downstream VMs (MX devices).

The picture below shows how the routes is announces to DUT. The green arrows indicate routes that announced by upstream M1. The blue arrows indicate routes that announced by downstream MX. The yellow line indicates subnets that directly connected to DUT, which need to be skipped when generating routes.
![](./img/announce_routes_m0.png)

### Implementation details

Some definitions:
|definition|description|
|:----|:----|
|colo|cluster of M0 devices|
|colo_number|number of COLOs|
|m0_number|number of subnet in a M0|
|m0_subnet_number|number of members in a M0 subnet|
|mx_number|number of MXs connected to a M0|
|mx_subnet_number|number of members in a MX subnet|

The total number of routes are controlled by the colo_number, m0_number, mx_subnet_number, m0_subnet_number and number of MX devices from the topology file.
We would have the following distribution:
- Routes announced by per M1 device, total number: 1 + 1 + (colo_number * m0_number - 1) * (m0_subnet_number + mx_number * mx_subnet_number)
   - 1 default route, prefix: 0.0.0.0/0.
   - 1 loopback route.
   - Subnet routes of M0 devices connected to M1 devices other than directly connected to DUT,
     count: (colo_number * m0_number - 1) * m0_subnet_number.
   - Subnet routes of MX devices connected to M0 devices connected M1 devices,
     count: (colo_number * m0_number - 1) * mx_number * mx_subnet_number.
- Routes announced by per MX routes, total number: 1 + mx_subnet_number
   - 1 loopback route.
   - Subunet routes of MX, count: mx_subnet_number.

### Key function
```
def fib_m0(topo, ptf_ip, action="announce"):
    """
    Entry of generating routes for M0 dut.
    """
    ... code ...

def generate_m0_routes(nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start, router_type, m0_subnet_size,
                       mx_number, mx_subnet_number, ip_base, mx_subnet_size, mx_asn_start, mx_index):
    """
    Call function that generates downstream routes or upstream routes by router_type
    """
    ... code ...

def generate_m0_upstream_routes(nexthop, colo_number, m0_number, m0_subnet_number, m0_asn_start, mx_number,
                                mx_subnet_number, ip_base, m0_subnet_size, mx_subnet_size, mx_asn_start):
    """
    Generate upstream routes. Firstly, generate default route. Secondly, generate subnet routes of M0 devices
    connected to M1 devices other than directly connected. Lastly, generate subnet routes of MX devices
    connected to M0 devices connected M1 devices.
    """
    ... code ...

def generate_m0_downstream_routes(nexthop, mx_subnet_number, mx_subnet_size, m0_subnet_number, m0_subnet_size, ip_base,
                                  mx_index):
    """
    Generate subnet routes of MX devices.
    """
    ... code ...

def generate_prefix(subnet_size, ip_base, offset):
    """
    Generate prefixs of route
    Args:
        subnet_size: subnet size of prefix generated
        ip_base: start ip
        offset: offset from start ip
    """
    ... code ...

def get_new_ip(curr_ip, skip_count):
    """
    Get the [skip_count]th ip after curr_ip
    """
    ... code ...
```
