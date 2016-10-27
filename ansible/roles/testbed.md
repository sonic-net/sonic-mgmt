# Testbed topology

                             Linux Host                                         Fanout Switch             DUT
    +---------------------------------------------------------------+          +--------------+     +---------------+
    |       PTF Docker                  Openvswitch                 |          |              |     |               |
    |   +----------------------+      +-------------+               |          |              |     |               |
    |   |                eth0  +------+             +--vlan101--+   |          |         Et1  +-----+ Ethernet0     |
    |   |                eth1  +------+             +--vlan102--|   |          |         Et2  +-----+ Ethernet4     |
    |   |                eth2  +------+             +--vlan103--|   |          |         Et3  +-----+ Ethernet8     |
    |   |                eth3  +------+             +--vlan104--|   |          |         Et4  +-----+ Ethernet12    |
    |   |                eth4  +------+             +--vlan105--|   |          |         Et5  +-----+ Ethernet16    |
    |   |                eth5  +------+             +--vlan106--|   |          |         Et6  +-----+ Ethernet20    |
    |   |                eth6  +------+             +--vlan107--|   |          |         Et7  +-----+ Ethernet24    |
    |   |                eth7  +------+             +--vlan108--|   |          |         Et8  +-----+ Ethernet28    |
    |   |                eth8  +------+             +--vlan109--|   |          |         Et9  +-----+ Etherent32    |
    |   |                eth9  +------+             +--vlan110--|   |          |         Et10 +-----+ Ethernet36    |
    |   |                eth10 +------+             +--vlan111--|   |          |         Et11 +-----+ Ethernet40    |
    |   |                eth11 +------+             +--vlan112--|   |          |         Et12 +-----+ Ethernet44    |
    |   |                eth12 +------+             +--vlan113--|   |          |         Et13 +-----+ Ethernet48    |
    |   |                eth13 +------+             +--vlan114--|   |          |         Et14 +-----+ Ethernet52    |
    |   |                eth14 +------+             +--vlan115--|   |          |         Et15 +-----+ Ethernet56    |
    |   |                eth15 +------+             +--vlan116--+---+-- eth0 --+ Et33    Et16 +-----+ Ethernet60    |
    |   |                eth16 +------+             +--vlan117--|   |          |         Et17 +-----+ Ethernet64    |
    |   |                eth17 +------+             +--vlan118--|   |          |         Et18 +-----+ Ethernet68    |
    |   |                eth18 +------+             +--vlan119--|   |          |         Et19 +-----+ Ethernet72    |
    |   |                eth19 +------+             +--vlan120--|   |          |         Et20 +-----+ Ethernet76    |
    |   |                eth20 +------+             +--vlan121--|   |          |         Et21 +-----+ Ethernet80    |
    |   |                eth21 +------+             +--vlan122--|   |          |         Et22 +-----+ Ethernet84    |
    | 	|                eth22 +------+             +--vlan123--|   |          |         Et23 +-----+ Ethernet88    |
    |   |                eth23 +------+             +--vlan124--|   |          |         Et24 +-----+ Ethernet92    |
    |   |                eth24 +------+             +--vlan125--|   |          |         Et25 +-----+ Ethernet96    |
    |   |                eth25 +------+             +--vlan126--|   |          |         Et26 +-----+ Ethernet100   |
    |   |                eth26 +------+             +--vlan127--|   |          |         Et27 +-----+ Ethernet104   |
    |   |                eth27 +------+             +--vlan128--|   |          |         Et28 +-----+ Ethernet108   |
    |   |                eth28 +------+             +--vlan129--|   |          |         Et29 +-----+ Ethernet112   |
    |   |                eth29 +------+             +--vlan130--|   |          |         Et30 +-----+ Ethernet116   |
    |   |                eth30 +------+             +--vlan131--|   |          |         Et31 +-----+ Ethernet120   |
    |   |                eth31 +------+             +--vlan132--+   |          |         Et32 +-----+ Ethernet124   |
    |   +----------------------+      +-------------+               |          |              |     |               | 
    |                                                               |          |              |     |               |
    +---------------------------------------------------------------+          +--------------+     +---------------+

- *PTF docker*: A docker container that has 32 ports with pre-installed PTF tools. See https://github.com/Azure/sonic-buildimage/tree/master/dockers/docker-ptf
- *Vlan ports*: 32 vlan ports are created on top of physical port, e.g., eth0, inside the Linux host
- *Openvswitch*: Connect 32 vlan ports to the 32 docker ports inside the Linux host. Openvswitch forwards the packet to the corresponding output port based on the incoming port. No L2/L3 forwarding is enabled in the Openvswitch.
- *Fanout switch*: A physical switch which enables VLAN trunking. Et33 is a vlan trunking port and is connected to the eth0 port of the linux host. Et1-Et32 are vlan access ports and are connect to DUT.
