OCS data plane topology definition
==================================

  -------------- --------------------- ---------------
  Date           Author                Comments
  July 9, 2025   Huang Xin, SVT team   Initial draft
  -------------- --------------------- ---------------

1. Purpose
----------

This document defines the topology of the Optical Circuit Switch (OCS)
data plane, specifying the physical structure, connectivity and
performance parameters to ensure reliable optical signal transmission

2. Scope
--------

This topology definition covers:

-   Physical fiber and node layout

-   Enable flexible reconfiguration of optical paths (Main objective)

-   Provide high-bandwidth, low-latency connectivity

3. Physical Topology Components
-------------------------------

![图示 AI
生成的内容可能不正确。](media/image1.png){width="5.768055555555556in"
height="4.6715277777777775in"}

### 3.1 OCS 

-   **Optical Switch Matrix**: 64×64 port configuration

### 3.2 Endpoint Connections

-   **Server Connections (Dell R760XS)**:

    -   2 CPUs each has 24 cores (48 cores);

    -   192G memory (16Gx12);

    -   hard disk:960Gx1

    -   Mellanox CX6 (NIC)

        -   ConnectX-6 DX 100GbE Dual Port

        -   ConnectX-6 100GbE Single Port

-   **Root Fanout:**

    -   **Arista-7260CX3-64**

        -   64 ports, 12.8T

        -   Supports LACP/LLDP passthrough

        -   Supports 802.1Q tunning (QinQ)

-   **Leaf Fanout: **

    -   **Arista 7060X6-64PE: (2U)**

        -   64X800GbE OSFP ports, 2SFP+ports

        -   64 ports 800G, 51.2T

        -   Migrate to 320 interfaces

        -   Supports LACP/LLDP passthrough

        -   Supports 802.1Q tunning (QinQ)

-   **Network Gateway Connections**:

    -   Inter-switch links to routers

4.Testing Objectives
--------------------

-   Full mesh capability

    -   any-to-any connectivity

    -   64x64 Simultaneous connectivity Test

-   Dynamic path provisioning

5. Deploy an OCS Testbed
------------------------

### 5.1 Testbed.yaml

### 5.2 Inventory file

### 5.3 Variation (host\_var setup\_environment)
