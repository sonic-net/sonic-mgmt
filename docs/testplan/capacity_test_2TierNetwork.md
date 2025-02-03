# Test Objective
This test aims to track switch power usage, temperature, queue watermark and health state.

# Test Setup
![Test Setup](./2TierNetwork.png)

1.	The testbed consists of four IXIA traffic generators (synchronized using a time-sync metronome) and five SONiC switches, where the BT1 switch is the Device Under Test (DUT).
2.	Each of the four BT0 switches is connected to the DUT via eight DAC cables. There are no direct connections between any two BT0 switches.
3.	Each BT0 switch is also connected to one IXIA traffic generator via eight optical cables. Similarly, there are no direct connections between any two IXIA devices.
4.	Both switches and IXIAs support four port breakout modes: 8x100Gbps, 4x200Gbps, 2x400Gbps, and 1x800Gbps. However, they must operate in the same mode. In 8x100Gbps mode, each cable supports eight links. In 4x200Gbps mode, each cable supports four links. So on and so forth.
5.	The routing configuration of the BT0 switches should ensure that all data traffic go through the DUT.

# Configuration
1. The test duration is configurable with default value of 1 hour. 

2. The data sampling rate is also configurable with default value of every 1 minute. 

3. The total traffic volume is configurable with default value of 6400Gbps per IXIA. 

# Test Steps
1. Stress the DUT by injecting all IXIA’s traffic (800G per physical port, 6400G per IXIA) into the testbed. Keep the traffic running for 1 hour:

2. Using the switch commands below or RPC (Remote Procedure Call), collect the DUT’s power usage level, platform temperature, queue watermark and interface traffic rates, respectively, every minute. Save the sampled raw data to a storage via an abstract interface provided by SONiC team.

# Metrics to check
```
PSU power usage: show platform psu. 
Sensor temperature: show platform temperature. Among of the outputs, “Cpu temp sensor“ and “Switch Card temp sensor” are of interest.
Queue watermark: show queue watermark. 
Interface counters: show interface counters. (The outputs include drop counters.)
```