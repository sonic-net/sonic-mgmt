 # Egress SFlow Test Plan



 <span id="_Toc205800613" class="anchor"><span id="_Toc463421032" class="anchor"><span id="_Toc463514628" class="anchor"></span></span></span>**Related documents**

 |                   |          |
 |-------------------|----------|
 | **Document Name** | **Link** |
 |  SFLOW HLD,Sflow testplan  | https://github.com/sonic-net/SONiC/tree/master/doc/sflow |





 ## **Overview**
 The purpose is to test the functionality of the sFlow monitoring system in both Ingress and Egress direction on the SONiC switch DUT . The test assumes that the Sonic device has been preconfigured according to the t0 topology.

 ### Scope
 ---------
 The test is targetting egress sflow functionality test on SONiC DUT with T0 configuration.The test will also cover testing egress sflow in combination with ingress sflow.

 ### Scale / Performance
 -------------------
 N/A

 ### Related **DUT** CLI commands
 ----------------------------

 | **Command**                                                      | **Comment** |
 |------------------------------------------------------------------|-------------|
 | **Configuration commands**                                       |             | 
 | config sflow enable/disable                                      |Enable/Disable sflow globally             |
 | config sflow sample-direction <rx/tx/both>                       |set sflow direction globally            |
 | config sflow interface <enable/disable>                          |Enable/Disable sflow interface level         |
 | config sflow interface sample-rate                                   |set sample-rate at interface level             |
 | config sflow interface sample-direction <rx/tx/both>             |set sflow direction at interface level            |
 | config sflow collector add/del                                   |collector configuration            |
 | **Show commands**                                                |             |
 | show sflow,show sflow interface                                  |global and interface level show commands             |
 
 
 ### Related DUT configuration files
 -----------------------------------
 Uses T0 Configuration
 
 ### Related SAI APIs
 ----------------
 sai_create_samplepacket<br />
 sai_remove_samplepacket<br />
 sai_set_samplepacket_attribute<br />
 sai_get_samplepacket_attribute<br />
 set SAI_PORT_ATTR_INGRESS_SAMPLEPACKET_ENABLE<br />
 set SAI_PORT_ATTR_EGRESS_SAMPLEPACKET_ENABLE<br />
 
 
 
 ## Test structure 
 ===============
 
 ### Setup configuration
 -------------------
 
 The test will run on the t0 testbed:
 
 ![testbed-t0.png](https://github.com/sonic-net/sonic-mgmt/blob/master/docs/testbed/img/testbed-t0.png?raw=true)
 
 - Initially in the set-up call platform dependency check will be done for egress sflow support by querying STATE_DB, if platform supports egress sflow then all the testcases under this testplan will be executed else will skip.
 - 2 ports from Vlan1000 are removed and used to reach sflow collector in ptf docker .
 - Traffic is sent from ptf docker with different packet sizes to the Leaf ports,server ports which are enabled with sflow .
 - Collection is implemented using the sflowtool. Counter sampling output and flow sampling output are directed to a text file. The test script parses the text file and validates the data according to the polling/sampling rate configured and the interfaces enabled.
 - Ingress and Egress samples will be identified using integer attribute PSAMPLE_ATTR_SAMPLE_GROUP - expects ingress samples to appear with group=1, and egress samples to appear with group=2 
 - Sflowtool to be installed in ptf docker to run these tests.
 - All the testcases will configure sample-rate = 512 unless specified
 
 **Terminology :**
 | **Term**                              | **Meaning**                            |
 |---------------------------------------|----------------------------------------|
 | leaf-port1                | DUT port connected to VM1              | 
 | server-port1                          | DUT port connected to PTF docker port1 |
 | server-port2                          | DUT port connected to PTF docker port2 |
 
 ### Test Cases
 
 #### Test Case #1
 
 ##### Test objective
 
 Verify that ingress and egress sampling on different ports (server-port1 and leaf-port1)
 
 | #    | Steps                                                        | Expected Result                                              |
 | ---- | :----------------------------------------------------------- | ------------------------------------------------------------ |
 | 1.   | 1. Enable sflow globally and set the sample-direction to 'tx' <br />2. Add a single collector with default port (6343), <br />3. Set the sample_rate to 512 on all ports<br /> 4. Send traffic from server- port1 to leaf-port1.| The configurations should be reflected in “show sflow” and "show sflow interface". <br />Verify only egress Samples should be received by the collector .|
 | 2.   | 1. At interface level for server-port1 set the sample-direction to 'rx'<br />2. Send traffic from server- port1 to leaf-port1  | The configurations should be reflected in “show sflow” and "show sflow interface".<br />Verify collector receives both ingress and egress samples. |
 | 3.   | 1. At global level set the sample-direction to 'rx'(i,e Disable egress sflow globally)<br />2. Send traffic from server- port1 to leaf-port1 | The configurations should be reflected in “show sflow” and "show sflow interface". only Ingress samples should be received by the collector.|
 | 4.   | 1. At interface level for leaf-port1 set the sample-direction to 'tx' <br />2. Send traffic from server- port1 to leaf-port1 | Verify collector receives both ingress and egress samples |
 
 #### Test Case #2
 
 ##### Test objective
 
 Verify that the ingress and egress sflow on the same port(server-port2).
 
 | #    | Steps                                                        | Expected Result                                              |
 | ---- | :----------------------------------------------------------- | ------------------------------------------------------------ |
 | 1.   | 1. Enable sflow globally <br /> 2.At interface level set sample-direction to both on server-port2<br /> 3. Send bi-directional traffic from server port1 and server-port2| Verify collector receives both ingress and egress samples.|
 | 2.   | 1. For server-port2,set the sample-direction to 'tx' <br />2. Send bi-directional traffic from server port1 and server-port2 | The configurations should be reflected in “show sflow” and "show sflow interface".<br />Verify collector receives only egress samples. |
 | 3.   | 1. For server-port2,set the sample-direction to 'rx' <br />2. Send bi-directional traffic from server port1 and server-port2 | The configurations should be reflected in “show sflow” and "show sflow interface".Verify collector receives only ingress samples.|
 | 4.   | 1.  For server-port2,set the sample-direction to 'both' <br />2. Send bi-directional traffic from server port1 and server-port2 | Verify collector receives both ingress and egress samples |
 | 5.   | 1.  For server-port1,set the sample-direction to 'both' <br />2. Send bi-directional traffic from server port1 and server-port2 | Verify collector receives both ingress and egress samples from server-port1 and server-port2 |
 
 #### Test Case #3
 
 ##### Test objective
 
 Verify that the ingress and egress sflow with different sample-rates on the different port.Also cover min(256) and max(8388608) sample-rate boundary cases
 
 | #    | Steps                                                        | Expected Result                                              |
 | ---- | :----------------------------------------------------------- | ------------------------------------------------------------ |
 | 1.   | 1. Enable sflow globally<br />2. For server-port1 set sample-rate = 512 <br />3.For leaf-port1 set the sample-direction to 'tx' <br />4. Send traffic from server-port1 and leaf-port1 | Verify collector receives both ingress and egress samples as per the configured sample-rates.|
 | 2.   | 1. Update the sample-rate to 512 for leaf-port1(egress-sflow) and 1024 for server-port1 (ingress-sflow) <br />2. Send traffic from server-port1 and leaf-port1 | Verify collector receives both ingress and egress samples as per the configured sample-rates |
 | 3.   | 1. Update sample-rate to 8388608 for server-port1(ingress sflow) and sample-rate to 256 for leaf-port1(egress-sflow) <br />2. Send traffic from server-port1 and leaf-port1 | Verify collector receives both ingress and egress samples as per the configured sample-rate.|
 | 4.   | 1. Update sample-rate to 8388608 for leaf-port1(egress-sflow) and 256 for server-port1(ingress sflow) <br />2. Send traffic from server-port1 and leaf-port1 | Verify collector receives both ingress and egress samples as per the configured sample-rate.|
 | 5.   | 1. set the sample-direction to 'both' on server-port1 and server-port2 <br />2. Set the sample-rate to 256 on server-port1 and 8388608 on server-port2<br />3. Send bi-directional traffic from server-port1 and server-port2  | Verify collector receives both ingress and egress samples from server-port1 and server-port2 and as per the configured sample-rate.|
 |Note: |For max sample_rate only configuration will be validation, as PTF I/O infra takes longer time for sending higher traffic rate.|
 
 
 #### Test Case #4
 
 ##### Test objective
 
 Verify that sflow configs with globally Disabled and enabled interface level.
 
 | #    | Steps                                                        | Expected Result                                              |
 | ---- | :----------------------------------------------------------- | ------------------------------------------------------------ |
 | 1.   | 1. Disable sflow globally.set the sample-direction to 'both' at global level<br />2. Enable sflow on server-port1 and set the direction to 'rx'<br />3. Enable sflow on leaf-port1 and set the sample-direction to 'tx'<br />4.Send traffic from server-port1 and leaf-port1| The configurations should be reflected in “show sflow” and "show sflow interface.Verify NO samples are received at the collector|
 | 2.   | 1. set the sample-direction to 'rx' at global level<br />2. Enable sflow on server-port1 and set the direction to 'rx'<br />3. Enable sflow on leaf-port1 and set the sample-direction to 'tx'<br />4.Send traffic from server-port1 and leaf-port1| The configurations should be reflected in “show sflow” and "show sflow interface.Verify NO samples are received at the collector.|
 | 3.   | 1. set the sample-direction to 'tx' at global level<br />2. Enable sflow on server-port1 and set the direction to 'rx'<br />3. Enable sflow on leaf-port1 and set the sample-direction to 'tx'<br />4.Send traffic from server-port1 and leaf-port1| The configurations should be reflected in “show sflow” and "show sflow interface. Verify NO samples are received at the collector.|
 | 4.   | 1. Enable sflow globally <br />2.Send traffic from server-port1 and server-port2| The configurations should be reflected in “show sflow” and "show sflow interface.Verify ingress samples are received at the collector.|
 
 
 #### Test Case #5
 
 ##### Test objective
 
 Verify that sflow sampling behaviour when enabled at global level and disable at interface level.
 
 | #    | Steps                                                        | Expected Result                                              |
 | ---- | :----------------------------------------------------------- | ------------------------------------------------------------ |
 | 1.   | 1. Enable sflow globally and set the sample-direction to 'both'.<br />2. Disable sflow on all interface using interface level configs.<br />3. Send traffic from server-port1 to leaf-port1| Verify sflow admin-state is Down on all ports.The configurations should be reflected in “show sflow” and "show sflow interface.Verify NO samples are received at collector|
 | 2.   | 1. Enable sflow globally and set the sample-direction to 'tx'.<br />2. Disable sflow on all interface using interface level configs and set the direction to both at interface level.<br />3. Send traffic from server-port1 to leaf-port1| Verify sflow admin-state is Down on all ports.The configurations should be reflected in “show sflow” and "show sflow interface.Verify NO samples are received at collector|
 | 3.   | 1. Enable sflow globally and set the sample-direction to 'rx'.<br />2. Disable sflow on all interface using interface level configs and set the direction to both at interface level.<br />3. Send traffic from server-port1 to leaf-port1| Verify sflow admin-state is Down on all ports.The configurations should be reflected in “show sflow” and "show sflow interface.Verify NO samples are received at collector|
 | 4.   | 1. Enable sflow globally and set the sample-direction to 'both'.<br />2. Enable sflow on all interface using interface level configs.<br />3. Send traffic from server-port1 to leaf-port1| Verify sflow admin-state is Down on all ports.The configurations should be reflected in “show sflow” and "show sflow interface.Verify both ingress and egress samples are received at collector.|
