# SmartSwitch PA Validation Offload test plan

* [Overview](#Overview)
   * [Scope](#Scope)
   * [Testbed](#Testbed)
   * [Setup configuration](#Setup%20configuration)
* [Test](#Test)
* [Test cases](#Test%20cases)
* [TODO](#TODO)
* [Open questions](#Open%20questions)

## Overview
The purpose is to test the functionality of PA Validation offload feature on the SONIC SmartSwitch DUT.

Feature HLD: https://github.com/sonic-net/SONiC/pull/1717

### Scope
Currently, there is already an implicit pa validation in the DASH pipeline for the inbound traffic, which is handled in the DPU. This will keep the same as it is, and the validation is already covered by the DASH vnet-to-vent test. So, this is not in scope of this test plan.
This test plan focuses on the new pa validation offload feature. The new feature will support the pa validation for traffic of all directions(inbound and outbound), and the pa validation is offloaded to the switch side.
This test is targeting to verify the pa validation offload functionality works as expected.
No scale and performance tests.

### Testbed
The test will run only on smartswitch testbeds.

### Setup configuration
No setup pre-configuration is required, the test will configure and clean up all the configuration.

Common tests configuration:
- Apply the data port IP addresses and static routes for the switch and DPUs.
- Apply Private link configuration on DPU0 with ENI0.

Common tests cleanup:
- IP addresses and static routes on switch and DPUs.
- All dash configurations on DPU0.

## Test

## Test cases
### Test case # 1 – PA validation single DPU single VNI
#### Test objective
Verify PA validation and offloading works on a single DPU with a single VNI.
#### Test steps
* Apply a pa validation entry for the VM VNI and pa.
* Check on the switch appl_db that there are ACL table and rule entries for the DPU and VNI.
* Send the ENI0 outbound pa matched packet from ptf to the smartswitch.
* Verify the packet is received by the ptf.
* Send ENI0 outbound pa unmatched packet from ptf to the smartswitch.
* Verify no packet is received by the ptf.
* Apply a new pa validation entry for the unmatched pa.
* Check new ACL rules are added to the switch appl_db.
* Send the pa unmatched packet again.
* Verify the packet is received by the ptf.
* Clean all the pa validation entries.
* Check all the acl rules are cleaned in switch appl_db.
* Send the pa matched and pa unmatched packets again.
* Verify all the packets are received by the ptf.
* Apply the pa validation entry for the matched pa again.
* Send the pa matched and pa unmatched packets again.
* Verify the pa unmatched packet is received by the ptf and the pa unmatched packet is not.

### Test case # 2 – PA validation single DPU multiple VNIs
#### Test objective
Verify on a same DPU, adding or deleting the PA validation entry of a VNI doesn't affect the PA validation for another VNI.
#### Test steps
* Apply pa validation entries for 2 VNIs on a same DPU, VNI1 is the VM VNI of ENI0 in the pl config, VNI2 is a dummy VNI.
* Send the ENI0 outbound pa matched packet from ptf to the smartswitch.
* Verify the packet is received by the ptf.
* Send ENI0 outbound pa unmatched packet from ptf to the smartswitch.
* Verify no packet is received by the ptf.
* Remove the pa validation entry for the dummy vni.
* Send the pa matched packet again.
* Verify the packet is received by ptf
* Send the pa unmatched packet again.
* Verify no packet is received by the ptf.
* Remove the pa validation entry for the real VN VNI and apply it again
* Send the pa matched and pa unmatched packets again.
* Verify the pa matched packet is received by ptf and the pa unmatched packet is not.

### Test case # 3 – PA validation multiple DPUs
#### Test objective
Verify there is no conflict of pa validation configurations among multiple DPUs.
#### Test steps
* Apply the same Private link configuration as DPU0 on DPU1 only with a different ENI - ENI1.
* Apply one pa validation entry for each ENI.
* Check on the switch appl_db that there are ACL tables and rules for DPU0 and DPU1.
* Send the ENI0 outbound pa matched packet from ptf to the smartswitch.
* Send the ENI1 outbound pa matched packet from ptf to the smartswitch.
* Verify the packets of ENI0 and ENI1 are both received by the ptf.
* Send the ENI0 outbound pa unmatched packet from ptf to the smartswitch.
* Send the ENI1 outbound pa unmatched packet from ptf to the smartswitch.
* Verify no packet is received by the ptf.
* Add a new pa validation entry for the ENI1 unmatched pa on DPU1.
* Send the ENI0 pa unmatched packet again.
* Verify no packet of ENI0 is received by the ptf.
* Send the ENI1 pa unmatched packet again.
* Verify the packet of ENI1 is received by the ptf.
* Remove the newly added pa validation entry for ENI1 on DPU1.
* Add the pa validation entry for the ENI0 unmatched pa on DPU0.
* Send the ENI0 pa unmatched packet again.
* Verify the packet of ENI0 is received by the ptf.
* Send the ENI1 pa unmatched packet again.
* Verify no packet of ENI1 is received by the ptf.
* Remove the pl configuration for ENI1 on DPU1.

### Test case # 4 – PA validation DPU shutdown
#### Test objective
Verify the pa validation config is removed when the dpu is shutdown.
#### Test steps
* Apply the pa validation entries for two DPUs.
* Check in switch appl_db there are the ACL tables and rules for DPU0 and DPU1.
* Shutdown the DPU0.
* Check the ACL table and rules are removed.
* Restart DPU0 and wait for it to boot up.
* Check there is no new ACL table and rules added for DPU0.

## TODO

## Open questions
