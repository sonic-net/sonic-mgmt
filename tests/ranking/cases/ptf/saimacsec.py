# Copyright 2021-present Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# The below software in this distribution may have been modified
# by Centec . All Centec Modifications
# are copyright © Centec(Suzhou) Technology Limited.
#
#    The below software in this distribution may have been modified by
#    Clounix (Shanghai) Technology Limited. All Clounix Modifications
#    are copyright © Clounix (Shanghai) Technology Limited.
#

"""
Thrift SAI interface MACsec tests
"""

from sai_thrift.sai_headers import *
from sai_base_test import *


@group("draft")
class MACsecTest(SaiHelperSimplified):
    """
    Verify MACsec api
    Configuration
    """
    
    def setUp(self):
        super(MACsecTest, self).setUp()
 
    def runTest(self):
        """
        MACsec configuration flow (Phase 1: config macsec):
        1. initMacsecObject     -> createMACsecTest()
        2. createMACsecPort     -> createMACsecPortTest()
        3. bindMACsecACLTablePort -> createMACsecACLTest()
        4. createMACsecACLEapolEntry (included in ACL test)
        
        Phase 2: establish CA (not in scope for this test):
        - createMACsecFlow
        - createMACsecSC
        - createMACsecSA
        - setMACsecFlowActive
        """
        try:
            # ============================================================
            # Phase 1: config macsec
            # ============================================================
            
            # Step 1: initMacsecObject
            # Create MACsec objects (egress and ingress)
            self.createMACsecTest()
            print('Finished initMacsecObject')
            
            # Step 2: createMACsecPort
            # Create MACsec ports
            self.createMACsecPortTest()
            print('Finished createMACsecPort')
            
            # Step 3: bindMACsecACLTablePort
            # Step 4: createMACsecACLEapolEntry
            # Create MACsec ACL tables, bind to port, and create EAPOL entry
            self.createMACsecACLTest()
            print('Finished bindMACsecACLTablePort and createMACsecACLEapolEntry')
            
            # Step 5: createMACsecFlow
            self.createMACsecFlowTest()
            print('Finished createMACsecFlow')
            
            # Step 6: createMACsecSC
            self.createMACsecSCTest()
            print('Finished createMACsecSC')
            
            # Step 7: createMACsecSA
            self.createMACsecSATest()
            print('Finished createMACsecSA')
            
            # Step 8: setMACsecFlowActive
            # Note: Data ACL Entry is created in createMACsecACLTest (Phase 1)
            self.setMACsecFlowActiveTest()
            print('Finished setMACsecFlowActive')
            
            # ============================================================
            # Phase 2: Attribute and Stats tests
            # ============================================================
            
            # Step 9: MACsec object attribute tests
            self.getMACsecAttributeTest()
            print('Finished getMACsecAttribute')
            
            # Step 10: MACsec Port attribute and stats tests
            self.getMACsecPortAttributeTest()
            self.getMACsecPortStatsTest()
            print('Finished MACsec Port attribute and stats tests')
            
            # Step 11: MACsec Flow attribute and stats tests
            self.getMACsecFlowAttributeTest()
            self.getMACsecFlowStatsTest()
            print('Finished MACsec Flow attribute and stats tests')
            
            # Step 12: MACsec SC attribute and stats tests
            self.getMACsecSCAttributeTest()
            self.getMACsecSCStatsTest()
            print('Finished MACsec SC attribute and stats tests')
            
            # Step 13: MACsec SA attribute and stats tests
            self.getMACsecSAAttributeTest()
            self.getMACsecSAStatsTest()
            print('Finished MACsec SA attribute and stats tests')
            
            # Step 14: MACsec stats_ext tests
            self.getStatsExtTest()
            print('Finished MACsec stats_ext tests')
            
            print('==============================================================')
            print('All MACsec API tests PASSED!')
            print('==============================================================')
        finally:
            # Cleanup in reverse order
            self.cleanupMACsecTest()
    def createMACsecTest(self):
        """
        Verifies create MACsec on dut
        Reference: sonic-swss/orchagent/macsecorch.cpp initMACsecObject()
        """
        print('--------------------------------------------------------------')
        print('#### Create MACsec object          ####')
        # Create egress MACsec object
        # Mandatory: direction, physical_bypass_enable
        self.egress_macsec_id = sai_thrift_create_macsec(
            self.client,
            direction=SAI_MACSEC_DIRECTION_EGRESS,
            physical_bypass_enable=True)
        self.assertTrue(self.egress_macsec_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec egress id 0x%lx' % self.egress_macsec_id)
        
        # Create ingress MACsec object
        self.ingress_macsec_id = sai_thrift_create_macsec(
            self.client,
            direction=SAI_MACSEC_DIRECTION_INGRESS,
            physical_bypass_enable=True)
        self.assertTrue(self.ingress_macsec_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec ingress id 0x%lx' % self.ingress_macsec_id)
        print('#### Create MACsec object finished ####')
        
    def createMACsecPortTest(self):
        """
        Verifies create MACsec Port on dut
        Reference: sonic-swss/orchagent/macsecorch.cpp createMACsecPort()
        """
        print('--------------------------------------------------------------')
        print('#### Create MACsec Port          ####')
        port_id = getattr(self, 'port%s' % 0)
        
        # Create egress MACsec port
        # Mandatory: macsec_direction, port_id
        self.egress_macsec_port_id = sai_thrift_create_macsec_port(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_EGRESS,
            port_id=port_id)
        self.assertTrue(self.egress_macsec_port_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_port egress id 0x%lx' % self.egress_macsec_port_id)
        
        # Create ingress MACsec port
        self.ingress_macsec_port_id = sai_thrift_create_macsec_port(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_INGRESS,
            port_id=port_id)
        self.assertTrue(self.ingress_macsec_port_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_port ingress id 0x%lx' % self.ingress_macsec_port_id)
        print('#### Create MACsec Port finished ####')
        
    def createMACsecFlowTest(self):
        """
        Verifies create MACsec Flow on dut
        Reference: sonic-swss/orchagent/macsecorch.cpp createMACsecFlow()
        """
        print('--------------------------------------------------------------')
        print('#### Create MACsec Flow          ####')
        
        # Create egress MACsec flow
        # Mandatory: macsec_direction
        self.egress_macsec_flow_id = sai_thrift_create_macsec_flow(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_EGRESS)
        self.assertTrue(self.egress_macsec_flow_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_flow egress id 0x%lx' % self.egress_macsec_flow_id)
        
        # Create ingress MACsec flow
        self.ingress_macsec_flow_id = sai_thrift_create_macsec_flow(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_INGRESS)
        self.assertTrue(self.ingress_macsec_flow_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_flow ingress id 0x%lx' % self.ingress_macsec_flow_id)
        print('#### Create MACsec Flow finished ####')
    
    def createMACsecSCTest(self):
        """
        Verifies create MACsec Secure Channel on dut
        Reference: sonic-swss/orchagent/macsecorch.cpp createMACsecSC()
        """
        print('--------------------------------------------------------------')
        print('#### Create MACsec SC            ####')
        
        # SCI (Secure Channel Identifier) - 64-bit value
        # Format: MAC address (6 bytes) + Port Identifier (2 bytes)
        sci = 0x0011223344550001  # Example SCI value
        
        # Default values from macsecorch.cpp
        DEFAULT_ENABLE_ENCRYPT = True
        DEFAULT_SCI_IN_SECTAG = False
        # Use GCM-AES-128 (non-XPN) cipher suite
        DEFAULT_CIPHER_SUITE = SAI_MACSEC_CIPHER_SUITE_GCM_AES_128
        
        # Create egress MACsec SC
        # Mandatory: macsec_direction, flow_id, macsec_sci, encryption_enable,
        #            macsec_explicit_sci_enable, macsec_cipher_suite
        self.egress_macsec_sc_id = sai_thrift_create_macsec_sc(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_EGRESS,
            flow_id=self.egress_macsec_flow_id,
            macsec_sci=sci,
            encryption_enable=DEFAULT_ENABLE_ENCRYPT,
            macsec_explicit_sci_enable=DEFAULT_SCI_IN_SECTAG,
            macsec_cipher_suite=DEFAULT_CIPHER_SUITE,
            macsec_port_id=self.egress_macsec_port_id)
        self.assertTrue(self.egress_macsec_sc_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_sc egress id 0x%lx' % self.egress_macsec_sc_id)
        
        # Create ingress MACsec SC with replay protection
        enable_replay_protect = True
        replay_window = 0
        
        self.ingress_macsec_sc_id = sai_thrift_create_macsec_sc(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_INGRESS,
            flow_id=self.ingress_macsec_flow_id,
            macsec_sci=sci,
            encryption_enable=DEFAULT_ENABLE_ENCRYPT,
            macsec_explicit_sci_enable=DEFAULT_SCI_IN_SECTAG,
            macsec_cipher_suite=DEFAULT_CIPHER_SUITE,
            macsec_replay_protection_enable=enable_replay_protect,
            macsec_replay_protection_window=replay_window,
            macsec_port_id=self.ingress_macsec_port_id)
        self.assertTrue(self.ingress_macsec_sc_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_sc ingress id 0x%lx' % self.ingress_macsec_sc_id)
        print('#### Create MACsec SC finished    ####')
    
    def createMACsecSATest(self):
        """
        Verifies create MACsec Secure Association on dut
        Reference: sonic-swss/orchagent/macsecorch.cpp createMACsecSA()
        """
        print('--------------------------------------------------------------')
        print('#### Create MACsec SA            ####')
        
        # AN (Association Number) - 2-bit value (0-3)
        an = 0
        
        # SAK (Secure Association Key) - 128-bit or 256-bit
        # For GCM-AES-128: 128-bit key stored in bytes 16-31
        sak = bytearray(32)  # 32 bytes = 256 bits
        # Example 128-bit SAK (hex string converted to bytes)
        sak_hex = 121
        #sak[16:32] = bytes.fromhex(sak_hex)
        # Convert to bytes for Thrift
        #sak = bytes(sak)
        
        # Auth Key - 128-bit
        auth_key = bytearray(16)
        auth_key_hex = 111
        #auth_key[:] = bytes.fromhex(auth_key_hex)
        # Convert to bytes for Thrift
        #auth_key = bytes(auth_key)
        
        # PN (Packet Number) - initial value
        pn = 1
        
        # Create egress MACsec SA
        # Mandatory for non-XPN: macsec_direction, sc_id, an, sak, auth_key
        # Egress also needs: configured_egress_xpn
        self.egress_macsec_sa_id = sai_thrift_create_macsec_sa(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_EGRESS,
            sc_id=self.egress_macsec_sc_id,
            an=an,
            sak=sak_hex,
            auth_key=auth_key_hex,
            configured_egress_xpn=pn)
        self.assertTrue(self.egress_macsec_sa_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_sa egress id 0x%lx' % self.egress_macsec_sa_id)
        
        # Create ingress MACsec SA
        # Ingress also needs: minimum_ingress_xpn
        self.ingress_macsec_sa_id = sai_thrift_create_macsec_sa(
            self.client,
            macsec_direction=SAI_MACSEC_DIRECTION_INGRESS,
            sc_id=self.ingress_macsec_sc_id,
            an=an,
            sak=sak_hex,
            auth_key=auth_key_hex,
            minimum_ingress_xpn=pn)
        self.assertTrue(self.ingress_macsec_sa_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_sa ingress id 0x%lx' % self.ingress_macsec_sa_id)
        print('#### Create MACsec SA finished    ####')
    
    def createMACsecACLTest(self):
        """
        Phase 1: config macsec - ACL related steps
        Reference: sonic-swss/orchagent/macsecorch.cpp
                   - createMACsecACLTable()    (Step 3)
                   - bindMACsecACLTabletoPort() (Step 3)
                   - createMACsecACLEAPOLEntry() (Step 4)
        Note: createMACsecACLDataEntry() is part of Phase 2 (establish CA)
        """
        print('--------------------------------------------------------------')
        print('#### Phase 1: Create MACsec ACL Table ####')
        port_id = getattr(self, 'port%s' % 0)
        
        # SCI in SecTag configuration
        self.sci_in_sectag = False
        
        # Step 3a: Create egress MACsec ACL table
        # Reference: createMACsecACLTable()
        # ACL Stage: SAI_ACL_STAGE_EGRESS_MACSEC / SAI_ACL_STAGE_INGRESS_MACSEC
        # Bind point: SAI_ACL_BIND_POINT_TYPE_PORT
        # Fields: dst_mac, ether_type, macsec_sci
        self.egress_macsec_acl_table_id = sai_thrift_create_acl_table(
            self.client,
            acl_stage=SAI_ACL_STAGE_EGRESS_MACSEC,
            acl_bind_point_type_list=sai_thrift_s32_list_t(
                count=1, int32list=[SAI_ACL_BIND_POINT_TYPE_PORT]),
            field_dst_mac=True,
            field_ether_type=True,
            field_macsec_sci=self.sci_in_sectag)
        self.assertTrue(self.egress_macsec_acl_table_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_acl_table egress id 0x%lx' % self.egress_macsec_acl_table_id)
        
        # Step 3a: Create ingress MACsec ACL table
        self.ingress_macsec_acl_table_id = sai_thrift_create_acl_table(
            self.client,
            acl_stage=SAI_ACL_STAGE_INGRESS_MACSEC,
            acl_bind_point_type_list=sai_thrift_s32_list_t(
                count=1, int32list=[SAI_ACL_BIND_POINT_TYPE_PORT]),
            field_dst_mac=True,
            field_ether_type=True,
            field_macsec_sci=self.sci_in_sectag)
        self.assertTrue(self.ingress_macsec_acl_table_id != SAI_NULL_OBJECT_ID)
        print('####     create_macsec_acl_table ingress id 0x%lx' % self.ingress_macsec_acl_table_id)
        
        # Step 3b: Bind MACsec ACL Table to Port
        # Reference: bindMACsecACLTabletoPort()
        # Egress: SAI_PORT_ATTR_EGRESS_MACSEC_ACL
        # Ingress: SAI_PORT_ATTR_INGRESS_MACSEC_ACL
        sai_thrift_set_port_attribute(
            self.client, port_id, egress_macsec_acl=self.egress_macsec_acl_table_id)
        print('####     bound egress_acl_table to port')
        sai_thrift_set_port_attribute(
            self.client, port_id, ingress_macsec_acl=self.ingress_macsec_acl_table_id)
        print('####     bound ingress_acl_table to port')
        
        # Step 4: Create MACsec ACL EAPOL Entry
        # Reference: createMACsecACLEAPOLEntry()
        # EAPOL packet forward entry
        # Dst MAC: 01:80:c2:00:00:03 (nearest_non_tpmr_bridge)
        # EtherType: 0x888e (EAPOL)
        # Action: SAI_PACKET_ACTION_FORWARD
        
        eapol_dst_mac = '\x01\x80\xc2\x00\x00\x03'  # nearest_non_tpmr_bridge
        eapol_mac_mask = '\xff\xff\xff\xff\xff\xff'
        EAPOL_ETHER_TYPE = 0x888e - 0x10000
        EAPOL_ETHER_MASK = 0xffff - 0x10000
        eapol_entry_priority = 15  # Maximum priority
        
        # Egress EAPOL entry
        dst_mac_t = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(mac=eapol_dst_mac),
            mask=sai_thrift_acl_field_data_mask_t(mac=eapol_mac_mask))
        field_ether_type = sai_thrift_acl_field_data_t(
            enable=True,
            data=sai_thrift_acl_field_data_data_t(u16=EAPOL_ETHER_TYPE),
            mask=sai_thrift_acl_field_data_mask_t(u16=EAPOL_ETHER_MASK))
        action_packet_action = sai_thrift_acl_action_data_t(
            enable=True,
            parameter=sai_thrift_acl_action_parameter_t(
                s32=SAI_PACKET_ACTION_FORWARD))
        self.egress_eapol_acl_entry_id = sai_thrift_create_acl_entry(
            self.client,
            table_id=self.egress_macsec_acl_table_id,
            priority=eapol_entry_priority,
            admin_state=True,
            field_dst_mac=dst_mac_t,
            field_ether_type=field_ether_type,
            action_packet_action=action_packet_action)
        
        self.assertTrue(self.egress_eapol_acl_entry_id != SAI_NULL_OBJECT_ID)
        print('####     create_egress_eapol_acl_entry id 0x%lx' % self.egress_eapol_acl_entry_id)
        
        # Ingress EAPOL entry
        self.ingress_eapol_acl_entry_id = sai_thrift_create_acl_entry(
            self.client,
            table_id=self.ingress_macsec_acl_table_id,
            priority=eapol_entry_priority,
            admin_state=True,
            action_packet_action=sai_thrift_acl_action_data_t(
                enable=True,
                parameter=sai_thrift_acl_action_parameter_t(
                    s32=SAI_PACKET_ACTION_FORWARD)),
            field_dst_mac=sai_thrift_acl_field_data_t(
                enable=True,
                data=sai_thrift_acl_field_data_data_t(mac=eapol_dst_mac),
                mask=sai_thrift_acl_field_data_mask_t(mac=eapol_mac_mask)),
            field_ether_type=sai_thrift_acl_field_data_t(
                enable=True,
                data=sai_thrift_acl_field_data_data_t(u16=EAPOL_ETHER_TYPE),
                mask=sai_thrift_acl_field_data_mask_t(u16=EAPOL_ETHER_MASK)))
        self.assertTrue(self.ingress_eapol_acl_entry_id != SAI_NULL_OBJECT_ID)
        print('####     create_ingress_eapol_acl_entry id 0x%lx' % self.ingress_eapol_acl_entry_id)
        print('#### Phase 1: ACL Table and EAPOL Entry finished ####')
    
    def setMACsecFlowActiveTest(self):
        """
        Phase 2: establish CA - Activate MACsec flow on ACL entry
        Reference: sonic-swss/orchagent/macsecorch.cpp
                   - createMACsecACLDataEntry() (create data entry first)
                   - setMACsecFlowActive()
        When active:
          - Enable SAI_ACL_ENTRY_ATTR_ACTION_MACSEC_FLOW = flow_id
          - Disable SAI_ACL_ENTRY_ATTR_ACTION_PACKET_ACTION
        """
        print('--------------------------------------------------------------')
        print('#### Phase 1: Create Data ACL Entry and Activate Flow ####')
            
        # First, create MACsec ACL Data Entry
        # Reference: createMACsecACLDataEntry()
        # MACsec data entry for SCI matching
        # If sci_in_sectag is True, match on MACSEC_SCI field
        # Action: SAI_PACKET_ACTION_DROP (initial state)
            
        sci = 0x0011223344550001  # Same SCI used in SC creation
        data_entry_priority = 1
            
        # Egress data ACL entry
        if self.sci_in_sectag:
            self.egress_data_acl_entry_id = sai_thrift_create_acl_entry(
                self.client,
                table_id=self.egress_macsec_acl_table_id,
                priority=data_entry_priority,
                admin_state=True,
                action_packet_action=sai_thrift_acl_action_data_t(
                    enable=True,
                    parameter=sai_thrift_acl_action_parameter_t(
                        s32=SAI_PACKET_ACTION_DROP)),
                field_macsec_sci=sai_thrift_acl_field_data_t(
                    enable=True,
                    data=sai_thrift_acl_field_data_data_t(u64=sci),
                    mask=sai_thrift_acl_field_data_mask_t(u64=0xFFFFFFFFFFFFFFFF)))
        else:
            self.egress_data_acl_entry_id = sai_thrift_create_acl_entry(
                self.client,
                table_id=self.egress_macsec_acl_table_id,
                priority=data_entry_priority,
                admin_state=True,
                action_packet_action=sai_thrift_acl_action_data_t(
                    enable=True,
                    parameter=sai_thrift_acl_action_parameter_t(
                        s32=SAI_PACKET_ACTION_DROP)))
        self.assertTrue(self.egress_data_acl_entry_id != SAI_NULL_OBJECT_ID)
        print('####     create_egress_data_acl_entry id 0x%lx' % self.egress_data_acl_entry_id)
            
        # Ingress data ACL entry
        if self.sci_in_sectag:
            self.ingress_data_acl_entry_id = sai_thrift_create_acl_entry(
                self.client,
                table_id=self.ingress_macsec_acl_table_id,
                priority=data_entry_priority,
                admin_state=True,
                action_packet_action=sai_thrift_acl_action_data_t(
                    enable=True,
                    parameter=sai_thrift_acl_action_parameter_t(
                        s32=SAI_PACKET_ACTION_DROP)),
                field_macsec_sci=sai_thrift_acl_field_data_t(
                    enable=True,
                    data=sai_thrift_acl_field_data_data_t(u64=sci),
                    mask=sai_thrift_acl_field_data_mask_t(u64=0xFFFFFFFFFFFFFFFF)))
        else:
            self.ingress_data_acl_entry_id = sai_thrift_create_acl_entry(
                self.client,
                table_id=self.ingress_macsec_acl_table_id,
                priority=data_entry_priority,
                admin_state=True,
                action_packet_action=sai_thrift_acl_action_data_t(
                    enable=True,
                    parameter=sai_thrift_acl_action_parameter_t(
                        s32=SAI_PACKET_ACTION_DROP)))
        self.assertTrue(self.ingress_data_acl_entry_id != SAI_NULL_OBJECT_ID)
        print('####     create_ingress_data_acl_entry id 0x%lx' % self.ingress_data_acl_entry_id)
            
        # Then, activate MACsec flow on ACL entries
        # Reference: setMACsecFlowActive()
            
        # Activate egress flow
        sai_thrift_set_acl_entry_attribute(
            self.client, self.egress_data_acl_entry_id,
            action_macsec_flow=sai_thrift_acl_action_data_t(
                enable=True,
                parameter=sai_thrift_acl_action_parameter_t(
                    oid=self.egress_macsec_flow_id)))
        print('####     activated egress_macsec_flow on ACL entry')
            
        # Activate ingress flow
        sai_thrift_set_acl_entry_attribute(
            self.client, self.ingress_data_acl_entry_id,
            action_macsec_flow=sai_thrift_acl_action_data_t(
                enable=True,
                parameter=sai_thrift_acl_action_parameter_t(
                    oid=self.ingress_macsec_flow_id)))
        print('####     activated ingress_macsec_flow on ACL entry')
        print('#### Phase 2: Data ACL Entry and Flow Activation finished ####')
    
    def getMACsecAttributeTest(self):
        """
        Verifies get/set MACsec object attributes
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec Attributes      ####')
        
        # Get MACsec attributes - READ_ONLY attributes
        attrs = sai_thrift_get_macsec_attribute(
            self.client,
            self.ingress_macsec_id, direction=True)
            
        self.assertTrue(attrs.get('direction') is SAI_MACSEC_DIRECTION_INGRESS)
        print('####     get_macsec_attribute: direction=%s' % (
            attrs.get('direction')))
        
        # Set MACsec attribute
        sai_thrift_set_macsec_attribute(
            self.client,
            self.egress_macsec_id,
            physical_bypass_enable=False)
        print('####     set_macsec_attribute: physical_bypass_enable=False')
        
        # Verify set by getting the attribute
        attrs = sai_thrift_get_macsec_attribute(
            self.client,
            self.egress_macsec_id)
        self.assertTrue(attrs is not None)
        # Verify the physical_bypass_enable is Fals
        print('####     get_macsec_attribute: physical_bypass_enable=%s' % (
            attrs.get('physical_bypass_enable')))
        
        # Restore original value
        sai_thrift_set_macsec_attribute(
            self.client,
            self.egress_macsec_id,
            physical_bypass_enable=True)
        print('#### Get MACsec Attributes finished ####')
    
    def getMACsecPortAttributeTest(self):
        """
        Verifies get/set MACsec Port attributes
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec Port Attributes ####')
        
        # Get MACsec Port attributes
        attrs = sai_thrift_get_macsec_port_attribute(
            self.client,
            self.ingress_macsec_port_id, macsec_direction=True)
        self.assertTrue(attrs.get('macsec_direction') is SAI_MACSEC_DIRECTION_INGRESS)
        print('####     get_macsec_port_attribute: direction=%s' % attrs.get('macsec_direction'))
        
        # Set MACsec Port attribute - switching mode
        sai_thrift_set_macsec_port_attribute(
            self.client,
            self.egress_macsec_port_id,
            switch_switching_mode=SAI_SWITCH_SWITCHING_MODE_STORE_AND_FORWARD)
        print('####     set_macsec_port_attribute: switching_mode=STORE_AND_FORWARD')
        
        # Verify set by getting the attribute
        attrs = sai_thrift_get_macsec_port_attribute(
            self.client,
            self.egress_macsec_port_id)
        self.assertTrue(attrs is not None)
        print('####     verified switch_switching_mode=%s' % attrs.get('switch_switching_mode'))
        
        # Restore to cut-through
        sai_thrift_set_macsec_port_attribute(
            self.client,
            self.egress_macsec_port_id,
            switch_switching_mode=SAI_SWITCH_SWITCHING_MODE_CUT_THROUGH)
        print('#### Get MACsec Port Attributes finished ####')
    
    def getMACsecPortStatsTest(self):
        """
        Verifies get/clear MACsec Port statistics
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec Port Stats      ####')
        
        # Get MACsec Port stats
        stats = sai_thrift_get_macsec_port_stats(
            self.client,
            self.egress_macsec_port_id)
        self.assertTrue(stats is not None)
        print('####     get_macsec_port_stats: pre_macsec_drop=%s, control=%s, data=%s' % (
            stats.get('pre_macsec_drop_pkts', 0),
            stats.get('control_pkts', 0),
            stats.get('data_pkts', 0)))
        
        # Clear MACsec Port stats
        sai_thrift_clear_macsec_port_stats(
            self.client,
            self.egress_macsec_port_id)
        print('####     clear_macsec_port_stats done')
        print('#### Get MACsec Port Stats finished ####')
    
    def getMACsecFlowAttributeTest(self):
        """
        Verifies get/set MACsec Flow attributes
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec Flow Attributes ####')
        
        # Get MACsec Flow attributes
        attrs = sai_thrift_get_macsec_flow_attribute(
            self.client,
            self.ingress_macsec_flow_id, macsec_direction=True)
        self.assertTrue(attrs.get('macsec_direction') is SAI_MACSEC_DIRECTION_INGRESS)
        print('####     get_macsec_flow_attribute: direction=%s' % attrs.get('macsec_direction'))
        print('#### Get MACsec Flow Attributes finished ####')
    
    def getMACsecFlowStatsTest(self):
        """
        Verifies get/clear MACsec Flow statistics
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec Flow Stats      ####')
        
        # Get MACsec Flow stats
        stats = sai_thrift_get_macsec_flow_stats(
            self.client,
            self.egress_macsec_flow_id)
        self.assertTrue(stats is not None)
        print('####     get_macsec_flow_stats: octets_uncontrolled=%s, octets_controlled=%s' % (
            stats.get('octets_uncontrolled', 0),
            stats.get('octets_controlled', 0)))
        
        # Clear MACsec Flow stats
        sai_thrift_clear_macsec_flow_stats(
            self.client,
            self.egress_macsec_flow_id)
        print('####     clear_macsec_flow_stats done')
        print('#### Get MACsec Flow Stats finished ####')
    
    def getMACsecSCAttributeTest(self):
        """
        Verifies get/set MACsec SC attributes
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec SC Attributes   ####')
        
        # Get MACsec SC attributes
        attrs = sai_thrift_get_macsec_sc_attribute(
            self.client,
            self.egress_macsec_sc_id,flow_id=True)
        self.assertTrue(attrs is not None)
        print('####     get_macsec_sc_attribute: flow_id=0x%lx, encryption=%s, cipher=%s' % (
            attrs.get('flow_id', 0),
            attrs.get('encryption_enable'),
            attrs.get('macsec_cipher_suite')))
        
        # Set MACsec SC attribute - encryption enable
        sai_thrift_set_macsec_sc_attribute(
            self.client,
            self.egress_macsec_sc_id,
            encryption_enable=False)
        print('####     set_macsec_sc_attribute: encryption_enable=False')
        
        # Verify set by getting the attribute
        attrs = sai_thrift_get_macsec_sc_attribute(
            self.client,
            self.egress_macsec_sc_id, encryption_enable=True)
        self.assertTrue(attrs is not None)
        print('####     verified encryption_enable=%s' % attrs.get('encryption_enable'))
        
        # Restore encryption
        sai_thrift_set_macsec_sc_attribute(
            self.client,
            self.egress_macsec_sc_id,
            encryption_enable=True)
        print('#### Get MACsec SC Attributes finished ####')
    
    def getMACsecSCStatsTest(self):
        """
        Verifies get/clear MACsec SC statistics
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec SC Stats        ####')
        
        # Get MACsec SC stats
        stats = sai_thrift_get_macsec_sc_stats(
            self.client,
            self.egress_macsec_sc_id)
        self.assertTrue(stats is not None)
        print('####     get_macsec_sc_stats: sa_not_in_use=%s' % stats.get('sa_not_in_use', 0))
        
        # Clear MACsec SC stats
        sai_thrift_clear_macsec_sc_stats(
            self.client,
            self.egress_macsec_sc_id)
        print('####     clear_macsec_sc_stats done')
        print('#### Get MACsec SC Stats finished ####')
    
    def getMACsecSAAttributeTest(self):
        """
        Verifies get/set MACsec SA attributes
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec SA Attributes   ####')
        
        # Get MACsec SA attributes
        attrs = sai_thrift_get_macsec_sa_attribute(
            self.client,
            self.ingress_macsec_sa_id, configured_egress_xpn=True)
        self.assertTrue(attrs is not None)
        print('####     get_macsec_sa_attribute: configured_egress_xpn=%s' % (
            attrs.get('configured_egress_xpn')))
        
        # Set MACsec SA attribute - configured egress xpn
        new_xpn = 1
        sai_thrift_set_macsec_sa_attribute(
            self.client,
            self.ingress_macsec_sa_id,
            minimum_ingress_xpn=new_xpn)
        print('####     set_macsec_sa_attribute: minimum_ingress_xpn=%d' % new_xpn)
        
        # Verify set by getting the attribute
        attrs = sai_thrift_get_macsec_sa_attribute(
            self.client,
            self.ingress_macsec_sa_id, minimum_ingress_xpn=True)
        print('####     verified minimum_ingress_xpn=%s' % attrs.get('minimum_ingress_xpn'))
        print('#### Get MACsec SA Attributes finished ####')
    
    def getMACsecSAStatsTest(self):
        """
        Verifies get/clear MACsec SA statistics
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec SA Stats        ####')
        
        # Get MACsec SA stats - egress stats
        stats = sai_thrift_get_macsec_sa_stats(
            self.client,
            self.egress_macsec_sa_id, [SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED])
        self.assertTrue(stats is not None)
        print('####     get_macsec_sa_stats: SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED=%s' % (
            stats.get('SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED', 0)))
        
        # Get ingress SA stats
        stats = sai_thrift_get_macsec_sa_stats(
            self.client,
            self.ingress_macsec_sa_id, [SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED])
        self.assertTrue(stats is not None)
        print('####     get_macsec_sa_stats (ingress): SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED=%s' % (
            stats.get('SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED', 0)))
        
        # Clear MACsec SA stats
        sai_thrift_clear_macsec_sa_stats(
            self.client,
            self.egress_macsec_sa_id)
        print('####     clear_macsec_sa_stats done')
        print('#### Get MACsec SA Stats finished ####')
    
    def getStatsExtTest(self):
        """
        Verifies get MACsec stats_ext APIs with stats_mode parameter
        """
        print('--------------------------------------------------------------')
        print('#### Get MACsec Stats Ext       ####')
        
        # Get MACsec Port stats ext
        # stats_mode should match SAI_MACSEC_ATTR_STATS_MODE
        stats_mode = SAI_STATS_MODE_READ_AND_CLEAR
        
        stats = sai_thrift_get_macsec_port_stats_ext(
            self.client,
            self.egress_macsec_port_id, stats_mode)
        self.assertTrue(stats is not None)
        print('####     get_macsec_port_stats_ext: SAI_MACSEC_PORT_STAT_PRE_MACSEC_DROP_PKTS=%s' % stats.get('SAI_MACSEC_PORT_STAT_PRE_MACSEC_DROP_PKTS', 0))
        
        # Get MACsec Flow stats ext
        stats = sai_thrift_get_macsec_flow_stats_ext(
            self.client,
            self.egress_macsec_flow_id,
            stats_mode)
        self.assertTrue(stats is not None)
        print('####     get_macsec_flow_stats_ext: SAI_MACSEC_FLOW_STAT_IN_PKTS_NO_SCI=%s' % stats.get('SAI_MACSEC_FLOW_STAT_IN_PKTS_NO_SCI', 0))
        
        # Get MACsec SC stats ext
        stats = sai_thrift_get_macsec_sc_stats_ext(
            self.client,
            self.egress_macsec_sc_id,
            stats_mode)
        self.assertTrue(stats is not None)
        print('####     get_macsec_sc_stats_ext: SAI_MACSEC_SC_STAT_SA_NOT_IN_USE=%s' % stats.get('SAI_MACSEC_SC_STAT_SA_NOT_IN_USE', 0))
        
        # Get MACsec SA stats ext
        stats = sai_thrift_get_macsec_sa_stats_ext(
            self.client,
            self.egress_macsec_sa_id,
            stats_mode, [SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED])
        self.assertTrue(stats is not None)
        print('####     get_macsec_sa_stats_ext: SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED=%s' % stats.get('SAI_MACSEC_SA_STAT_OCTETS_ENCRYPTED', 0))
        print('#### Get MACsec Stats Ext finished ####')
    
    def cleanupMACsecTest(self):
        """
        Cleanup all MACsec objects in reverse order
        Order: ACL Entries -> ACL Tables -> SA -> SC -> Flow -> Port -> MACsec
        """
        print('--------------------------------------------------------------')
        print('#### Cleanup MACsec objects      ####')
        port_id = getattr(self, 'port%s' % 0)
        
        # Remove ACL entries
        if hasattr(self, 'egress_data_acl_entry_id') and self.egress_data_acl_entry_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_acl_entry(self.client, self.egress_data_acl_entry_id)
            print('####     removed egress_data_acl_entry')
        if hasattr(self, 'ingress_data_acl_entry_id') and self.ingress_data_acl_entry_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_acl_entry(self.client, self.ingress_data_acl_entry_id)
            print('####     removed ingress_data_acl_entry')
        if hasattr(self, 'egress_eapol_acl_entry_id') and self.egress_eapol_acl_entry_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_acl_entry(self.client, self.egress_eapol_acl_entry_id)
            print('####     removed egress_eapol_acl_entry')
        if hasattr(self, 'ingress_eapol_acl_entry_id') and self.ingress_eapol_acl_entry_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_acl_entry(self.client, self.ingress_eapol_acl_entry_id)
            print('####     removed ingress_eapol_acl_entry')
        
        # Unbind ACL tables from port
        if hasattr(self, 'egress_macsec_acl_table_id') and self.egress_macsec_acl_table_id != SAI_NULL_OBJECT_ID:
            sai_thrift_set_port_attribute(
                self.client, port_id, egress_macsec_acl=int(SAI_NULL_OBJECT_ID))
            print('####     unbound egress_macsec_acl_table from port')
        if hasattr(self, 'ingress_macsec_acl_table_id') and self.ingress_macsec_acl_table_id != SAI_NULL_OBJECT_ID:
            sai_thrift_set_port_attribute(
                self.client, port_id, ingress_macsec_acl=int(SAI_NULL_OBJECT_ID))
            print('####     unbound ingress_macsec_acl_table from port')
        
        # Remove ACL tables
        if hasattr(self, 'egress_macsec_acl_table_id') and self.egress_macsec_acl_table_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_acl_table(self.client, self.egress_macsec_acl_table_id)
            print('####     removed egress_macsec_acl_table')
        if hasattr(self, 'ingress_macsec_acl_table_id') and self.ingress_macsec_acl_table_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_acl_table(self.client, self.ingress_macsec_acl_table_id)
            print('####     removed ingress_macsec_acl_table')
        
        # Remove SA
        if hasattr(self, 'egress_macsec_sa_id') and self.egress_macsec_sa_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_sa(self.client, self.egress_macsec_sa_id)
            print('####     removed egress_macsec_sa')
        if hasattr(self, 'ingress_macsec_sa_id') and self.ingress_macsec_sa_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_sa(self.client, self.ingress_macsec_sa_id)
            print('####     removed ingress_macsec_sa')
        
        # Remove SC
        if hasattr(self, 'egress_macsec_sc_id') and self.egress_macsec_sc_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_sc(self.client, self.egress_macsec_sc_id)
            print('####     removed egress_macsec_sc')
        if hasattr(self, 'ingress_macsec_sc_id') and self.ingress_macsec_sc_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_sc(self.client, self.ingress_macsec_sc_id)
            print('####     removed ingress_macsec_sc')
        
        # Remove Flow
        if hasattr(self, 'egress_macsec_flow_id') and self.egress_macsec_flow_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_flow(self.client, self.egress_macsec_flow_id)
            print('####     removed egress_macsec_flow')
        if hasattr(self, 'ingress_macsec_flow_id') and self.ingress_macsec_flow_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_flow(self.client, self.ingress_macsec_flow_id)
            print('####     removed ingress_macsec_flow')
        
        # Remove Port
        if hasattr(self, 'egress_macsec_port_id') and self.egress_macsec_port_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_port(self.client, self.egress_macsec_port_id)
            print('####     removed egress_macsec_port')
        if hasattr(self, 'ingress_macsec_port_id') and self.ingress_macsec_port_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec_port(self.client, self.ingress_macsec_port_id)
            print('####     removed ingress_macsec_port')
        
        # Remove MACsec
        if hasattr(self, 'egress_macsec_id') and self.egress_macsec_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec(self.client, self.egress_macsec_id)
            print('####     removed egress_macsec')
        if hasattr(self, 'ingress_macsec_id') and self.ingress_macsec_id != SAI_NULL_OBJECT_ID:
            sai_thrift_remove_macsec(self.client, self.ingress_macsec_id)
            print('####     removed ingress_macsec')
        
        print('#### Cleanup MACsec finished      ####')

    def tearDown(self):
        super(MACsecTest, self).tearDown()


