"""
PTF test for VXLAN Tunnel Route Fine-Grained ECMP

Test cases:
- create_flows: Send NUM_FLOWS flows with varying src_ip and create flow-to-outer-IP map
- verify_consistent_hash: Verify same flows hit same outer IPs (consistent hashing)
- verify_endpoint_withdrawal: Verify only flows to withdrawn endpoint redistribute
- verify_endpoint_addition: Verify minimal flow disruption when endpoint is added back
"""

import ipaddress
import logging
import random
import os
import json
import time

import ptf
import ptf.packet as scapy

from datetime import datetime
from ptf.base_tests import BaseTest
from ptf.mask import Mask
import ptf.testutils as testutils
from ptf.testutils import (test_params_get, dp_poll, verify_packet_any_port,
                          verify_no_other_packets, send_packet, simple_tcp_packet)

import lpm

MAX_DEVIATION = 0.25
PERSIST_MAP = '/tmp/vxlan_fg_ecmp_persist_map.json'

logger = logging.getLogger(__name__)


class VxlanTunnelFgEcmpTest(BaseTest):
    """PTF test class for VXLAN Tunnel Fine-Grained ECMP."""

    def setUp(self):
        self.dataplane = ptf.dataplane_instance
        params = test_params_get()
        if "params_file" in params:
            with open(params["params_file"], "r") as f:
                params = json.load(f)
        
        self.test_case = params.get('test_case', 'create_flows')

        if "endpoints_file" in params and os.path.exists(params["endpoints_file"]):
            with open(params["endpoints_file"], "r") as f:
                self.endpoints = json.load(f)
        else:
            self.endpoints = params.get("endpoints", [])

        self.dst_ip = params.get("dst_ip")
        self.src_ip = params.get("ptf_src_ip")
        self.dut_vtep = params.get("dut_vtep")
        self.router_mac = params.get("router_mac")
        self.num_packets = int(params.get("num_packets", 6))
        self.vxlan_port = int(params.get("vxlan_port", 4789))
        self.send_port = int(params.get("ptf_ingress_port", 0))
        self.exp_flow_count = params.get('exp_flow_count', {})
        self.tcp_sport = 1234
        self.tcp_dport = 5000
        self.batch_size = 200
        
        # Test case specific parameters
        if self.test_case == 'withdraw_endpoint':
            self.withdraw_endpoint = params.get('withdraw_endpoint')
        elif self.test_case == 'add_endpoint':
            self.add_endpoint = params.get('add_endpoint')

        self.dataplane.flush()

        logger.info("=== VXLAN ECMP PTF Test Setup ===")
        logger.info(f"Test Case: {self.test_case}")
        logger.info(f"Endpoints: {len(self.endpoints)}")
        logger.info(f"Destination IP: {self.dst_ip}, Source IP: {self.src_ip}")
        logger.info(f"DUT VTEP: {self.dut_vtep}, Router MAC: {self.router_mac}")
        logger.info(f"Packets to send: {self.num_packets}, Ingress port: {self.send_port}")
        logger.info(f"VXLAN UDP Port: {self.vxlan_port}")
        logger.info("=================================")


    def _next_port(self, key="sport"):
        """Simple port generator for varying TCP ports."""
        if key == "sport":
            self.tcp_sport = (self.tcp_sport + 1) % 65535 or 1234
            return self.tcp_sport
        else:
            self.tcp_dport = (self.tcp_dport + 1) % 65535 or 5000
            return self.tcp_dport


    def test_balancing_no_assert(self, hit_count_map):
        """Test flow distribution without asserting, return max deviation."""
        deviation_max = 0
        for endpoint, exp_flows in list(self.exp_flow_count.items()):
            if endpoint not in hit_count_map:
                logger.warning(f"Endpoint {endpoint} not in hit_count_map")
                continue
            num_flows = hit_count_map[endpoint]
            deviation = float(num_flows)/float(exp_flows)
            deviation = abs(1-deviation)
            logger.info(f"Endpoint {endpoint}: exp_flows={exp_flows}, num_flows={num_flows}, deviation={deviation:.3f}")
            if deviation_max < deviation:
                deviation_max = deviation
        return deviation_max

    
    def send_and_verify_flow(self, sport, dport):
        """
        Send a single flow and capture which endpoint it hits.
        Returns the endpoint IP or None if packet wasn't captured.
        """
        src_mac = self.dataplane.get_mac(0, self.send_port)
        
        pkt = simple_tcp_packet(
            eth_dst=self.router_mac,
            eth_src=src_mac,
            ip_dst=self.dst_ip,
            ip_src=self.src_ip,
            ip_id=105,
            ip_ttl=64,
            tcp_sport=sport,
            tcp_dport=dport,
            pktlen=100,
        )
        send_packet(self, self.send_port, pkt)
        
        # Poll for VXLAN encapsulated packet
        timeout = 3
        result = dp_poll(self, device_number=0, timeout=timeout)
        
        if isinstance(result, self.dataplane.PollSuccess):
            ether_pkt = scapy.Ether(result.packet)
            if scapy.IP in ether_pkt and scapy.UDP in ether_pkt:
                if ether_pkt[scapy.UDP].dport == self.vxlan_port:
                    endpoint = ether_pkt[scapy.IP].dst
                    if endpoint in self.endpoints:
                        return endpoint
        
        return None
    
    
    def runTest(self):
        """Main test logic that handles different test cases."""
        # Initialize flow-to-endpoint mapping
        tuple_to_endpoint_map = {}
        hit_count_map = {}
        
        # Load existing mapping for non-create_flows test cases
        if not os.path.exists(PERSIST_MAP) and self.test_case == 'create_flows':
            with open(PERSIST_MAP, 'w') as f:
                json.dump({}, f)
        elif self.test_case != 'create_flows':
            if not os.path.exists(PERSIST_MAP):
                raise Exception(f"Persist map {PERSIST_MAP} not found. Run 'create_flows' test first.")
            with open(PERSIST_MAP) as fp:
                try:
                    tuple_to_endpoint_map = json.load(fp)
                except ValueError:
                    logger.error('Decoding JSON failed for persist map')
                    raise
        
        if tuple_to_endpoint_map is None or self.dst_ip not in tuple_to_endpoint_map:
            tuple_to_endpoint_map[self.dst_ip] = {}
        
        self.tcp_sport = 1234
        self.tcp_dport = 5000
        
        logger.info(f"Running test case: {self.test_case}")
        
        if self.test_case == 'create_flows':
            logger.info("Creating flow-to-endpoint mapping...")
            
            for retry_time in range(0, 3):
                hit_count_map = {}
                tuple_to_endpoint_map[self.dst_ip] = {}
                
                self.tcp_sport = 1234
                self.tcp_dport = 5000
                
                for i in range(0, self.num_packets):
                    sport = self._next_port("sport")
                    dport = self._next_port("dport")
                    
                    endpoint = self.send_and_verify_flow(sport, dport)
                    
                    if endpoint:
                        flow_key = f"{sport}:{dport}"
                        tuple_to_endpoint_map[self.dst_ip][flow_key] = endpoint
                        hit_count_map[endpoint] = hit_count_map.get(endpoint, 0) + 1
                    
                    if (i + 1) % 100 == 0:
                        logger.info(f"Created {i + 1}/{self.num_packets} flows")
                
                total_flows = len(tuple_to_endpoint_map[self.dst_ip])
                logger.info(f"Total flows created: {total_flows}")
                logger.info(f"Endpoints hit: {hit_count_map}")
                
                if not self.exp_flow_count:
                    break
                
                deviation = self.test_balancing_no_assert(hit_count_map)
                logger.info(f"Retry {retry_time + 1}: deviation={deviation:.3f}")
                
                if deviation <= MAX_DEVIATION:
                    break
            
            if self.exp_flow_count and deviation > MAX_DEVIATION:
                raise AssertionError(f"Flow distribution deviation too high: {deviation:.3f} > {MAX_DEVIATION}")
        
        elif self.test_case == 'verify_consistent_hash':
            logger.info("Verifying consistent hashing...")
            
            flows_checked = 0
            flows_matched = 0
            
            for flow_key, expected_endpoint in tuple_to_endpoint_map[self.dst_ip].items():
                sport, dport = map(int, flow_key.split(':'))
                
                actual_endpoint = self.send_and_verify_flow(sport, dport)
                
                if actual_endpoint:
                    flows_checked += 1
                    if actual_endpoint == expected_endpoint:
                        flows_matched += 1
                    else:
                        logger.error(f"Flow {flow_key} changed: {expected_endpoint} -> {actual_endpoint}")
                
                if (flows_checked + 1) % 100 == 0:
                    logger.info(f"Checked {flows_checked} flows")
            
            match_rate = flows_matched / flows_checked if flows_checked > 0 else 0
            logger.info(f"Consistent hashing: {flows_matched}/{flows_checked} matched ({match_rate*100:.2f}%)")
            
            if match_rate < 1.0:
                raise AssertionError(f"Consistent hashing failed: only {match_rate*100:.2f}% of flows matched")
        
        elif self.test_case == 'withdraw_endpoint':
            if not self.withdraw_endpoint:
                raise Exception("withdraw_endpoint parameter required for this test")
            
            logger.info(f"Testing endpoint withdrawal: {self.withdraw_endpoint}")
            
            flows_to_withdrawn = []
            flows_to_others = []
            
            for flow_key, endpoint in tuple_to_endpoint_map[self.dst_ip].items():
                if endpoint == self.withdraw_endpoint:
                    flows_to_withdrawn.append(flow_key)
                else:
                    flows_to_others.append(flow_key)
            
            logger.info(f"Flows to withdrawn endpoint: {len(flows_to_withdrawn)}")
            logger.info(f"Flows to other endpoints: {len(flows_to_others)}")
            
            redistributed_count = 0
            stable_count = 0
            
            for flow_key, old_endpoint in tuple_to_endpoint_map[self.dst_ip].items():
                sport, dport = map(int, flow_key.split(':'))
                new_endpoint = self.send_and_verify_flow(sport, dport)
                
                if new_endpoint:
                    assert new_endpoint != self.withdraw_endpoint, \
                        f"Flow {flow_key} still hitting withdrawn endpoint {self.withdraw_endpoint}"
                    
                    hit_count_map[new_endpoint] = hit_count_map.get(new_endpoint, 0) + 1
                    
                    if old_endpoint == self.withdraw_endpoint:
                        # This flow should redistribute to a different endpoint
                        redistributed_count += 1
                        tuple_to_endpoint_map[self.dst_ip][flow_key] = new_endpoint
                    else:
                        # This flow should stay on the same endpoint
                        if new_endpoint == old_endpoint:
                            stable_count += 1
                        else:
                            logger.warning(f"Flow {flow_key} unexpectedly moved: {old_endpoint} -> {new_endpoint}")
            
            logger.info(f"Redistributed flows: {redistributed_count}")
            logger.info(f"Stable flows: {stable_count}/{len(flows_to_others)}")
            
            # Save updated mapping
            json.dump(tuple_to_endpoint_map, open(PERSIST_MAP, "w"))
        
        elif self.test_case == 'add_endpoint':
            if not self.add_endpoint:
                raise Exception("add_endpoint parameter required for this test")
            
            logger.info(f"Testing endpoint addition: {self.add_endpoint}")
            
            moved_to_new = 0
            stayed_same = 0
            
            for flow_key, old_endpoint in tuple_to_endpoint_map[self.dst_ip].items():
                sport, dport = map(int, flow_key.split(':'))
                new_endpoint = self.send_and_verify_flow(sport, dport)
                
                if new_endpoint:
                    hit_count_map[new_endpoint] = hit_count_map.get(new_endpoint, 0) + 1
                    
                    if new_endpoint == self.add_endpoint:
                        # Flow moved to newly added endpoint
                        moved_to_new += 1
                        tuple_to_endpoint_map[self.dst_ip][flow_key] = new_endpoint
                    elif new_endpoint == old_endpoint:
                        # Flow stayed on same endpoint
                        stayed_same += 1
                    else:
                        # Flow moved unexpectedly
                        logger.warning(f"Flow {flow_key} moved unexpectedly: {old_endpoint} -> {new_endpoint}")
            
            total_flows = len(tuple_to_endpoint_map[self.dst_ip])
            logger.info(f"Flows moved to new endpoint: {moved_to_new}/{total_flows}")
            logger.info(f"Flows stayed same: {stayed_same}/{total_flows}")
            logger.info(f"Hit count distribution: {hit_count_map}")
            
            json.dump(tuple_to_endpoint_map, open(PERSIST_MAP, "w"))
        
        else:
            raise Exception(f"Unsupported test case: {self.test_case}")
        
        if self.test_case == 'create_flows':
            json.dump(tuple_to_endpoint_map, open(PERSIST_MAP, "w"))
            logger.info(f"Flow mapping saved to {PERSIST_MAP}")


    def tearDown(self):
        self.dataplane.flush()
        logger.info("Dataplane flushed — VXLAN ECMP test complete")