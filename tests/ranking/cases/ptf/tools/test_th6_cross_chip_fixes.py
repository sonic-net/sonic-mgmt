#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import ast
import os
import unittest


TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
PTF_DIR = os.path.dirname(TOOLS_DIR)


def method_source(file_name, class_name, method_name):
    path = os.path.join(PTF_DIR, file_name)
    with open(path, encoding='utf-8') as f:
        source = f.read()
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name == class_name:
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                        and child.name == method_name:
                    return ast.get_source_segment(source, child)
    raise AssertionError('%s.%s not found in %s' %
                         (class_name, method_name, file_name))


class Th6CrossChipFixesTest(unittest.TestCase):

    def assert_reuses_default_bridge_port(self, file_name, class_name):
        setup = method_source(file_name, class_name, 'setUp')
        self.assertIn('_get_default_port_bridge_port_map()', setup)
        self.assertIn('port_to_bp.get(port_oid)', setup)
        self.assertIn('if port_bp is None:', setup)

    def test_neighbor_setup_reuses_default_bridge_port(self):
        self.assert_reuses_default_bridge_port(
            'ext_sai_l3_neighbor_scale_test.py', 'SaiHelperScaleNeighbor')

    def test_nexthop_setup_reuses_default_bridge_port(self):
        self.assert_reuses_default_bridge_port(
            'ext_sai_l3_nexthop_scale_test.py', 'SaiHelperScaleNexthop')

    def test_neighbor_uses_only_its_own_rifs(self):
        body = method_source('ext_sai_l3_neighbor_scale_test.py',
                             'SaiHelperScaleNeighbor', 'get_all_rif_list')
        self.assertIn('self.port_rif_list + self.vlan_rif_list', body)

    def test_nexthop_uses_only_its_own_rifs(self):
        body = method_source('ext_sai_l3_nexthop_scale_test.py',
                             'SaiHelperScaleNexthop', 'get_all_rif_list')
        self.assertIn('self.port_rif_list + self.vlan_rif_list', body)

    def test_nexthop_creates_neighbor_before_next_hop(self):
        body = method_source('ext_sai_l3_nexthop_scale_test.py',
                             'SaiHelperScaleNexthop', '_create_nexthops')
        self.assertLess(body.index('sai_thrift_create_neighbor_entry'),
                        body.index('sai_thrift_create_next_hop'))
        self.assertIn('isinstance(nh_id, int)', body)
        self.assertIn('nh_id != SAI_NULL_OBJECT_ID', body)

    def test_nexthop_removal_precedes_neighbor_removal(self):
        body = method_source('ext_sai_l3_nexthop_scale_test.py',
                             'SaiHelperScaleNexthop', '_remove_nexthops')
        self.assertLess(body.index('sai_thrift_remove_next_hop'),
                        body.index('sai_thrift_remove_neighbor_entry'))
        self.assertIn("isinstance(nh.get('nh_id'), int)", body)

    def test_nexthop_cases_are_bounded_by_neighbor_capacity(self):
        expectations = (
            ('L3IPv4NexthopScaleTest',
             ('available_ipv4_neighbor_entry',)),
            ('L3IPv6NexthopScaleTest',
             ('available_ipv6_neighbor_entry',)),
            ('L3IPv4IPv6NexthopScaleTest',
             ('available_ipv4_neighbor_entry',
              'available_ipv6_neighbor_entry')),
        )
        for class_name, attrs in expectations:
            body = method_source('ext_sai_l3_nexthop_scale_test.py',
                                 class_name, 'runTest')
            for attr in attrs:
                self.assertIn(attr, body)
            self.assertIn('min(', body)

    def assert_removes_next_hop_before_neighbor(self, class_name):
        body = method_source('ext_sai_l3_ecmp_scale_test.py', class_name,
                             '_cleanup_background_topology')
        self.assertLess(body.index('sai_thrift_remove_next_hop'),
                        body.index('sai_thrift_remove_neighbor_entry'))

    def test_ipv4_route_flap_cleanup_removes_next_hop_first(self):
        self.assert_removes_next_hop_before_neighbor(
            'L3IPv4EcmpRouteFlapTest')

    def test_ipv6_route_flap_cleanup_removes_next_hop_first(self):
        self.assert_removes_next_hop_before_neighbor(
            'L3IPv6EcmpRouteFlapTest')

    def test_brcm_policer_uses_ingress_acl_without_counter_action_list(self):
        body = method_source('ext_sai_counter_stress_test.py',
                             'CollectPolicerCountersTest', 'runTest')
        self.assertIn("SAI_ACL_STAGE_INGRESS if get_platform() == 'brcm'", body)
        self.assertIn("if get_platform() == 'brcm':", body)
        brcm_branch = body.split("if get_platform() == 'brcm':", 1)[1] \
                          .split('else:', 1)[0]
        self.assertNotIn('enable_counter_packet_action_list=', brcm_branch)

    def test_acl_counter_table_declares_counter_action(self):
        body = method_source('ext_sai_counter_stress_test.py',
                             'CollectACLCountersTest', 'runTest')
        self.assertIn('acl_action_type_list=', body)
        self.assertIn('SAI_ACL_ACTION_TYPE_COUNTER', body)


if __name__ == '__main__':
    unittest.main()
