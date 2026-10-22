#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Unit tests for capability_report.py HTML rendering.

Assertions target the contract the reader depends on: English UI, full enum
names in child rows, both meanings of the slash, aggregate counts, and the
Source column carrying case name plus outcome.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import capability_report as cr  # noqa: E402


def cell(attr, op, value, verdict, sources=(), enum_type=None, applicable=True):
    return {'module': 'sairoute', 'attr': attr, 'op': op, 'value': value,
            'verdict': verdict, 'sources': list(sources),
            'enum_type': enum_type, 'applicable': applicable}


PA = 'SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION'


class RenderTest(unittest.TestCase):

    def _doc(self, cells):
        return {'cells': cells,
                'summary': {'supported': 1, 'not_supported': 1, 'not_tested': 1,
                            'total': 3, 'unjoined_records': 0}}

    def test_child_rows_use_full_enum_name(self):
        html = cr.render(self._doc([
            cell(PA, 'create', 'SAI_PACKET_ACTION_DROP', 'supported',
                 enum_type='sai_packet_action_t'),
        ]))
        self.assertIn('SAI_PACKET_ACTION_DROP', html)

    def test_ui_text_is_english(self):
        html = cr.render(self._doc([cell(PA, 'create', None, 'not_tested')]))
        for token in ('Supported', 'Not supported', 'Not tested',
                      'Granularity', 'Source', 'create', 'set', 'read'):
            self.assertIn(token, html)
        for zh in ('支持', '未测到', '不支持', '粒度', '来源'):
            self.assertNotIn(zh, html)

    def test_source_column_shows_case_and_outcome(self):
        html = cr.render(self._doc([
            cell(PA, 'create', 'SAI_PACKET_ACTION_LOG', 'not_supported',
                 sources=[{'case': 'saiacl.AclLogTest', 'outcome': 'FAILED (failures=1)'}],
                 enum_type='sai_packet_action_t'),
        ]))
        self.assertIn('saiacl.AclLogTest', html)
        self.assertIn('FAILED', html)

    def test_many_sources_are_folded(self):
        srcs = [{'case': 'm.C%d' % i, 'outcome': 'OK'} for i in range(155)]
        html = cr.render(self._doc([
            cell(PA, 'create', 'SAI_PACKET_ACTION_DROP', 'supported',
                 sources=srcs, enum_type='sai_packet_action_t'),
        ]))
        self.assertIn('+150', html)          # 5 shown, 150 folded

    def test_inapplicable_op_renders_slash(self):
        html = cr.render(self._doc([
            cell('SAI_VLAN_ATTR_MEMBER_LIST', 'create', None, 'not_tested',
                 applicable=False),
        ]))
        self.assertIn('／', html)

    def test_attr_row_shows_aggregate_for_expandable_attr(self):
        cells = [
            cell(PA, 'create', 'SAI_PACKET_ACTION_DROP', 'supported',
                 enum_type='sai_packet_action_t'),
            cell(PA, 'create', 'SAI_PACKET_ACTION_TRAP', 'supported',
                 enum_type='sai_packet_action_t'),
            cell(PA, 'create', 'SAI_PACKET_ACTION_LOG', 'not_tested',
                 enum_type='sai_packet_action_t'),
        ]
        html = cr.render(self._doc(cells))
        self.assertIn('2/3', html)

    def test_module_grouping_present(self):
        html = cr.render(self._doc([cell(PA, 'create', None, 'not_tested')]))
        self.assertIn('sairoute', html)

    def test_filter_controls_present(self):
        html = cr.render(self._doc([cell(PA, 'create', None, 'not_tested')]))
        for ctrl in ('id="f-module"', 'id="f-verdict"', 'id="f-granularity"',
                     'id="f-search"'):
            self.assertIn(ctrl, html)

    def test_unjoined_warning_shown_when_nonzero(self):
        doc = self._doc([cell(PA, 'create', None, 'not_tested')])
        doc['summary']['unjoined_records'] = 7
        html = cr.render(doc)
        self.assertIn('unjoined', html.lower())

    def test_output_is_single_self_contained_file(self):
        html = cr.render(self._doc([cell(PA, 'create', None, 'not_tested')]))
        self.assertNotIn('<script src=', html)
        self.assertNotIn('<link rel="stylesheet"', html)


class VerdictMatrixTest(unittest.TestCase):
    """The matrix explaining how declaration x measurement picks a state."""

    DOC = {'cells': [cell(PA, 'create', None, 'supported')],
           'summary': {'supported': 1, 'not_supported': 0, 'not_tested': 0,
                       'total': 1, 'unjoined_records': 0}}

    def _matrix(self):
        html = cr.render(self.DOC)
        start = html.index('<table class="vm">')
        return html[start:html.index('</table>', start)]

    def test_names_both_axes(self):
        matrix = self._matrix()
        self.assertIn('Declared in SAI spec', matrix)
        self.assertIn('Measured on chip', matrix)

    def test_covers_every_measured_outcome(self):
        matrix = self._matrix()
        for outcome in ('Passed', 'Failed', 'Not run'):
            self.assertIn(outcome, matrix)

    def test_undeclared_row_is_all_slashes(self):
        matrix = self._matrix()
        row = matrix[matrix.index('Not declared'):]
        self.assertEqual(row.count(cr.NA_SLASH), 3)

    def test_wording_comes_from_the_shared_verdict_text(self):
        """Otherwise the explanation drifts from the tables it explains."""
        matrix = self._matrix()
        for text in cr.VERDICT_TEXT.values():
            self.assertIn(text, matrix)

    def test_precedes_the_module_tables(self):
        html = cr.render(self.DOC)
        self.assertLess(html.index('<table class="vm">'),
                        html.index('<details'))


if __name__ == '__main__':
    unittest.main()
