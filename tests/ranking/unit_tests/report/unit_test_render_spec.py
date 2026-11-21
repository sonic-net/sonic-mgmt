from html.parser import HTMLParser

from tests.ranking.report import render_spec


class _AttributeParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.attributes.extend(name for name, _ in attrs)


def _definition():
    return {
        ('neighbor_scale', 'create'): {
            'display_name': 'Neighbor throughput',
            'metric_type': 'throughput',
            'direction': 'higher_better',
            'unit': 'entries/s',
            'operations': ['create'],
        },
    }


def test_same_metric_raw_observations_are_preserved_and_report_is_averaged():
    actual = render_spec.build_actual_specs([
        {
            'case': 'scale.IPv4',
            'spec_results': [{
                'spec_name': 'neighbor_scale', 'operation': 'create',
                'actual_value': 100, 'extra': {'scenario': 'ipv4'},
            }],
        },
        {
            'case': 'scale.IPv6',
            'spec_results': [{
                'spec_name': 'neighbor_scale', 'operation': 'create',
                'actual_value': 200, 'extra': {'scenario': 'ipv6'},
            }],
        },
    ])

    rows = render_spec.build_spec_rows(
        actual, _definition(), _definition())

    assert [(row.test_class, row.scenario, row.value) for row in rows] == [
        ('scale.IPv4', 'ipv4', 100),
        ('scale.IPv6', 'ipv6', 200),
    ]
    page = render_spec.render_section(
        render_spec.summarize(rows), rows, actual)

    assert page.count('<strong>Neighbor throughput</strong>') == 1
    assert '<span class="val">150.00</span>' in page
    assert '<h2>Performance</h2>' in page
    assert 'Create average' not in page
    assert 'Throughput <span class="section-note">(rps' in page
    for raw_provenance in ('scale.IPv4', 'scale.IPv6', 'ipv4', 'ipv6'):
        assert raw_provenance not in page


def test_scale_report_uses_maximum_across_raw_observations():
    definitions = {
        ('ipv4_prefix', ''): {
            'display_name': 'IPv4 route scale',
            'metric_type': 'scale',
            'direction': 'higher_better',
            'unit': 'entries',
            'operations': [None],
        },
    }
    actual = render_spec.build_actual_specs([
        {
            'case': 'scale.Small',
            'spec_results': [{
                'spec_name': 'ipv4_prefix', 'actual_value': 100,
            }],
        },
        {
            'case': 'scale.Large',
            'spec_results': [{
                'spec_name': 'ipv4_prefix', 'actual_value': 200,
            }],
        },
    ])
    rows = render_spec.build_spec_rows(actual, definitions, definitions)

    page = render_spec.render_section(
        render_spec.summarize(rows), rows, actual)

    assert page.count('<strong>IPv4 route scale</strong>') == 1
    assert '<span class="val">200</span>' in page
    assert 'Reported scale' in page
    assert 'scale.Small' not in page
    assert 'scale.Large' not in page


def test_summary_counts_unique_metric_operation_cells():
    rows = [
        render_spec.SpecRow(
            spec_name='neighbor_scale', operation='create',
            unit='entries/s',
            direction='higher_better', value=100, details={},
            result='MEASURED', test_class='scale.IPv4',
            display_name='Neighbor throughput', metric_type='throughput'),
        render_spec.SpecRow(
            spec_name='neighbor_scale', operation='create',
            unit='entries/s',
            direction='higher_better', value=200, details={},
            result='MEASURED', test_class='scale.IPv6',
            display_name='Neighbor throughput', metric_type='throughput'),
        render_spec.SpecRow(
            spec_name='ipv4_prefix', operation='',
            unit='entries', direction='higher_better', value=100,
            details={}, result='MEASURED', test_class='scale.Small',
            display_name='IPv4 route scale', metric_type='scale'),
        render_spec.SpecRow(
            spec_name='ipv4_prefix', operation='',
            unit='entries', direction='higher_better', value=200,
            details={}, result='MEASURED', test_class='scale.Large',
            display_name='IPv4 route scale', metric_type='scale'),
        render_spec.SpecRow(
            spec_name='ipv4_route_fill_rate', operation='',
            unit='%', direction='higher_better',
            value=90, details={}, result='MEASURED',
            test_class='scale.Sequential',
            display_name='IPv4 route fill rate', metric_type='fill_rate'),
        render_spec.SpecRow(
            spec_name='ipv4_route_fill_rate', operation='',
            unit='%', direction='higher_better',
            value=95, details={}, result='MEASURED',
            test_class='scale.Random',
            display_name='IPv4 route fill rate', metric_type='fill_rate'),
    ]

    summary = render_spec.summarize(rows)

    assert (summary.perf_measured, summary.perf_total) == (1, 1)
    assert (summary.scale_measured, summary.scale_total) == (1, 1)
    assert (summary.fill_measured, summary.fill_total) == (1, 1)


def test_duplicate_metric_in_one_scenario_keeps_each_occurrence():
    actual = render_spec.build_actual_specs([{
        'case': 'scale.Repeated',
        'spec_results': [
            {'spec_name': 'neighbor_scale', 'operation': 'create',
             'actual_value': 10},
            {'spec_name': 'neighbor_scale', 'operation': 'create',
             'actual_value': 20},
        ],
    }])

    rows = render_spec.build_spec_rows(
        actual, _definition(), _definition())

    assert [(row.occurrence, row.value) for row in rows] == [(0, 10), (1, 20)]


def test_unmeasured_operation_stays_on_the_aggregated_metric_row():
    actual = render_spec.build_actual_specs([{
        'case': 'scale.Partial',
        'spec_results': [{
            'spec_name': 'neighbor_scale', 'operation': 'create',
            'actual_value': 100, 'extra': {'scenario': 'ipv4'},
        }],
    }])
    definitions = {
        ('neighbor_scale', 'create'): {
            'display_name': 'Neighbor throughput',
            'metric_type': 'throughput', 'direction': 'higher_better',
            'unit': 'entries/s', 'operations': ['create', 'remove'],
        },
        ('neighbor_scale', 'remove'): {
            'display_name': 'Neighbor throughput',
            'metric_type': 'throughput', 'direction': 'higher_better',
            'unit': 'entries/s', 'operations': ['create', 'remove'],
        },
    }

    rows = render_spec.build_spec_rows(actual, definitions, definitions)

    assert [
        (row.operation, row.test_class, row.scenario, row.result)
        for row in rows
    ] == [
        ('create', 'scale.Partial', 'ipv4', 'MEASURED'),
        ('remove', 'scale.Partial', 'ipv4', 'NOT MEASURED'),
    ]
    page = render_spec.render_section(
        render_spec.summarize(rows), rows, actual)

    assert page.count('<strong>Neighbor throughput</strong>') == 1
    assert 'scale.Partial' not in page
    assert '<span class="na">n/m</span>' in page
    assert '<td class="na-slash">／</td>' not in page


def test_spec_report_escapes_artifact_text_and_html_attributes():
    payload = 'x\" onmouseover=\"alert(1)<script>'
    actual = render_spec.build_actual_specs([{
        'case': payload,
        'spec_results': [{
            'spec_name': payload, 'operation': 'create', 'actual_value': 1,
            'extra': {'scenario': payload, 'error': payload},
        }],
    }])
    definitions = {
        (payload, 'create'): {
            'display_name': payload, 'metric_type': 'throughput',
            'direction': 'higher_better',
            'unit': payload, 'operations': ['create'],
        },
    }
    rows = render_spec.build_spec_rows(actual, definitions, definitions)
    summary = render_spec.summarize(rows)

    page = render_spec.render_section(
        summary, rows, actual)

    assert payload not in page
    assert '<script>' not in page
    assert '&quot; onmouseover=&quot;alert(1)&lt;script&gt;' in page
    parser = _AttributeParser()
    parser.feed(page)
    assert 'onmouseover' not in parser.attributes


def test_spec_renderer_exposes_a_document_free_section():
    actual = render_spec.build_actual_specs([{
        'case': 'scale.IPv4',
        'spec_results': [{
            'spec_name': 'neighbor_scale', 'operation': 'create',
            'actual_value': 100, 'extra': {'scenario': 'ipv4'},
        }],
    }])
    rows = render_spec.build_spec_rows(actual, _definition(), _definition())
    summary = render_spec.summarize(rows)

    section = render_spec.render_section(summary, rows, actual)

    for markup in ('<!DOCTYPE', '<html', '<head', '<body'):
        assert markup not in section
    assert 'Neighbor throughput' in section
    assert '.summary-grid' in render_spec.styles()


def test_specification_tables_scroll_inside_the_report_panel():
    actual = render_spec.build_actual_specs([{
        'case': 'scale.IPv4',
        'spec_results': [{
            'spec_name': 'neighbor_scale', 'operation': 'create',
            'actual_value': 100, 'extra': {'scenario': 'ipv4'},
        }],
    }])
    rows = render_spec.build_spec_rows(actual, _definition(), _definition())
    summary = render_spec.summarize(rows)

    section = render_spec.render_section(summary, rows, actual)

    assert '<div class="table-scroll"><table>' in section
    assert section.count('<div class="table-scroll">') == section.count('<table>')
    assert section.count('</table></div>') == section.count('<table>')
    styles = render_spec.styles()
    assert '.table-scroll {' in styles
    assert 'overflow-x: auto' in styles


def test_specification_uses_expanded_user_facing_labels():
    definitions = {
        ('acl_counter_read', 'read'): {
            'display_name': 'ACL counter read', 'metric_type': 'counter',
            'unit': 'ms',
            'direction': 'lower_better', 'operations': ['read'],
        },
    }
    actual = render_spec.build_actual_specs([{
        'case': 'counter.Case',
        'spec_results': [{
            'spec_name': 'acl_counter_read', 'operation': 'read',
            'actual_value': 1.0, 'count': 2,
            'duration_seconds': 0.001,
        }],
    }])
    rows = render_spec.build_spec_rows(actual, definitions, definitions)
    rows.append(
        render_spec.SpecRow(
            spec_name='route_latency', operation='create',
            unit='ms', direction='lower_better',
            value=1, details={}, result='MEASURED',
            test_class='route.Case', display_name='Route latency',
            metric_type='latency'))

    section = render_spec.render_section(
        render_spec.summarize(rows), rows, {})

    assert '<h2>Performance &amp; Scale</h2>' in section
    assert 'SAI Spec Test Report' not in section
    assert section.count('<h2>Performance</h2>') == 1
    assert '<h3>Operation latency' in section
    assert 'Counter Performance' not in section
    assert 'Operation Latency (ms)' not in section
    assert 'ACL counter read' in section
    assert '<td>GET</td>' in section
    assert '2 counters' in section
    assert '1.00' in section
    assert 'ms' in section
    assert 'Route latency' in section
    assert 'counter.Case' not in section
    assert 'Counter perf' not in section
    assert 'Op Latency' not in section
    assert 'Read 2 acl counters' not in section


def test_performance_separates_throughput_and_latency_units():
    rows = [
        render_spec.SpecRow(
            spec_name='route_throughput', operation='create', unit='rps',
            direction='higher_better', value=100, details={},
            result='MEASURED', test_class='route.Throughput',
            display_name='Route throughput', metric_type='throughput'),
        render_spec.SpecRow(
            spec_name='acl_counter_read', operation='read', unit='ms',
            direction='lower_better', value=2.5, details={'count': 512},
            result='MEASURED', test_class='counter.ACL',
            display_name='ACL counter read', metric_type='counter'),
        render_spec.SpecRow(
            spec_name='route_latency', operation='create', unit='ms',
            direction='lower_better', value=0.5, details={},
            result='MEASURED', test_class='route.Latency',
            display_name='Route latency', metric_type='latency'),
        render_spec.SpecRow(
            spec_name='ipv4_prefix', operation='', unit='entries',
            direction='higher_better', value=1000, details={},
            result='MEASURED', test_class='scale.IPv4',
            display_name='IPv4 route scale', metric_type='scale'),
    ]

    section = render_spec.render_section(
        render_spec.summarize(rows), rows, {})

    assert section.count('<table>') == 3
    assert section.count('<h2>Performance</h2>') == 1
    assert section.count('<h2>Scale</h2>') == 1
    assert '<h3>Throughput' in section
    assert '<h3>Operation latency' in section
    assert 'Counter Performance' not in section
    assert 'Operation Latency (ms)' not in section
    throughput = section.split('<h3>Throughput', 1)[1].split(
        '<h3>Operation latency', 1)[0]
    latency = section.split('<h3>Operation latency', 1)[1].split(
        '<h2>Scale</h2>', 1)[0]
    assert 'Route throughput' in throughput
    assert 'ACL counter read' not in throughput
    assert 'Route latency' not in throughput
    assert 'rps' in throughput
    assert 'ms' not in throughput
    assert 'ACL counter read' in latency
    assert 'Route latency' in latency
    assert 'ms' in latency
    assert 'rps' not in latency
    assert '<th>Operation</th><th>Time</th><th>Workload</th>' in latency
    assert '2.50</span><span class="unit">ms</span>' in section
    assert '512 counters' in section
    assert '0.50</span><span class="unit">ms</span>' in section


def test_scale_and_fill_validation_render_as_separate_sections():
    actual = {
        ('ipv4_prefix', '', 'scale.RouteCase', '', 0): {'value': 1000},
    }
    scale_rows = [render_spec.SpecRow(
        spec_name='ipv4_prefix', operation='', unit='entries',
        direction='higher_better', value=1000, details={},
        result='MEASURED', test_class='scale.RouteCase',
        display_name='IPv4 route scale', metric_type='scale')]
    fill_rows = [
        {
            'test_class': 'scale.Sequential',
            'spec_name': 'ipv4_route_fill_rate',
            'display_name': 'IPv4 route scale',
            'fill': 100.0,
            'installed': 1000,
            'order': 'sequential',
            'result': 'MEASURED',
        },
        {
            'test_class': 'scale.Random',
            'spec_name': 'ipv4_route_fill_rate',
            'display_name': 'IPv4 route scale',
            'fill': 90.0,
            'installed': 900,
            'order': 'random',
            'result': 'MEASURED',
        },
    ]

    table = render_spec._scale_table(scale_rows, fill_rows, actual)

    assert '<h2>Scale</h2>' in table
    assert '<h2>Fill Validation</h2>' in table
    scale_section, fill_section = table.split('<h2>Fill Validation</h2>')
    assert '>Reported scale</th>' in scale_section
    assert '<th>Installed</th>' not in scale_section
    assert '<th>Fill rate</th>' not in scale_section
    assert '<th>Installed</th><th>Fill rate</th>' in fill_section
    assert 'Capacity' not in table
    assert 'Attempted' not in table
    assert 'attempted' not in table
    assert table.count('IPv4 route scale') >= 2
    assert '2 scenarios' in table
    assert 'aria-expanded="false"' in table
    assert 'scale.Sequential' in table
    assert 'scale.Random' in table
    assert 'sequential' in table
    assert 'random' in table
    assert '1,000' in table
    assert '900' in table
    assert '90.00%' in table


def test_mixed_fill_rate_preserves_individual_scale_rows():
    actual = {
        ('ipv4_prefix', '', 'scale.Mixed', '', 0): {'value': 1000},
        ('ipv6_prefix', '', 'scale.Mixed', '', 0): {'value': 900},
    }
    scale_rows = [
        render_spec.SpecRow(
            spec_name='ipv4_prefix', operation='', unit='entries',
            direction='higher_better', value=1000, details={},
            result='MEASURED', test_class='scale.Mixed',
            display_name='IPv4 route scale', metric_type='scale'),
        render_spec.SpecRow(
            spec_name='ipv6_prefix', operation='', unit='entries',
            direction='higher_better', value=900, details={},
            result='MEASURED', test_class='scale.Mixed',
            display_name='IPv6 route scale', metric_type='scale'),
    ]
    fill_rows = [{
        'test_class': 'scale.Mixed',
        'spec_name': 'ipv4_ipv6_route_fill_rate',
        'display_name': 'IPv4/IPv6 route scale',
        'fill': 95.0,
        'installed': 855,
        'order': 'sequential',
        'result': 'MEASURED',
    }]

    table = render_spec._scale_table(scale_rows, fill_rows, actual)

    assert 'IPv4 route scale' in table
    assert 'IPv6 route scale' in table
    assert 'IPv4/IPv6 route scale' in table


def test_scale_table_allows_duplicate_display_names():
    rows = [
        render_spec.SpecRow(
            spec_name='first_scale', operation='', unit='entries',
            direction='higher_better', value=10, details={},
            result='MEASURED', test_class='scale.First',
            display_name='Shared scale', metric_type='scale'),
        render_spec.SpecRow(
            spec_name='second_scale', operation='', unit='entries',
            direction='higher_better', value=20, details={},
            result='MEASURED', test_class='scale.Second',
            display_name='Shared scale', metric_type='scale'),
    ]

    table = render_spec._scale_table(rows, [], {})

    assert table.count('Shared scale') == 2


def test_explicit_metric_type_and_display_name_drive_counter_rendering():
    registry = {
        'acl_counter_read': {
            'display_name': 'ACL counter read',
            'description': 'Total time to read ACL counters',
            'metric_type': 'counter',
            'operations': ['read'],
            'unit': 'ms',
            'direction': 'lower_better',
            'include_in_report': True,
        },
    }
    definitions = render_spec.build_registry_definitions(registry)
    actual = render_spec.build_actual_specs([{
        'case': 'counter.CollectACL',
        'spec_results': [{
            'spec_name': 'acl_counter_read',
            'operation': 'read',
            'count': 512,
            'actual_value': 1436.0,
        }],
    }])
    rows = render_spec.build_spec_rows(actual, definitions, definitions)

    page = render_spec.render_section(
        render_spec.summarize(rows), rows, actual)

    assert '<th>Spec name</th>' in page
    assert 'ACL counter read' in page
    assert 'acl_counter_read' not in page
    assert '512' in page
    assert '1,436.00' in page
    assert 'ms' in page


def test_metric_type_selects_report_section_without_name_or_direction_guessing():
    registry = {
        'custom_rate': {
            'display_name': 'Custom rate',
            'description': 'A deliberately unusual rate definition',
            'metric_type': 'throughput',
            'operations': ['verify'],
            'unit': 'items/s',
            'direction': 'lower_better',
            'include_in_report': True,
        },
    }
    definitions = render_spec.build_registry_definitions(registry)
    actual = render_spec.build_actual_specs([{
        'case': 'custom.Rate',
        'spec_results': [{
            'spec_name': 'custom_rate',
            'operation': 'verify',
            'actual_value': 10,
        }],
    }])
    rows = render_spec.build_spec_rows(actual, definitions, definitions)

    page = render_spec.render_section(
        render_spec.summarize(rows), rows, actual)

    assert '<h2>Performance</h2>' in page
    assert 'Operation Latency' not in page
    assert '<span class="val">10.00</span>' in page
    assert 'Throughput <span class="section-note">(rps' in page


def test_route_flap_is_merged_into_performance_as_group_and_member_rows():
    registry = {
        'ipv4_route_scale': {
            'display_name': 'IPv4 route throughput',
            'description': 'IPv4 route operation throughput',
            'metric_type': 'throughput',
            'operations': ['create', 'remove'],
            'unit': 'routes/s',
            'direction': 'higher_better',
        },
        'route_flap': {
            'display_name': 'Route flap throughput',
            'description': 'ECMP route flap throughput',
            'metric_type': 'throughput',
            'operations': ['group_create', 'member_create'],
            'unit': 'routes/s',
            'direction': 'higher_better',
        },
    }
    definitions = render_spec.build_registry_definitions(registry)
    actual = render_spec.build_actual_specs([{
        'case': 'route.Scale',
        'spec_results': [
            {'spec_name': 'ipv4_route_scale', 'operation': 'create',
             'actual_value': 100},
            {'spec_name': 'route_flap', 'operation': 'group_create',
             'actual_value': 200},
            {'spec_name': 'route_flap', 'operation': 'member_create',
             'actual_value': 300},
        ],
    }])
    rows = render_spec.build_spec_rows(actual, definitions, definitions)

    page = render_spec.render_section(
        render_spec.summarize(rows), rows, actual)

    assert page.count('<h2>Performance</h2>') == 1
    assert 'Route Flap (rps)' not in page
    assert 'IPv4 route throughput' in page
    assert 'Route flap — group' in page
    assert 'Route flap — member' in page
    assert 'Group create' not in page
    assert 'Member create' not in page
    assert '<span class="val">100.00</span>' in page
    assert 'Throughput <span class="section-note">(rps' in page


def test_fill_rate_rows_are_selected_by_metric_type_not_spec_name_suffix():
    registry = {
        'table_occupancy': {
            'display_name': 'Table fill rate',
            'description': 'Installed entries as a percentage of scale',
            'metric_type': 'fill_rate',
            'operations': ['learn'],
            'unit': 'percent',
            'direction': 'higher_better',
        },
    }
    definitions = render_spec.build_registry_definitions(registry)
    results = [{
        'case': 'table.Fill',
        'spec_results': [{
            'spec_name': 'table_occupancy',
            'operation': 'learn',
            'actual_value': 90.0,
            'extra': {'success_route_cnt': 900, 'order': 'sequential'},
        }],
    }]

    rows = render_spec.build_fill_rate_rows(results, definitions)

    assert len(rows) == 1
    assert rows[0]['display_name'] == 'Table fill rate'
    assert rows[0]['fill'] == 90.0
    assert rows[0]['installed'] == 900
    assert rows[0]['order'] == 'sequential'


def test_fill_rate_rows_preserve_fdb_success_count():
    registry = {
        'fdb_fill_rate': {
            'display_name': 'FDB entry scale',
            'metric_type': 'fill_rate',
            'operations': ['learn'],
            'unit': 'percent',
            'direction': 'higher_better',
        },
    }
    definitions = render_spec.build_registry_definitions(registry)
    results = [{
        'case': 'scale.Fdb',
        'spec_results': [{
            'spec_name': 'fdb_fill_rate',
            'operation': 'learn',
            'actual_value': 93.82,
            'extra': {'success_count': 7685},
        }],
    }]

    rows = render_spec.build_fill_rate_rows(results, definitions)

    assert rows[0]['installed'] == 7685
