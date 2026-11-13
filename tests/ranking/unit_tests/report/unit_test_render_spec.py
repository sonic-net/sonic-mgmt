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
            'result_type': 'performance',
            'direction': 'higher_better',
            'unit': 'entries/s',
            'operations': ['create'],
        },
    }


def test_same_metric_from_different_cases_and_scenarios_is_preserved():
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
    for expected in ('scale.IPv4', 'scale.IPv6', 'ipv4', 'ipv6', '100', '200'):
        assert expected in page


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


def test_unmeasured_operation_stays_on_the_measured_scenario_row():
    actual = render_spec.build_actual_specs([{
        'case': 'scale.Partial',
        'spec_results': [{
            'spec_name': 'neighbor_scale', 'operation': 'create',
            'actual_value': 100, 'extra': {'scenario': 'ipv4'},
        }],
    }])
    definitions = {
        ('neighbor_scale', 'create'): {
            'result_type': 'performance', 'direction': 'higher_better',
            'unit': 'entries/s', 'operations': ['create', 'remove'],
        },
        ('neighbor_scale', 'remove'): {
            'result_type': 'performance', 'direction': 'higher_better',
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
    assert page.count(
        '<span class="src">scale.Partial · ipv4</span>') == 1
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
            'result_type': 'performance', 'direction': 'higher_better',
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
    assert 'neighbor_scale' in section
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
    rows = [
        render_spec.SpecRow(
            spec_name='acl_counter_read', operation='read',
            result_type='performance', unit='ms', direction='lower_better',
            value=1, details={'duration_seconds': 0.001,
                              'observed_count': 2},
            result='MEASURED', test_class='counter.Case'),
        render_spec.SpecRow(
            spec_name='route_latency', operation='create',
            result_type='performance', unit='ms', direction='lower_better',
            value=1, details={}, result='MEASURED',
            test_class='route.Case'),
    ]

    section = render_spec.render_section(
        render_spec.summarize(rows), rows, {})

    assert '<h2>Performance &amp; Scale</h2>' in section
    assert 'SAI Spec Test Report' not in section
    assert 'Counter Performance' in section
    assert 'Operation Latency (ms)' in section
    assert 'Read 2 ACL counters' in section
    assert 'Counter perf' not in section
    assert 'Op Latency' not in section
    assert 'Read 2 acl counters' not in section
