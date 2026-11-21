from tests.ranking.report import render_capability


def _sample_document(source_case='sairoute.multipleRoutesTest'):
    return {
        'cells': [
            {
                'module': 'sairoute',
                'attr': 'SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION',
                'op': 'create',
                'value': 'SAI_PACKET_ACTION_FORWARD',
                'enum_type': 'sai_packet_action_t',
                'applicable': True,
                'verdict': 'supported',
                'sources': [{'case': source_case, 'outcome': 'passed'}],
            },
            {
                'module': 'sairoute',
                'attr': 'SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION',
                'op': 'create',
                'value': 'SAI_PACKET_ACTION_DROP',
                'enum_type': 'sai_packet_action_t',
                'applicable': True,
                'verdict': 'partially_supported',
                'sources': [
                    {'case': 'sairoute.multipleRoutesTest',
                     'outcome': 'passed'},
                    {'case': 'sairoute.dropRouteTest', 'outcome': 'failed'},
                ],
            },
            {
                'module': 'sairoute',
                'attr': 'SAI_ROUTE_ENTRY_ATTR_NEXT_HOP_ID',
                'op': 'create',
                'value': None,
                'enum_type': None,
                'applicable': True,
                'verdict': 'not_supported',
                'sources': [
                    {'case': 'sairoute.dropRouteTest', 'outcome': 'failed'},
                ],
            },
            {
                'module': 'sairoute',
                'attr': 'SAI_ROUTE_ENTRY_ATTR_META_DATA',
                'op': 'set',
                'value': None,
                'enum_type': None,
                'applicable': True,
                'verdict': 'not_tested',
                'sources': [],
            },
        ],
        'summary': {
            'supported': 1,
            'partially_supported': 1,
            'not_supported': 1,
            'not_tested': 1,
            'total': 4,
        },
    }


def test_capability_renderer_exposes_a_scoped_document_free_section():
    section = render_capability.render_section({
        'cells': [],
        'summary': {
            'supported': 0,
            'partially_supported': 0,
            'not_supported': 0,
            'not_tested': 0,
            'total': 0,
        },
    })

    for markup in ('<!DOCTYPE', '<html', '<head', '<body'):
        assert markup not in section
    assert 'Capability Matrix' in section
    assert '<h2>SAI Capability Report</h2>' not in section
    assert '.filters' in render_capability.styles()
    script = render_capability.script()
    assert "document.getElementById('report-capability-panel')" in script
    assert 'root.querySelectorAll' in script


def test_summary_separates_attributes_cells_and_coverage():
    section = render_capability.render_section(_sample_document())

    for label in (
            'Attributes', 'Capability cells', 'Tested cells', 'Coverage',
            'Supported', 'Partial', 'Not supported', 'Not tested'):
        assert label in section
    assert '75.0%' in section


def test_zero_total_coverage_is_safe():
    section = render_capability.render_section({'cells': [], 'summary': {}})

    assert '0.0%' in section


def test_verdict_help_is_collapsed_after_filters():
    section = render_capability.render_section(_sample_document())

    assert '<details class="verdict-help">' in section
    assert '<summary>How verdicts work</summary>' in section
    assert '<details class="verdict-help" open>' not in section
    assert section.index('class="filters"') < section.index('verdict-help')


def test_verdict_help_uses_the_approved_axis_and_state_labels():
    section = render_capability.render_section(_sample_document())

    matrix = section[section.index('<table class="vm">'):]
    corner = ('<th class="vm-corner"><div class="vm-axis-labels">'
              '<span>Test results on chip &rarr;</span>'
              '<span>&darr; Operation allowed by SAI</span></div></th>')
    assert corner in matrix
    assert 'class="vm-axis-row"' not in matrix
    assert 'colspan="5"' not in matrix
    for label in ('ALL PASSED', 'MIXED', 'ALL FAILED', 'NOT RUN',
                  'ALLOWED', 'NOT ALLOWED'):
        assert label in section
    for verdict in ('Supported', 'Partially supported', 'Not supported',
                    'Not tested'):
        assert verdict in section
    assert 'Measured on chip' not in section
    assert 'Declared in SAI spec' not in section


def test_verdict_explanations_use_one_term_per_table_row():
    section = render_capability.render_section(_sample_document())

    assert '<table class="verdict-legend">' in section
    legend = section[section.index('<table class="verdict-legend">'):]
    expected_terms = (
        'Allowed', 'Not allowed', 'Supported', 'Partially supported',
        'Not supported', 'Not tested', '／',
    )
    for term in expected_terms:
        assert '<tr><th>%s</th><td>' % term in legend
    assert '<tr><th>n/N</th><td>' not in legend
    assert ('Timeout, error, and skipped cases are inconclusive; they are '
            'shown in Evidence and do not change the verdict.') in legend
    assert '<div class="legend">' not in section


def test_verdict_labels_are_consistent_across_report_controls_and_summaries():
    section = render_capability.render_section(_sample_document())

    assert '<h3>Partially supported</h3>' in section
    assert '<option value="partially_supported">Partially supported</option>' in section
    assert '1 partially supported' in section
    assert '>PARTIAL<' not in section
    assert 'negative evidence' not in section
    assert 'All conclusive test results passed' in section
    assert 'Both passing and failing conclusive test results' in section
    assert 'All conclusive test results failed' in section
    assert 'No conclusive test results are available' in section
    assert 'decisive case results' not in section


def test_modules_start_collapsed_with_status_summary():
    section = render_capability.render_section(_sample_document())

    assert '<details class="module" data-module="sairoute">' in section
    assert '3 attributes' in section
    assert '2 tested' in section
    assert '1 partial' in section
    assert '1 not supported' in section
    assert 'data-module="sairoute" open' not in section


def test_filter_script_auto_opens_only_matching_modules_and_keeps_state():
    script = render_capability.script()

    assert 'data-filter-open' in script
    assert 'd.open = live > 0;' in script
    assert "removeAttribute('data-filter-open')" in script
    assert 'position: sticky' in render_capability.styles()


def test_attribute_table_keeps_core_columns_and_embeds_granularity():
    section = render_capability.render_section(_sample_document())

    assert '<th>Attribute</th>' in section
    assert '<th>Granularity</th>' not in section
    assert '<th>Source</th>' not in section
    assert 'class="gran-tag"' in section
    assert 'Enum value (2)' in section
    assert '<span class="gran-tag">Attribute</span>' in section
    assert '<option value="attr">Attribute</option>' in section
    assert '<option value="value">Enum value</option>' in section


def test_operation_headers_use_sai_api_get_terminology():
    section = render_capability.render_section(_sample_document())

    for label in ('CREATE', 'SET', 'GET'):
        assert '<th>%s</th>' % label in section
    assert '<th>READ</th>' not in section


def test_sources_are_rendered_as_escaped_evidence():
    section = render_capability.render_section(
        _sample_document(source_case='<script>'))

    assert 'class="evidence"' in section
    assert 'sairoute.multipleRoutesTest' in section
    assert '&lt;script&gt;' in section
    assert '<script> (passed)' not in section


def test_evidence_prioritizes_failures_and_exposes_all_grouped_sources():
    sources = [
        {'case': 'case.pass.%02d' % index, 'outcome': 'passed'}
        for index in range(8)
    ]
    sources.extend([
        {'case': 'case.timeout', 'outcome': 'timeout'},
        {'case': 'case.failed', 'outcome': 'failed'},
    ])

    evidence = render_capability._evidence(sources)

    assert '10 cases &middot; 1 failed &middot; 1 timeout &middot; 8 passed' in evidence
    preview = evidence[evidence.index('class="evidence-preview"'):
                       evidence.index('class="evidence-more"')]
    assert preview.index('case.failed') < preview.index('case.timeout')
    assert preview.index('case.timeout') < preview.index('case.pass.00')
    assert 'case.pass.02' in preview
    assert 'case.pass.03' not in preview
    assert '<summary>Show remaining 5</summary>' in evidence
    for name in ('case.pass.03', 'case.pass.04', 'case.pass.05',
                 'case.pass.06', 'case.pass.07'):
        assert name in evidence


def test_value_rows_keep_the_full_sai_enum_name():
    section = render_capability.render_section(_sample_document())

    assert 'SAI_PACKET_ACTION_FORWARD' in section
    assert 'SAI_PACKET_ACTION_DROP' in section


def test_missing_value_level_operations_are_not_tested_not_not_allowed():
    section = render_capability.render_section(_sample_document())

    start = section.index('<td class="c-attr">SAI_PACKET_ACTION_FORWARD')
    child_row = section[start:section.index('</tr>', start)]
    assert child_row.count('Not tested') == 2
    assert 'class="na-slash"' not in child_row
    # Parent-level applicability remains unchanged and still uses the slash.
    assert 'class="na-slash"' in section


def test_filters_keep_each_label_with_its_control():
    section = render_capability.render_section(_sample_document())

    assert section.count('class="filter-field') == 4
    for label, control in (
            ('Module', '<select id="f-module">'),
            ('Verdict', '<select id="f-verdict">'),
            ('Granularity', '<select id="f-granularity">'),
            ('Search', '<input id="f-search"')):
        label_pos = section.index('>%s</label>' % label)
        field_start = section.rfind('<div class="filter-field', 0, label_pos)
        field_end = section.index('</div>', field_start)
        field = section[field_start:field_end]
        assert '>%s</label>' % label in field
        assert control in field

    styles = render_capability.styles()
    assert '.filter-field {' in styles
    assert '.filter-field.search {' in styles
    assert '.filter-field select {' in styles
    select_rule = styles[styles.index('.filter-field select {'):]
    select_rule = select_rule[:select_rule.index('}')]
    assert 'min-width: 0' in select_rule


def test_value_attribute_name_is_an_accessible_toggle_button():
    section = render_capability.render_section(_sample_document())

    assert ('<button type="button" class="attr-toggle" '
            'aria-expanded="false"') in section
    assert 'aria-controls="cap-value-' in section
    assert '<span class="twisty" aria-hidden="true">' in section
    assert '<strong>SAI_ROUTE_ENTRY_ATTR_PACKET_ACTION</strong>' in section
    assert 'id="cap-value-' in section

    script = render_capability.script()
    assert "tr.querySelector('.attr-toggle')" in script
    assert "setAttribute('aria-expanded', open ? 'true' : 'false')" in script
    assert "t.addEventListener('click'" not in script
