from pathlib import Path


SECTIONS = {
    'result_section': '<p>RESULT BODY</p>',
    'capability_section': '<p>CAPABILITY BODY</p>',
    'spec_section': '<p>SPEC BODY</p>',
}


def test_unified_report_shell_has_three_accessible_local_tabs():
    module_path = Path('tests/ranking/report/render_report.py')
    assert module_path.is_file(), 'unified report shell is missing'

    from tests.ranking.report import render_report

    page = render_report.render(
        **SECTIONS,
        styles={
            'report-results-panel': '.result-test{color:green}',
            'report-capability-panel': '.cap-test{color:blue}',
        },
        scripts=['window.capabilityReady=true;'],
    )

    assert page.count('role="tab"') == 3
    assert page.count('role="tabpanel"') == 3
    assert page.count('aria-selected="true" tabindex="0"') == 1
    assert page.count('aria-selected="false" tabindex="-1"') == 2
    assert "candidate.setAttribute('tabindex', active ? '0' : '-1')" in page
    assert 'id="report-results-tab" role="tab"' in page
    assert 'aria-controls="report-results-panel" aria-selected="true"' in page
    assert 'id="report-results-panel" role="tabpanel"' in page
    assert 'aria-labelledby="report-results-tab"' in page
    assert 'id="report-capability-panel" role="tabpanel"' in page
    assert 'aria-labelledby="report-capability-tab" hidden' in page
    assert 'id="report-specification-panel" role="tabpanel"' in page
    assert 'aria-labelledby="report-specification-tab" hidden' in page
    assert '>Performance &amp; Scale</button>' in page
    assert '>Specification</button>' not in page
    for content in ('RESULT BODY', 'CAPABILITY BODY', 'SPEC BODY'):
        assert content in page
    assert 'window.capabilityReady=true;' in page
    assert 'aria-selected' in page and 'panel.hidden' in page
    assert '#report-results-panel .result-test' in page
    assert '#report-capability-panel .cap-test' in page
    assert '<iframe' not in page
    assert '<link ' not in page
    assert '<script src=' not in page


def test_unified_report_omits_environment_summary_by_default():
    from tests.ranking.report import render_report

    page = render_report.render(**SECTIONS)

    assert '<section class="report-environment"' not in page
    assert 'DUT ASIC' not in page


def test_unified_report_renders_and_escapes_environment_summary():
    from tests.ranking.report import render_report

    page = render_report.render(
        **SECTIONS,
        environment_summary={
            'asic': 'td5<script>',
            'platform': 'Broadcom&Vendor',
            'dut_ip': '192.0.2.10',
            'ptf_ip': '192.0.2.20',
        })

    assert 'aria-label="Test environment"' in page
    assert '<dt>DUT ASIC</dt><dd>TD5&lt;SCRIPT&gt;</dd>' in page
    assert '<dt>ASIC Vendor</dt><dd>Broadcom&amp;Vendor</dd>' in page
    assert '<dt>Platform</dt>' not in page
    assert '<dt>DUT IP</dt><dd>192.0.2.10</dd>' in page
    assert '<dt>PTF IP</dt><dd>192.0.2.20</dd>' in page
    assert 'td5<script>' not in page


def test_unified_report_owns_layout_without_nested_section_padding():
    from tests.ranking.report import render_report

    page = render_report.render(**SECTIONS)

    assert '#ranking-unified-report > .report-panel {' in page
    assert 'min-width: 0' in page
    assert '#ranking-unified-report > .report-panel > .container {' in page
    assert 'padding: 0' in page
    assert 'box-shadow: none' in page
