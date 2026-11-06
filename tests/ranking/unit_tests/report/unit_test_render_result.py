import re

import pytest

from tests.ranking.report import render_result


def _module_open_states(page):
    return {
        module: bool(open_attr)
        for open_attr, module in re.findall(
            r'<details class="module"( open)?>\s*<summary>'
            r'<span class="module-name">([^<]+)</span>', page)
    }


def test_result_report_renders_manifest_baseline_and_not_tested_cases():
    page = render_result.render([
        {
            'case': 'sairoute.multipleRoutesTest',
            'status': 'passed',
            'duration_seconds': 22.96,
            'log_href': '../cases/sairoute/logs/multipleRoutesTest.log',
        },
        {
            'case': 'sairoute.dropRouteTest',
            'status': 'not_tested',
            'duration_seconds': None,
            'log_href': None,
        },
    ])

    assert 'sairoute.multipleRoutesTest' in page
    assert '>PASS<' in page
    assert '22.960 s' in page
    assert '../cases/sairoute/logs/multipleRoutesTest.log' in page
    assert 'sairoute.dropRouteTest' in page
    assert '>NOT TESTED<' in page
    assert 'Tested</span><strong>1</strong>' in page
    assert 'Not tested</span><strong>1</strong>' in page


def test_result_report_maps_every_final_case_status():
    rows = []
    for index, status in enumerate(('failed', 'skipped', 'timeout')):
        rows.append({
            'case': 'module.Case{}'.format(index),
            'status': status,
            'duration_seconds': index + 0.25,
            'log_href': '../cases/module/logs/Case{}.log'.format(index),
        })

    page = render_result.render(rows)

    for label in ('FAIL', 'SKIP', 'TIMEOUT'):
        assert '>{}<'.format(label) in page


def test_result_report_summarizes_statuses_and_groups_modules():
    rows = []
    for index, status in enumerate(
            ('passed', 'failed', 'skipped', 'timeout')):
        rows.append({
            'case': 'sairoute.Case{}'.format(index),
            'status': status,
            'duration_seconds': index + 0.25,
            'log_href': '../cases/sairoute/logs/Case{}.log'.format(index),
        })
    rows.append({
        'case': 'saisanity.NotRun',
        'status': 'not_tested',
        'duration_seconds': None,
        'log_href': None,
    })

    page = render_result.render(rows)

    for status in ('passed', 'failed', 'skipped', 'timeout', 'not_tested'):
        assert ('data-status="{}"><span>{}</span><strong>1</strong>'.format(
            status, status.replace('_', ' ').title())) in page
        assert ('class="segment {}" style="width:20.0%"'.format(
            status)) in page
    assert 'Pass rate</span><strong>25.0%</strong>' in page
    assert 'Execution coverage</span><strong>80.0%</strong>' in page
    assert _module_open_states(page) == {
        'sairoute': True,
        'saisanity': False,
    }
    assert '1 passed · 1 failed · 1 skipped · 1 timeout' in page
    assert '1 not tested' in page


def test_result_report_handles_an_empty_manifest():
    page = render_result.render([])

    assert 'Pass rate</span><strong>0.0%</strong>' in page
    assert 'Execution coverage</span><strong>0.0%</strong>' in page
    assert 'No cases in manifest.' in page


def test_result_report_preserves_first_module_and_case_occurrence_order():
    page = render_result.render([
        {
            'case': 'second.FirstCase',
            'status': 'passed',
            'duration_seconds': 1,
            'log_href': '../cases/second/logs/FirstCase.log',
        },
        {
            'case': 'first.OnlyCase',
            'status': 'passed',
            'duration_seconds': 2,
            'log_href': '../cases/first/logs/OnlyCase.log',
        },
        {
            'case': 'second.LastCase',
            'status': 'passed',
            'duration_seconds': 3,
            'log_href': '../cases/second/logs/LastCase.log',
        },
    ])

    assert page.index('>second</span>') < page.index('>first</span>')
    assert page.index('second.FirstCase') < page.index('second.LastCase')


def test_result_report_escapes_case_module_and_log_url():
    page = render_result.render([{
        'case': 'module&lt;.Case<script>',
        'status': 'passed',
        'duration_seconds': 1,
        'log_href': '../logs/case?value="quoted"&next=<unsafe>',
    }])

    assert '<span class="module-name">module&amp;lt;</span>' in page
    assert 'module&amp;lt;.Case&lt;script&gt;' in page
    assert ('href="../logs/case?value=&quot;quoted&quot;&amp;next='
            '&lt;unsafe&gt;"') in page
    assert '<script>' not in page


def test_result_report_rejects_an_unknown_status():
    with pytest.raises(ValueError, match='unknown case status: broken'):
        render_result.render([{
            'case': 'module.Case',
            'status': 'broken',
            'duration_seconds': None,
            'log_href': None,
        }])


def test_result_report_links_to_sibling_reports():
    page = render_result.render([])

    assert ('<a class="report-link" href="capability.html">'
            'Capability Report</a>') in page
    assert ('<a class="report-link" href="spec.html">'
            'Specification Report</a>') in page
