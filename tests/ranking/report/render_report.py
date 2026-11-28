"""Compose the three Ranking report sections into one self-contained page."""

from html import escape
import re


_COMMENT = re.compile(r'/\*.*?\*/', re.DOTALL)

_SHELL_CSS = """
:root {
  --report-bg: #f4f6f8;
  --report-panel: #ffffff;
  --report-border: #d8dee4;
  --report-text: #1f2328;
  --report-muted: #59636e;
  --report-accent: #596fd6;
}
* { box-sizing: border-box; }
body {
  margin: 0; padding: 28px; background: var(--report-bg);
  color: var(--report-text);
  font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.report-shell {
  max-width: 1500px; margin: 0 auto; padding: 32px 36px;
  background: var(--report-panel); border: 1px solid var(--report-border);
  border-radius: 12px; box-shadow: 0 2px 12px rgba(31,35,40,.06);
}
.report-shell > h1 {
  margin: 0; padding-bottom: 16px; border-bottom: 2px solid var(--report-accent);
  font-size: 25px; line-height: 1.25;
}
.report-environment {
  margin: 16px 0 0; padding: 12px 16px; border: 1px solid var(--report-border);
  border-radius: 8px; background: #f6f8fa;
}
.report-environment dl {
  display: grid; grid-template-columns: repeat(4, minmax(130px, 1fr));
  gap: 12px 20px; margin: 0;
}
.report-environment div { min-width: 0; }
.report-environment dt {
  color: var(--report-muted); font-size: 12px; font-weight: 600;
  text-transform: uppercase;
}
.report-environment dd {
  margin: 2px 0 0; overflow-wrap: anywhere; font-weight: 600;
}
.report-tabs {
  display: flex; flex-wrap: wrap; gap: 6px; margin: 18px 0 22px;
  border-bottom: 1px solid var(--report-border);
}
.report-tabs button {
  margin-bottom: -1px; padding: 10px 16px; border: 1px solid transparent;
  border-radius: 7px 7px 0 0; background: transparent;
  color: var(--report-muted); font: inherit; font-weight: 600; cursor: pointer;
}
.report-tabs button:hover { color: var(--report-text); background: #f6f8fa; }
.report-tabs button[aria-selected="true"] {
  color: var(--report-text); background: var(--report-panel);
  border-color: var(--report-border) var(--report-border) var(--report-panel);
}
.report-tabs button:focus-visible {
  outline: 2px solid var(--report-accent); outline-offset: 2px;
}
.report-panel[hidden] { display: none; }
#ranking-unified-report > .report-panel {
  min-width: 0; margin: 0; padding: 0; background: transparent;
}
#ranking-unified-report > .report-panel > .container {
  max-width: none; margin: 0; padding: 0; border: 0;
  border-radius: 0; background: transparent; box-shadow: none;
}
@media (max-width: 640px) {
  body { padding: 10px; }
  .report-shell { padding: 20px 14px; }
  .report-tabs { display: grid; grid-template-columns: 1fr; border-bottom: 0; }
  .report-tabs button { margin: 0; border-radius: 6px; text-align: left; }
  .report-tabs button[aria-selected="true"] { border-color: var(--report-border); }
  .report-environment dl { grid-template-columns: 1fr 1fr; }
}
"""

_TAB_SCRIPT = """
(function () {
  var root = document.getElementById('ranking-unified-report');
  var tabs = [].slice.call(root.querySelectorAll('.report-tabs button'));
  function select(tab) {
    tabs.forEach(function (candidate) {
      var active = candidate === tab;
      candidate.setAttribute('aria-selected', active ? 'true' : 'false');
      candidate.setAttribute('tabindex', active ? '0' : '-1');
      var panel = root.querySelector('#' + candidate.getAttribute('aria-controls'));
      panel.hidden = !active;
    });
  }
  tabs.forEach(function (tab, index) {
    tab.addEventListener('click', function () { select(tab); });
    tab.addEventListener('keydown', function (event) {
      if (event.key !== 'ArrowLeft' && event.key !== 'ArrowRight') { return; }
      event.preventDefault();
      var offset = event.key === 'ArrowRight' ? 1 : -1;
      var next = tabs[(index + offset + tabs.length) % tabs.length];
      next.focus();
      select(next);
    });
  });
})();
"""


def _matching_brace(text, opening):
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == '{':
            depth += 1
        elif text[index] == '}':
            depth -= 1
            if depth == 0:
                return index
    raise ValueError('unbalanced report CSS')


def _selector(selector, scope):
    selector = selector.strip()
    if selector in (':root', 'body'):
        return scope
    if selector.startswith(':root '):
        return scope + selector[len(':root'):]
    if selector.startswith('body '):
        return scope + selector[len('body'):]
    return '{} {}'.format(scope, selector)


def _scope_css(css, panel_id):
    """Prefix ordinary selectors while preserving nested media rules."""
    css = _COMMENT.sub('', css)
    scope = '#' + panel_id
    output = []
    position = 0
    while position < len(css):
        opening = css.find('{', position)
        if opening < 0:
            break
        header = css[position:opening].strip()
        closing = _matching_brace(css, opening)
        body = css[opening + 1:closing]
        if header.startswith(('@media', '@supports')):
            output.append('{}{{{}}}'.format(
                header, _scope_css(body, panel_id)))
        elif header.startswith('@'):
            output.append('{}{{{}}}'.format(header, body))
        else:
            scoped = ', '.join(
                _selector(selector, scope) for selector in header.split(','))
            output.append('{}{{{}}}'.format(scoped, body))
        position = closing + 1
    return '\n'.join(output)


def _environment_markup(summary):
    if summary is None:
        return ''
    fields = (
        ('DUT ASIC', str(summary['asic']).upper()),
        ('ASIC Vendor', str(summary['platform']).title()),
        ('DUT IP', summary['dut_ip']),
        ('PTF IP', summary['ptf_ip']),
    )
    items = ''.join(
        '<div><dt>{}</dt><dd>{}</dd></div>'.format(
            escape(label, quote=True), escape(str(value), quote=True))
        for label, value in fields)
    return ('<section class="report-environment" aria-label="Test environment">'
            '<dl>{}</dl></section>'.format(items))


def render(*, result_section, capability_section, spec_section,
           styles=None, scripts=None, environment_summary=None):
    """Return the only published Ranking report document."""
    styles = styles or {}
    scripts = scripts or []
    scoped_styles = [
        _scope_css(css, panel_id)
        for panel_id, css in styles.items()
        if css
    ]
    local_scripts = '\n'.join(script for script in scripts if script)
    environment = _environment_markup(environment_summary)
    return '''<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SAI Ranking Test Report</title>
<style>{shell_css}\n{section_css}</style></head>
<body><main class="report-shell" id="ranking-unified-report">
<h1>SAI Ranking Test Report</h1>
{environment}
<nav class="report-tabs" role="tablist" aria-label="Report sections">
<button id="report-results-tab" role="tab"
 aria-controls="report-results-panel" aria-selected="true" tabindex="0"
 type="button">Test Results</button>
<button id="report-capability-tab" role="tab"
 aria-controls="report-capability-panel" aria-selected="false" tabindex="-1"
 type="button">Capability</button>
<button id="report-specification-tab" role="tab"
 aria-controls="report-specification-panel" aria-selected="false" tabindex="-1"
 type="button">Performance &amp; Scale</button>
</nav>
<section class="report-panel" id="report-results-panel" role="tabpanel"
 aria-labelledby="report-results-tab">{result}</section>
<section class="report-panel" id="report-capability-panel" role="tabpanel"
 aria-labelledby="report-capability-tab" hidden>{capability}</section>
<section class="report-panel" id="report-specification-panel" role="tabpanel"
 aria-labelledby="report-specification-tab" hidden>{spec}</section>
</main><script>{tab_script}\n{local_scripts}</script></body></html>'''.format(
        shell_css=_SHELL_CSS,
        section_css='\n'.join(scoped_styles),
        environment=environment,
        result=result_section,
        capability=capability_section,
        spec=spec_section,
        tab_script=_TAB_SCRIPT,
        local_scripts=local_scripts,
    )
