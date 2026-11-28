import io
from pathlib import Path

import pytest

from tests.ranking.run.live_console import FAILURE_TAIL_LINES, LiveConsole


def test_compact_console_bounds_failure_tail_and_preserves_root_exception():
    output = io.StringIO()
    console = LiveConsole('compact', 'sairoute.RouteTest', output.write)
    console.start()
    console.feed(b'Traceback (most recent call last):\n')
    for number in range(FAILURE_TAIL_LINES + 20):
        console.feed('File "case.py", line {}\n'.format(number).encode())
    console.feed(b'RuntimeError: generic root cause\n')
    console.finish('FAIL', 1.25, '/controller/run.log')
    text = output.getvalue()
    assert 'Traceback (most recent call last):' in text
    assert 'RuntimeError: generic root cause' in text
    assert 'earlier failure lines suppressed' in text
    assert text.count('File "case.py"') < FAILURE_TAIL_LINES + 20
    assert 'FAIL duration=1.25s' in text


@pytest.mark.parametrize('mode,contains', [('full', True), ('off', False)])
def test_full_and_off_modes_are_chunk_safe(mode, contains):
    output = io.StringIO()
    console = LiveConsole(mode, 'sairoute.RouteTest', output.write)
    console.start()
    console.feed(b'partial')
    console.feed(b' line\n')
    console.finish('FAIL', 0.5)
    assert ('partial line' in output.getvalue()) is contains


def test_broken_pipe_disables_display_without_raising_or_changing_result():
    calls = []

    def broken(text):
        calls.append(text)
        raise BrokenPipeError('viewer closed')

    console = LiveConsole('full', 'sairoute.RouteTest', broken)
    console.start()
    console.feed(b'case output\n')
    console.finish('ERROR', 0.1)
    assert console.output_failed is True
    assert len(calls) == 1


def test_pass_summary_accepts_path_artifact():
    output = io.StringIO()
    console = LiveConsole('compact', 'sairoute.RouteTest', output.write)
    console.start()

    console.finish('PASS', 0.25, Path('/controller/run.log'))

    assert 'PASS duration=0.25s run.log=/controller/run.log' in output.getvalue()
