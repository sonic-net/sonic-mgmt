from unittest.mock import Mock

from tests.common.platform.bmc_utils import BmcLogAnalyzer


def test_event_log_analyze_scans_rotated_logs_in_chronological_order():
    duthost = Mock()
    duthost.shell.side_effect = [
        {},
        {
            'stdout': (
                'start-LogAnalyzer-power-delay.2026-09-06-23:23:51\n'
                'NOTICE: STARTUP: Switch-Host already ONLINE\n'
            )
        },
    ]
    analyzer = BmcLogAnalyzer(duthost, 'power-delay')
    analyzer.match_regex = [r'.*STARTUP:.*']

    result = analyzer.analyze('power-delay.2026-09-06-23:23:51')

    command = duthost.shell.call_args_list[1].args[0]
    assert command.index('event.log.5.gz') < command.index('event.log.2.gz')
    assert command.index('event.log.2.gz') < command.index('event.log.1 ')
    assert command.endswith("| sed -n '/start-LogAnalyzer-power-delay.2026-09-06-23:23:51/,$p'")
    assert result['total']['match'] == 1