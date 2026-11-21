"""Stable artifact names and log framing shared across Ranking Run stages."""


OUTCOME_FILE = 'outcome.json'
RUN_LOG_FILE = 'run.log'
CONSOLE_HEADER = '===== PTF console output =====\n'
INTERNAL_HEADER = '\n===== PTF internal log =====\n'


def extract_console(text):
    """Return the user-facing PTF console section from one complete run log."""
    if not isinstance(text, str) or not text.startswith(CONSOLE_HEADER):
        raise ValueError('run.log is missing its console header')
    return text[len(CONSOLE_HEADER):].split(INTERNAL_HEADER, 1)[0]
