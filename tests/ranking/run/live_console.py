"""Best-effort live PTF display that never changes execution semantics."""

import codecs
from collections import deque
import re
import sys


PORT_PROGRESS = re.compile(
    r'(?i)(?:(?:turn(?:ing)?\s+up|set(?:ting)?|configur\w*|creat\w*|initializ\w*)\s+.*\bport\b|'
    r'\b(?:port\s*\d+|Ethernet\d+(?:_\d+)?)\b)')
COLLECTOR_RESULT = re.compile(r'(?i)\[RESULT\]\s+Overall:')
MILESTONE = re.compile(
    r'(?i)(?:connect(?:ing|ed)?.*(?:thrift|rpc)|(?:running|starting|executing)\s+(?:PTF\s+)?test|'
    r'test\s+case|setup\s+(?:complete|done)|initializ\w*\s+(?:complete|done))')
FAILURE_EVIDENCE = re.compile(
    r'(?i)^(?:FAIL:|ERROR:|Traceback\b|File\s+"|AssertionError\b|FAILED\s*\(|ERRORS?\s*\(|'
    r'[A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Failure|Exit|Interrupt):|'
    r'Ran\s+\d+\s+tests?\b|skipped(?:=|\s))')
FAILURE_HEADER = re.compile(r'(?i)^(?:FAIL:|ERROR:|Traceback\b)')
FAILURE_TAIL_LINES = 12


class LiveConsole:
    """Render one case's PTF console independently of its recorded result."""

    def __init__(self, mode, case, sink=None):
        if mode not in ('compact', 'full', 'off'):
            raise ValueError('invalid Ranking live log mode')
        self.mode = mode
        self.case = case
        self.sink = sys.stdout.write if sink is None else sink
        owner = sys.stdout if sink is None else getattr(sink, '__self__', None)
        self.flusher = getattr(owner, 'flush', None)
        self.output_failed = False
        self.decoder = codecs.getincrementaldecoder('utf-8')('replace')
        self.pending = ''
        self.port_lines = 0
        self.other_lines = 0
        self.failure_header = None
        self.failure_tail = deque(maxlen=FAILURE_TAIL_LINES)
        self.failure_suppressed = 0
        self.started = False

    def _emit(self, text):
        if self.mode == 'off' or self.output_failed:
            return
        try:
            self.sink('[ranking][{}] {}\n'.format(self.case, text))
            if callable(self.flusher):
                self.flusher()
        except Exception:
            self.output_failed = True

    def start(self):
        if not self.started and self.mode != 'off':
            self._emit('START')
        self.started = True

    def _line(self, line):
        if self.mode == 'off':
            return
        if self.mode == 'compact':
            stripped = line.strip()
            if not stripped or COLLECTOR_RESULT.search(stripped):
                return
            if FAILURE_EVIDENCE.search(stripped):
                if self.failure_header is None and FAILURE_HEADER.search(stripped):
                    self.failure_header = stripped
                else:
                    if len(self.failure_tail) == self.failure_tail.maxlen:
                        self.failure_suppressed += 1
                    self.failure_tail.append(stripped)
                return
            if PORT_PROGRESS.search(stripped):
                self.port_lines += 1
                return
            if not MILESTONE.search(stripped):
                self.other_lines += 1
                return
            line = stripped
        self._emit(line)

    def feed(self, payload):
        if self.mode == 'off' or not payload:
            return
        text = self.pending + self.decoder.decode(payload, final=False)
        lines = text.splitlines(keepends=True)
        self.pending = ''
        for line in lines:
            if line.endswith(('\n', '\r')):
                self._line(line.rstrip('\r\n'))
            else:
                self.pending = line

    def finish(self, status, duration, log_path=None):
        """Finish display from the executor's normalized result only."""
        if status not in ('PASS', 'FAIL', 'SKIP', 'ERROR'):
            raise ValueError('invalid Ranking console status')
        if self.mode == 'off':
            return
        tail = self.pending + self.decoder.decode(b'', final=True)
        self.pending = ''
        if tail:
            self._line(tail)
        if self.mode == 'compact' and self.failure_header:
            self._emit(self.failure_header)
        if self.mode == 'compact' and self.failure_suppressed:
            self._emit('{} earlier failure lines suppressed'.format(
                self.failure_suppressed))
        if self.mode == 'compact':
            for line in self.failure_tail:
                self._emit(line)
        if self.mode == 'compact' and self.port_lines:
            self._emit('{} repetitive port lines suppressed'.format(self.port_lines))
        if self.mode == 'compact' and self.other_lines:
            self._emit('{} non-essential lines suppressed'.format(self.other_lines))
        summary = '{} duration={:.2f}s'.format(status, duration)
        if log_path:
            summary += ' run.log=' + str(log_path)
        self._emit(summary)
