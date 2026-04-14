"""
Utility functions can re-used in testing scripts.
"""
import re
import time
import logging

logging_logger = logging.getLogger()


# internal used function
def _parse_column_positions(sep_line, sep_char='-'):
    prev = ' ',
    positions = []
    for pos, char in enumerate(sep_line + ' '):
        if char == sep_char:
            if char != prev:
                left = pos
        else:
            if char != prev:
                right = pos
                positions.append((left, right))
        prev = char
    return positions


# sync from sonic.py SonicHost.parse_show
def parse_show(output_lines):
    result = []

    sep_line_pattern = re.compile(r"^( *-+ *)+$")
    sep_line_found = False
    for idx, line in enumerate(output_lines):
        if sep_line_pattern.match(line):
            sep_line_found = True
            header_line = output_lines[idx-1]
            sep_line = output_lines[idx]
            content_lines = output_lines[idx+1:]
            break

    if not sep_line_found:
        logging.info(
            'Failed to find separation line in the show command output')
        return result

    try:
        positions = _parse_column_positions(sep_line)
    except Exception as e:
        logging.info(
            'Possibly bad command output, exception: {}'.format(repr(e)))
        return result

    headers = []
    for (left, right) in positions:
        headers.append(header_line[left:right].strip().lower())

    for content_line in content_lines:
        # When an empty line is encountered while parsing the tabulate content, it is highly possible that the
        # tabulate content has been drained. The empty line and rest of the lines should not be parsed.
        if len(content_line) == 0:
            break
        item = {}
        for idx, (left, right) in enumerate(positions):
            k = headers[idx]
            v = content_line[left:right].strip()
            item[k] = v
        result.append(item)

    return result


def __retry_internal(f, exceptions=Exception, tries=3, delay=2, logger=logging_logger):
    """
    @summary: Execute function with retry mechanism
    @param f: Function to execute
    @param exceptions: Exceptions to retry on
    @param tries: Retry attempts
    @param delay: Base delay between retries
    @param logger: Logger instance
    @return: Function result
    """
    if tries == 0:
        return f()
    for i in range(tries):
        try:
            return f()
        except exceptions as e:
            if i == tries - 1:
                raise
            if logger is not None:
                logger.warning('%s, retrying in %s seconds...', e, delay)
            time.sleep(delay)


def retry_call(f, fargs=None, fkwargs=None, exceptions=Exception, tries=3, delay=2, logger=logging_logger):
    """
    @summary: Call function with retry mechanism
    @param f: Target function
    @param fargs: Positional args
    @param fkwargs: Keyword args
    @param exceptions: Exceptions to retry on
    @param tries: Retry attempts
    @param delay: Base delay between retries
    @param logger: Logger instance
    @return: Function result
    """
    def _wrapped_f():
        return f(*(fargs or []), **(fkwargs or {}))
    return __retry_internal(_wrapped_f, exceptions, tries, delay, logger)
