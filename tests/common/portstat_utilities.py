import logging

logger = logging.getLogger('__name__')


def parse_column_positions(separation_line, separation_char='-'):
    '''Parse the position of each columns in the command output

    Args:
        separation_line (string): The output line separating actual data and column headers
        separation_char (str, optional): The character used in separation line. Defaults to '-'.

    Returns:
        [list]: A list. Each item is a tuple with two elements. The first element is start position of a column. The
                second element is the end position of the column.
    '''
    prev = ' ',
    positions = []
    for pos, char in enumerate(separation_line + ' '):
        if char == separation_char:
            if char != prev:
                left = pos
        else:
            if char != prev:
                right = pos
                positions.append((left, right))
        prev = char
    return positions


def parse_portstat(content_lines):
    '''Parse the output of portstat command

    Args:
        content_lines (list): The output lines of portstat command

    Returns:
        list: A dictionary, key is interface name, value is a dictionary of fields/values
    '''

    header_line = ''
    separation_line = ''
    separation_line_number = 0
    reminder_line_number = len(content_lines)
    for idx, line in enumerate(content_lines):
        if line.find('----') >= 0:
            header_line = content_lines[idx-1]
            separation_line = content_lines[idx]
            separation_line_number = idx
        if 'Reminder' in line:
            reminder_line_number = idx

    try:
        positions = parse_column_positions(separation_line)
    except Exception:
        logger.error('Possibly bad command output')
        return {}

    headers = []
    for pos in positions:
        header = header_line[pos[0]:pos[1]].strip().lower()
        headers.append(header)

    if not headers:
        return {}

    results = {}
    for line in content_lines[separation_line_number+1:reminder_line_number]:
        if not line.strip(): # skip empty line or newline
            continue
        portstats = []
        for pos in positions:
            portstat = line[pos[0]:pos[1]].strip()
            portstats.append(portstat)

        intf = portstats[0]
        results[intf] = {}
        for idx in range(1, len(portstats)):    # Skip the first column interface name
            results[intf][headers[idx]] = portstats[idx]

    return results
