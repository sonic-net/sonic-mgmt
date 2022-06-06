import re
import logging


def parse_column_positions(sep_line, sep_char='-'):
    """Parse the position of each columns in the command output

    Args:
        sep_line: The output line separating actual data and column headers
        sep_char: The character used in separation line. Defaults to '-'.

    Returns:
        Returns a list. Each item is a tuple with two elements. The first element is start position of a column. The
        second element is the end position of the column.
    """
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


def parse_tabular_output(output_lines):
    """Parse the output using a generic pattern.

    This method can adapt to the column changes as long as the output format follows the pattern of
    'show interface status'.

    The key is to have a line of headers. Then a separation line with '-' under each column header. Both header and
    column content are within the width of '-' chars for that column.

    For example, part of the output of command 'show interface status':

    admin@str-msn2700-02:~$ show interface status
          Interface            Lanes    Speed    MTU    FEC    Alias             Vlan    Oper    Admin             Type    Asym PFC
    ---------------  ---------------  -------  -----  -----  -------  ---------------  ------  -------  ---------------  ----------
          Ethernet0          0,1,2,3      40G   9100    N/A     etp1  PortChannel0002      up       up   QSFP+ or later         off
          Ethernet4          4,5,6,7      40G   9100    N/A     etp2  PortChannel0002      up       up   QSFP+ or later         off
          Ethernet8        8,9,10,11      40G   9100    N/A     etp3  PortChannel0005      up       up   QSFP+ or later         off
    ...

    The parsed example will be like:
        [{
            "oper": "up",
            "lanes": "0,1,2,3",
            "fec": "N/A",
            "asym pfc": "off",
            "admin": "up",
            "type": "QSFP+ or later",
            "vlan": "PortChannel0002",
            "mtu": "9100",
            "alias": "etp1",
            "interface": "Ethernet0",
            "speed": "40G"
          },
          {
            "oper": "up",
            "lanes": "4,5,6,7",
            "fec": "N/A",
            "asym pfc": "off",
            "admin": "up",                                                                                                                                                                                                                             "type": "QSFP+ or later",                                                                                                                                                                                                                  "vlan": "PortChannel0002",                                                                                                                                                                                                                 "mtu": "9100",                                                                                                                                                                                                                             "alias": "etp2",
            "interface": "Ethernet4",
            "speed": "40G"
          },
          {
            "oper": "up",
            "lanes": "8,9,10,11",
            "fec": "N/A",
            "asym pfc": "off",
            "admin": "up",
            "type": "QSFP+ or later",
            "vlan": "PortChannel0005",
            "mtu": "9100",
            "alias": "etp3",
            "interface": "Ethernet8",
            "speed": "40G"
          },
          ...
        ]

    Args:
        output_lines(list): The output of show command that will be executed.

    Returns:
        Return the parsed output of the show command in a list of dictionary. Each list item is a dictionary,
        corresponding to one content line under the header in the output. Keys of the dictionary are the column
        headers in lowercase.
    """
    result = []

    sep_line_pattern = re.compile(r"^( *-+ *)+$")   #lgtm [py/redos]
    sep_line_found = False
    for idx, line in enumerate(output_lines):
        if sep_line_pattern.match(line):
            sep_line_found = True
            header_line = output_lines[idx - 1]
            sep_line = output_lines[idx]
            content_lines = output_lines[idx + 1:]
            break

    if not sep_line_found:
        logging.error('Failed to find separation line in the show command output')
        return result

    try:
        positions = parse_column_positions(sep_line)
    except Exception as e:
        logging.error('Possibly bad command output, exception: {}'.format(repr(e)))
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
