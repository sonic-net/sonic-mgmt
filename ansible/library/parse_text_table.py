#!/usr/bin/python
from ansible.module_utils.basic import *

DOCUMENTATION = '''
---
module:  parse_text_table
version_added:  "2.0"
author: Joe Lazaro (@joeslazaro)
short_description: Parse a text table and convert it to a dict or list of dicts
description: |
    Expects a text table with with fixed-width columns and '-' 
    characters as separators between the column headers and the data. It will
    produce a list of dicts corresponding to each row of data. It will also
    create a dictionary keyed by the value of the first column, so you can
    choose the most convenient return value type to process the result. 
    
    Note: If the first column of a table row is empty, then that row will not
    currently be stored in the parsed_table_dict return value, so be careful if
    that is a possibility. 
Options:
    - option-name: text
      description: The text table to be parsed
      required: True
      Default: None
'''

EXAMPLES = '''
- name: Extract the IP interfaces table from a previous command's output
  parse_text_table:
    text: my_registered_var.stdout
    return_as: 'dict'
'''

RETURN = '''
parsed_table_list:
    description: A list of dictionaries containing each values for table row
    returned: always
    type: list

parsed_table_dict:
    description: A dictionary of table row values, keyed by the first column
    returned: always
    type: dict
'''


def parse_text_table(text):
    """Extract a table based on fixed-width columns from a block of text

    Arguments:
        text: Text table to be parsed

    This uses a table header separator to determine column widths, then
    captures the appropriate number of characters for each column until an
    empty line is reached.

    Example input text:

    admin@lab-ignw-seastone-dut-li1:~$ show ip interfaces
    Interface        IPv4 address/mask    Admin/Oper
    ---------------  -------------------  ------------
    PortChannel0001  10.0.0.56/31         up/up
    PortChannel0002  10.0.0.58/31         up/up
    PortChannel0003  10.0.0.60/31         up/up
    PortChannel0004  10.0.0.62/31         up/up
    Vlan1000         192.168.0.1/21       up/up
    docker0          240.127.1.1/24       up/down
    eth0             10.50.0.8/22         up/up
    lo               127.0.0.1/8          up/up
    """

    re_separator_line = re.compile(r'(\s*-+)+')
    re_column = re.compile('\s*-+')
    headers = None
    row_pattern = None
    prev_row = None
    result_rows = []
    result_dict = {}

    for line in text.splitlines():
        if re_separator_line.match(line):
            if headers is not None:
                break   # Found table footer

            # Create a regex pattern to capture each column (by width)
            pattern_pieces = []
            for col_match in re_column.finditer(line):
                col_width = len(col_match.group())
                pattern_pieces.append('(.{0,' + str(col_width) + '})')
            row_pattern = ''.join(pattern_pieces)

            # Look at the row above the separator and capture the header text
            # to be used as dictionary keys for each column value
            match = re.match(row_pattern, prev_row)
            if match:
                headers = list(map(str.strip, match.groups()))
                # print("Found text table headers:{}".format(headers))
            else:
                err_msg = "Failed parsing headers from line:{}".format(prev_row)
                raise ValueError(err_msg)
        elif headers is None:
            pass  # Ignoring line because no header seen yet
        elif len(line.strip()) == 0:
            break  # Found end of data (blank line)
        else:
            match = re.match(row_pattern, line)
            if match:
                cols = list(map(str.strip, match.groups()))
                row_dict = {}
                for index, col in enumerate(cols):
                    row_dict[headers[index]] = col
                # Store the row in both the list and dictionary return values
                result_rows.append(row_dict)
                key = row_dict[headers[0]]
                if len(key.strip()) > 0:
                    result_dict[key] = row_dict
            # else:
            #     logger.trace('Table line did not match the pattern:' + line)

        prev_row = line
    return result_rows, result_dict


def main():
    module = AnsibleModule(
        argument_spec=dict(
            text=dict(required=True, type='str'),
        ),
        supports_check_mode=False)

    p = module.params
    list_result, dict_result = parse_text_table(p['text'])
    module.exit_json(ansible_facts={
        'parsed_table_list': list_result,
        'parsed_table_dict': dict_result})


if __name__ == '__main__':
    main()
