import re


PLATFORM_COMP_PATH_TEMPLATE = '/usr/share/sonic/device/{}/platform_components.json'
FW_TYPE_INSTALL = 'install'
FW_TYPE_UPDATE = 'update'


def show_firmware(duthost):
    out = duthost.command("fwutil show status")
    num_spaces = 2
    curr_chassis = ""
    output_data = {"chassis": {}}
    status_output = out['stdout']
    separators = re.split(r'\s{2,}', status_output.splitlines()[1])  # get separators
    output_lines = status_output.splitlines()[2:]

    for line in output_lines:
        data = []
        start = 0

        for sep in separators:
            curr_len = len(sep)
            data.append(line[start:start+curr_len].strip())
            start += curr_len + num_spaces

        if data[0].strip() != "":
            curr_chassis = data[0].strip()
            output_data["chassis"][curr_chassis] = {"component": {}}

        output_data["chassis"][curr_chassis]["component"][data[2]] = data[3]

    return output_data
