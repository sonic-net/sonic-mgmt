import os
import re

def update_cable_len(duthost, buffer_files):
    update_results = list()
    for file_info in buffer_files:
        file_status = "NotFound"
        out = duthost.stat(path=file_info)
        if out['stat']['exists']:
             file_status = "Found"
             default_cable_found = False
             cable_len_found = False
             path, orig_file = os.path.split(file_info)
             file_prefix = orig_file.split(".")[0]
             new_file = "{}_new.j2".format(file_prefix)
             duthost.fetch(src=file_info, dest=orig_file, flat="yes")
             wd = open(new_file, 'w')
             with open(orig_file, 'r') as rd:
                 for line in rd.readlines():
                     # replace default_cable line to use 300m
                     if 'default_cable' in line:
                         default_cable_found = True
                         match = re.match("(.*)default_cable(.*?)(\d+)(.*)", line)
                         if match:
                             new_line = match.group(1) + "default_cable" + match.group(2) + "300" + match.group(4) + "\n"
                             wd.write(new_line)
                             continue
                         else:
                             file_status = "Error"
                     elif default_cable_found:
                         # add ports2cable map when not present
                         if 'macro' in line:
                             new_multi_line = "{%- set ports2cable = {\n"\
                                              "        'torrouter_server'       : '300m',\n"\
                                              "        'leafrouter_torrouter'   : '300m',\n"\
                                              "        'spinerouter_leafrouter' : '300m'\n"\
                                              "        }\n"\
                                              "-%}\n\n"
                             wd.write(new_multi_line)
                             default_cable_found = False

                         elif 'ports2cable' in line:
                             cable_len_found = True

                         elif cable_len_found:
                             # update ports2cable map to use 300m
                             if "}" not in line:
                                 match = re.match("(.*):(.*?)(\d+)(.*)", line)
                                 if match:
                                     new_line = match.group(1) + ":" + match.group(2) + "300" + match.group(4) + "\n"
                                     wd.write(new_line)
                                     continue
                                 else:
                                     file_status = "Error"
                             else:
                                 cable_len_found = False
                                 default_cable_found = False

                     wd.write(line)

        update_results.append(file_status)
    return update_results
