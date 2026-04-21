#!/usr/bin/env python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import json
import sys
import yaml

with open("./rendereddocfragments.txt", 'w') as df_fd:
    with open(sys.argv[2], 'r') as fd:
        json_docs = json.load(fd)

        # ansible-doc has introduced a 'doc.plugin_name' on branch 'stable-2.17'
        # This change generated the following sanity tests error.
        # invalid-documentation: DOCUMENTATION.plugin_name: extra keys not allowed @ data['plugin_name'].
        # This will be removed from the module documentation

        json_docs[sys.argv[1]]['doc'].pop('plugin_name', '')
        json_docs[sys.argv[1]]['doc'].pop('collection', '')
        json_docs[sys.argv[1]]['doc'].pop('filename', '')
        json_docs[sys.argv[1]]['doc'].pop('has_action', '')

        df_fd.write('DOCUMENTATION = """\n')
        df_fd.write(yaml.dump(json_docs[sys.argv[1]]['doc'], default_flow_style=False))
        df_fd.write('"""\n\n')

        df_fd.write('EXAMPLES = """')
        df_fd.write(json_docs[sys.argv[1]]['examples'])
        df_fd.write('"""\n\n')

        df_fd.write('RETURN = r"""')
        data = json_docs[sys.argv[1]]['return']
        if isinstance(data, dict):
            df_fd.write(yaml.dump(data, default_flow_style=False))
        else:
            df_fd.write(data)
        df_fd.write('"""\n\n')
