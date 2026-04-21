#!/usr/bin/python3

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

import os
from contextlib import contextmanager
import pexpect


@contextmanager
def generator(tmpdir):
    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "x"
    env["GENERATE_VARS_CONF_DIR"] = str(tmpdir)
    env["GENERATE_VARS_OUT_DIR"] = str(tmpdir)
    gen = pexpect.spawn('./generate-vars', env=env)
    try:
        yield gen
    finally:
        gen.terminate(force=True)


INITIAL_CONF = """
[generate_vars]
"""


def test_initial_conf(tmpdir):
    conf = tmpdir.join("dr.conf")
    conf.write(INITIAL_CONF)
    with generator(tmpdir) as gen:
        # TODO: Use regex
        gen.expect('override')
        # Add dry run
        gen.sendline('y')
        # "/tmp/dr_ovirt-ansible/mapping_vars.yml"
        assert os.path.exists("/tmp/dr_ovirt-ansible/mapping_vars.yml")
