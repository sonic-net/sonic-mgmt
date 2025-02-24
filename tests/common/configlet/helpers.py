#! /usr/bin/env python

import datetime
import inspect
import logging
import os
import sys

logger = logging.getLogger(__name__)

do_print = os.path.exists("/etc/sonic/sonic-environment")
do_flush = False

prefix_msgs = []


def set_log_prefix_msg(m=""):
    global prefix_msgs

    prefix_msgs = []
    if m:
        prefix_msgs.append(m)


def get_log_prefix_msg():
    msg = ":".join(prefix_msgs)
    return msg+": " if msg else ""


def get_prefix_lvl():
    return len(prefix_msgs)


def set_prefix_lvl(lvl):
    global prefix_msgs

    while (len(prefix_msgs) > lvl):
        prefix_msgs.pop()


def append_log_prefix_msg(m="", lvl=len(prefix_msgs)):
    global prefix_msgs

    if m:
        if lvl < len(prefix_msgs):
            prefix_msgs[lvl] = m
        else:
            prefix_msgs.append(m)


def log_init(name):
    global logger

    logger = logging.getLogger(name)


def log_msg(lgr_fn, m):
    tstr = datetime.datetime.now().strftime("%H:%M:%S")
    msg = "{}:{}:{} {}{}".format(inspect.stack()[2][1], inspect.stack()[2][2], tstr, get_log_prefix_msg(), m)
    lgr_fn(msg)
    if do_print:
        print(msg)
        if do_flush:
            sys.stdout.flush()


def log_error(m):
    log_msg(logger.error, m)


def log_info(m):
    log_msg(logger.info, m)


def log_warn(m):
    log_msg(logger.warning, m)


def log_debug(m):
    log_msg(logger.debug, m)


def set_print(flush=False):
    global do_print, do_flush

    do_print = True
    do_flush = flush
