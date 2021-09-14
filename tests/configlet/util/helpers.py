#! /usr/bin/env python

from datetime import datetime
import inspect
import logging

logger = logging.getLogger(__name__)

do_print = False

def log_init(name):
    global logger

    logger = logging.getLogger(name)


def log_msg(lgr_fn, m):
    tstr = datetime.now().strftime("%H:%M:%S")
    msg = "{}:{}:{} {}".format(inspect.stack()[2][1], inspect.stack()[2][2], tstr, m)
    lgr_fn(msg)
    if do_print:
        print(msg)


def log_error(m):
    log_msg(logger.error, m)


def log_info(m):
    log_msg(logger.info, m)


def log_warn(m):
    log_msg(logger.warning, m)


def log_debug(m):
    log_msg(logger.debug, m)


def set_print():
    global do_print

    do_print = True
