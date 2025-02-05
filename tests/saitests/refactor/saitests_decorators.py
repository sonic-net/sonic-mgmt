#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import wraps

from qos_helper import log_message
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter


class SaitestsDecorator:
    lifecycle = {} # record lifecycle for skip duplicated decorator function

    def __init__(self, func, param, enter=True, exit=False):
        self.func = func
        self.param = param
        self.enter = enter
        self.exit = exit

    def __call__(self, method):
        @wraps(method)
        def wrapper(self_instance, *args, **kwargs):
            method_name = method.__name__
            func_name = self.func.__name__
            instance_id = id(self_instance)

            if SaitestsDecorator.lifecycle.get(method_name, {}).get(func_name, {}).get(instance_id, False):
                # if lifecycle is existing, bypass decorator function
                return method(self_instance, *args, **kwargs)

            if method_name not in SaitestsDecorator.lifecycle:
                SaitestsDecorator.lifecycle[method_name] = {}
            if func_name not in SaitestsDecorator.lifecycle[method_name]:
                SaitestsDecorator.lifecycle[method_name][func_name] = {}
                SaitestsDecorator.lifecycle[method_name][func_name][instance_id] = True

            try:
                if self.enter:
                    self.func(self_instance, method, None, self.param, *args, **kwargs)

                result = method(self_instance, *args, **kwargs)

                if self.exit:
                    self.func(self_instance, method, self.param, result, *args, **kwargs)

                return result
            finally:
                # destroy lifecycle
                if method_name in SaitestsDecorator.lifecycle and func_name in SaitestsDecorator.lifecycle[method_name]:
                    del SaitestsDecorator.lifecycle[method_name][func_name][instance_id]
                if not SaitestsDecorator.lifecycle[method_name][func_name]:
                    del SaitestsDecorator.lifecycle[method_name][func_name]
                if not SaitestsDecorator.lifecycle[method_name]:
                    del SaitestsDecorator.lifecycle[method_name]

        return wrapper


def step_banner(self, method_name, param, result, *args, **kwargs):
    log_message(f'Entering {method_name} with args={args} kwargs={kwargs}', to_stderr=True)


def step_result(self, method_name, param, result, *args, **kwargs):
    if result is None:
        log_message(f'Exiting {method_name} with no return value', to_stderr=True)
    else:
        log_message(f'Exiting {method_name} with result={result}', to_stderr=True)


def diag_counter(self, method_name, param, result, *args, **kwargs):
    if param == 'initialize':
        initialize_diag_counter(self)
    elif param == 'capture':
        capture_diag_counter(self, method_name)
    elif param == 'summarize':
        summarize_diag_counter(self)
