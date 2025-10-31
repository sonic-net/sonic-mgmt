#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from functools import wraps
import operator
from collections import defaultdict

from qos_helper import log_message, qos_test_assert
from counter_collector import CounterCollector, initialize_diag_counter, capture_diag_counter, summarize_diag_counter


class SaitestsDecorator:
    lifecycle = {}  # record lifecycle for skip duplicated decorator function

    def __init__(self, func, param, enter=True, exit=False):
        self.func = func
        self.param = param
        self.enter = enter
        self.exit = exit

    def __call__(self, method):
        @wraps(method)
        def wrapper(instance, *args, **kwargs):
            method_name = method.__name__
            func_name = self.func.__name__
            instance_id = id(instance)

            if SaitestsDecorator.lifecycle.get(method_name, {}).get(func_name, {}).get(instance_id, False):
                # if lifecycle is existing, bypass decorator function
                return method(instance, *args, **kwargs)

            if method_name not in SaitestsDecorator.lifecycle:
                SaitestsDecorator.lifecycle[method_name] = {}
            if func_name not in SaitestsDecorator.lifecycle[method_name]:
                SaitestsDecorator.lifecycle[method_name][func_name] = {}
                SaitestsDecorator.lifecycle[method_name][func_name][instance_id] = True

            try:
                result = None
                if self.enter:
                    self.func(self, instance, method, self.param, result, *args, **kwargs)

                result = method(instance, *args, **kwargs)

                if self.exit:
                    self.func(self, instance, method, self.param, result, *args, **kwargs)

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


def summarize_length(value, max_length=100):
    value_str = str(value)
    return value_str if len(value_str) <= max_length else value_str[:max_length] + "..."


def summarize_structure(value):
    if isinstance(value, (int, float, str, list, tuple, dict)):
        return value
    elif hasattr(value, "__dict__"):
        return f"{type(value).__name__} object with id {id(value)}"
    else:
        return f"{type(value).__name__} with id {id(value)}"


def show_banner(decorator_instance, testcase_instance, testcase_method, param, result, *args, **kwargs):
    def summarize(value):
        if isinstance(value, (int, float, str, list, tuple, dict)):
            return summarize_length(value)
        else:
            return summarize_structure(value)

    summarized_args = [summarize(arg) for arg in args]
    summarized_kwargs = {k: summarize(v) for k, v in kwargs.items()}

    log_message(
        f"Entering {testcase_method.__name__} with args={summarized_args} kwargs={summarized_kwargs}", to_stderr=True
    )


def show_result(decorator_instance, testcase_instance, testcase_method, param, result, *args, **kwargs):
    log_message(f"Exiting {testcase_method.__name__} with result={result}", to_stderr=True)


def diag_counter(decorator_instance, testcase_instance, testcase_method, param, result, *args, **kwargs):
    if param == "initialize":
        initialize_diag_counter(testcase_instance)
    elif param == "capture":
        capture_diag_counter(testcase_instance, testcase_method.__name__)
    elif param == "summarize":
        summarize_diag_counter(testcase_instance)


def check_counter(decorator_instance, testcase_instance, testcase_method, param, result, *args, **kwargs):
    if not hasattr(decorator_instance, "cache_check_counter"):
        # collect counter base value in enter stage
        decorator_instance.cache_check_counter = defaultdict(lambda: defaultdict(dict))
        for port, port_rules in param.items():
            port_id = getattr(testcase_instance, port)
            for counter_name, _ in port_rules.items():
                counter = CounterCollector(testcase_instance, counter_name, port_ids=[port_id])
                counter.collect_counter(testcase_method.__name__ + ".before", compare=True)
                decorator_instance.cache_check_counter[port_id][counter_name] = counter
    else:
        # collect counter changed value in exit stage, anc compare with base value
        for port, port_rules in param.items():
            port_id = getattr(testcase_instance, port)
            for counter_name, counter_rules in port_rules.items():
                counter = decorator_instance.cache_check_counter[port_id][counter_name]
                counter.collect_counter(testcase_method.__name__ + ".after", compare=True)
                for field_name, field_rules in counter_rules.items():
                    if hasattr(testcase_instance, field_name):
                        # for trigger_pfc_check_rules, one of field name is "PfcPgxTxPkt", its value is depend on specific testcase
                        # parameter in ptf command line, so we need to get the value from testcase instance, which the "PfcPgxTxPkt"
                        # is stored in testcase instance during step_build_param stage.
                        field_name = getattr(testcase_instance, field_name)
                    delta = counter.get_counter_delta(
                        testcase_method.__name__ + ".after", testcase_method.__name__ + ".before", port_id, field_name
                    )
                    ops = {
                        "==": operator.eq,
                        "<=": operator.le,
                        ">=": operator.ge,
                        "<": operator.lt,
                        ">": operator.gt,
                        "!=": operator.ne,
                    }
                    target = field_rules["target"]
                    if not isinstance(target, int):
                        target = getattr(testcase_instance, target)
                    qos_test_assert(testcase_instance, ops[field_rules["operate"]](delta, target), field_rules["error"])
