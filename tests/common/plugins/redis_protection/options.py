"""Shared opt-in mode argument for pytest and the test runner."""
import argparse


def add_mode_option(parser):
    parser.addoption('--redis-protection-mode', choices=('legacy', 'enforce'), default=None,
                     help='Select Redis mode for this run; run_tests.sh prepares and restores the DUTs')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False, allow_abbrev=False)
    parser.add_argument('--redis-protection-mode', choices=('legacy', 'enforce'))
    options, _ = parser.parse_known_args()
    print(options.redis_protection_mode or '')
