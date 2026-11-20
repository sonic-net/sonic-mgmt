"""Check raw CLI expectations for legacy and protected Redis processes."""

import ast
from pathlib import Path
from unittest.mock import Mock

import pytest


def scope_check():
    path = Path(__file__).resolve().parents[2] / 'redis/files/check_redis_access.py'
    tree = ast.parse(path.read_text())
    functions = [node for node in tree.body if isinstance(node, ast.FunctionDef)
                 and node.name in ('require', 'protection_scope')]
    namespace = {}
    exec(compile(ast.Module(body=functions, type_ignores=[]), str(path), 'exec'), namespace)
    return namespace['protection_scope']


@pytest.mark.parametrize('mixed', [False, True])
def test_missing_process_requires_explicit_matching_tcp_exception(mixed):
    local = {'redis': {'unix_socket_path': '/run/redis.sock', 'port': 0},
             'redis_bmp': {'unix_socket_path': '/run/bmp.sock', 'port': 6400}}
    intent = {'mode': 'enforce', 'tcp_exceptions': ['redis_bmp']}
    selected = {'/run/redis.sock': {}}
    if mixed:
        assert scope_check()(local, selected, allow_tcp_exceptions=True, intent=intent) == {'redis_bmp'}
    else:
        with pytest.raises(AssertionError):
            scope_check()(local, selected)


@pytest.mark.parametrize('exceptions', [['unknown'], ['redis_bmp', 'redis_bmp'], [], 'redis_bmp'])
def test_invalid_exceptions_cannot_hide_missing_protection(exceptions):
    local = {'redis': {'unix_socket_path': '/run/redis.sock', 'port': 0},
             'redis_bmp': {'unix_socket_path': '/run/bmp.sock', 'port': 6400}}
    with pytest.raises(AssertionError):
        scope_check()(local, {'/run/redis.sock': {}}, allow_tcp_exceptions=True,
                      intent={'mode': 'enforce', 'tcp_exceptions': exceptions})


@pytest.mark.parametrize('ports,selected', [((6379, 6400), ['/run/redis.sock']),
                                            ((0, 0), ['/run/redis.sock']), ((0, 6400), ['/run/bmp.sock']),
                                            ((0, 6400), ['/run/redis.sock', '/run/bmp.sock']), ((0, 6400), [])])
def test_mixed_scope_rejects_inconsistent_listeners_or_policy(ports, selected):
    local = {'redis': {'unix_socket_path': '/run/redis.sock', 'port': ports[0]},
             'redis_bmp': {'unix_socket_path': '/run/bmp.sock', 'port': ports[1]}}
    with pytest.raises(AssertionError):
        scope_check()(local, dict.fromkeys(selected), allow_tcp_exceptions=True,
                      intent={'mode': 'enforce', 'tcp_exceptions': ['redis_bmp']})


def test_full_protection_does_not_require_exception_configuration():
    local = {'redis': {'unix_socket_path': '/run/redis.sock', 'port': 0},
             'redis_bmp': {'unix_socket_path': '/run/bmp.sock', 'port': 0}}
    assert scope_check()(local, dict.fromkeys(['/run/redis.sock', '/run/bmp.sock'])) == set()


@pytest.mark.parametrize('protected', [False, True])
@pytest.mark.parametrize('case', ['write', 'denied', 'other_error', 'denied_but_changed'])
def test_raw_cli_expectation_depends_on_process_protection(protected, case):
    path = Path(__file__).resolve().parents[2] / 'redis/files/check_redis_access.py'
    tree = ast.parse(path.read_text())
    require = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
                   and node.name == 'require')
    cli = next(node for node in tree.body if isinstance(node, ast.FunctionDef)
               and node.name == 'cli_checks')
    check = next(node for node in cli.body if isinstance(node, ast.FunctionDef)
                 and node.name == 'check_raw_write')
    namespace = {}
    exec(compile(ast.Module(body=[require, check], type_ignores=[]), str(path), 'exec'), namespace)
    responses = {'write': ((0, b'OK', b''), b'value'),
                 'denied': ((0, b'NOPERM write denied', b''), None),
                 'other_error': ((1, b'', b'connection refused'), None),
                 'denied_but_changed': ((0, b'NOPERM write denied', b''), b'value')}
    result, stored = responses[case]
    client = Mock()
    client.get.return_value = stored
    accepted = case == ('denied' if protected else 'write')
    arguments = (result, client, 'scratch', b'value', protected, 'stdin')
    if accepted:
        namespace['check_raw_write'](*arguments)
    else:
        with pytest.raises(AssertionError):
            namespace['check_raw_write'](*arguments)
