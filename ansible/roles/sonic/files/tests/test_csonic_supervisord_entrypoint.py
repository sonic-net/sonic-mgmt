import os
import subprocess
from pathlib import Path


ENTRYPOINT = Path(__file__).parents[1] / 'csonic_supervisord_entrypoint.sh'


def run_entrypoint(tmp_path, helper_exists, initial_value=None):
    config = tmp_path / 'config_db.json'
    config.write_text('{}')
    supervisor_config = tmp_path / 'supervisord.conf'
    supervisor_config.write_text('')

    helper = tmp_path / 'frr_startup_init.sh'
    if helper_exists:
        helper.write_text(
            'initialize_frr_startup_environment() {\n'
            '    [[ "$1" == "--normal-start" ]] || return 2\n'
            '    export BGPD_GRACEFUL_RESTART_ARG="from-helper"\n'
            '}\n'
        )

    supervisor = tmp_path / 'supervisord'
    supervisor.write_text(
        '#!/bin/bash\n'
        'printf "%s" "$BGPD_GRACEFUL_RESTART_ARG"\n'
    )
    supervisor.chmod(0o755)

    entrypoint = tmp_path / 'entrypoint.sh'
    entrypoint.write_text(
        ENTRYPOINT.read_text()
        .replace('/var/sonic/config_db.json', str(config))
        .replace('/etc/supervisor/conf.d/supervisord.conf', str(supervisor_config))
        .replace('/usr/bin/frr_startup_init.sh', str(helper))
        .replace('/usr/local/bin/supervisord', str(supervisor))
    )
    entrypoint.chmod(0o755)

    env = os.environ.copy()
    env.pop('BGPD_GRACEFUL_RESTART_ARG', None)
    if initial_value is not None:
        env['BGPD_GRACEFUL_RESTART_ARG'] = initial_value
    result = subprocess.run(
        [str(entrypoint)],
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def test_uses_shared_frr_startup_initializer(tmp_path):
    assert run_entrypoint(tmp_path, helper_exists=True) == 'from-helper'


def test_retains_safe_default_for_older_images(tmp_path):
    assert run_entrypoint(tmp_path, helper_exists=False) == ''
    assert run_entrypoint(
        tmp_path, helper_exists=False, initial_value='provided'
    ) == 'provided'
