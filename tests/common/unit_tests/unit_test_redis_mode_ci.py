"""Check paired-plan inputs and preservation of topology-specific arguments."""
from pathlib import Path

import yaml


PIPELINES = Path(__file__).resolve().parents[3] / '.azure-pipelines'


def test_manual_modes_and_image_source_are_shared():
    source = (PIPELINES / 'pre_defined_pr_test.yml').read_text()
    config = yaml.safe_load(source)
    parameters = {item['name']: item for item in config['parameters']}
    assert parameters['REDIS_PROTECTION_MODE']['default'] == 'unchanged'
    assert parameters['REDIS_PROTECTION_MODE']['values'] == ['unchanged', 'legacy', 'enforce', 'both']
    assert "replace(parameters.REDIS_PROTECTION_MODE, 'both', 'legacy,enforce')" in source
    assert 'KVM_BUILD_ID: ${{ parameters.KVM_BUILD_ID }}' in source
    assert 'MGMT_COMMIT_HASH: ${{ parameters.MGMT_COMMIT_HASH }}' in source
    assert 'dependsOn: []' not in source, 'Paired plans must not cancel one another during parallel setup'
    assert 'condition: succeededOrFailed()' in source
    assert 'EXTRA_COMMON_PARAMS: "--redis-protection-mode=${{ redis_mode }}"' in source


def test_mode_suffix_retains_topology_defaults_and_override_contract():
    config = yaml.safe_load((PIPELINES / 'pr_test_template.yml').read_text())
    parameters = {item['name']: item for item in config['parameters']}
    assert parameters['EXTRA_COMMON_PARAMS']['default'] == ''
    tested = {}
    for job in config['jobs']:
        for step in job.get('steps', []):
            if step.get('template') != 'run-test-elastictest-template.yml':
                continue
            args = step['parameters']['COMMON_EXTRA_PARAMS']
            assert args.endswith('${{ parameters.EXTRA_COMMON_PARAMS }}')
            assert '${{ each param in parameters.OVERRIDE_PARAMS }}' in step['parameters']
            tested[job['job']] = args
    assert len(tested) == 12
    for name, args in tested.items():
        assert '--disable_sai_validation' in args
        if 'dualtor' in name or 'vpp' in name:
            assert '--disable_loganalyzer' in args
        if 't0_sonic' in name:
            assert '--neighbor_type=sonic' in args
