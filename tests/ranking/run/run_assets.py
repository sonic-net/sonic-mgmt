"""Load topology-independent assets consumed by Ranking case execution."""

from pathlib import Path

from tests.ranking.common.case_selection import load_case_manifest


def _existing(path, description):
    path = Path(path).resolve()
    if not path.is_file():
        raise ValueError('{} must be an existing file: {}'.format(
            description, path))
    return str(path)


def load_run_assets(ranking_root=None):
    """Return topology-independent assets consumed by case execution."""
    ranking_root = (Path(ranking_root).resolve() if ranking_root is not None
                    else Path(__file__).resolve().parent.parent)
    cases_root = ranking_root / 'cases'
    config = {
        'manifest': _existing(cases_root / 'manifest.json', 'case manifest'),
        'runner_path': _existing(
            ranking_root / 'run' / 'ptf_runner.py', 'container runner'),
    }
    config['manifest_data'] = load_case_manifest(config['manifest'])
    return config
