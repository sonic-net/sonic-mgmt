from pathlib import Path

import pytest

from tests.ranking.common import artifact_store


def test_exclusive_locks_one_real_output_directory(tmp_path):
    with artifact_store.exclusive(tmp_path):
        assert (tmp_path / '.ranking.lock').is_file()
        with pytest.raises(
                RuntimeError,
                match='another Ranking command is already active'):
            with artifact_store.exclusive(tmp_path):
                pass


def test_exclusive_rejects_a_symlinked_output_directory(tmp_path):
    target = tmp_path / 'target'
    target.mkdir()
    alias = tmp_path / 'alias'
    alias.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match='output root must be a real directory'):
        with artifact_store.exclusive(alias):
            pass


def test_exclusive_accepts_a_canonical_path_object(tmp_path):
    canonical = Path(tmp_path).resolve()

    with artifact_store.exclusive(canonical):
        assert (canonical / '.ranking.lock').is_file()
