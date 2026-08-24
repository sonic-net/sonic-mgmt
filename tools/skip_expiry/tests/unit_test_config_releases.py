from pathlib import Path

from tools.skip_expiry.skip_issue_expiry_impl.config import load_skip_expiry_config


def test_load_skip_expiry_config_parses_release_include_exclude(tmp_path: Path) -> None:
    config_file = tmp_path / "SKIP_EXPIRY_CONFIG.yaml"
    config_file.write_text(
        """
maintainers:
  - maintainer1
expiry:
  default_days: 120
releases:
  includes:
    - '^202\\d{3}$'
    - '^release-.*$'
  excludes:
    - '202205'
    - 'release-old'
""".strip(),
        encoding="utf-8",
    )

    config = load_skip_expiry_config(config_file)

    assert config.maintainers == ["maintainer1"]
    assert config.expiry_days == 120
    assert config.release_includes == [r"^202\d{3}$", r"^release-.*$"]
    assert config.release_excludes == ["202205", "release-old"]
