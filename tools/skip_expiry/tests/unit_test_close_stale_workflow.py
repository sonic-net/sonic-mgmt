"""Pin the invariants the stale-issue workflow's exemption of skip-tracked issues depends on."""
from pathlib import Path
from typing import Dict

import yaml

from tools.skip_expiry.skip_issue_expiry_impl.config import load_skip_expiry_config
from tools.skip_expiry.skip_issue_expiry_impl.expiry import EXPIRED_LABEL

REPO_ROOT = Path(__file__).resolve().parents[3]


def _stale_step_inputs() -> Dict[str, object]:
    workflow = yaml.safe_load((REPO_ROOT / ".github/workflows/close-stale.yml").read_text(encoding="utf-8"))
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if str(step.get("uses", "")).startswith("actions/stale@"):
                return step["with"]
    raise AssertionError("close-stale.yml has no actions/stale step")


def test_stale_workflow_exempts_the_label_the_expiry_manager_applies() -> None:
    exempt = [label.strip() for label in str(_stale_step_inputs()["exempt-issue-labels"]).split(",")]

    assert EXPIRED_LABEL in exempt


def test_skip_expiry_window_is_shorter_than_the_stale_window() -> None:
    # An issue idle for days-before-stale must already be past its expiry window, or it has no label to exempt it.
    config = load_skip_expiry_config(REPO_ROOT / ".github/SKIP_EXPIRY_CONFIG.yaml")

    assert config.expiry_days < int(_stale_step_inputs()["days-before-stale"])
