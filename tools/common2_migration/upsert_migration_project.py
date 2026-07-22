#!/usr/bin/env python3
"""Upsert the common -> common2 migration dashboard into a GitHub Project (v2).

Reads the machine-readable JSON produced by ``migration_dashboard.py`` and
creates/updates one draft-issue card per candidate module in a GitHub Project.

Design notes (mirrors tools/skip_expiry/.../reporting.py conventions):

* Each module becomes a Project *draft issue*. The card title is the module
  path; a rich body carries the dependency/impact detail and the per-function
  sub-tasks so a contributor can pick something small.
* Rows are matched (upsert) on the card **Title** (which holds the module
  path), so hand-added issues with other titles are never touched.
* Fields are discovered from the Project. Any column that does not exist yet is
  skipped with a warning (so the script still works while you add columns).
* The built-in **Status** field is treated as human-owned: it is set to
  ``Todo`` only when a card is first created and to ``Done`` for already-migrated
  modules; it is otherwise left alone so contributor progress is preserved.
* Only the Python standard library is used (urllib) -- no pip install needed.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Dict, List, Optional

logger = logging.getLogger("upsert_migration_project")

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"

# Project field (column) names this script writes to. Create these columns in
# the Project; missing ones are skipped gracefully. The upsert key is the
# built-in card **Title** (which holds the module path), so no dedicated
# "Module" column is needed.

DEFAULT_DASHBOARD_PATH = "https://github.com/OWNER/REPO/blob/DEFAULT_BRANCH/tools/common2_migration/migration_dashboard.md"  # noqa: E501


def build_dashboard_path() -> str:
    """Return the workflow run URL when available, else a repo-relative blob URL."""
    server = os.getenv("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.getenv("GITHUB_REPOSITORY", "").strip()
    run_id = os.getenv("GITHUB_RUN_ID", "").strip()
    run_attempt = os.getenv("GITHUB_RUN_ATTEMPT", "").strip()

    if repository and run_id:
        url = f"{server}/{repository}/actions/runs/{run_id}"
        if run_attempt:
            url += f"/attempts/{run_attempt}"
        return url

    if repository:
        ref_name = os.getenv("GITHUB_REF_NAME", "").strip()
        if not ref_name:
            ref_name = os.getenv("GITHUB_REF", "").strip().replace("refs/heads/", "", 1)
        if ref_name:
            return f"{server}/{repository}/blob/{ref_name}/tools/common2_migration/migration_dashboard.md"

    return DEFAULT_DASHBOARD_PATH


DASHBOARD_PATH = build_dashboard_path()

TEXT_FIELDS = {
    # column name -> function producing the string from a task dict
    "Target": lambda t: t["target_path"],
    "Domain": lambda t: t["domain"],
    "Dependency Details": lambda t: DASHBOARD_PATH,
}

NUMBER_FIELDS = {
    "Rank": lambda t: t["rank"],
    "Tier": lambda t: t["tier"],
    "Score": lambda t: round(float(t["score"]), 2),
    "Direct Tests": lambda t: len(t["impacted_tests"]),
    "Transitive Tests": lambda t: len(t["impacted_tests_transitive"]),
    "Module Deps": lambda t: len(t["depends_on_direct"]),
    "LOC": lambda t: t["loc"],
    "Functions/Classes": lambda t: t["num_functions"] + t["num_classes"],
    "Typed %": lambda t: int(round(float(t["typed_ratio"]) * 100)),
}


def resolve_auth_token() -> str:
    """Resolve the token used for GraphQL mutations.

    This mirrors the skip-expiry workflow: prefer the GitHub App token from
    GITHUB_APP_TOKEN or GH_APP_TOKEN, then use the legacy PROJECT_TOKEN if
    present, and finally fall back to the standard GITHUB_TOKEN environment
    variable.
    """
    for env_var in ("GITHUB_APP_TOKEN", "GH_APP_TOKEN"):
        token = os.getenv(env_var, "").strip()
        if token:
            return token
    for env_var in ("PROJECT_TOKEN",):
        token = os.getenv(env_var, "").strip()
        if token:
            return token
    return os.getenv("GITHUB_TOKEN", "").strip()


def graphql(token: str, query: str, variables: dict) -> dict:
    """POST a GraphQL request with simple retry/backoff (stdlib only)."""
    body = json.dumps({"query": query, "variables": variables}).encode("utf-8")
    headers = {
        "Authorization": f"bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sonic-mgmt-common2-migration-dashboard",
    }
    max_retries = 3
    for attempt in range(max_retries + 1):
        req = urllib.request.Request(GITHUB_GRAPHQL_URL, data=body, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 502, 503) and attempt < max_retries:
                sleep = min(60.0, 2 ** attempt)
                logger.warning("GraphQL HTTP %d; retry in %.0fs", exc.code, sleep)
                time.sleep(sleep)
                continue
            detail = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"GraphQL HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            if attempt < max_retries:
                sleep = min(60.0, 2 ** attempt)
                logger.warning("GraphQL network error %s; retry in %.0fs", exc, sleep)
                time.sleep(sleep)
                continue
            raise
        errors = payload.get("errors") or []
        if errors:
            raise RuntimeError(f"GraphQL errors: {errors}")
        return payload.get("data") or {}
    raise RuntimeError("GraphQL retries exhausted")


class MigrationProjectUpserter:
    """Creates/updates one draft-issue card per module in a Project (v2)."""

    def __init__(self, token: str, project_id: str, dry_run: bool = False) -> None:
        self.token = token.strip()
        self.project_id = project_id.strip()
        self.dry_run = dry_run
        if not self.token:
            raise ValueError("a token is required (GITHUB_APP_TOKEN / GH_APP_TOKEN / GITHUB_TOKEN)")
        if not self.project_id:
            raise ValueError("a project id is required")
        self.field_map: Dict[str, dict] = {}
        self.items_by_key: Dict[str, str] = {}
        self.field_values: Dict[str, Dict[str, object]] = {}
        self.content_ids: Dict[str, str] = {}
        self.content_bodies: Dict[str, str] = {}
        self.field_warnings: set[str] = set()
        self.created = 0
        self.updated_fields = 0
        self.updated_bodies = 0
        self._load_fields()
        self._load_items()

    # -- discovery ---------------------------------------------------------

    def _load_fields(self) -> None:
        query = """
        query($projectId: ID!) {
          node(id: $projectId) {
            ... on ProjectV2 {
              fields(first: 100) {
                nodes {
                  ... on ProjectV2FieldCommon { id name dataType }
                  ... on ProjectV2SingleSelectField {
                    id name dataType options { id name }
                  }
                }
              }
            }
          }
        }
        """
        data = graphql(self.token, query, {"projectId": self.project_id})
        nodes = (((data.get("node") or {}).get("fields") or {}).get("nodes")) or []
        for field in nodes:
            name = (field.get("name") or "").strip()
            if name and field.get("id"):
                self.field_map[name.lower()] = field
        logger.info("Discovered %d project field(s)", len(self.field_map))

    def _load_items(self) -> None:
        query = """
        query($projectId: ID!, $cursor: String) {
          node(id: $projectId) {
            ... on ProjectV2 {
              items(first: 100, after: $cursor) {
                nodes {
                  id
                  content {
                    ... on DraftIssue { id title body }
                  }
                  fieldValues(first: 100) {
                    nodes {
                      ... on ProjectV2ItemFieldTextValue {
                        text field { ... on ProjectV2FieldCommon { name } }
                      }
                      ... on ProjectV2ItemFieldNumberValue {
                        number field { ... on ProjectV2FieldCommon { name } }
                      }
                      ... on ProjectV2ItemFieldSingleSelectValue {
                        name field { ... on ProjectV2FieldCommon { name } }
                      }
                    }
                  }
                }
                pageInfo { hasNextPage endCursor }
              }
            }
          }
        }
        """
        cursor = None
        while True:
            data = graphql(self.token, query,
                           {"projectId": self.project_id, "cursor": cursor})
            items = (((data.get("node") or {}).get("items") or {}).get("nodes")) or []
            page = (((data.get("node") or {}).get("items") or {}).get("pageInfo")) or {}
            for item in items:
                content = item.get("content") or {}
                # Upsert key = the card title (holds the module path). Cards
                # without a DraftIssue title (e.g. hand-added issues) are ignored.
                key = (content.get("title") or "").strip()
                if not key:
                    continue
                self.items_by_key[key] = item["id"]
                self.field_values[key] = self._normalize_values(item)
                if content.get("id"):
                    self.content_ids[key] = content["id"]
                    self.content_bodies[key] = content.get("body") or ""
            if not page.get("hasNextPage"):
                break
            cursor = page.get("endCursor")
        logger.info("Loaded %d managed card(s)", len(self.items_by_key))

    @staticmethod
    def _normalize_values(item: dict) -> Dict[str, object]:
        out: Dict[str, object] = {}
        nodes = (((item.get("fieldValues") or {}).get("nodes")) or [])
        for value in nodes:
            field = value.get("field") or {}
            name = (field.get("name") or "").strip().lower()
            if not name:
                continue
            if "text" in value:
                out[name] = value.get("text")
            elif "number" in value:
                out[name] = value.get("number")
            elif "name" in value:
                out[name] = value.get("name")
        return out

    # -- helpers -----------------------------------------------------------

    def _field(self, name: str, expected_data_type: Optional[str] = None) -> Optional[dict]:
        field = self.field_map.get(name.lower())
        if not field:
            warning_key = f"missing:{name.lower()}"
            if warning_key not in self.field_warnings:
                logger.warning("field '%s' missing; skipping", name)
                self.field_warnings.add(warning_key)
            return None
        if expected_data_type:
            actual_data_type = (field.get("dataType") or "").upper()
            expected = expected_data_type.upper()
            if actual_data_type != expected:
                warning_key = f"type:{name.lower()}:{expected}"
                if warning_key not in self.field_warnings:
                    logger.warning(
                        "field '%s' has dataType '%s' but expected '%s'; skipping",
                        name, field.get("dataType"), expected_data_type,
                    )
                    self.field_warnings.add(warning_key)
                return None
        return field

    def _cached(self, key: str, field_name: str) -> object:
        return self.field_values.get(key, {}).get(field_name.lower())

    def _remember(self, key: str, field_name: str, value: object) -> None:
        self.field_values.setdefault(key, {})[field_name.lower()] = value

    # -- mutations ---------------------------------------------------------

    def _create_card(self, title: str, body: str) -> Optional[str]:
        if self.dry_run:
            logger.info("[dry-run] create card: %s", title)
            self.created += 1
            return None
        mutation = """
        mutation($projectId: ID!, $title: String!, $body: String!) {
          addProjectV2DraftIssue(
            input: {projectId: $projectId, title: $title, body: $body}
          ) { projectItem { id } }
        }
        """
        data = graphql(self.token, mutation,
                       {"projectId": self.project_id, "title": title, "body": body})
        item = (((data.get("addProjectV2DraftIssue") or {}).get("projectItem")) or {})
        item_id = (item.get("id") or "").strip()
        if item_id:
            self.created += 1
        return item_id or None

    def _update_draft_body(self, content_id: str, body: str) -> None:
        """Update an existing draft-issue body (needs the DraftIssue content id)."""
        if self.dry_run or not content_id:
            return
        mutation = """
        mutation($draftId: ID!, $body: String!) {
          updateProjectV2DraftIssue(input: {draftIssueId: $draftId, body: $body}) {
            draftIssue { id }
          }
        }
        """
        graphql(self.token, mutation, {"draftId": content_id, "body": body})

    def _set_text(self, item_id: str, name: str, value: str) -> None:
        field = self._field(name, "TEXT")
        if not field:
            return
        if self.dry_run:
            return
        if value is None:
            return
        if str(value).strip() == "":
            return
        mutation = """
        mutation($p: ID!, $i: ID!, $f: ID!, $v: String!) {
          updateProjectV2ItemFieldValue(
            input: {projectId: $p, itemId: $i, fieldId: $f, value: {text: $v}}
          ) { projectV2Item { id } }
        }
        """
        graphql(self.token, mutation, {"p": self.project_id, "i": item_id,
                                       "f": field["id"], "v": str(value)})

    def _set_number(self, item_id: str, name: str, value: float) -> None:
        field = self._field(name, "NUMBER")
        if not field:
            return
        if self.dry_run:
            return
        mutation = """
        mutation($p: ID!, $i: ID!, $f: ID!, $v: Float!) {
          updateProjectV2ItemFieldValue(
            input: {projectId: $p, itemId: $i, fieldId: $f, value: {number: $v}}
          ) { projectV2Item { id } }
        }
        """
        graphql(self.token, mutation, {"p": self.project_id, "i": item_id,
                                       "f": field["id"], "v": float(value)})

    def _set_single_select(self, item_id: str, name: str, option: str) -> None:
        field = self._field(name, "SINGLE_SELECT")
        if not field:
            return  # optional field
        option_id = None
        for opt in field.get("options") or []:
            if (opt.get("name") or "").strip().lower() == option.lower():
                option_id = opt.get("id")
                break
        if not option_id or self.dry_run:
            if not option_id:
                logger.warning("option '%s' not found in field '%s'", option, name)
            return
        mutation = """
        mutation($p: ID!, $i: ID!, $f: ID!, $o: String!) {
          updateProjectV2ItemFieldValue(
            input: {projectId: $p, itemId: $i, fieldId: $f,
                    value: {singleSelectOptionId: $o}}
          ) { projectV2Item { id } }
        }
        """
        graphql(self.token, mutation, {"p": self.project_id, "i": item_id,
                                       "f": field["id"], "o": option_id})

    # -- per-field change-detected apply -----------------------------------

    def _apply_text(self, item_id: str, key: str, name: str, value: str) -> None:
        if str(self._cached(key, name) or "") == str(value):
            return
        self._set_text(item_id, name, value)
        self._remember(key, name, str(value))
        self.updated_fields += 1

    def _apply_number(self, item_id: str, key: str, name: str, value: float) -> None:
        cached = self._cached(key, name)
        if cached is not None and float(cached) == float(value):
            return
        self._set_number(item_id, name, value)
        self._remember(key, name, float(value))
        self.updated_fields += 1

    # -- upsert ------------------------------------------------------------

    def upsert(self, task: dict, migrated: bool) -> None:
        key = task["rel_path"]
        title = key
        body = build_card_body(task, migrated)
        item_id = self.items_by_key.get(key)
        newly_created = False
        if not item_id:
            item_id = self._create_card(title, body)
            newly_created = True
            if item_id:
                self.items_by_key[key] = item_id
        if not item_id:
            return  # dry-run or creation failed

        # Refresh the body on existing cards only when the analysis changed.
        if not newly_created and self.content_bodies.get(key, "") != body:
            self._update_draft_body(self.content_ids.get(key, ""), body)
            self.content_bodies[key] = body
            self.updated_bodies += 1

        for name, getter in TEXT_FIELDS.items():
            self._apply_text(item_id, key, name, str(getter(task)))
        for name, getter in NUMBER_FIELDS.items():
            self._apply_number(item_id, key, name, float(getter(task)))

        cached_status = self._cached(key, "status")
        if migrated:
            if cached_status != "Done":
                self._set_single_select(item_id, "Status", "Done")
                self._remember(key, "status", "Done")
        elif newly_created:
            if cached_status != "Todo":
                self._set_single_select(item_id, "Status", "Todo")
                self._remember(key, "status", "Todo")


def build_card_body(task: dict, migrated: bool) -> str:
    """Compose the draft-issue Markdown body with detail and sub-tasks."""
    lines: List[str] = []
    state = "✅ Already migrated" if migrated else "🚧 Available to migrate"
    lines.append(f"**{state}**")
    lines.append("")
    lines.append(f"- **Source:** `{task['rel_path']}`")
    lines.append(f"- **Proposed target:** `{task['target_path']}`")
    lines.append(f"- **Domain:** `{task['domain']}`")
    lines.append(
        f"- **Effort:** rank {task['rank']} · tier {task['tier']} "
        f"· score {float(task['score']):.2f} (lower = easier)"
    )
    lines.append(
        f"- **Size:** {task['loc']} LOC · "
        f"{task['num_functions'] + task['num_classes']} functions/classes · "
        f"{int(round(float(task['typed_ratio']) * 100))}% typed · "
        f"docstrings {int(round(float(task['documented_ratio']) * 100))}%"
    )
    lines.append("")

    deps = task.get("depends_on_direct") or []
    trans = [d for d in (task.get("depends_on_transitive") or []) if d not in deps]
    lines.append("### Dependencies (migrate or bridge these too)")
    if deps:
        lines.append("**Direct dependencies**")
        for dep in deps:
            lines.append(f"- `{dep}`")
        if trans:
            lines.append("")
            lines.append("**Transitive dependencies**")
            for dep in trans:
                lines.append(f"- `{dep}`")
    else:
        lines.append("- _none — self-contained, safe to migrate in isolation_")
    lines.append("")

    direct = task.get("impacted_tests") or []
    tx = task.get("impacted_tests_transitive") or []
    lines.append("### Impact (tests to re-validate)")
    lines.append(
        f"- **{len(direct)}** test(s) import it directly; "
        f"**{len(tx)}** affected transitively."
    )
    if direct:
        lines.append("")
        lines.append("**Directly impacted tests**")
        for path in direct:
            lines.append(f"- `{path}`")
    if tx:
        lines.append("")
        lines.append("**Transitively impacted tests**")
        for path in tx:
            lines.append(f"- `{path}`")
    lines.append("")

    pending = [s for s in (task.get("symbols") or []) if not s.get("migrated")]
    lines.append(f"### Function/class sub-tasks ({len(pending)})")
    lines.append("_Pick a single one for a bite-sized contribution._")
    for sym in sorted(pending, key=lambda s: s.get("score", 0)):
        lines.append(
            f"- [ ] `{sym['name']}` ({sym['kind']}, tier {sym['tier']}, "
            f"{sym['loc']} LOC, {int(round(float(sym['typed_ratio']) * 100))}% typed)"
        )
    lines.append("")
    lines.append("---")
    lines.append("_Auto-generated by the common2 Migration Dashboard workflow. "
                 "Do not edit the title (`Module` path) — it is the sync key._")
    return "\n".join(lines)


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", required=True,
                        help="Path to migration_dashboard.json.")
    parser.add_argument("--project-id", default=os.getenv("PROJECT_ID", ""),
                        help="Project (v2) node id.")
    parser.add_argument("--dry-run", action="store_true",
                        help="Log intended changes without mutating the project.")
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    args = parse_args(argv)

    token = resolve_auth_token()
    if not token:
        logger.error("GITHUB_APP_TOKEN, GH_APP_TOKEN, or GITHUB_TOKEN must be set")
        return 2

    with open(args.json, "r", encoding="utf-8") as handle:
        payload = json.load(handle)

    project_id = args.project_id.strip()
    if not project_id:
        logger.error("provide --project-id")
        return 2

    upserter = MigrationProjectUpserter(token, project_id, dry_run=args.dry_run)

    tasks = payload.get("tasks") or []
    migrated = payload.get("migrated") or []
    for task in tasks:
        upserter.upsert(task, migrated=False)
    for task in migrated:
        upserter.upsert(task, migrated=True)

    logger.info(
        "Done. cards created=%d, field updates=%d, body updates=%d, "
        "total managed=%d (dry_run=%s)",
        upserter.created, upserter.updated_fields, upserter.updated_bodies,
        len(upserter.items_by_key), args.dry_run,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
