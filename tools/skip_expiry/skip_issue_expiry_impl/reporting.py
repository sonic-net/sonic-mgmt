import logging
import os
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests

logger = logging.getLogger(__name__)

GITHUB_GRAPHQL_URL = "https://api.github.com/graphql"


def _graphql_request_with_token(token: str, query: str, variables: dict) -> dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "sonic-mgmt-skip-expiry-reporting",
    }

    for attempt in range(2):
        try:
            response = requests.post(
                GITHUB_GRAPHQL_URL,
                headers=headers,
                json={"query": query, "variables": variables},
                timeout=30,
            )
            response.raise_for_status()
            payload = response.json()
            errors = payload.get("errors") or []
            if errors:
                raise RuntimeError(f"GraphQL errors: {errors}")
            return payload.get("data") or {}
        except Exception as exc:  # pragma: no cover - runtime protection
            if attempt == 0:
                logger.warning("GraphQL request failed, retrying once: %s", exc)
                continue
            logger.error("GraphQL request failed after retry: %s", exc)
            raise

    raise RuntimeError("Unexpected GraphQL retry termination")


def graphql_request(query: str, variables: dict) -> dict:
    """Execute a GraphQL request using GITHUB_TOKEN from environment."""
    token = os.getenv("GITHUB_TOKEN", "").strip()
    if not token:
        raise ValueError("GITHUB_TOKEN is required")
    return _graphql_request_with_token(token, query, variables)


@dataclass
class TestReportData:
    test_id: str
    title: str
    expiry_date: str
    current_status: str
    issue_url: str
    owner: str
    fields: Dict[str, object]


class ProjectV2Reporter:
    """Maintains skip-expiry report rows in a GitHub Project V2."""

    def __init__(self, token: str, project_id: str, dry_run: bool = False) -> None:
        self.token = (token or "").strip()
        self.project_id = (project_id or "").strip()
        self.dry_run = dry_run

        if not self.token:
            raise ValueError("GITHUB_TOKEN is required for Project V2 reporting")
        if not self.project_id:
            raise ValueError("PROJECT_ID is required for Project V2 reporting")

        self.existing_items: Dict[str, str] = {}
        self.field_map: Dict[str, Dict[str, object]] = {}
        self.created_count = 0
        self.updated_count = 0
        self.skipped_count = 0

        self.field_map = self._fetch_project_fields()
        self.fetch_project_items()

    def graphql_request(self, query: str, variables: dict) -> dict:
        """Execute a GraphQL request with one retry on failure."""
        return _graphql_request_with_token(self.token, query, variables)

    def _fetch_project_fields(self) -> Dict[str, Dict[str, object]]:
        query = """
        query($projectId: ID!) {
          node(id: $projectId) {
            ... on ProjectV2 {
              fields(first: 100) {
                nodes {
                  ... on ProjectV2Field {
                    id
                    name
                    dataType
                  }
                  ... on ProjectV2SingleSelectField {
                    id
                    name
                    dataType
                    options {
                      id
                      name
                    }
                  }
                  ... on ProjectV2IterationField {
                    id
                    name
                    dataType
                  }
                }
              }
            }
          }
        }
        """

        data = self.graphql_request(query, {"projectId": self.project_id})
        fields = (((data.get("node") or {}).get("fields") or {}).get("nodes") or [])

        field_map: Dict[str, Dict[str, object]] = {}
        for field in fields:
            if not isinstance(field, dict):
                continue
            name = (field.get("name") or "").strip()
            field_id = field.get("id")
            if not name or not field_id:
                continue
            field_map[name.lower()] = field

        logger.info("Loaded %d Project V2 field definitions", len(field_map))
        return field_map

    def fetch_project_items(self) -> List[Dict[str, str]]:
        """Fetch all project items and build in-memory cache keyed by test_id."""
        query = """
        query($projectId: ID!, $cursor: String) {
          node(id: $projectId) {
            ... on ProjectV2 {
              items(first: 100, after: $cursor) {
                nodes {
                  id
                  content {
                    ... on DraftIssue {
                      title
                    }
                    ... on Issue {
                      title
                    }
                    ... on PullRequest {
                      title
                    }
                  }
                  fieldValues(first: 100) {
                    nodes {
                      ... on ProjectV2ItemFieldTextValue {
                        text
                        field {
                          ... on ProjectV2Field {
                            id
                            name
                          }
                          ... on ProjectV2SingleSelectField {
                            id
                            name
                          }
                          ... on ProjectV2IterationField {
                            id
                            name
                          }
                        }
                      }
                    }
                  }
                }
                pageInfo {
                  hasNextPage
                  endCursor
                }
              }
            }
          }
        }
        """

        cursor = None
        records: List[Dict[str, str]] = []
        existing_items: Dict[str, str] = {}

        while True:
            data = self.graphql_request(query, {"projectId": self.project_id, "cursor": cursor})
            items = ((((data.get("node") or {}).get("items") or {}).get("nodes")) or [])
            page_info = (((data.get("node") or {}).get("items") or {}).get("pageInfo") or {})

            for item in items:
                if not isinstance(item, dict):
                    continue

                item_id = (item.get("id") or "").strip()
                if not item_id:
                    continue

                test_id = self._extract_test_id(item)
                if not test_id:
                    continue

                if test_id in existing_items:
                    logger.warning(
                        "Duplicate project item for test_id=%s (existing=%s new=%s); using first",
                        test_id,
                        existing_items[test_id],
                        item_id,
                    )
                    continue

                existing_items[test_id] = item_id
                records.append({"item_id": item_id, "test_id": test_id})

            if not page_info.get("hasNextPage"):
                break
            cursor = page_info.get("endCursor")

        self.existing_items = existing_items
        logger.info("Cached %d existing project item(s)", len(existing_items))
        return records

    def _extract_test_id(self, item: Dict[str, object]) -> str:
        field_values = (((item.get("fieldValues") or {}).get("nodes")) or [])
        for value in field_values:
            if not isinstance(value, dict):
                continue
            field = value.get("field") or {}
            field_name = ((field.get("name") or "").strip()).lower()
            if field_name == "test_id":
                text = (value.get("text") or "").strip()
                if text:
                    return text

        title = ((((item.get("content") or {}).get("title")) or "").strip())
        return title

    def find_existing_item(self, test_id: str) -> Optional[str]:
        return self.existing_items.get((test_id or "").strip())

    def _field(self, field_name: str) -> Optional[Dict[str, object]]:
        return self.field_map.get(field_name.lower())

    def create_project_item(self, test_data: TestReportData) -> Optional[str]:
        if self.dry_run:
            logger.info("[DRY-RUN] create project item for test_id=%s", test_data.test_id)
            self.created_count += 1
            return None

        mutation = """
        mutation($projectId: ID!, $title: String!) {
          addProjectV2DraftIssue(input: {projectId: $projectId, title: $title}) {
            projectItem {
              id
            }
          }
        }
        """

        data = self.graphql_request(mutation, {"projectId": self.project_id, "title": test_data.title})
        project_item = (((data.get("addProjectV2DraftIssue") or {}).get("projectItem")) or {})
        item_id = (project_item.get("id") or "").strip()
        if not item_id:
            logger.error("Failed to create project item for test_id=%s", test_data.test_id)
            return None

        self._update_text_field(item_id, "test_id", test_data.test_id)
        self.existing_items[test_data.test_id] = item_id
        self.created_count += 1
        logger.info("Created project row for test_id=%s", test_data.test_id)
        return item_id

    def _update_text_field(self, item_id: str, field_name: str, value: str) -> None:
        field = self._field(field_name)
        if not field:
            logger.warning("Project field '%s' not found; skipping update", field_name)
            return

        field_id = field.get("id")
        if not field_id:
            logger.warning("Project field '%s' has no id; skipping update", field_name)
            return

        if self.dry_run:
            logger.info("[DRY-RUN] update text field %s for item %s", field_name, item_id)
            return

        mutation = """
        mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $value: String!) {
          updateProjectV2ItemFieldValue(
            input: {
              projectId: $projectId,
              itemId: $itemId,
              fieldId: $fieldId,
              value: { text: $value }
            }
          ) {
            projectV2Item {
              id
            }
          }
        }
        """

        self.graphql_request(
            mutation,
            {
                "projectId": self.project_id,
                "itemId": item_id,
                "fieldId": field_id,
                "value": value,
            },
        )

    def _clear_field_value(self, item_id: str, field_name: str) -> None:
        field = self._field(field_name)
        if not field:
            logger.warning("Project field '%s' not found; skipping clear", field_name)
            return

        field_id = field.get("id")
        if not field_id:
            logger.warning("Project field '%s' has no id; skipping clear", field_name)
            return

        if self.dry_run:
            logger.info("[DRY-RUN] clear field %s for item %s", field_name, item_id)
            return

        mutation = """
        mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!) {
          clearProjectV2ItemFieldValue(
            input: {
              projectId: $projectId,
              itemId: $itemId,
              fieldId: $fieldId
            }
          ) {
            projectV2Item {
              id
            }
          }
        }
        """

        self.graphql_request(
            mutation,
            {
                "projectId": self.project_id,
                "itemId": item_id,
                "fieldId": field_id,
            },
        )

    def _update_date_field(self, item_id: str, field_name: str, value: str) -> None:
        if not str(value or "").strip():
            self._clear_field_value(item_id, field_name)
            return

        field = self._field(field_name)
        if not field:
            logger.warning("Project field '%s' not found; skipping update", field_name)
            return

        field_id = field.get("id")
        if not field_id:
            logger.warning("Project field '%s' has no id; skipping update", field_name)
            return

        if self.dry_run:
            logger.info("[DRY-RUN] update date field %s for item %s", field_name, item_id)
            return

        mutation = """
        mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $dateValue: Date!) {
          updateProjectV2ItemFieldValue(
            input: {
              projectId: $projectId,
              itemId: $itemId,
              fieldId: $fieldId,
              value: { date: $dateValue }
            }
          ) {
            projectV2Item {
              id
            }
          }
        }
        """

        self.graphql_request(
            mutation,
            {
                "projectId": self.project_id,
                "itemId": item_id,
                "fieldId": field_id,
                "dateValue": value,
            },
        )

    def _update_current_status_field(self, item_id: str, status_value: str) -> None:
        field = self._field("current_status")
        if not field:
            logger.warning("Project field 'current_status' not found; skipping update")
            return

        field_id = field.get("id")
        if not field_id:
            logger.warning("Project field 'current_status' has no id; skipping update")
            return

        options = field.get("options") or []
        option_id = None
        for option in options:
            if not isinstance(option, dict):
                continue
            if (option.get("name") or "").strip().lower() == status_value.lower():
                option_id = option.get("id")
                break

        if self.dry_run:
            logger.info("[DRY-RUN] update current_status field for item %s to %s", item_id, status_value)
            return

        if option_id:
            mutation = """
            mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
              updateProjectV2ItemFieldValue(
                input: {
                  projectId: $projectId,
                  itemId: $itemId,
                  fieldId: $fieldId,
                  value: { singleSelectOptionId: $optionId }
                }
              ) {
                projectV2Item {
                  id
                }
              }
            }
            """
            self.graphql_request(
                mutation,
                {
                    "projectId": self.project_id,
                    "itemId": item_id,
                    "fieldId": field_id,
                    "optionId": option_id,
                },
            )
            return

        logger.warning("No current_status single-select option found for '%s'; trying text update", status_value)
        self._update_text_field(item_id, "current_status", status_value)

    def _update_number_field(self, item_id: str, field_name: str, value: float) -> None:
        field = self._field(field_name)
        if not field:
            logger.warning("Project field '%s' not found; skipping update", field_name)
            return

        field_id = field.get("id")
        if not field_id:
            logger.warning("Project field '%s' has no id; skipping update", field_name)
            return

        if self.dry_run:
            logger.info("[DRY-RUN] update number field %s for item %s", field_name, item_id)
            return

        mutation = """
        mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $numberValue: Float!) {
          updateProjectV2ItemFieldValue(
            input: {
              projectId: $projectId,
              itemId: $itemId,
              fieldId: $fieldId,
              value: { number: $numberValue }
            }
          ) {
            projectV2Item {
              id
            }
          }
        }
        """

        self.graphql_request(
            mutation,
            {
                "projectId": self.project_id,
                "itemId": item_id,
                "fieldId": field_id,
                "numberValue": float(value),
            },
        )

    def _update_single_select_field(self, item_id: str, field_name: str, value: str) -> None:
        field = self._field(field_name)
        if not field:
            logger.warning("Project field '%s' not found; skipping update", field_name)
            return

        field_id = field.get("id")
        if not field_id:
            logger.warning("Project field '%s' has no id; skipping update", field_name)
            return

        option_id = None
        for option in field.get("options") or []:
            if not isinstance(option, dict):
                continue
            if (option.get("name") or "").strip().lower() == value.lower():
                option_id = option.get("id")
                break

        if not option_id:
            logger.warning(
                "No single-select option found for field '%s' value '%s'; clearing field instead",
                field_name,
                value,
            )
            self._clear_field_value(item_id, field_name)
            return

        if self.dry_run:
            logger.info("[DRY-RUN] update single-select field %s for item %s", field_name, item_id)
            return

        mutation = """
        mutation($projectId: ID!, $itemId: ID!, $fieldId: ID!, $optionId: String!) {
          updateProjectV2ItemFieldValue(
            input: {
              projectId: $projectId,
              itemId: $itemId,
              fieldId: $fieldId,
              value: { singleSelectOptionId: $optionId }
            }
          ) {
            projectV2Item {
              id
            }
          }
        }
        """

        self.graphql_request(
            mutation,
            {
                "projectId": self.project_id,
                "itemId": item_id,
                "fieldId": field_id,
                "optionId": option_id,
            },
        )

    def _update_generic_field(self, item_id: str, field_name: str, value: object) -> None:
        if value is None or value == "":
            self._clear_field_value(item_id, field_name)
            return

        field = self._field(field_name)
        if not field:
            logger.warning("Project field '%s' not found; skipping update", field_name)
            return

        data_type = str(field.get("dataType") or "").upper()
        if data_type == "DATE":
            self._update_date_field(item_id, field_name, str(value))
            return
        if data_type == "NUMBER":
            try:
                numeric = float(value)
            except (TypeError, ValueError):
                logger.warning("Invalid numeric value for field '%s': %r", field_name, value)
                return
            self._update_number_field(item_id, field_name, numeric)
            return
        if data_type == "SINGLE_SELECT":
            self._update_single_select_field(item_id, field_name, str(value))
            return

        if isinstance(value, bool):
            self._update_text_field(item_id, field_name, "true" if value else "false")
            return
        if isinstance(value, list):
            self._update_text_field(item_id, field_name, ", ".join(str(item) for item in value))
            return
        self._update_text_field(item_id, field_name, str(value))

    def update_project_item(self, item_id: str, test_data: TestReportData) -> None:
        if not item_id:
            self.skipped_count += 1
            logger.warning("Skipping update with empty item_id for test_id=%s", test_data.test_id)
            return

        self._update_date_field(item_id, "expiry_date", test_data.expiry_date)
        self._update_current_status_field(item_id, test_data.current_status)
        self._update_text_field(item_id, "issue_url", test_data.issue_url)
        self._update_text_field(item_id, "owner", test_data.owner)
        self._update_text_field(item_id, "test_id", test_data.test_id)
        for field_name, field_value in test_data.fields.items():
            self._update_generic_field(item_id, field_name, field_value)
        self.updated_count += 1
        logger.info("Updated project row for test_id=%s", test_data.test_id)

    def upsert_project_item(self, test_data: TestReportData) -> None:
        if not test_data.test_id:
            self.skipped_count += 1
            logger.info("Skipping project upsert for row with missing test_id")
            return

        item_id = self.find_existing_item(test_data.test_id)
        if item_id:
            self.update_project_item(item_id, test_data)
            return

        item_id = self.create_project_item(test_data)
        if item_id is None and not self.dry_run:
            self.skipped_count += 1
            return

        if item_id:
            self.update_project_item(item_id, test_data)

    def summary(self) -> Dict[str, int]:
        return {
            "created": self.created_count,
            "updated": self.updated_count,
            "skipped": self.skipped_count,
        }


def create_reporter_from_env() -> Optional[ProjectV2Reporter]:
    token = os.getenv("GITHUB_TOKEN", "").strip()
    project_id = os.getenv("PROJECT_ID", "").strip()
    dry_run_raw = os.getenv("SKIP_EXPIRY_REPORT_DRY_RUN", "false").strip().lower()
    dry_run = dry_run_raw in {"1", "true", "yes", "on"}

    if not project_id:
        logger.info("PROJECT_ID is not set; skip Project V2 reporting")
        return None

    try:
        return ProjectV2Reporter(token=token, project_id=project_id, dry_run=dry_run)
    except Exception:
        logger.exception("Failed to initialize Project V2 reporter; reporting disabled")
        return None
