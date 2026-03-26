import json
import requests
import sys
import re
from dashboard_utils import singleton 
from db_tool_sonicsol import PostgresDBConnectionSonicSol
from requests.auth import HTTPBasicAuth
from datetime import datetime
import os

JIRA_USERNAME = 'ayushisr@cisco.com'
JIRA_API_URL = 'https://miggbo.atlassian.net/rest/api/3/'
JIRA_DATA_URL = JIRA_API_URL + 'myself'
JIRA_ISSUES_URL = JIRA_API_URL + "issue/"
JIRA_CUSTOM_FIELD_URL = JIRA_API_URL + "field"
JIRA_SEARCH_URL = JIRA_API_URL + "search/jql?"
SONIC_SOL_JIRA_TOKEN = os.getenv("DASHBOARD_JENKINS_API_TOKEN")
JIRA_AUTH = (
    JIRA_USERNAME,
    SONIC_SOL_JIRA_TOKEN
)

HEADERS = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}

TEST_RUN_LABEL_RE = re.compile(r"^TestRunID:(.+)$")

def normalize_title(title):
    if not title:
        return ""
    return title.replace("n't", " not").replace("'ed", " ed")


def parse_jira_datetime(created):
       return datetime.strptime(created, "%Y-%m-%dT%H:%M:%S.%f%z")

@singleton
class Jira:

    def __init__(self, auth=None):
        jira_token = SONIC_SOL_JIRA_TOKEN
        self.jira_auth = JIRA_AUTH
        #if auth:
        '''elif jira_token_env:
            print("JIRA API token not specified exiplicitly, checking env variable")
            self.jira_auth = jira_token_env
        else:
            print("Token not specifed during initialization, and couldn't find it in env variable as well! Please set jira token to use Jira class.")
            exit(1)

        '''
        if not self._verify_jira_auth(self.jira_auth):
            exit(1)

    @staticmethod
    def _verify_jira_auth(jira_auth):
        response = requests.get(JIRA_DATA_URL, auth=jira_auth, headers=HEADERS, timeout=15)

        if "expand" in response.text:
            print("Your token is good")
            return True
        else:
            print("Your token is BAD")
            #log.debug(response.text)
            return False

    def get_issue(self, issue):
        response = requests.get(JIRA_ISSUES_URL + str(issue), auth=self.jira_auth, timeout=10)
        json_r = json.loads(response.text)
        #print("Issue %s: %s" % (issue, json_r))
        return json_r

    def get_issues_from_epic(self, epic_field, blocked):
        """
        blocked=False: fetch non-blocked issues in epic
        blocked=True: fetch blocked issues in epic
        """
        all_issues = []
        max_results = 100
        more_pages = False
        token = ""

        while True:
            jql_parts = [
                f"parentEpic='{epic_field}'",
                "type IN (Bug, Improvement, Story, Task)"
            ]

            if blocked:
                jql_parts.append("status = Blocked")

            jql = " AND ".join(jql_parts)

            url = f"{JIRA_SEARCH_URL}jql={jql}&maxResults={max_results}&fields=summary,created,status,labels"

            if more_pages:
                url += f"&nextPageToken={token}"

            print(f"Fetching JIRA issues with URL: {url}\nIssues gone through: {len(all_issues)}")

            try:
                response = requests.get(url, auth=self.jira_auth, headers=HEADERS, timeout=20)
                response.raise_for_status()
            except requests.exceptions.RequestException as e:
                print(f"Error fetching JIRA issues from {url}: {e}")
                return []

            try:
                json_r = response.json()
            except json.JSONDecodeError as e:
                print(f"Error decoding JSON response from {url}: {e}. Response text: {response.text}")
                return []

            if 'issues' not in json_r:
                print(f"No 'issues' key found in response for URL: {url}. Response: {json_r}")
                break

            all_issues.extend(json_r['issues'])

            if json_r.get('isLast') is False:
                more_pages = True
                token = json_r.get('nextPageToken', "")
            else:
                break

        return all_issues

    def extract_new_rows_from_issues(self, issues):
        """
        Convert Jira issues into DB rows:
        (test_case_id, jira_id, jira_status, title, start_time)

        Only labels matching TestRunID:<value> are used.
        """
        rows = []
        seen = set()

        for issue in issues:
            issue_key = issue.get('key')
            fields = issue.get('fields', {})

            labels = fields.get('labels', []) or []
            jira_status = fields.get('status', {}).get('name', 'N/A')
            title = normalize_title(fields.get('summary', ''))
            created = fields.get('created')

            if not issue_key or not created:
                continue

            try:
                start_time = parse_jira_datetime(created)
            except ValueError:
                print(f"Skipping issue {issue_key}: invalid created date {created}")
                continue

            for label in labels:
                match = TEST_RUN_LABEL_RE.match(label)
                if not match:
                    continue

                test_case_id = match.group(1).strip()
                if not test_case_id:
                    continue

                # Store the full Jira key, not just the numeric suffix
                jira_id = issue_key

                dedupe_key = (test_case_id, jira_id)
                if dedupe_key in seen:
                    continue

                seen.add(dedupe_key)

                rows.append((
                    test_case_id,
                    jira_id,
                    jira_status,
                    title,
                    start_time
                ))

        return rows 
        
    def insert_new_rows(self, rows, db):
        """
        Insert only new Jira + test_case combinations.
        Existing rows are ignored.
        """
        if not rows:
            print("No discovered rows to insert")
            return

        sql =  "INSERT INTO jira_ids (test_case_id, jira_id, jira_status, title, start_time)" 
        sql += " VALUES %s" 
        sql += " ON CONFLICT (test_case_id, jira_id) DO NOTHING"

        ret = db.execute_values(sql, rows)  
        return ret

    def get_tracked_rows_from_db(self, db):
        """
        Returns all tracked rows from jira_ids.
        """
        jiras = db.find("jira_ids", column_list=["test_case_id", "jira_id", "jira_status", "title", "start_time"])

        return jiras

    def refresh_existing_rows(self, db):
        """
        Go through all Jira IDs currently stored in jira_ids
        and update status/title for all matching rows.
        """
        tracked_rows = self.get_tracked_rows_from_db(db)

        if not tracked_rows:
            print("No tracked rows found in jira_ids")
            return

        unique_jira_ids = sorted({row[1] for row in tracked_rows})
        print(f"Refreshing {len(unique_jira_ids)} unique Jira issues from jira_ids")

        update_rows = []

        for jira_id in unique_jira_ids:
            try:
                issue = self.get_issue(jira_id)
            except requests.exceptions.RequestException as e:
                print(f"Failed to fetch Jira {jira_id}: {e}")
                continue

            fields = issue.get('fields', {})
            jira_status = fields.get('status', {}).get('name', '')
            title = normalize_title(fields.get('summary', ''))

            update_rows.append({
                "jira_status": jira_status,
                "title": title,
                "jira_id": jira_id
            })

        if not update_rows:
            print("No Jira issues were successfully fetched for refresh")
            return

        db.update_many_by_key("jira_ids", update_rows, key_column="jira_id")
        
        print(f"Refreshed {len(update_rows)} Jira issues in jira_ids")



if __name__ == '__main__':
    jira = Jira()

    db = PostgresDBConnectionSonicSol(use_backup=False)

    epic_names = [
        'MIGSOFTWAR-22954',
        'MIGSOFTWAR-25462',
        'MIGSOFTWAR-12014',
        'MIGSOFTWAR-25469',
        'MIGSOFTWAR-26045',
        'MIGSOFTWAR-30485',
        'MIGSOFTWAR-29043',
        'MIGSOFTWAR-31386'
    ]

    all_candidate_rows = []
    seen_global = set()

    for epic in epic_names:
        non_blocked_issues = jira.get_issues_from_epic(epic, blocked=False)
        blocked_issues = jira.get_issues_from_epic(epic, blocked=True)

        combined_issues = non_blocked_issues + blocked_issues
        candidate_rows = jira.extract_new_rows_from_issues(combined_issues)

        for row in candidate_rows:
            dedupe_key = (row[0], row[1])  # (test_case_id, jira_id)
            if dedupe_key in seen_global:
                continue
            seen_global.add(dedupe_key)
            all_candidate_rows.append(row)

    ret1 = jira.insert_new_rows(all_candidate_rows, db)
    jira.refresh_existing_rows(db)

    sys.exit(ret1)

    db.close_connection()
        