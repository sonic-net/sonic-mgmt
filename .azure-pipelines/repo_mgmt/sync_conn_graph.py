import git
import os
import requests
import json
import sys
import yaml
import fnmatch
import logging
from requests.auth import HTTPBasicAuth
from datetime import datetime

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

MGMT_REPOSITOR_ID = '5380e8f7-6e2a-4154-8dee-f3be7b096894'
MSSONIC_USERNAME = 'mssonic'
MSSONIC_PUBLIC_TOKEN = os.environ.get('MSSONIC_PUBLIC_TOKEN')

SOURCE_BRANCH = 'internal'
TARGET_BRANCHES = ['internal-202012', 'internal-202205', 'internal-202305', 'internal-202311', 'internal-202405']
CREATE_GRAPH_BRANCHES = ['internal-202012', 'internal-202205', 'internal-202305']
ANSIBLE_INVENTORY_LIST = ['testbed.yaml', 'veos', 'wan_sonic_tb', 'wan_vtestbed.yaml']

ANSIBLE_PATH = 'ansible/'
TOPO_FILE_PATH = 'ansible/vars/'
TOPO_FILE_PATTERN = "topo_*.yml"
LAB_GRAPHFILE_PATH = 'ansible/files/'
LAB_GRAPH_GROUPS_FILE = "graph_groups.yml"
GROUP_VARS_PATH = 'ansible/group_vars/'
HOST_VARS_PATH = 'ansible/host_vars/'
INV_MAPPING_FILE = "group_vars/all/inv_mapping.yml"
SUPPORTED_CSV_FILES = {
    "devices": "sonic_{}_devices.csv",
    "links": "sonic_{}_links.csv",
    "pdu_links": "sonic_{}_pdu_links.csv",
    "console_links": "sonic_{}_console_links.csv",
    "bmc_links": "sonic_{}_bmc_links.csv",
}
CREATE_GRAPH_FILE = "creategraph.py"
EXCLUDE_FILES = ['ansible/group_vars/all/secrets.json']

NEW_BRANCH_HEADER = 'auto_sync_conn_graph'
REPO_URL = 'https://dev.azure.com/mssonic/internal/_git/sonic-mgmt-int'
PULL_REQUEST_URL_PREFIX = f'https://dev.azure.com/mssonic/internal/_apis/git/repositories/{MGMT_REPOSITOR_ID}/pullrequests'
HEADERS = {'Content-Type': 'application/json'}
AUTH = HTTPBasicAuth('', MSSONIC_PUBLIC_TOKEN)


def set_up_git_env(repo):
    """Set up git environment for git commands"""
    repo.git.config('user.name', MSSONIC_USERNAME)
    repo.git.config('user.email', f'{MSSONIC_USERNAME}@microsoft.com')


def close_previous_pull_requests(branch):
    url = f'{PULL_REQUEST_URL_PREFIX}?sourceRefName=refs/heads/{branch}&api-version=7.1-preview.1'
    response = requests.get(
        url,
        headers=HEADERS,
        auth=AUTH
    )

    pull_requests = response.json().get("value", [])
    if len(pull_requests) > 0:
        pr_id = pull_requests[0].get("pullRequestId")
        pr_status = pull_requests[0].get("status")
        if pr_id and pr_status != "completed":
            logger.info(f"Abandom pull request for branch {branch} since pipeline is going to create new pull request with latest code.")
            response = requests.patch(
                url=f'{PULL_REQUEST_URL_PREFIX}/{pr_id}?api-version=7.1-preview.1',
                headers=HEADERS,
                auth=AUTH,
                json={"status": "abandoned"}
            )
            if response.status_code == 200:
                logger.info(f"Pull request {pr_id} is abandoned.")
            else:
                logger.info(f"Failed to abandon pull request {pr_id}. Status code: {response.status_code}, Response: {response.text}")


def remove_useless_remote_branches_and_prs(repo, url_with_token, pull_request_info):
    """Remove remote branches that are not in the target branch list"""
    # Fetch the latest changes from the remote repository
    repo.git.execute(['git', 'fetch', url_with_token])
    # Get a list of remote branches contains new branch header
    remote_branches = [ref.remote_head for ref in repo.remotes.origin.refs if NEW_BRANCH_HEADER in ref.remote_head]
    logger.info(f"Remote branches: {remote_branches}")

    pr_sub_string = '/' + str(pull_request_info['pullRequestId']) + '/' if pull_request_info else ''
    logger.info(f"pr_sub_string: {pr_sub_string}")
    is_pr_already_created = False

    for branch in remote_branches:
        if pr_sub_string and pr_sub_string in branch:
            logger.info(f"Skip branch {branch} since pull request {pull_request_info['pullRequestId']} has been created.")
            is_pr_already_created = True
            continue
        logger.info(f"Delete branch {branch} since pull request is completed or abandoned.")
        repo.git.execute(['git', 'push', url_with_token, '--delete', branch])
        close_previous_pull_requests(branch)
    return is_pr_already_created


def get_graph_files(repo_path):
    graph_file_list = []

    # add all topo files under ansible/vars/
    topo_file_path = os.path.join(repo_path, TOPO_FILE_PATH)
    for root, dirs, files in os.walk(topo_file_path):
        for file in files:
            if fnmatch.fnmatch(file, TOPO_FILE_PATTERN):
                file_relpath = os.path.relpath(os.path.join(root, file), topo_file_path)
                graph_file_list.append(os.path.join(TOPO_FILE_PATH, file_relpath))

    # add all files under ansible/group_vars/
    group_vars_path = os.path.join(repo_path, GROUP_VARS_PATH)
    for root, dirs, files in os.walk(group_vars_path):
        for file in files:
            file_relpath = os.path.relpath(os.path.join(root, file), group_vars_path)
            graph_file_list.append(os.path.join(GROUP_VARS_PATH, file_relpath))

    # add all files under ansible/host_vars/
    host_vars_path = os.path.join(repo_path, HOST_VARS_PATH)
    for root, dirs, files in os.walk(host_vars_path):
        for file in files:
            file_relpath = os.path.relpath(os.path.join(root, file), host_vars_path)
            graph_file_list.append(os.path.join(HOST_VARS_PATH, file_relpath))

    # get all graph group names from graph_groups.yml
    graph_group_file = os.path.join(repo_path, LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE)
    with open(graph_group_file) as fd:
        graph_groups = yaml.safe_load(fd)

    # add all graph files under ansible/files/
    for group in graph_groups:
        ANSIBLE_INVENTORY_LIST.append(group)
        csv_files = {k: os.path.join(LAB_GRAPHFILE_PATH, v.format(group)) for k, v in SUPPORTED_CSV_FILES.items()}
        for file_name in csv_files.values():
            graph_file_list.append(file_name)

    # add all inventory files under ansible/
    for inv in ANSIBLE_INVENTORY_LIST:
        file_path = os.path.join(ANSIBLE_PATH, inv)
        graph_file_list.append(file_path)

    for file_name in graph_file_list[:]:
        file_path = os.path.join(repo_path, file_name)
        if not os.path.exists(file_path):
            logger.info(f"File {file_name} does not exist in internal branch. Remove from graph file list...")
            graph_file_list.remove(file_name)

    for file_path in EXCLUDE_FILES:
        if file_path in graph_file_list:
            graph_file_list.remove(file_path)

    return graph_groups, graph_file_list


def get_source_pull_request_info(repo, files):
    latest_commit_id = repo.git.log('-n 1', '--format=%H', '--', files)
    logger.info("latest_commit_id: {}".format(latest_commit_id))
    completed_pr_url = f'{PULL_REQUEST_URL_PREFIX}?status=completed&api-version=7.1-preview.1'
    completed_prs_response = requests.get(
        completed_pr_url,
        headers=HEADERS,
        auth=AUTH
    )
    if completed_prs_response.status_code == 200:
        completed_prs = completed_prs_response.json().get("value", [])
    else:
        logger.info("Failed to get completed pull requests")
        return

    try:
        pull_request = [pr for pr in completed_prs if pr.get("lastMergeCommit", {}).get("commitId") == latest_commit_id]
        pull_request_url = f'{PULL_REQUEST_URL_PREFIX}?pullRequestId={pull_request[0]["pullRequestId"]}&api-version=7.1-preview.1'
        pull_request_response = requests.get(
            pull_request_url,
            headers=HEADERS,
            auth=AUTH
        )
        logger.info("pull_request_response: {}".format(pull_request_response.status_code))
        if pull_request_response.status_code == 200:
            pull_request_info = pull_request_response.json()
            logger.info("pull_request_info: {}".format(pull_request_info))
            return pull_request_info
        else:
            logger.info("Failed to get pull request info with error code {}.".format(pull_request_response.status_code))
            return
    except Exception as e:
        logger.info("Failed to find pull request info for {}".format(e))
        return


def create_graph_xml(repo_path, graph_groups):
    inv_mapping_file_path = os.path.join(repo_path, ANSIBLE_PATH, INV_MAPPING_FILE)
    create_graph_file_path = os.path.join(repo_path, LAB_GRAPHFILE_PATH, CREATE_GRAPH_FILE)
    graph_xml_list = []
    with open(inv_mapping_file_path) as fd:
        inv_mapping = yaml.safe_load(fd)

    lab_graph_path = os.path.join(repo_path, LAB_GRAPHFILE_PATH)
    os.chdir(lab_graph_path)

    for group, graph_xml in inv_mapping.items():
        if group not in graph_groups:
            continue
        logger.info(f"Creating graph xml for {group}...")
        try:
            result = os.system(f"python2 {create_graph_file_path} -i {group} -o {graph_xml}")
            if result != 0:
                logger.info(f"Failed to create {graph_xml} for {group}.")
                return
        except Exception as e:
            logger.info(f"Failed to create {graph_xml} for {group}. Error: {e}")
            return
        graph_xml_list.append(os.path.join(repo_path, LAB_GRAPHFILE_PATH, graph_xml))

    os.chdir(repo_path)
    return graph_xml_list


def compare_and_create_pull_request(repo, repo_path, url_with_token, source_branch, target_branch,
                                    graph_groups, files_to_compare, pull_request_info):
    # Fetch the branches
    repo.git.execute(['git', 'fetch', url_with_token, f'refs/heads/{source_branch}:refs/remotes/origin/{source_branch}'])
    repo.git.execute(['git', 'fetch', url_with_token, f'refs/heads/{target_branch}:refs/remotes/origin/{target_branch}'])
    has_diff = False

    if target_branch not in CREATE_GRAPH_BRANCHES:
        files_to_compare.append(os.path.join(LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE))

    if pull_request_info:
        branch_suffix = str(pull_request_info['pullRequestId']) + '/' + datetime.now().strftime('%Y%m%d%H%M%S')
    else:
        branch_suffix = datetime.now().strftime('%Y%m%d%H%M%S')
    new_branch = NEW_BRANCH_HEADER + '/' + target_branch + '/' + branch_suffix
    repo.create_head(new_branch, f'origin/{target_branch}')
    repo.heads[new_branch].checkout()
    logger.info(f"Checking out to new branch {new_branch}...")

    # Compare the specified files
    for file_name in files_to_compare:
        file_path = os.path.join(repo_path, file_name)
        if not os.path.exists(file_path):
            target_content = ''
        else:
            target_content = repo.git.show(f'refs/remotes/origin/{target_branch}:{file_name}')
        source_content = repo.git.show(f'refs/remotes/origin/{source_branch}:{file_name}')

        if source_content != target_content:
            logger.info(f"File {file_name} is different between {source_branch} and {target_branch}. Overwriting...")

            # Overwrite the file from the source branch
            repo.git.checkout(f'refs/remotes/origin/{source_branch}', file_name)

            # Commit changes
            repo.git.add(file_name)
            has_diff = True

    if target_branch not in CREATE_GRAPH_BRANCHES:
        files_to_compare.remove(os.path.join(LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE))

    if has_diff:
        if target_branch in CREATE_GRAPH_BRANCHES:
            graph_xml_list = create_graph_xml(repo_path, graph_groups)
            if graph_xml_list:
                for file_name in graph_xml_list:
                    repo.git.add(file_name)
            else:
                logger.info(f"Failed to create graph xml, skip branch {target_branch}...")
                repo.git.reset('--hard')
                for untracked_file in repo.untracked_files:
                    os.remove(os.path.join(repo_path, untracked_file))
                return

        repo.git.commit(m=f'Overwrite conn graph files from {source_branch} to {target_branch}')
        # Push changes to the target branch
        repo.git.execute(['git', 'push', url_with_token, new_branch])
        # Create pull request
        logger.info(f"Creating pull request from {new_branch} to {target_branch}...")
        create_pull_request(new_branch, target_branch, pull_request_info)


def create_pull_request(source_branch, target_branch, pull_request_info):
    reviewers = []
    reviewer = {}
    additional_title = ""
    additional_description = ""
    if pull_request_info:
        reviewer['id'] = pull_request_info['createdBy']['id']
        reviewers.append(reviewer)
        additional_title = f" by PR {pull_request_info['pullRequestId']}"
        additional_description = f"This pull request is created from {REPO_URL}/pullrequest/{pull_request_info['pullRequestId']}"
    repository_url = f'{PULL_REQUEST_URL_PREFIX}?api-version=7.1-preview.1'
    title = f"[Auto Created{additional_title}] Sync connection graph facts from internal to {target_branch}"
    description = "Across different branches, the connection graph facts should remain consistent. " \
                  "However, as the code undergoes continuous updates, the disparities between " \
                  "connection graph facts files among different branches are becoming more " \
                  "pronounced, which divergence poses significant challenges for cherry-pick. " \
                  "To address these differences and reduce the time spent synchronizing branches, " \
                  "we can automate the creation of pull requests by running a pipeline. " \
                  "This pull request use the connection graph facts from the internal branch to " \
                  "overwrite other branches, thereby synchronizing the connection graph facts across " \
                  "different branches." \
                  f"{additional_description}"

    source_branch = f'refs/heads/{source_branch}'
    target_branch = f'refs/heads/{target_branch}'

    data = {
        'sourceRefName': source_branch,
        'targetRefName': target_branch,
        'title': title,
        'description': description,
        'reviewers': reviewers
    }

    response = requests.post(
        repository_url,
        headers=HEADERS,
        auth=AUTH,
        data=json.dumps(data)
    )

    if response.status_code == 201:
        pull_request_link = f"{REPO_URL}/pullrequest/{response.json()['pullRequestId']}"
        logger.info(f"Pull request to {target_branch} created successfully, link: {pull_request_link}")
    else:
        logger.info(f"Failed to create pull request. Status code: {response.status_code}, Response: {response.text}")


if __name__ == "__main__":
    current_dir = os.getcwd()
    repo_path = os.path.join(current_dir, "../../")
    repo = git.Repo(repo_path)
    set_up_git_env(repo)
    url_with_token = f'https://x-access-token:{MSSONIC_PUBLIC_TOKEN}@dev.azure.com/mssonic/internal/_git/sonic-mgmt-int'

    graph_groups, graph_files = get_graph_files(repo_path)
    logger.info(f"Graph groups: {graph_groups}, files to compare: {graph_files}")

    pull_request_info = get_source_pull_request_info(repo, graph_files)
    is_pr_already_created = remove_useless_remote_branches_and_prs(repo, url_with_token, pull_request_info)
    if is_pr_already_created:
        sys.exit(0)

    for branch in TARGET_BRANCHES:
        logger.info("################################################################################################")
        logger.info(f"Comparing files between {SOURCE_BRANCH} and {branch}...")
        compare_and_create_pull_request(repo, repo_path, url_with_token, SOURCE_BRANCH, branch, graph_groups, graph_files, pull_request_info)
