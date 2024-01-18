import git
import os
import requests
import json
import sys
import yaml
import logging
from requests.auth import HTTPBasicAuth
from datetime import datetime

logging.basicConfig(stream=sys.stdout, level=logging.INFO)
logger = logging.getLogger(__name__)

MGMT_REPOSITOR_ID = os.environ.get('MGMT_REPOSITOR_ID')
MSSONIC_USERNAME = os.environ.get('MSSONIC_USERNAME')
MSSONIC_PUBLIC_TOKEN = os.environ.get('MSSONIC_PUBLIC_TOKEN')

SOURCE_BRANCH = 'internal'
TARGET_BRANCH = ['internal-202012', 'internal-202205', 'internal-202305', 'internal-202311']
ANSIBLE_INVENTORY_LIST = ['testbed.yaml', 'veos', 'wan_sonic_tb', 'wan_vtestbed.yaml']

ANSIBLE_PATH = 'ansible/'
LAB_GRAPHFILE_PATH = 'ansible/files/'
LAB_GRAPH_GROUPS_FILE = "graph_groups.yml"
INV_MAPPING_FILE = "group_vars/all/inv_mapping.yml"
SUPPORTED_CSV_FILES = {
    "devices": "sonic_{}_devices.csv",
    "links": "sonic_{}_links.csv",
    "pdu_links": "sonic_{}_pdu_links.csv",
    "console_links": "sonic_{}_console_links.csv",
    "bmc_links": "sonic_{}_bmc_links.csv",
}
CREATE_GRAPH_FILE = "creategraph.py"

NEW_BRANCH_HEADER = 'auto_sync_conn_graph'


def set_up_git_env(repo):
    """Set up git environment for git commands"""
    repo.git.config('user.name', MSSONIC_USERNAME)
    repo.git.config('user.email', f'{MSSONIC_USERNAME}@microsoft.com')


def remove_useless_remote_branches(repo, url_with_token):
    """Remove remote branches that are not in the target branch list"""
    # Fetch the latest changes from the remote repository
    repo.git.execute(['git', 'fetch', url_with_token])
    # Get a list of remote branches contains new branch header
    remote_branches = [ref.remote_head for ref in repo.remotes.origin.refs if NEW_BRANCH_HEADER in ref.remote_head]
    logger.info(f"Remote branches: {remote_branches}")

    headers = {
        'Content-Type': 'application/json',
    }
    for branch in remote_branches:
        url = f'https://dev.azure.com/mssonic/internal/_apis/git/repositories/{MGMT_REPOSITOR_ID}/pullrequests?sourceRefName=refs/heads/{branch}&api-version=7.1-preview.1'
        response = requests.get(
            url,
            headers=headers,
            auth=HTTPBasicAuth('', MSSONIC_PUBLIC_TOKEN),
        )

        # Check if the request was successful (status code 200)
        if response.status_code == 200 and response.json()['count'] == 0:
            logger.info(f"Delete branch {branch} since pull request is completed or abandoned.")
            repo.git.execute(['git', 'push', url_with_token, '--delete', branch])


def get_graph_files(repo_path):
    graph_file_list = []
    graph_group_file = os.path.join(repo_path, LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE)
    with open(graph_group_file) as fd:
        graph_groups = yaml.safe_load(fd)

    for group in graph_groups:
        ANSIBLE_INVENTORY_LIST.append(group)
        csv_files = {k: os.path.join(LAB_GRAPHFILE_PATH, v.format(group)) for k, v in SUPPORTED_CSV_FILES.items()}
        for file_name in csv_files.values():
            graph_file_list.append(file_name)

    for inv in ANSIBLE_INVENTORY_LIST:
        file_path = ANSIBLE_PATH + inv
        graph_file_list.append(file_path)

    for file_name in graph_file_list[:]:
        file_path = os.path.join(repo_path, file_name)
        if not os.path.exists(file_path):
            logger.info(f"File {file_name} does not exist in internal branch. Remove from graph file list...")
            graph_file_list.remove(file_name)

    return graph_groups, graph_file_list


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
            os.system(f"python {create_graph_file_path} -i {group} -o {graph_xml}")
        except Exception as e:
            logger.info(f"Failed to create graph xml for {group}. Error: {e}")
            continue
        graph_xml_list.append(os.path.join(repo_path, LAB_GRAPHFILE_PATH, graph_xml))

    os.chdir(repo_path)
    return graph_xml_list


def compare_and_create_pull_request(repo, repo_path, url_with_token, source_branch, target_branch, graph_groups, files_to_compare):
    # Fetch the branches
    repo.git.execute(['git', 'fetch', url_with_token, f'refs/heads/{source_branch}:refs/remotes/origin/{source_branch}'])
    repo.git.execute(['git', 'fetch', url_with_token, f'refs/heads/{target_branch}:refs/remotes/origin/{target_branch}'])
    has_diff = False

    if target_branch == 'internal-202311':
        files_to_compare.append(os.path.join(LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE))

    # Create a new branch from the target branch
    current_timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
    new_branch = NEW_BRANCH_HEADER + '/' + target_branch + '/' + current_timestamp
    repo.create_head(new_branch, f'origin/{target_branch}')
    repo.heads[new_branch].checkout()

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

    if target_branch == 'internal-202311':
        files_to_compare.remove(os.path.join(LAB_GRAPHFILE_PATH, LAB_GRAPH_GROUPS_FILE))

    if has_diff:
        if target_branch in ['internal-202012', 'internal-202205', 'internal-202305']:
            graph_xml_list = create_graph_xml(repo_path, graph_groups)
            for file_name in graph_xml_list:
                repo.git.add(file_name)

        repo.git.commit(m=f'Overwrite conn graph files from {source_branch} to {target_branch}')
        # Push changes to the target branch
        repo.git.execute(['git', 'push', url_with_token, new_branch])
        # Create pull request
        create_pull_request(new_branch, target_branch)


def create_pull_request(source_branch, target_branch):
    repository_url = f'https://dev.azure.com/mssonic/internal/_apis/git/repositories/{MGMT_REPOSITOR_ID}/pullrequests?api-version=7.1-preview.1'
    title = f"[Auto Created] Sync connection graph facts from internal to {target_branch}"
    description = '''
        Across different branches, the connection graph facts should remain consistent. 
        However, as the code undergoes continuous updates, the disparities between connection graph facts files among different branches are becoming more pronounced, which divergence poses significant challenges for cherry-pick. 
        To address these differences and reduce the time spent synchronizing branches, we can automate the creation of pull requests by running a pipeline. 
        This pull request use the connection graph facts from the internal branch to overwrite other branches, thereby synchronizing the connection graph facts across different branches.
        '''
    source_branch = f'refs/heads/{source_branch}'
    target_branch = f'refs/heads/{target_branch}'

    headers = {
        'Content-Type': 'application/json',
    }
    data = {
        'sourceRefName': source_branch,
        'targetRefName': target_branch,
        'title': title,
        'description': description
    }

    response = requests.post(
        repository_url,
        headers=headers,
        auth=HTTPBasicAuth('', MSSONIC_PUBLIC_TOKEN),
        data=json.dumps(data)
    )

    if response.status_code == 201:
        pull_request_link = f"https://dev.azure.com/mssonic/internal/_git/sonic-mgmt-int/pullrequest/{response.json()['pullRequestId']}"
        logger.info(f"Pull request to {target_branch} created successfully, link: {pull_request_link}")
    else:
        logger.info(f"Failed to create pull request. Status code: {response.status_code}, Response: {response.text}")


if __name__ == "__main__":
    current_dir = os.getcwd()
    repo_path = os.path.join(current_dir, "../../")
    repo = git.Repo(repo_path)
    set_up_git_env(repo)
    url_with_token = f'https://x-access-token:{MSSONIC_PUBLIC_TOKEN}@dev.azure.com/mssonic/internal/_git/sonic-mgmt-int'

    remove_useless_remote_branches(repo, url_with_token)
    graph_groups, graph_files = get_graph_files(repo_path)
    logger.info(f"Graph groups: {graph_groups}, files to compare: {graph_files}")

    for branch in TARGET_BRANCH:
        logger.info("################################################################################################")
        logger.info(f"Comparing files between {SOURCE_BRANCH} and {branch}...")
        compare_and_create_pull_request(repo, repo_path, url_with_token, SOURCE_BRANCH, branch, graph_groups, graph_files)
