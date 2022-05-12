import json
import os
import re
import socket
import subprocess
from io import open

from azure.storage.blob import BlobServiceClient
from celery import Celery
from scandir import scandir

app = Celery("sonic_executor")


class Config:
    broker_url = os.environ["CELERY_BROKER_URL"]
    result_backend = os.environ["CELERY_BROKER_URL"]
    task_default_queue = 'sonic_executor'
    worker_prefetch_multiplier = 1
    worker_concurrency = 1
    task_acks_late = True


app.config_from_object(Config)
blob_service_client = BlobServiceClient.from_connection_string(os.environ["BLOB_CONN_STRING"])
container_client = blob_service_client.get_container_client(os.environ["BLOB_CONTAINER"])


def get_dut(tb, testbed_file="vtestbed.csv"):
    with open(testbed_file, encoding='utf-8') as f:
        for line in f:
            line_info = line.split(",")
            if line_info[0] == tb:
                return line_info[9].replace("[", "").replace("]", "")
    return None


def set_env(relative_pwd="", project_root="/data/sonic-mgmt"):
    os.environ["ANSIBLE_CONFIG"] = "{}/ansible".format(project_root)
    os.environ["ANSIBLE_LIBRARY"] = "{}/ansible/library/".format(project_root)
    os.environ["ANSIBLE_CONNECTION_PLUGINS"] = "{}/ansible/plugins/connection".format(project_root)
    os.environ["ANSIBLE_TERMINAL_PLUGINS"] = "{}/ansible/terminal_plugins".format(project_root)
    os.environ["ANSIBLE_CLICONF_PLUGINS"] = "{}/ansible/cliconf_plugins".format(project_root)
    os.environ["PWD"] = "{}/{}".format(project_root, relative_pwd) if relative_pwd else project_root


@app.task(bind=True, name='run_test')
def run_test(self, test_plan_id, test_file, testbed):
    print("running : " + test_file)
    set_env(relative_pwd="tests")

    dut = get_dut(testbed)
    print("dut={}, testbed={}".format(dut, testbed))
    self.update_state(state='STARTED', meta={'file': test_file, 'host': socket.gethostname()})
    log_file_path, test_name = parse_test_name_and_log_file_path(test_file)

    if not os.path.exists(os.path.join("logs", log_file_path)):
        os.mkdir(os.path.join("logs", log_file_path))

    with open("logs/{}_output.log".format(test_name), 'wb') as output_f:
        try:
            ret = subprocess.check_call(
                ["pytest", test_file, "--inventory=veos_vtb", "--host-pattern={}".format(dut),
                 "--testbed={}".format(testbed),
                 "--testbed_file=vtestbed.csv", "--log-cli-level=warning", "--log-file-level=debug",
                 "--kube_master=unset",
                 "--showlocals", "--assert=plain", "--show-capture=no", "-rav",
                 "--ignore=ptftests",
                 "--ignore=acstests", "--ignore=saitests", "--ignore=scripts", "--ignore=k8s", "--ignore=sai_qualify",
                 "--maxfail=1",
                 "--log-file=logs/{}.log".format(test_name),
                 "--junit-xml=logs/{}.xml".format(test_name),
                 "--skip_sanity"
                 ], stdout=output_f, stderr=subprocess.STDOUT)
            result = {'ret': ret, 'test_result': 'PASSED'}
        except subprocess.CalledProcessError as e:
            result = {'ret': e.returncode, 'test_result': 'FAILED', 'err_msg': str(e)}
    try:
        with open("logs/{}.log".format(test_name), "rb") as data:
            container_client.get_blob_client("{}/{}.log".format(test_plan_id, test_name))\
                .upload_blob(data, blob_type="BlockBlob")
        with open("logs/{}.xml".format(test_name), "rb") as data:
            container_client.get_blob_client("{}/{}.xml".format(test_plan_id, test_name))\
                .upload_blob(data, blob_type="BlockBlob")
        with open("logs/{}_output.log".format(test_name), "rb") as data:
            container_client.get_blob_client("{}/{}_output.log".format(test_plan_id, test_name))\
                .upload_blob(data, blob_type="BlockBlob")
    except Exception as e:
        pass

    return result


def parse_test_name_and_log_file_path(test_file):
    test_name = test_file.split(".py")[0]
    if "/" in test_file:
        idx = test_file.rindex("/")
        log_file_path = test_file[0: idx]
    else:
        log_file_path = ""
    return log_file_path, test_name


@app.task(bind=True, name='analysis_task')
def analysis_task(self, test_cases):
    set_env(relative_pwd="tests")
    test_cases = json.loads(test_cases, encoding='utf-8')
    files = set(os.listdir('.'))
    to_test_set = set()
    not_test_set = set()

    if (not test_cases["features"]) and (not test_cases["scripts"]):
        to_test_set.add(fetch_all_tests())
    else:
        for feature in test_cases["features"]:
            if feature in files and os.path.isdir(feature):
                to_test_set.update(fetch_all_tests(feature))
        for test_case in test_cases["scripts"]:
            if os.path.isfile(test_case):
                to_test_set.add(test_case)

    for feature in test_cases["features_exclude"]:
        if feature in files and os.path.isdir(feature):
            not_test_set.update(fetch_all_tests(feature))
    for test_case in test_cases["scripts_exclude"]:
        if os.path.isfile(test_case):
            not_test_set.add(test_case)

    result = to_test_set - not_test_set
    self.update_state(state='SUCCESS', meta={'test_cases': list(result)})
    return list(result)


def fetch_all_tests(feature="."):
    hits = []

    def find_in_dir_subdir(direc):
        content = scandir(direc)
        for entry in content:
            if re.match(r"^test_.*\.py$", entry.name):
                hits.append(os.path.join(direc, entry.name))

            elif entry.is_dir():
                try:
                    find_in_dir_subdir(os.path.join(direc, entry.name))
                except UnicodeDecodeError:
                    print("Could not resolve " + os.path.join(direc, entry.name))
                    continue

    find_in_dir_subdir(feature)
    return hits
