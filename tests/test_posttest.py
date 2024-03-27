import pytest
import logging
import time
import os
import glob
import tarfile
import gzip
from tests.common.helpers.assertions import pytest_require

logger = logging.getLogger(__name__)

pytestmark = [
    pytest.mark.posttest,
    pytest.mark.topology('util', 'any'),
    pytest.mark.sanity_check(skip_sanity=True),
    pytest.mark.disable_loganalyzer,
    pytest.mark.skip_check_dut_health
]

LOG_SAVE_PATH = 'logs/'


def extract_tar_gz_file(tar_file_path, extract_path):
    logger.info("Extracting {} to {}".format(tar_file_path, extract_path))
    with tarfile.open(tar_file_path, 'r') as tar:
        members = tar.getmembers()
        for member in members:
            try:
                logger.info("Extract {}".format(member.name))
                tar.extract(member, path=extract_path)
            except Exception as e:
                logger.info("Error extracting {}: {}".format(member.name, e))


def extract_gz_file(gz_file_path):
    extracted_file_path = os.path.splitext(gz_file_path)[0]
    logger.info("Extracting {} to {}".format(gz_file_path, extracted_file_path))
    with gzip.open(gz_file_path, 'rb') as f_in:
        with open(extracted_file_path, 'wb') as f_out:
            f_out.write(f_in.read())
    os.remove(gz_file_path)


def extract_dump_and_syslog(tar_file_path, dump_path, dir_name):
    logger.info("Extracting tar.gz dump file {}".format(tar_file_path))
    extract_tar_gz_file(tar_file_path, dump_path)
    # rename dump folder
    os.rename(tar_file_path.split('.tar.gz')[0], os.path.join(dump_path, dir_name))
    # renmae .tar.gz dump file
    os.rename(tar_file_path, os.path.join(dump_path, dir_name + '.tar.gz'))

    syslog_path = dump_path + dir_name + '/log/'
    syslog_gz_files = glob.glob(os.path.join(syslog_path, 'syslog*.gz'))
    logger.info("Extracting syslog gz files: {}".format(syslog_gz_files))
    if len(syslog_gz_files) > 0:
        for syslog_gz in syslog_gz_files:
            extract_gz_file(syslog_gz)


def test_collect_techsupport(request, duthosts, enum_dut_hostname):
    since = request.config.getoption("--posttest_show_tech_since")
    if since == '':
        since = 'yesterday'
    log_dir = request.config.getoption("--log_dir")
    duthost = duthosts[enum_dut_hostname]
    """
    A util for collecting techsupport after tests.

    Since nightly test on Jenkins will do a cleanup at the beginning of tests,
    we need a method to save history logs and dumps. This util does the job.
    """
    logger.info("Collecting techsupport since {}".format(since))
    # Because Jenkins is configured to save artifacts from tests/logs,
    # and this util is mainly designed for running on Jenkins,
    # save path is fixed to logs for now.
    out = duthost.command("show techsupport --since {}".format(since), module_ignore_errors=True)
    if out['rc'] == 0:
        tar_file = out['stdout_lines'][-1]
        tar_file_name = tar_file.split('/')[-1]
        dump_path = LOG_SAVE_PATH + 'dump/'
        duthost.fetch(src=tar_file, dest=dump_path, flat=True)

        if not log_dir:
            log_dir = tar_file.split('/')[-1].split('.tar.gz')[0]
        tar_file_path = os.path.join(dump_path, tar_file_name)
        logger.info("tar_file_path: {}, dump_path: {}".format(tar_file_path, dump_path))
        extract_dump_and_syslog(tar_file_path, dump_path, log_dir)

    assert True


def test_restore_container_autorestart(duthosts, enum_dut_hostname, enable_container_autorestart):
    duthost = duthosts[enum_dut_hostname]
    enable_container_autorestart(duthost)
    # Wait sometime for snmp reloading
    SNMP_RELOADING_TIME = 30
    time.sleep(SNMP_RELOADING_TIME)


def test_recover_rsyslog_rate_limit(duthosts, enum_dut_hostname):
    duthost = duthosts[enum_dut_hostname]
    # We don't need to recover the rate limit on vs testbed
    pytest_require(duthost.facts['asic_type'] != 'vs', "Skip on vs testbed")
    features_dict, succeed = duthost.get_feature_status()
    if not succeed:
        # Something unexpected happened.
        # We don't want to fail here because it's an util
        logging.warn("Failed to retrieve feature status")
        return
    for feature_name, state in list(features_dict.items()):
        if 'enabled' not in state:
            continue
        if feature_name == "telemetry":
            # Skip telemetry if there's no docker image
            output = duthost.shell("docker images", module_ignore_errors=True)['stdout']
            if "sonic-telemetry" not in output:
                continue
        duthost.modify_syslog_rate_limit(feature_name, rl_option='enable')
