from __future__ import print_function, division
import json
from datetime import datetime
import sys
import argparse
import pytz

from kusto_connector import KustoConnector
from data_deduplicator import DataDeduplicator
from data_analyzer import DataAnalyzer
from config import configuration
import logging
import pandas as pd
import os

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)


def main(excluded_testbed_keywords, excluded_testbed_keywords_setup_error, included_branch, released_branch):
    current_time = datetime.now(tz=pytz.UTC)
    logger.info(configuration)
    configuration["testbeds"] = {}
    configuration["testbeds"]["excluded_testbed_keywords"] = excluded_testbed_keywords
    configuration["testbeds"]["excluded_testbed_keywords_setup_error"] = excluded_testbed_keywords_setup_error

    configuration["branch"]["included_branch"] = included_branch
    configuration["branch"]["released_branch"] = released_branch

    deduper = DataDeduplicator(configuration)
    kusto_connector = KustoConnector(configuration, current_time)
    general = DataAnalyzer(kusto_connector, deduper, configuration, current_time)
    
    failure_new_icm_table, failure_duplicated_icm_table, failure_info = general.run_failure_cross_branch()
    excluse_setup_error_dict = {}
    excluse_common_summary_dict = {}
    setup_error_new_icm_table = []
    setup_error_duplicated_icm_table = []
    common_summary_new_icm_table = []
    common_summary_duplicated_icm_table = []
    branches_wanted = []
    branches_wanted_dict = {}

    common_summary_new_icm_table, common_summary_duplicated_icm_table, common_summary_failures_info = general.run_common_summary_failure()
    logger.info("=================Exclude the following common summary cases=================")
    for case in common_summary_new_icm_table + common_summary_duplicated_icm_table:
        key = case["testcase"] + "#" + case["branch"]
        if key in common_summary_failures_info:
            excluse_common_summary_dict[key] = common_summary_failures_info[key]
    logger.info(json.dumps(excluse_common_summary_dict, indent=4))

    logger.info("=================Common summary failed cases=================")
    logger.info("Found {} IcM for common summary cases".format(
        len(common_summary_new_icm_table)))
    for index, case in enumerate(common_summary_new_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
    logger.info("Found {} duplicated IcM for commom summary failed cases".format(
        len(common_summary_duplicated_icm_table)))
    for index, case in enumerate(common_summary_duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))

    logger.info("=================General failure cases=================")
    logger.info("Found {} IcM for general failure cases".format(
        len(failure_new_icm_table)))
    for index, case in enumerate(failure_new_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
    logger.info("Found {} duplicated IcM for general failure cases".format(
        len(failure_duplicated_icm_table)))
    for index, case in enumerate(failure_duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
    
    failures_df = pd.DataFrame(failure_new_icm_table, columns=['subject', 'branch', 'failure_summary'])
    with open('logs/failures_df_post.csv', 'w') as file:
        failures_df.to_csv(file, index=False)
    aggregated_df = deduper.find_similar_summaries_and_count(failures_df)

    with open('logs/aggregated_df_post.csv', 'w') as file:
        aggregated_df.to_csv(file, index=False)
    logger.debug("The count of failures before aggregation: {} after:{}".format(len(failures_df), len(aggregated_df)))
    aggregated_failure_new_icm_list = [item for item in failure_new_icm_table if item['subject'] in list(aggregated_df['subject'])]
 
    logger.info("=================After aggregation, general failure cases=================")
    logger.info("Found {} IcM for general aggregated failure cases".format(
        len(aggregated_failure_new_icm_list)))
    for index, case in enumerate(aggregated_failure_new_icm_list):
        logger.info("{}: {}".format(index + 1, case['subject']))
        logger.info("summary: {}".format(case['failure_summary']))

    origin_data = [
        {"table": aggregated_failure_new_icm_list, "type": "general"}
    ]
    for branch in branches_wanted:
        origin_data.append(
            {"table": branches_wanted_dict[branch]["new_icm_table"], "type": branch})
    final_error_list, final_failure_list, uploading_dupplicated_list = deduper.deduplication(
        setup_error_new_icm_table, common_summary_new_icm_table, origin_data, configuration["branch"]["included_branch"])
    logger.info(
        "=================After deduplication, final result=================")
    logger.info("Will report {} new error cases".format(len(final_error_list)))
    for index, case in enumerate(final_error_list):
        logger.info("{}: {}".format(index + 1, case['subject']))
        logger.info("summary: {}".format(case['failure_summary']))
    logger.info("Will report {} new failure cases".format(
        len(final_failure_list)))
    for index, case in enumerate(final_failure_list):
        logger.info("{}: {}".format(index + 1, case['subject']))
        logger.info("summary: {}".format(case['failure_summary']))
    logger.info("Will report {} duplicated cases".format(
        len(uploading_dupplicated_list)))
    for index, case in enumerate(uploading_dupplicated_list):
        logger.info("{}: {}".format(index + 1, case['subject']))

    duplicated_icm_table_wanted = []
    for branch in branches_wanted:
        duplicated_icm_table_wanted += branches_wanted_dict[branch]["duplicated_icm_table"]
    duplicated_icm_table = setup_error_duplicated_icm_table + common_summary_duplicated_icm_table + failure_duplicated_icm_table + \
        duplicated_icm_table_wanted + uploading_dupplicated_list
    logger.info(
        "=================After deduplication, total duplicated IcMs=================")
    logger.info("Total duplicated cases {}".format(len(duplicated_icm_table)))
    for index, case in enumerate(duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
        logger.info("summary: {}".format(case['failure_summary']))

    final_list = final_error_list + final_failure_list
    autoblame_table = general.generate_autoblame_ado_data(final_list)
    logger.info("=================AutoBlame items=================")
    if autoblame_table:
        logger.info("Total number of Autoblame items {}".format(len(autoblame_table)))
    else:
        logger.error("There is something wrong with Autoblame search.")
    # for index, case in enumerate(autoblame_table):
    #     logger.info("{}: {} {}".format(
    #         index + 1, case['autoblame_id']))

    general.upload_to_kusto(final_list, duplicated_icm_table, autoblame_table)

    end_time = datetime.now(tz=pytz.UTC)
    logger.info("Cost {} for this run.".format(end_time - current_time))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description="Analyze test result")


    parser.add_argument(
        "--exclude_testbed", "-extb",
        type=str,
        required=False,
        help="The list of testbeds to be excluded (as a comma-delimited list)",
    )

    parser.add_argument(
        "--exclude_testbed_setup_error", "-exerr",
        type=str,
        required=False,
        help="The list of testbed setup error to be excluded (as a comma-delimited list)",
    )

    parser.add_argument(
        "--included_branch", "-incbr",
        type=str,
        required=False,
        help="The list of branches to include (as a JSON list)"
    )

    parser.add_argument(
        "--released_branch", "-rlsbr",
        type=str,
        required=False,
        help="The list of released branches (as a JSON list)"
    )

    args = parser.parse_args()
    
    excluded_testbed_keywords = args.exclude_testbed.split(",")
    excluded_testbed_keywords_setup_error = args.exclude_testbed_setup_error.split(",")
    included_branch = json.loads(args.included_branch)
    released_branch = json.loads(args.released_branch)

    logger.info("excluded_testbed_keywords={}, excluded_testbed_keywords_setup_error={}"
        .format(excluded_testbed_keywords, excluded_testbed_keywords_setup_error))

    logger.info(f"included_branch={included_branch}, released_branch={released_branch}")

    main(
        excluded_testbed_keywords, 
        excluded_testbed_keywords_setup_error,
        included_branch,
        released_branch
    )

