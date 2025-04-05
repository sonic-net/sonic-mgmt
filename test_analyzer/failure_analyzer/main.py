from __future__ import print_function, division
import json
from datetime import datetime
import argparse
import pytz

from kusto_connector import KustoConnector
from data_deduplicator import DataDeduplicator
from data_analyzer import DataAnalyzer
from config import configuration, logger, FAILURES_AFTER_ANALYSIS_CSV, FAILURES_AFTER_AGGREGATION_CSV
import pandas as pd


def main(excluded_testbed_keywords, excluded_testbed_keywords_setup_error, included_branch, released_branch, upload_flag):
    current_time = datetime.now(tz=pytz.UTC)
    logger.info(configuration)
    configuration["testbeds"] = {}
    configuration["testbeds"]["excluded_testbed_keywords"] = excluded_testbed_keywords
    configuration["testbeds"]["excluded_testbed_keywords_setup_error"] = excluded_testbed_keywords_setup_error

    configuration["branch"]["included_branch"] = included_branch
    configuration["branch"]["released_branch"] = released_branch
    configuration["upload"] = upload_flag
    logger.info("level_priority: {}".format(configuration['level_priority']))
    for level in configuration['level_priority']:
        configuration.update(read_types_configuration(level, configuration["icm_decision_config"].get(level, {}).get("types", [])))

    deduper = DataDeduplicator()
    kusto_connector = KustoConnector(current_time)
    analyzer = DataAnalyzer(kusto_connector, deduper, current_time)

    common_summary_new_icm_table = []
    common_summary_duplicated_icm_table = []
    branches_wanted = []
    branches_wanted_dict = {}

    common_summary_new_icm_table, common_summary_duplicated_icm_table = analyzer.run_common_summary_failure()

    logger.info("=================Common summary failed cases=================")
    logger.info("Found {} IcM for common summary cases".format(
        len(common_summary_new_icm_table)))
    for index, case in enumerate(common_summary_new_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
    logger.info("Found {} duplicated IcM for commom summary failed cases".format(
        len(common_summary_duplicated_icm_table)))
    for index, case in enumerate(common_summary_duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))

    failure_new_icm_table, failure_duplicated_icm_table = analyzer.run_failure_cross_branch()

    logger.info("=================General failure cases=================")
    logger.info("Found {} IcM for general failure cases".format(
        len(failure_new_icm_table)))
    for index, case in enumerate(failure_new_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
    logger.info("Found {} duplicated IcM for general failure cases".format(
        len(failure_duplicated_icm_table)))
    for index, case in enumerate(failure_duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))

    logger.info("=================Start aggregation=================")
    failures_df = deduper.prepare_data_for_clustering(failure_new_icm_table)
    failures_df.to_csv(FAILURES_AFTER_ANALYSIS_CSV, index=False)
    aggregated_df = deduper.find_similar_summaries_and_count(failures_df, analyzer.week_failed_testcases_df)
    aggregated_df.to_csv(FAILURES_AFTER_AGGREGATION_CSV, index=False)
    logger.debug("The count of failures before aggregation: {} after:{}".format(len(failures_df), len(aggregated_df)))

    # Create a mapping from subject to failure_summary
    subject_to_summary = dict(zip(aggregated_df['subject'], aggregated_df['failure_summary']))

    # Update failure_new_icm_table items with the aggregated failure_summary
    aggregated_failure_new_icm_list = []
    for item in failure_new_icm_table:
        if item['subject'] in subject_to_summary:
            if item['failure_summary'] == '' or not item['failure_summary']:
                logger.debug("{} summary is empty, will use the one in the aggregated_df".format(item['subject']))
                item['failure_summary'] = subject_to_summary[item['subject']]
            elif item['failure_summary'] != subject_to_summary[item['subject']]:
                logger.debug("{} summary is not same as the one in the aggregated_df".format(item['subject']))
                logger.debug("  - {}: {}".format(item['failure_summary'], subject_to_summary[item['subject']]))
                item['failure_summary'] = subject_to_summary[item['subject']]
            aggregated_failure_new_icm_list.append(item)

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
        common_summary_new_icm_table, origin_data, configuration["branch"]["included_branch"])
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
    duplicated_icm_table = common_summary_duplicated_icm_table + failure_duplicated_icm_table + \
        duplicated_icm_table_wanted + uploading_dupplicated_list
    logger.info(
        "=================After deduplication, total duplicated IcMs=================")
    logger.info("Total duplicated cases {}".format(len(duplicated_icm_table)))
    for index, case in enumerate(duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
        logger.info("summary: {}".format(case['failure_summary']))

    final_list = final_error_list + final_failure_list
    autoblame_table = analyzer.generate_autoblame_ado_data(final_list)
    logger.info("=================AutoBlame items=================")
    if autoblame_table:
        logger.info("Total number of Autoblame items {}".format(len(autoblame_table)))
    else:
        logger.error("There is something wrong with Autoblame search.")

    analyzer.upload_to_kusto(final_list, duplicated_icm_table, autoblame_table)

    end_time = datetime.now(tz=pytz.UTC)
    logger.info("Cost {} for this run.".format(end_time - current_time))

def read_types_configuration(level, type_list):
    """
        Read 'types' configuration for the given level.
    """
    config_level = level + "_config"
    excluded_types_level = level + "_excluded_types"
    config_level_dict = {}
    excluded_types = []
    for c in type_list:
        name = c["name"]
        config_level_dict[name] = c
        if not c.get("included", True):
            excluded_types.append(c['name'])
    return {
        excluded_types_level: excluded_types,
        config_level: config_level_dict
    }


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

    parser.add_argument(
        "--upload", "-u",
        default=False,
        action='store_true',
        required=False,
        help="If upload test result to kusto, by default is False",
    )
    args = parser.parse_args()

    excluded_testbed_keywords = args.exclude_testbed.split(",")
    excluded_testbed_keywords_setup_error = args.exclude_testbed_setup_error.split(",")
    included_branch = json.loads(args.included_branch)
    released_branch = json.loads(args.released_branch)
    upload_flag = args.upload

    logger.info("excluded_testbed_keywords={}, excluded_testbed_keywords_setup_error={}"
        .format(excluded_testbed_keywords, excluded_testbed_keywords_setup_error))

    logger.info(f"included_branch={included_branch}, released_branch={released_branch}")

    main(
        excluded_testbed_keywords,
        excluded_testbed_keywords_setup_error,
        included_branch,
        released_branch,
        upload_flag
    )
