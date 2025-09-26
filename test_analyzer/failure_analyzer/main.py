from __future__ import print_function, division
import json
from datetime import datetime
import argparse
import pytz

from kusto_connector import KustoConnector
from data_deduplicator import DataDeduplicator
from data_analyzer import DataAnalyzer
from AI_analyzer import LLMFailureCategorizer
from config import (
    configuration, logger,
    LEGACY_AFTER_ANALYSIS_CSV, LEGACY_AFTER_AGGREGATION_CSV, LEGACY_AFTER_DEDUPLICATION_CSV,
    LEGACY_AFTER_DEDUPLICATION_ICM_CSV,
    FLAKY_AFTER_ANALYSIS_CSV, FLAKY_AFTER_AGGREGATION_CSV, FLAKY_AFTER_DEDUPLICATION_ICM_CSV,
    FLAKY_AFTER_DEDUPLICATION_CSV,
    CONSISTENT_AFTER_ANALYSIS_CSV, CONSISTENT_AFTER_AGGREGATION_CSV,
    CONSISTENT_AFTER_DEDUPLICATION_ICM_CSV
)
import pandas as pd


def log_failure_cases(title, new_icm_table, duplicated_icm_table, include_summary_new=False,
                      include_summary_duplicated=False):
    """
    Common function to log failure case information in a consistent format.

    Args:
        title (str): The title/category for the logging section
        new_icm_table (list): List of new ICM cases
        duplicated_icm_table (list): List of duplicated ICM cases
        include_summary (bool): Whether to include failure summary in the output
    """
    logger.info(f"================={title}=================")
    logger.info("Found {} IcM for {} cases".format(len(new_icm_table), title.lower()))
    for index, case in enumerate(new_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
        if include_summary_new and case.get('failure_summary'):
            logger.info("summary: {}".format(case['failure_summary']))

    logger.info("Found {} duplicated IcM for {} cases".format(len(duplicated_icm_table), title.lower()))
    for index, case in enumerate(duplicated_icm_table):
        logger.info("{}: {}".format(index + 1, case['subject']))
        if include_summary_duplicated and case.get('failure_summary'):
            logger.info("summary: {}".format(case['failure_summary']))
    logger.info(f"================={title} end =================")


def main(excluded_testbed_keywords, excluded_testbed_keywords_setup_error, included_branch,
         released_branch, upload_flag):
    current_time = datetime.now(tz=pytz.UTC)
    logger.info(configuration)
    configuration["testbeds"] = {}
    configuration["testbeds"]["excluded_testbed_keywords"] = excluded_testbed_keywords
    configuration["testbeds"]["excluded_testbed_keywords_setup_error"] = (
        excluded_testbed_keywords_setup_error)

    configuration["branch"]["included_branch"] = included_branch
    configuration["branch"]["released_branch"] = released_branch
    configuration["upload"] = upload_flag
    logger.info("level_priority: {}".format(configuration['level_priority']))
    for level in configuration['level_priority']:
        configuration.update(read_types_configuration(
            level, configuration["icm_decision_config"].get(level, {}).get("types", [])))

    deduper = DataDeduplicator()
    kusto_connector = KustoConnector(current_time)
    analyzer = DataAnalyzer(kusto_connector, deduper, current_time)

    common_summary_new_icm_table = []
    common_summary_duplicated_icm_table = []

    common_summary_new_icm_table, common_summary_duplicated_icm_table = (
        analyzer.run_common_summary_failure())

    log_failure_cases("Common summary failure cases", common_summary_new_icm_table,
                      common_summary_duplicated_icm_table, True, False)

    legacy_new_icm_table, legacy_duplicated_icm_table = analyzer.run_legacy_failure()
    log_failure_cases("Legacy failure cases", legacy_new_icm_table, legacy_duplicated_icm_table,
                      True, True)

    aggregated_legacy_new_icm_list, legacy_aggregated_df = deduper.process_aggregated_failures(
        "legacy", legacy_new_icm_table, legacy_duplicated_icm_table, analyzer,
        LEGACY_AFTER_ANALYSIS_CSV, LEGACY_AFTER_AGGREGATION_CSV, LEGACY_AFTER_DEDUPLICATION_ICM_CSV
    )

    log_failure_cases("After aggregation, legacy failure cases", aggregated_legacy_new_icm_list,
                      legacy_duplicated_icm_table, True, True)

    consistent_new_icm_table, consistent_duplicated_icm_table = analyzer.run_consistent_failure()
    log_failure_cases("Consistent failure cases", consistent_new_icm_table,
                      consistent_duplicated_icm_table, True, True)

    aggregated_consistent_new_icm_list, consistent_aggregated_df = deduper.process_aggregated_failures(
        "consistent", consistent_new_icm_table, consistent_duplicated_icm_table, analyzer,
        CONSISTENT_AFTER_ANALYSIS_CSV, CONSISTENT_AFTER_AGGREGATION_CSV, CONSISTENT_AFTER_DEDUPLICATION_ICM_CSV
    )
    log_failure_cases("After aggregation, consistent failure cases", aggregated_consistent_new_icm_list,
                      consistent_duplicated_icm_table, True, True)

    logger.info("=================Deduplicating legacy aggregated df against consistent "
                "aggregated df=================")
    legacy_deduplicated_vs_consistent_df = deduper.deduplicate_dataframe_clusters(
        consistent_aggregated_df, legacy_aggregated_df)
    legacy_deduplicated_vs_consistent_df.to_csv(LEGACY_AFTER_DEDUPLICATION_CSV, index=True)
    logger.info(f"After deduplication with consistent failure cases, kept "
                f"{len(legacy_deduplicated_vs_consistent_df)} unique legacy failure cases, "
                f"before is {len(legacy_aggregated_df)}")

    aggregated_legacy_new_icm_list = deduper.filter_out_icm_list(
        "legacy", legacy_new_icm_table, legacy_deduplicated_vs_consistent_df)

    log_failure_cases("After aggregation, legacy failure cases", aggregated_legacy_new_icm_list,
                      legacy_duplicated_icm_table, True, True)

    flaky_new_icm_table, flaky_duplicated_icm_table = analyzer.run_flaky_failure()

    log_failure_cases("Flaky failure cases", flaky_new_icm_table, flaky_duplicated_icm_table)

    aggregated_flaky_new_icm_list, flaky_aggregated_df = deduper.process_aggregated_failures(
        "flaky", flaky_new_icm_table, flaky_duplicated_icm_table, analyzer,
        FLAKY_AFTER_ANALYSIS_CSV, FLAKY_AFTER_AGGREGATION_CSV, FLAKY_AFTER_DEDUPLICATION_ICM_CSV
    )

    # Deduplicate flaky_aggregated_df against consistent_aggregated_df and legacy failures
    logger.info("=================Deduplicating flaky failure case aggregated df against "
                "consistent and legacy aggregated dfs=================")
    # Combine legacy and consistent dataframes to use as reference for flaky deduplication
    combined_reference_df = pd.concat([consistent_aggregated_df, legacy_deduplicated_vs_consistent_df],
                                      ignore_index=True)
    logger.info(f"Combined dataframe has {len(consistent_aggregated_df)} consistent + "
                f"{len(legacy_deduplicated_vs_consistent_df)} legacy = "
                f"{len(combined_reference_df)} total entries")

    flaky_deduplicated_df = deduper.deduplicate_dataframe_clusters(combined_reference_df, flaky_aggregated_df)
    flaky_deduplicated_df.to_csv(FLAKY_AFTER_DEDUPLICATION_CSV, index=True)
    logger.info(f"After deduplication with combined df, kept {len(flaky_deduplicated_df)} "
                f"unique flaky entries")

    aggregated_flaky_new_icm_list = deduper.filter_out_icm_list("flaky", flaky_new_icm_table,
                                                                flaky_deduplicated_df)

    log_failure_cases("After aggregation, flaky failure cases", aggregated_flaky_new_icm_list,
                      flaky_duplicated_icm_table, True, True)

    # AI-based flaky case analysis
    ai_analyzer = LLMFailureCategorizer()
    ai_flaky_new_icm_table, ai_flaky_duplicated_icm_table = ai_analyzer.run_ai_flaky_analysis(analyzer)

    log_failure_cases("After deduplication, AI flaky failure cases", ai_flaky_new_icm_table,
                      ai_flaky_duplicated_icm_table, True, True)

    origin_data = [
        {"table": common_summary_new_icm_table, "type": "common"},
        {"table": aggregated_legacy_new_icm_list, "type": "legacy"},
        {"table": aggregated_consistent_new_icm_list, "type": "consistent"},
        {"table": aggregated_flaky_new_icm_list, "type": "flaky"},
        {"table": ai_flaky_new_icm_table, "type": "ai_flaky"},
    ]
    logger.info(f"Type common Count {len(common_summary_new_icm_table)}")
    logger.info(f"Type legacy Count {len(aggregated_legacy_new_icm_list)}")
    logger.info(f"Type consistent Count {len(aggregated_consistent_new_icm_list)}")
    logger.info(f"Type flaky Count {len(aggregated_flaky_new_icm_list)}")
    logger.info(f"Type ai_flaky Count {len(ai_flaky_new_icm_table)}")

    final_failure_list, uploading_dupplicated_list = deduper.deduplication(
        origin_data, configuration["branch"]["included_branch"]
        )

    duplicated_icm_table = (common_summary_duplicated_icm_table + legacy_duplicated_icm_table +
                            flaky_duplicated_icm_table + consistent_duplicated_icm_table +
                            uploading_dupplicated_list)
    log_failure_cases("After deduplication, final result", final_failure_list, duplicated_icm_table,
                      True, False)

    autoblame_table = analyzer.generate_autoblame_ado_data(final_failure_list)
    logger.info("=================AutoBlame items=================")
    if autoblame_table:
        logger.info("Total number of Autoblame items {}".format(len(autoblame_table)))
    else:
        logger.error("There is something wrong with Autoblame search.")
    analyzer.upload_to_kusto(final_failure_list, duplicated_icm_table, autoblame_table)

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
