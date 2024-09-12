from config import configuration
import logging
import pytz
from datetime import datetime, timedelta
import json
import copy
import sys
from rapidfuzz import process, fuzz
import pandas as pd


ICM_PREFIX = '[SONiC_Nightly][Failed_Case]'

logging.basicConfig(
    stream=sys.stdout,
    level=logging.DEBUG,
    format='%(asctime)s :%(name)s:%(lineno)d %(levelname)s - %(message)s')

logger = logging.getLogger(__name__)

def get_deduplicator():
    return DataDeduplicator(configuration)

class DataDeduplicator:
    def __init__(self, config_info):
        configuration = config_info
        current_time = datetime.now(tz=pytz.UTC)
        self.current_time = current_time

        self.new_icm_number_limit = configuration['icm_limitation']['new_icm_number_limit']
        self.setup_error_limit = configuration['icm_limitation']['setup_error_limit']
        self.failure_limit = configuration['icm_limitation']['failure_limit']
        self.platform_limit = configuration['icm_limitation']['platform_limit']
        self.icm_20201231_limit = configuration['icm_limitation']['icm_20201231_limit']
        self.icm_20220531_limit = configuration['icm_limitation']['icm_20220531_limit']
        self.icm_20230531_limit = configuration['icm_limitation']['icm_20230531_limit']
        self.icm_202311_limit = configuration['icm_limitation']['icm_202311_limit']
        self.icm_master_limit = configuration['icm_limitation']['icm_master_limit']
        self.icm_internal_limit = configuration['icm_limitation']['icm_internal_limit']
        self.max_icm_count_per_module = configuration['icm_limitation']['max_icm_count_per_module']

    def deduplication(self, setup_error_new_icm_table, common_summary_new_icm_table, original_failure_dict):
        """
        Deduplicate the IcM list, remove the duplicated IcM
        """
        duplicated_icm_list = []
        unique_title = set()
        final_icm_list = []
        error_final_icm_list = []
        count_platform_test = 0
        count_202012 = 0
        count_202205 = 0
        count_202305 = 0
        count_202311 = 0
        count_master = 0
        count_internal = 0

        logger.info("limit the number of setup error cases to {}".format(
            self.setup_error_limit))
        logger.info("limit the number of general failure cases to {}".format(
            self.failure_limit))
        logger.info("limit the number of platform_tests cases to {}".format(
            self.platform_limit))
        logger.info("limit the number of 20201231 cases to {}".format(
            self.icm_20201231_limit))
        logger.info("limit the number of 20220531 cases to {}".format(
            self.icm_20220531_limit))
        logger.info("limit the number of 20230531 cases to {}".format(
            self.icm_20230531_limit))
        logger.info("limit the number of 202311 cases to {}".format(
            self.icm_202311_limit))
        logger.info("limit the number of master cases to {}".format(
            self.icm_master_limit))
        logger.info("limit the number of internal cases to {}".format(
            self.icm_internal_limit))

        if len(setup_error_new_icm_table) > self.setup_error_limit:
            error_final_icm_list = setup_error_new_icm_table[:self.setup_error_limit]
        else:
            error_final_icm_list = setup_error_new_icm_table
        setup_set = set()
        common_summary_new_icm_list = []
        for icm in error_final_icm_list:
            setup_set.add(icm['subject'])
        for icm in common_summary_new_icm_table:
            if icm['subject'] not in setup_set:
                common_summary_new_icm_list.append(icm)
        failure_new_icm_table = []
        for data in original_failure_dict:
            if data['type'] == 'general':
                failure_new_icm_table = common_summary_new_icm_list + data['table']
                data['table'] = failure_new_icm_table
                logger.info("There are {} general failure cases".format(len(failure_new_icm_table)))
                break
        for data in original_failure_dict:
            icm_table = data['table']
            failure_type = data['type']
            for candidator in icm_table:
                if candidator['subject'] in unique_title:
                    candidator['trigger_icm'] = False
                    duplicated_icm_list.append(candidator)
                    logger.info("Found duplicated item in appending IcM list, not trigger IcM for:{}".format(
                        candidator['subject']))
                    continue
                # If the title is not in unique_title set, check if it is duplicated with the uploading IcM
                unique_title.add(candidator['subject'])
                duplicated_flag = False

                # For loop every uploading IcM title, avoid generating lower level IcM for same failure
                for uploading_new_icm in final_icm_list:
                    # For platform_test, we aggregate branches, don't trigger same IcM for different branches
                    if 'platform_tests' in candidator['module_path']:
                        icm_branch = candidator['branch']
                        for branch_name in configuration["branch"]["included_branch"]:
                            replaced_title = candidator['subject'].replace(
                                icm_branch, branch_name)
                            # If the uploading IcM title is the lower than the one in final_icm_list, don't trigger IcM
                            if uploading_new_icm['subject'] in replaced_title:
                                logger.info("For platform_tests, found lower case for branch {}, not trigger IcM: \
                                    the IcM in final_icm_list {}, duplicated one {}".format(icm_branch, uploading_new_icm['subject'], candidator['subject']))
                                candidator['trigger_icm'] = False
                                duplicated_icm_list.append(candidator)
                                duplicated_flag = True
                                break
                            # if the uploading IcM title is the higher than the one in final_icm_list, replace the one in final_icm_list
                            elif replaced_title in uploading_new_icm['subject']:
                                logger.info("For platform_tests, found lower case for branch {}, replace {} in final_icm_list with \
                                    {}".format(icm_branch, uploading_new_icm['subject'], candidator['subject']))
                                final_icm_list.remove(uploading_new_icm)
                                final_icm_list.append(candidator)
                                duplicated_flag = True
                                break
                        if duplicated_flag:
                            break
                    # If the uploading IcM title is the lower than the one in final_icm_list, don't trigger IcM
                    elif uploading_new_icm['subject'] in candidator['subject']:
                        logger.info("Found lower case, not trigger IcM: \
                            the IcM in final_icm_list {}, duplicated one {}".format(uploading_new_icm['subject'], candidator['subject']))
                        candidator['trigger_icm'] = False
                        duplicated_icm_list.append(candidator)
                        duplicated_flag = True
                        break
                    # if the uploading IcM title is the higher than the one in final_icm_list, replace the one in final_icm_list
                    elif candidator['subject'] in uploading_new_icm['subject']:
                        # Don't trigger IcM for duplicated cases, avoid IcM throttling
                        logger.info("Found lower case, replace {} in final_icm_list with \
                                    {}".format(uploading_new_icm['subject'], candidator['subject']))
                        final_icm_list.remove(uploading_new_icm)
                        final_icm_list.append(candidator)
                        duplicated_flag = True
                        break
                if not duplicated_flag:
                    candidator_branch = candidator['branch']
                    if 'platform_tests' in candidator['module_path']:
                        count_platform_test += 1
                        if count_platform_test > self.platform_limit:
                            logger.info("Reach the limit of platform_test case, ignore this IcM {}".format(
                                candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                    if candidator_branch == "20201231":
                        if count_202012 >= self.icm_20201231_limit:
                            logger.info("Reach the limit of 202012 case: {}, ignore this IcM {}".format(
                                self.icm_20201231_limit, candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                        else:
                            count_202012 += 1
                    elif candidator_branch == "20220531":
                        if count_202205 >= self.icm_20220531_limit:
                            logger.info("Reach the limit of 202205 case: {}, ignore this IcM {}".format(
                                self.icm_20220531_limit, candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                        else:
                            count_202205 += 1
                    elif candidator_branch == "20230531":
                        if count_202305 >= self.icm_20230531_limit:
                            logger.info("Reach the limit of 202305 case: {}, ignore this IcM {}".format(
                                self.icm_20230531_limit, candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                        else:
                            count_202305 += 1
                    elif candidator_branch == "master":
                        if count_master >= self.icm_master_limit:
                            logger.info("Reach the limit of master case: {}, ignore this IcM {}".format(
                                self.icm_master_limit, candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                        else:
                            count_master += 1
                    elif candidator_branch == "internal":
                        if count_internal >= self.icm_internal_limit:
                            logger.info("Reach the limit of internal case: {}, ignore this IcM {}".format(
                                self.icm_internal_limit, candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                        else:
                            count_internal += 1
                    elif "202311" in candidator_branch:
                        if count_202311 >= self.icm_202311_limit:
                            logger.info("Reach the limit of 202311 case: {}, ignore this IcM {}".format(
                                self.icm_202311_limit, candidator['subject']))
                            candidator['trigger_icm'] = False
                            continue
                        else:
                            count_202311 += 1
                    logger.info("Add branch {} type {} : {} to final_icm_list".format(
                        candidator_branch, failure_type, candidator['subject']))
                    final_icm_list.append(candidator)
        logger.info("Count summary: platform_test {}, 202012 {}, 202205 {}, 202305 {}, 202311 {}, master {}, internal {}".format(
            count_platform_test, count_202012, count_202205, count_202305, count_202311, count_master, count_internal))
        logger.info("Check if subject mismatch for setup error IcM")
        for kusto_row_item in error_final_icm_list:
            self.check_subject_match(kusto_row_item)
        logger.info("Check if subject mismatch for failure IcM")
        for kusto_row_item in final_icm_list:
            self.check_subject_match(kusto_row_item)
        logger.info("Check if subject mismatch for duplicated IcM")
        for kusto_row_item in duplicated_icm_list:
            self.check_subject_match(kusto_row_item)
        logger.debug("final_icm_list={}".format(json.dumps(final_icm_list, indent=4)))
        return error_final_icm_list, final_icm_list, duplicated_icm_list

    def check_subject_match(self, kusto_row):
        """
        Check if the subject match with asic/hwsku/osversion
        """
        asic_name = kusto_row['failure_level_info']['asic'] if 'asic' in kusto_row['failure_level_info'] else None
        hwsku_name = kusto_row['failure_level_info']['hwsku'] if 'hwsku' in kusto_row['failure_level_info'] else None
        osversion_name = kusto_row['failure_level_info']['osversion'] if 'osversion' in kusto_row['failure_level_info'] else None
        subject_name = kusto_row['subject']
        if asic_name and asic_name not in subject_name:
            logger.error("In check_subject_match: asic {} not in subject {}".format(asic_name, subject_name))
        if hwsku_name and hwsku_name not in subject_name:
            logger.error("In check_subject_match: hwsku {} not in subject {}".format(hwsku_name, subject_name))
        if osversion_name and osversion_name not in subject_name:
            logger.error("In check_subject_match: osversion {} not in subject {}".format(osversion_name, subject_name))

        return

    def find_similar_summaries_and_count(self, dataframe_data):
        unique_summaries = {}
        summaries_to_indices = {}  # Map summaries to their indices

        for index, row in dataframe_data.iterrows():
            summary = row["failure_summary"]
            branch = row["branch"]
            subject = row["subject"]

            if branch not in unique_summaries:
                unique_summaries[branch] = {}
                summaries_to_indices[branch] = {}

            if summary == '':
                unique_summaries[branch][index] = summary
                summaries_to_indices[branch].setdefault(summary, []).append(index)
                continue
            if summary in configuration["summary_white_list"]:
                unique_summaries[branch][index] = summary
                summaries_to_indices[branch].setdefault(summary, []).append(index)
                continue
            if not unique_summaries[branch]:
                unique_summaries[branch][index] = summary
                summaries_to_indices[branch][summary] = [index]
                continue

            # Replace the fuzzywuzzy process.extractOne call with RapidFuzz equivalent
            result = process.extractOne(
                summary, unique_summaries[branch].values(), scorer=fuzz.WRatio
            )
            if result:
                matched_summary, highest_score, _ = (
                    result  # Ignoring the index if not needed
                )
            else:
                # Handle the case where there's no match
                matched_summary, highest_score = None, None
            # matched_summary, highest_score = process.extractOne(summary, unique_summaries.values())

            logger.debug(
                "{}:{}===matched_summary={}, summary={}, hightest_score={}".format(
                    index, subject, matched_summary[:80], summary[:80], highest_score
                )
            )
            if highest_score < int(configuration["threshold"]["fuzzy_rate"]):
                unique_summaries[branch][index] = summary
                summaries_to_indices[branch][summary] = [index]
            else:
                # Find the original summary corresponding to the matched summary for mapping
                for orig_summary, indices in summaries_to_indices[branch].items():
                    if matched_summary in orig_summary:
                        summaries_to_indices[branch][orig_summary].append(index)
                        break

        # Count the occurrences of each summary for each branch
        summary_counts = {}
        for branch, indices in summaries_to_indices.items():
            summary_counts[branch] = {
                summary: len(indices) for summary, indices in indices.items()
            }

        # Create a new DataFrame from the filtered summaries
        new_df = pd.DataFrame()
        for branch, summaries in unique_summaries.items():
            branch_df = dataframe_data[dataframe_data["branch"] == branch]
            new_df = pd.concat([new_df, branch_df.loc[summaries.keys()]])

        # Add the 'count' column to the new DataFrame
        new_df["count"] = new_df.apply(lambda row: summary_counts[row["branch"]][row["failure_summary"]], axis=1)

        # Select the desired columns
        new_df = new_df[["subject", "branch", "failure_summary", "count"]]

        return new_df

    def is_matched_active_icm(self, target_summary, active_icm_df):
        """
        Calculate the similarity between target_summary and all summaries in active_icm_df
        Save the similarity into a new column in active_icm_df
        after all, compare the similarity with the threshold, if it is
        higher than the threshold, return True and highest matched row in active_icm_df
        """

        active_icm_df['SourceCreateDate'] = pd.to_datetime(active_icm_df['SourceCreateDate'])
        valid_date = self.current_time - timedelta(days=configuration["threshold"]["summary_expiration_days"])

        # valid_active_icm_df.loc[:, 'Similarity'] = valid_active_icm_df['FailureSummary'].apply(lambda x: fuzz.ratio(target_summary, x))

        valid_active_icm_df = active_icm_df[active_icm_df['SourceCreateDate'] >= valid_date]
        valid_active_icm_df_copy = valid_active_icm_df.copy()
        # valid_active_icm_df['Similarity'] = valid_active_icm_df['FailureSummary'].apply(lambda x: fuzz.ratio(target_summary, x))
        valid_active_icm_df_copy.loc[:, 'Similarity'] = valid_active_icm_df_copy['FailureSummary'].apply(lambda x: fuzz.ratio(target_summary, x))

        highest_similarity = valid_active_icm_df_copy['Similarity'].max()
        if highest_similarity >= int(configuration["threshold"]["fuzzy_rate"]):
            highest_matched_rows = valid_active_icm_df_copy.loc[valid_active_icm_df_copy['Similarity'] == highest_similarity]
            for index, row in highest_matched_rows.iterrows():
                logger.debug("Matched Row: CreatedDate={}, Title={}, Summary={}".format(row['SourceCreateDate'], row['Title'], row['FailureSummary']))
            logger.debug("highest_similarity={}".format(highest_similarity))
            return True, highest_matched_rows.iloc[0]
        else:
            return False, None

    def is_same_with_active_icm_by_gpt(self, target_summary, active_icm_df):
        """
        Check if the target_summaryis is same with any of summary in active_icm_df by Chatgpt
        """
        # TODO:
        pass

    def set_failure_summary(self, kusto_data_list, week_failed_testcases_df):
        if week_failed_testcases_df is None:
            logger.info("week_failed_testcases_df is None")
            return kusto_data_list

        week_failed_testcases_df_copy = week_failed_testcases_df.copy()  # Create a copy of the DataFrame

        for kusto_data in kusto_data_list:
            case_branch = kusto_data['module_path'] + '.' + kusto_data['testcase'] + "#" + kusto_data['branch']
            # Add conditional filters if they exist
            asic = kusto_data['failure_level_info'].get('asic')
            hwsku = kusto_data['failure_level_info'].get('hwsku')
            osversion = kusto_data['failure_level_info'].get('osversion')
            logger.info("{}: asic={}, hwsku={}, osversion={}".format(case_branch, asic, hwsku, osversion))

            query_conditions = [
                f"ModulePath == '{kusto_data['module_path']}'",
                f"opTestCase == '{kusto_data['testcase']}'",
                f"BranchName == '{kusto_data['branch']}'"
            ]
            if asic:
                query_conditions.append(f"AsicType.str.lower() == '{asic.lower()}'")
            if hwsku:
                query_conditions.append(f"HardwareSku.str.lower() == '{hwsku.lower()}'")
            if osversion:
                query_conditions.append(f"OSVersion.str.lower() == '{osversion.lower()}'")

            query_string = " & ".join(query_conditions)
            # Apply the combined filters to get the filtered DataFrame
            failed_results_df = week_failed_testcases_df_copy.query(query_string)

            logger.debug("{} failed_results_df=\n{}".format(case_branch, failed_results_df[['TestCase', 'Summary']]))
            if len(failed_results_df) > 0:
                if all(failed_results_df['Summary'].apply(lambda x: fuzz.ratio(x, failed_results_df['Summary'].iloc[0])) >=
                       int(configuration['threshold']['fuzzy_rate'])):
                    kusto_data['failure_summary'] = failed_results_df['Summary'].iloc[0]
                    logger.info("{}:{} {} {} Share similar summary and it can be aggregated: {}".format(case_branch,asic, hwsku, osversion, kusto_data['failure_summary']))
                else:
                    kusto_data['failure_summary'] = ''
                    logger.info("{}:{} {} {} Don't share similar summary but it can't be aggregated".format(case_branch, asic, hwsku, osversion))
            else:
                kusto_data['failure_summary'] = ''
                logger.info("{}: No failed results found".format(case_branch))
        no_summary_count = sum(1 for icm in kusto_data_list if 'failure_summary' not in icm)
        has_summary_count = sum(1 for icm in kusto_data_list if 'failure_summary' in icm)
        logger.info("{}:{} {} {} Number of cases without failure_summary:{}".format(case_branch, asic, hwsku, osversion, no_summary_count))
        logger.info("{}:{} {} {} Number of cases with failure_summary:{}".format(case_branch, asic, hwsku, osversion, has_summary_count))
        return kusto_data_list

    def deduplicate_limit_with_active_icm(self, kusto_data_list, icm_count_dict, active_icm_df):
        new_icm_list = []
        duplicated_icm_list = []
        new_icm_count = 0
        active_icm_list = active_icm_df['Title'].tolist()
        for idx, icm in enumerate(kusto_data_list):
            module_path = icm["module_path"]
            testcase = icm["testcase"]
            branch = icm["branch"]
            case_branch = module_path + '.' + testcase + "#" + branch
            logger.info("Check if there is existing active IcM for {}"
                        .format(icm['subject']))
            duplicated_flag = False

            # For loop every active IcM title, avoid generating smaller level IcM for same failure
            for icm_title in active_icm_list:
                # For platform_test, we aggregate branches, don't trigger same IcM for different branches
                # if 'platform_tests' in icm['module_path']:
                #     icm_branch = icm['branch']
                #     for branch_name in configuration["branch"]["included_branch"]:
                #         replaced_title = icm['subject'].replace(
                #             icm_branch, branch_name)
                #         if icm_title in ICM_PREFIX + replaced_title:
                #             logger.info("{}: For platform_tests, found same case for branch {}, not trigger IcM:\n\t active IcM {}\t duplicated one {}".format(
                #                 case_branch, icm_branch, icm_title, icm['subject']))
                #             icm['trigger_icm'] = False
                #             duplicated_icm_list.append(icm)
                #             duplicated_flag = True
                #             break
                #     if duplicated_flag:
                #         break
                if icm_title in ICM_PREFIX + icm['subject']:
                    # Don't trigger IcM for duplicated cases, avoid IcM throttling
                    logger.info("{}: Found same title or higher title item in active IcM list, not trigger IcM:\n active IcM {}\t duplicated one {}".format(
                        case_branch, icm['subject'], icm['subject']))
                    icm['trigger_icm'] = False
                    duplicated_icm_list.append(icm)
                    duplicated_flag = True
                    break
            if icm['failure_summary']:
                logger.info("{} has failure_summary:{}".format(case_branch, icm['failure_summary']))
                is_matched, matched_row = self.is_matched_active_icm(icm['failure_summary'], active_icm_df)
                if is_matched:
                    logger.info("{}: Found summary matched item in active IcM list, not trigger IcM:\n\t \
                                active IcM {}\n summary:{}\n duplicated one {}\n summary:{}".format(
                        case_branch, matched_row['Title'], matched_row['FailureSummary'], icm['subject'], icm['failure_summary']))

                    icm['trigger_icm'] = False
                    duplicated_icm_list.append(icm)
                    duplicated_flag = True
                    continue
            if not duplicated_flag:
                module_path = icm['module_path']
                items = module_path.split('.')
                if 'everflow' in items[0]:
                    if icm_count_dict['everflow_count'] >= configuration['icm_limitation']['max_icm_count_per_module']:
                        logger.info(
                            "There are already 10 IcMs for everflow, inhibit this one avoid generating so many similar cases.")
                        kusto_data = kusto_data_list[:idx]
                        logger.info("kusto_data={}".format(kusto_data))
                        break
                    else:
                        icm_count_dict['everflow_count'] += 1
                if len(items) > 1 and 'test_qos_sai' in items[1]:
                    if icm_count_dict['qos_sai_count'] >= configuration['icm_limitation']['max_icm_count_per_module']:
                        logger.info(
                            "There are already 10 IcMs for qos_sai, inhibit this one avoid generating so many similar cases.")
                        kusto_data = kusto_data_list[:idx]
                        logger.info("kusto_data={}".format(kusto_data))
                        break
                    else:
                        icm_count_dict['qos_sai_count'] += 1
                if 'acl' in items[0]:
                    if icm_count_dict['acl_count'] >= configuration['icm_limitation']['max_icm_count_per_module']:
                        logger.info(
                            "There are already 10 IcMs for acl, inhibit this one avoid generating so many similar cases.")
                        kusto_data = kusto_data_list[:idx]
                        break
                    else:
                        icm_count_dict['acl_count'] += 1
                logger.info("Got new IcM for this run: {} idx = {}".format(
                    icm['subject'], idx))
                new_icm_list.append(icm)
                new_icm_count += 1
        updated_icm_count_dict = copy.deepcopy(icm_count_dict)
        logger.info("{}: There are {} new IcMs for this run".format(case_branch, new_icm_count))
        return new_icm_list, duplicated_icm_list, updated_icm_count_dict