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

class DataDeduplicator:
    def __init__(self):
        current_time = datetime.now(tz=pytz.UTC)
        self.current_time = current_time

        self.new_icm_number_limit = configuration['icm_limitation']['new_icm_number_limit']
        self.setup_error_limit = configuration['icm_limitation']['setup_error_limit']
        self.failure_limit = configuration['icm_limitation']['failure_limit']
        self.platform_limit = configuration['icm_limitation']['platform_limit']

        # For each branch, set a limit for created IcMs
        default_icm_limit = configuration['icm_limitation']['default_branch_limit']
        for branch in configuration['branch']['included_branch']:
            icm_branch_limit_key = f"icm_{branch}_limit"
            # If there is a configured limit, that should take precedence to allow for overriding default
            icm_branch_limit = configuration['icm_limitation'].get(icm_branch_limit_key, default_icm_limit)
            setattr(self, icm_branch_limit_key, icm_branch_limit)

        self.max_icm_count_per_module = configuration['icm_limitation']['max_icm_count_per_module']

    def deduplication(self, setup_error_new_icm_table, common_summary_new_icm_table, original_failure_dict, branches):
        """
        Deduplicate the IcM list, remove the duplicated IcM.
        """
        duplicated_icm_list = []
        unique_title = set()
        final_icm_list = []
        error_final_icm_list = []
        count_platform_test = 0
        branch_counts = {branch: 0 for branch in branches}  # Initialize counts for each branch

        logger.info("limit the number of setup error cases to {}".format(self.setup_error_limit))
        logger.info("limit the number of general failure cases to {}".format(self.failure_limit))
        logger.info("limit the number of platform_tests cases to {}".format(self.platform_limit))

        # Logging limits for each branch
        for branch in branches:
            limit_name = f"icm_{branch}_limit"
            limit = getattr(self, limit_name, None)
            if limit is not None:
                logger.info(f"limit the number of {branch} cases to {limit}")

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
                    logger.info(f"Found duplicated item in appending IcM list, not trigger IcM for: {candidator['subject']}")
                    continue

                unique_title.add(candidator['subject'])
                duplicated_flag = False

                for uploading_new_icm in final_icm_list:
                    # TODO
                    # if 'platform_tests' in candidator['module_path']:
                    #     icm_branch = candidator['branch']
                    #     for branch_name in branches:
                    #         replaced_title = candidator['subject'].replace(icm_branch, branch_name)
                    #         if uploading_new_icm['subject'] in replaced_title:
                    #             logger.info(f"For platform_tests, found lower case for branch {icm_branch}, not trigger IcM: \
                    #                         the IcM in final_icm_list {uploading_new_icm['subject']}, duplicated one {candidator['subject']}")
                    #             candidator['trigger_icm'] = False
                    #             duplicated_icm_list.append(candidator)
                    #             duplicated_flag = True
                    #             break
                    #         elif replaced_title in uploading_new_icm['subject']:
                    #             logger.info(f"For platform_tests, found lower case for branch {icm_branch}, replace {uploading_new_icm['subject']} \
                    #                         in final_icm_list with {candidator['subject']}")
                    #             final_icm_list.remove(uploading_new_icm)
                    #             final_icm_list.append(candidator)
                    #             duplicated_flag = True
                    #             break
                    #     if duplicated_flag:
                    #         break
                    duplicated_flag = self.check_duplicates(uploading_new_icm['subject'], candidator)
                    if duplicated_flag:
                        duplicated_icm_list.append(candidator)
                        logger.info(f"Found lower case, not trigger IcM: the IcM in final_icm_list {uploading_new_icm['subject']}, duplicated one {candidator['subject']}")
                        break
                    duplicated_flag = self.check_duplicates(candidator['subject'], uploading_new_icm)
                    if duplicated_flag:
                        logger.info(f"Found lower case, replace {uploading_new_icm['subject']} in final_icm_list with {candidator['subject']}")
                        final_icm_list.remove(uploading_new_icm)
                        duplicated_icm_list.append(uploading_new_icm)
                        final_icm_list.append(candidator)
                        duplicated_flag = True
                        break

                if not duplicated_flag:
                    candidator_branch = candidator['branch']
                    if 'platform_tests' in candidator['module_path']:
                        count_platform_test += 1
                        if count_platform_test > self.platform_limit:
                            logger.info(f"Reach the limit of platform_test case, ignore this IcM {candidator['subject']}")
                            candidator['trigger_icm'] = False
                            continue

                    # Check that this branch is part of a release we care about (i.e. 20231105, if we have specified 202311 in config)
                    candidator_branch_prefix_list = [branch for branch in branch_counts.keys() if candidator_branch.startswith(branch)]

                    if len(candidator_branch_prefix_list) > 0:
                        candidator_branch_prefix = candidator_branch_prefix_list[0]
                        branch_limit_attr = f"icm_{candidator_branch_prefix}_limit"
                        branch_limit = getattr(self, branch_limit_attr)
                        if branch_counts[candidator_branch_prefix] >= branch_limit:
                            logger.info(f"Reach the limit of {candidator_branch_prefix} case: {branch_limit}, ignore this IcM {candidator['subject']}")
                            candidator['trigger_icm'] = False
                            continue
                        branch_counts[candidator_branch_prefix] += 1

                    logger.info(f"Add branch {candidator_branch} type {failure_type} : {candidator['subject']} to final_icm_list")
                    final_icm_list.append(candidator)

        logger.info("Count summary: platform_test {}, ".format(count_platform_test) +
                    ", ".join(f"{branch} {count}" for branch, count in branch_counts.items()))
        for kusto_row_item in error_final_icm_list:
            self.check_subject_match(kusto_row_item)
        for kusto_row_item in final_icm_list:
            self.check_subject_match(kusto_row_item)
        for kusto_row_item in duplicated_icm_list:
            self.check_subject_match(kusto_row_item)
        logger.debug(f"final_icm_list={json.dumps(final_icm_list, indent=4)}")

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
        for topology_config in configuration["icm_decision_config"]["topology"]["types"]:
            week_failed_testcases_df_copy['Topology'] = week_failed_testcases_df_copy['Topology'].replace(
                topology_config["testbed_topology"], topology_config["id"])

        for kusto_data in kusto_data_list:
            case_branch = kusto_data['module_path'] + '.' + kusto_data['testcase'] + "#" + kusto_data['branch']
            # Add conditional filters if they exist
            asic = kusto_data['failure_level_info'].get('asic')
            topology = kusto_data['failure_level_info'].get('topology')
            hwsku = kusto_data['failure_level_info'].get('hwsku')
            osversion = kusto_data['failure_level_info'].get('osversion')
            logger.info("{}: asic={}, topology={}, hwsku={}, osversion={}".format(case_branch, asic, topology, hwsku, osversion))

            query_conditions = [
                f"ModulePath == '{kusto_data['module_path']}'",
                f"opTestCase == '{kusto_data['testcase']}'",
                f"BranchName == '{kusto_data['branch']}'"
            ]
            if asic:
                query_conditions.append(f"AsicType.str.lower() == '{asic.lower()}'")
            if topology:
                query_conditions.append(f"Topology.str.lower() == '{topology.lower()}'")
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
                    logger.info("{}:{} {} {} {} Share similar summary and it can be aggregated: {}".format(case_branch,asic, topology, hwsku, osversion, kusto_data['failure_summary']))
                else:
                    kusto_data['failure_summary'] = ''
                    logger.info("{}:{} {} {} {} Don't share similar summary but it can't be aggregated".format(case_branch, asic, topology, hwsku, osversion))
            else:
                kusto_data['failure_summary'] = ''
                logger.info("{}: No failed results found".format(case_branch))
        no_summary_count = sum(1 for icm in kusto_data_list if 'failure_summary' not in icm)
        has_summary_count = sum(1 for icm in kusto_data_list if 'failure_summary' in icm)
        logger.info("{}:{} {} {} {} Number of cases without failure_summary:{}".format(case_branch, asic, topology, hwsku, osversion, no_summary_count))
        logger.info("{}:{} {} {} {} Number of cases with failure_summary:{}".format(case_branch, asic, topology, hwsku, osversion, has_summary_count))
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
                duplicated_flag = self.check_duplicates(icm_title, icm)
                if duplicated_flag:
                    duplicated_icm_list.append(icm)
                    logger.info("{}: Found same title or higher title item in active IcM list, not trigger IcM:\n active IcM {}\t duplicated one {}".format(
                        case_branch, icm_title, icm['subject']))
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

    def combined_level_split(self, title):
        """
            Split the title for combined level
            e.g. split [case_a][branch_b][hwskuA_20240510.16] into [case_a][branch_b][hwskuA] and [case_a][branch_b][20240510.16]
        """
        last_bracket_start = title.rindex('[')
        last_bracket_end = title.rindex(']')
        combined_level = title[last_bracket_start+1:last_bracket_end]

        prefix = title[:last_bracket_start]

        last_underscore = combined_level.rindex('_')
        level1 = combined_level[:last_underscore]
        level2 = combined_level[last_underscore+1:]
        component = []
        if level2.find('.') == -1:
            component.append(level2)
            level2 = None
            title2 = prefix
        else:
            level2 = level2[:level2.index('.')]
            title2 = "{}[{}]".format(prefix, level2)
            component.append(level2)

        title1 = "{}[{}]".format(prefix, level1)
        component.append(level1)
        return {
            'components': component,
            'titles': [title1, title2]
        }

    def check_duplicates(self, active_icm_title, icm):
        duplicated_flag = False
        if active_icm_title in ICM_PREFIX + icm['subject']:
            icm['trigger_icm'] = False
            duplicated_flag = True
            return duplicated_flag
        if icm['failure_level_info'].get('is_combined', False):
            combined_split = self.combined_level_split(icm['subject'])
            for subject in combined_split['titles']:
                if active_icm_title in ICM_PREFIX + subject:
                    icm['trigger_icm'] = False
                    duplicated_flag = True
                    return duplicated_flag
            components = combined_split['components']
            if all(component in active_icm_title for component in components):    #[case_a][20240510][topologyA_hwskuC] is duplicated with [case_a][20240510][topologyA][asicB][hwskuC]
                icm['trigger_icm'] = False
                duplicated_flag = True
        return duplicated_flag
