from data_deduplicator import DataDeduplicator
from kusto_connector import KustoConnector
import traceback
import requests
import uuid
from datetime import timedelta, datetime, timezone
from azure.kusto.data.helpers import dataframe_from_result_table
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import prettytable
import pytz
import math
import copy
import json
import pandas as pd
from config import configuration, logger, AUTH, ICM_PREFIX, \
        BRANCH_PREFIX_LEN, LEGACY_CSV, ALL_RESUTLS_CSV, \
        FLAKY_CSV, CONSISTENT_CSV, NEW_ICM_CSV, \
        DUPLICATE_CASES_CSV, ACTIVE_ICM_CSV


class BasicAnalyzer(object):
    def __init__(self, kusto_connector: KustoConnector, deduper: DataDeduplicator, current_time) -> None:
        self.kusto_connector = kusto_connector
        self.deduper = deduper

        self.search_start_time = current_time - \
            timedelta(days=int(configuration['threshold']['duration_days']))

        self.child_standby_list = []

        logger.info("worker number: {}".format(
            configuration['worker_number']))
        logger.info(
            "====== initiate target parent relationships into memory list ======")
        # self.init_parent_relations2list([PARENT_ID1, PARENT_ID2])
        # self.collect_sonic_nightly_ado()
        logger.info(
            "Found {} work items for sonic-nightly.".format(len(self.child_standby_list)))

    def collect_sonic_nightly_ado(self):
        ado_response = self.kusto_connector.query_ado()
        active_icm_df = dataframe_from_result_table(
            ado_response.primary_results[0])
        self.child_standby_list = active_icm_df.to_dict(orient='records')
        logger.info("Existing ADO number: {}\n All ADO list={}".format(
            len(self.child_standby_list), self.child_standby_list))

    def init_parent_relations2list(self, parent_id_list):
        """
        Request url of given parent_id to get its relations including parent, child, relative
        Get child fields by above children url, then store one standby list for next function search_ADO
        """
        for parent_id in parent_id_list:
            workitem_parent_url = "https://dev.azure.com/msazure/One/_apis/wit/workitems?id=" + \
                str(parent_id) + "&$expand=all"
            logger.info("parent workitem url:{}".format(workitem_parent_url))
            try:
                parent_relations = requests.get(
                    workitem_parent_url, auth=AUTH).json()["relations"]
                if not parent_relations:
                    logger.error(
                        "Failed to get work items from parent_id {}".format(parent_id))
                    return

                child_url_set = set()
                for relation in parent_relations:
                    if relation and relation["attributes"]["name"] == "Child":
                        child_url_set.add(relation["url"])
                child_url_list = list(child_url_set)
            except Exception as e:
                logger.error(
                    "Get parent work item but throw an exception: {}".format((repr(e))))
                logger.error(traceback.format_exc())
                return

            with ThreadPoolExecutor() as executor:
                futures = [executor.submit(
                    self.child_url_extract_fields, url) for url in child_url_list]
                for future in as_completed(futures):
                    self.child_standby_list.append(future.result())

    def child_url_extract_fields(self, child_url):
        if not child_url:
            logger.eror("child url is null")
            return
        try:
            child_dict = requests.get(child_url, auth=AUTH).json()
            child_fields_dict = child_dict["fields"]
            if not child_fields_dict:
                logger.eror(
                    "Failed to get fields of work items from child_id {}".format(child_dict["id"]))
                return
        except Exception as e:
            logger.error(
                "Get child work items but throw an exception: {}".format((repr(e))))
            logger.error(traceback.format_exc())
            return
        child_core_attribute = {
            "ID": child_dict["id"],
            "title": child_fields_dict.get("System.Title", "No title"),
            "URL": child_dict["url"],
            "status": child_fields_dict.get("System.State", "No status"),
            "owner": child_fields_dict["System.CreatedBy"].get("displayName", "No owner"),
            "tags": child_fields_dict.get("System.Tags", "No tag"),
            "createdDate": child_fields_dict.get("System.CreatedDate", "No CreatedDate"),
            "changedDate": child_fields_dict.get("System.ChangedDate", "No ChangedDate")
        }
        return child_core_attribute


class DataAnalyzer(BasicAnalyzer):
    """analyze failed test cases"""

    def __init__(self, kusto_connector, deduper, current_time) -> None:
        super().__init__(kusto_connector, deduper, current_time)
        self.common_trigger = False
        self.legacy_trigger = False
        self.consistent_trigger = False
        self.flaky_trigger = False

        self.icm_count_dict, self.active_icm_df = self.analyze_active_icm()

    def run_flaky_failure(self):
        logger.info(
            "========== Start searching flaky failure case ==============")

        waiting_list = []
        flaky_df = self.collect_flaky_failure()
        flaky_failed_testcases = {}
        for index, row in flaky_df.iterrows():
            module_path = row['ModulePath']
            testcase = row['opTestCase']
            branch = row['BranchName']
            key = module_path + '.' + testcase + "#" + branch
            if key not in flaky_failed_testcases:
                flaky_failed_testcases[key] = {}
                flaky_failed_testcases[key]['OSVersion'] = row['OSVersion']
                flaky_failed_testcases[key]['BranchName'] = row['BranchName']
                flaky_failed_testcases[key]['FullCaseName'] = row['FullCaseName']
                flaky_failed_testcases[key]['FailedType'] = row['FailedType']
                flaky_failed_testcases[key]['Summary'] = row['Summary']

        logger.info("Found {} kinds of flaky failed test cases.".format(
            len(flaky_failed_testcases)))
        flaky_failed_testcases_list = list(flaky_failed_testcases.keys())
        logger.info("Total flaky failure cases cross branches in waiting: {}".format(
            len(flaky_failed_testcases_list)))
        for index, item in enumerate(flaky_failed_testcases_list):
            item_dict = {
                "index": index + 1,
                "case_branch": item,
                "is_module_path": False,
                "is_common_summary": False,
                "summary": flaky_failed_testcases[item]['Summary'],
                "failed_type": flaky_failed_testcases[item]['FailedType']
            }
            waiting_list.append(item_dict)
        self.common_trigger = False
        self.legacy_trigger = False
        self.flaky_trigger = True
        self.consistent_trigger = False
        flaky_new_icm_table, flaky_duplicated_icm_table = self.multiple_process(
            waiting_list, flaky_df)
        return flaky_new_icm_table, flaky_duplicated_icm_table

    def run_consistent_failure(self):
        logger.info(
            "========== Start searching consistent failure case ==============")

        waiting_list = []
        consistent_df = self.collect_consistent_failure()
        consistent_failed_testcases = {}
        for index, row in consistent_df.iterrows():
            module_path = row['ModulePath']
            testcase = row['opTestCase']
            branch = row['BranchName']
            key = module_path + '.' + testcase + "#" + branch
            if key not in consistent_failed_testcases:
                consistent_failed_testcases[key] = {}
                consistent_failed_testcases[key]['OSVersion'] = row['OSVersion']
                consistent_failed_testcases[key]['BranchName'] = row['BranchName']
                consistent_failed_testcases[key]['FullCaseName'] = row['FullCaseName']

        logger.info("Found {} kinds of consistent failed test cases.".format(
            len(consistent_failed_testcases)))
        consistent_failed_testcases_list = list(consistent_failed_testcases.keys())
        logger.info("Total consistent failure cases cross branches in waiting: {}".format(
            len(consistent_failed_testcases_list)))
        logger.debug("consistent_failed_testcases_list: {}".format(consistent_failed_testcases_list))
        for index, item in enumerate(consistent_failed_testcases_list):
            item_dict = {
                "index": index + 1,
                "case_branch": item,
                "is_module_path": False,
                "is_common_summary": False,
                "failed_type": "consistent"
            }
            waiting_list.append(item_dict)
        self.common_trigger = False
        self.legacy_trigger = False
        self.flaky_trigger = False
        self.consistent_trigger = True
        consistent_new_icm_table, consistent_duplicated_icm_table = self.multiple_process(
            waiting_list, consistent_df)
        return consistent_new_icm_table, consistent_duplicated_icm_table

    def run_common_summary_failure(self):
        logger.info(
            "========== Start searching common summary failure cases ==============")
        waiting_list = []
        summary_failures_df = self.collect_common_summary_failure()
        summary_cases = {}
        for idx, row in summary_failures_df.iterrows():
            module_path = row['ModulePath']
            if module_path is None or module_path == "":
                continue
            branch = row['BranchName']
            key = module_path + "#" + branch
            if key not in summary_cases:
                summary_cases[key] = {}
                summary_cases[key]['Summary'] = row['Summary']
                summary_cases[key]['BranchName'] = row['BranchName']
                summary_cases[key]['ModulePath'] = row['ModulePath']

        logger.info("Found {} failures with common summary in total.".format(
            len(summary_failures_df)))
        logger.info("Found {} kinds of common summary failures.".format(
            len(summary_cases)))

        summary_failures_list = list(summary_cases.keys())
        logger.info("Total common summary failure cases in waiting: {}".format(
            len(summary_failures_list)))
        for index, item in enumerate(summary_failures_list):
            item_dict = {
                "index": index + 1,
                "case_branch": item,
                "is_module_path": True,
                "is_common_summary": True,
                "summary": summary_cases[item]['Summary']
            }
            waiting_list.append(item_dict)
            logger.info("{}: {} : {}".format(index + 1, item, summary_cases[item]['Summary'][:80]))
        self.common_trigger = True
        self.legacy_trigger = False
        self.flaky_trigger = False
        self.consistent_trigger = False
        common_summary_new_icm_table, common_summary_duplicated_icm_table = self.multiple_process(
            waiting_list)
        logger.debug("New common summary Icms\n{}".format(common_summary_new_icm_table))
        for row in common_summary_duplicated_icm_table:
            logger.debug("Common summary Icms dulicated Subject: {}".format(row['subject']))
        return common_summary_new_icm_table, common_summary_duplicated_icm_table

    def run_legacy_failure(self):
        waiting_list = []
        failed_testcases_df = self.collect_legacy_failure()
        failed_testcases = {}
        for index, row in failed_testcases_df.iterrows():
            module_path = row['ModulePath']
            testcase = row['opTestCase']
            branch = row['BranchName']
            key = module_path + '.' + testcase + "#" + branch
            if key not in failed_testcases:
                failed_testcases[key] = {}
                failed_testcases[key]['OSVersion'] = row['OSVersion']
                failed_testcases[key]['BranchName'] = row['BranchName']
                failed_testcases[key]['FullCaseName'] = row['FullCaseName']

        logger.info("Found {} kinds of failed test cases.".format(
            len(failed_testcases)))
        failed_testcases_list = list(failed_testcases.keys())
        logger.info("Total legacy failure cases in waiting: {}".format(
            len(failed_testcases_list)))
        logger.debug("failed_testcases_list: {}".format(failed_testcases_list))
        for index, failed_testcase in enumerate(failed_testcases_list):
            item_dict = {
                "index": index + 1,
                "case_branch": failed_testcase,
                "is_module_path": False,
                "is_common_summary": False
            }
            waiting_list.append(item_dict)
        self.common_trigger = False
        self.legacy_trigger = True
        self.flaky_trigger = False
        self.consistent_trigger = False
        failure_new_icm_table, failure_duplicated_icm_table = self.multiple_process(
            waiting_list, failed_testcases_df)
        return failure_new_icm_table, failure_duplicated_icm_table

    def multiple_process(self, waiting_list, week_failed_testcases_df=None):
        """Multiple process to analyze test cases"""

        # break_flag = False
        new_icm_table = []
        duplicated_icm_table = []
        logger.info(
            "============== Start searching history result ================")
        # We can use a with statement to ensure threads are cleaned up promptly
        with concurrent.futures.ThreadPoolExecutor(max_workers=configuration['worker_number']) as executor:
            tasks = []
            for item_dict in waiting_list:
                # Start the load operations and mark each future with test case name
                logger.info("[{}] Start analysising test_case_branch={}, is_module_path={}".format(
                    item_dict["index"], item_dict["case_branch"], item_dict["is_module_path"]))
                tasks.append(executor.submit(
                    self.analysis_process, item_dict))
            for task in concurrent.futures.as_completed(tasks):
                kusto_data = []
                new_icm_list = []
                duplicated_icm_list = []
                try:
                    kusto_data = task.result()
                except Exception as exc:
                    logger.error("Task {} generated an exception: {}".format(
                        task, exc))
                    logger.error(traceback.format_exc())

                if len(kusto_data) != 0:
                    logger.debug(
                        "After analysis_process, task {} completed, check duplication for {} kusto_data".format(
                            task, len(kusto_data)))
                    kusto_data = self.deduper.set_failure_summary(kusto_data, week_failed_testcases_df)
                    new_icm_list, duplicated_icm_list, self.icm_count_dict = (
                        self.deduper.deduplicate_limit_with_active_icm(
                            kusto_data, self.icm_count_dict, self.active_icm_df))
                if len(new_icm_list) != 0:
                    new_icm_table.extend(new_icm_list)
                if len(duplicated_icm_list) != 0:
                    duplicated_icm_table.extend(duplicated_icm_list)
        return new_icm_table, duplicated_icm_table

    def rearrange_icm_list(self, icm_list, branches):
        """
        Rearrange the icm list based on branch and shorten the upload time.
        Parameters:
            icm_list: List of ICMs.
            branches: List of branch names to categorize the ICMs.
        Return: rearranged_icm_list[][]
        """
        # Initialize branch dictionary with empty lists for each branch
        branch_dict = {branch: [] for branch in branches}

        # Split the icm list into branch-specific lists
        for icm in icm_list:
            branch = icm['branch']
            matched = False
            for key in branch_dict.keys():
                if key in branch:
                    branch_dict[key].append(icm)
                    matched = True
                    break
            if not matched:
                branch_dict.setdefault('internal', []).append(icm)  # Default to 'internal' if branch doesn't match

        # Log branch counts
        for branch, icms in branch_dict.items():
            logger.info(f"There are {len(icms)} IcMs in {branch} branch")

        # Calculate the number of upload batches required
        max_branch_length = max(len(icms) for icms in branch_dict.values())
        upload_times = math.ceil(max_branch_length / configuration['threshold']['icm_number_threshold'])

        # Create the rearranged_icm_list with a looping mechanism
        rearranged_icm_list = []
        for _ in range(upload_times):
            temp_icm_list = []
            for branch, icms in branch_dict.items():
                for _ in range(min(len(icms), configuration['threshold']['icm_number_threshold'])):
                    temp_icm_list.append(icms.pop(0))
            rearranged_icm_list.append(temp_icm_list)

        return rearranged_icm_list

    def upload_to_kusto(self, new_icm_table, duplicated_icm_table, autoblame_table):
        """
        Upload data to kusto
        """
        logger.info(
            "================= Upload duplicated IcMs to kusto =====================")
        self.print_analysis_table(duplicated_icm_table)
        logger.info(
            "================= Upload new IcMs to kusto =====================")
        self.print_analysis_table(new_icm_table)
        logger.info(
            "================= Duplicated IcMs title list =====================")
        for index, duplicated_icm in enumerate(duplicated_icm_table):
            logger.info("{} Duplicated IcM subject = {}".format(
                index + 1, duplicated_icm["subject"]))
        logger.info(
            "================= New IcMs title list =====================")
        for index, new_icm in enumerate(new_icm_table):
            logger.info("{} New IcM subject = {}".format(
                index + 1, new_icm["subject"]))
        logger.info("There are {} duplicated IcMs in total for this run.".format(
            len(duplicated_icm_table)))
        logger.info("There are {} new IcMs in total for this run.".format(
            len(new_icm_table)))
        logger.info("There are {} Autoblame commit in total.".format(
            len(autoblame_table)))
        # The actual ingested time is about 5 mins later after uploading to kusto
        # In order to make Geneva to capture incidents in time,
        # move upload_timestamp to 5 mins ago
        ingested_time = str(datetime.utcnow() - timedelta(minutes=5))
        for row in autoblame_table:
            row['upload_timestamp'] = ingested_time
        self.kusto_connector.upload_autoblame_data(autoblame_table)

        final_upload_icm_table = self.rearrange_icm_list(new_icm_table, configuration['branch']['included_branch'])

        # Flatten final_upload_icm_table for CSV saving
        flattened_final_upload_icm_table = []
        for idx, each_upload_list in enumerate(final_upload_icm_table):
            ingested_time = str(datetime.utcnow() + timedelta(minutes=7))
            for each_icm in each_upload_list:
                each_icm['upload_timestamp'] = ingested_time
                flattened_final_upload_icm_table.append(each_icm)

            logger.info("Upload {} IcMs to kusto.".format(len(each_upload_list)))
            self.kusto_connector.upload_analyzed_data(each_upload_list)
            if idx != len(final_upload_icm_table) - 1:
                logger.info(
                    "Sleep for 30 mins to cover kusto ingestion delay and avoid IcM throttling...")
                time.sleep(30 * 60)

        # Save flattened final_upload_icm_table to CSV
        if flattened_final_upload_icm_table:
            final_upload_df = pd.DataFrame(flattened_final_upload_icm_table)
            # Reorder columns according to the specified format
            final_upload_df = self._reorder_csv_columns(final_upload_df)
            final_upload_df.to_csv(NEW_ICM_CSV, index=True)
            logger.info("Saved {} new ICMs to {}".format(len(flattened_final_upload_icm_table), NEW_ICM_CSV))

        ingested_time = str(datetime.utcnow() + timedelta(minutes=7))
        for row in duplicated_icm_table:
            row['upload_timestamp'] = ingested_time

        # Save duplicated_icm_table to CSV
        if duplicated_icm_table:
            duplicated_df = pd.DataFrame(duplicated_icm_table)
            # Reorder columns according to the specified format
            duplicated_df = self._reorder_csv_columns(duplicated_df)
            duplicated_df.to_csv(DUPLICATE_CASES_CSV, index=True)
            logger.info("Saved {} duplicated ICMs to {}".format(len(duplicated_icm_table), DUPLICATE_CASES_CSV))

        logger.info("Upload {} duplicated IcMs table to kusto.".format(
            len(duplicated_icm_table)))
        self.kusto_connector.upload_analyzed_data(duplicated_icm_table)
        return

    def _reorder_csv_columns(self, df):
        """
        Reorder DataFrame columns according to the specified order.
        Expected order: upload_timestamp, module_path, testcase, branch, subject,
        trigger_icm, failure_level_info, per_testbed_info, per_asic_info,
        per_topology_info, per_hwsku_info, per_hwsku_topo_info,
        per_os_version_info, per_hwsku_osversion_info, per_topology_hwsku_info,
        autoblame_id, failure_summary
        """
        # Define the desired column order
        desired_order = [
            'upload_timestamp', 'module_path', 'testcase', 'branch', 'subject',
            'trigger_icm', 'failure_level_info', 'per_testbed_info', 'per_asic_info',
            'per_topology_info', 'per_hwsku_info', 'per_hwsku_topo_info',
            'per_os_version_info', 'per_hwsku_osversion_info', 'per_topology_hwsku_info',
            'autoblame_id', 'failure_summary'
        ]

        # Keep only columns that exist in the DataFrame and add missing ones with empty values
        missing_columns = [col for col in desired_order if col not in df.columns]

        # Find extra columns that are not in desired_order
        extra_columns = [col for col in df.columns if col not in desired_order]

        # Add missing columns with empty string values
        for col in missing_columns:
            df[col] = ''

        # Create final column order: desired_order + extra_columns
        final_order = desired_order + extra_columns

        # Reorder columns and return
        return df[final_order]

    def collect_previous_upload_record(self, title):
        """ The table header looks like this, save all of these information
        project project UploadTimestamp, ModulePath, TestCase, Branch, Subject
        """
        previous_upload_results_response = self.kusto_connector.query_previsou_upload_record(title)
        previous_upload_results_df = dataframe_from_result_table(
            previous_upload_results_response.primary_results[0])
        logger.info(previous_upload_results_df)

        return previous_upload_results_df

    def collect_active_icm(self):
        """The table header looks like this, save all of these information
        project IncidentId, Title, SourceCreateDate, ModifiedDate, Status
        """
        active_icm_response = self.kusto_connector.query_active_icm()
        active_icm_df = dataframe_from_result_table(
            active_icm_response.primary_results[0])
        return active_icm_df

    def count_icm(self, active_icm_list):
        everflow_count = 0
        qos_sai_count = 0
        acl_count = 0
        for active_icm_title in active_icm_list:
            if active_icm_title.startswith(ICM_PREFIX):
                subtitle = active_icm_title[len(ICM_PREFIX)+1:]
                index = subtitle.find(']')
                subtitle = subtitle[:index]
            items = subtitle.split('.')
            if 'everflow' in items[0]:
                everflow_count += 1
            if len(items) > 1 and 'test_qos_sai' in items[1]:
                qos_sai_count += 1
            if 'acl' in items[0]:
                acl_count += 1

        icm_count_dict = {
            'everflow_count': everflow_count,
            'qos_sai_count': qos_sai_count,
            'acl_count': acl_count
        }
        logger.info("count for active IcM:{}".format(icm_count_dict))
        return icm_count_dict

    def analyze_active_icm(self):
        """
        Collect and analyse the active IcM, print the active IcM information
        Enhanced version: Query all upload records once instead of querying for each ICM individually
        """
        logger.info(
            "=============== Analyze active IcM ================")
        active_icm_df = self.collect_active_icm()
        active_icm_list = active_icm_df['Title'].tolist()
        active_icm_df["FailureSummary"] = ""
        active_icm_df["Branch"] = ""

        # Initialize new columns for flaky analysis
        active_icm_df["is_flaky"] = False
        active_icm_df["flaky_category"] = ""
        active_icm_df["AI_flaky_category"] = ""

        # Query all upload records with TriggerIcM=true at once (more efficient)
        logger.info("Querying all upload records with TriggerIcM=true...")
        all_upload_records_response = self.kusto_connector.query_all_upload_records_with_trigger_icm()
        all_upload_records_df = dataframe_from_result_table(all_upload_records_response.primary_results[0])
        logger.info(f"Found {len(all_upload_records_df)} upload records with TriggerIcM=true")

        # Create a mapping dictionary for efficient lookup
        # Key: Subject, Value: {FailureSummary, Branch, UploadTimestamp, FailureLevelInfo} from the most recent record
        upload_records_map = {}
        for _, record in all_upload_records_df.iterrows():
            subject = record['Subject']
            upload_timestamp = record['UploadTimestamp']

            # Keep only the most recent record for each subject
            # Compare timestamps to ensure we always have the latest record
            if subject not in upload_records_map or upload_timestamp > upload_records_map[subject]['UploadTimestamp']:
                upload_records_map[subject] = {
                    'FailureSummary': record['FailureSummary'],
                    'Branch': record['Branch'],
                    'UploadTimestamp': upload_timestamp,
                    'FailureLevelInfo': record.get('FailureLevelInfo', '')
                }

        # Process each active ICM using the preloaded upload records
        for index, row in active_icm_df.iterrows():
            icm_title = row['Title']
            # Remove the prefix before searching
            if icm_title.startswith(ICM_PREFIX):
                search_title = icm_title[len(ICM_PREFIX):]
            else:
                search_title = icm_title

            # Look up in our preloaded records instead of querying each time
            if search_title in upload_records_map:
                record_data = upload_records_map[search_title]
                active_icm_df.at[index, 'FailureSummary'] = record_data['FailureSummary']
                active_icm_df.at[index, 'Branch'] = record_data['Branch']

                # Parse FailureLevelInfo JSON to extract flaky information
                failure_level_info = record_data.get('FailureLevelInfo', '')

                if failure_level_info:
                    try:
                        # Extract flaky information from FailureLevelInfo
                        is_flaky = failure_level_info.get('is_flaky', False)
                        flaky_category = failure_level_info.get('flaky_category', '')
                        AI_flaky_category = failure_level_info.get('AI_flaky_category', '')

                        # Set the values in the DataFrame
                        active_icm_df.at[index, 'is_flaky'] = is_flaky
                        active_icm_df.at[index, 'flaky_category'] = flaky_category
                        active_icm_df.at[index, 'AI_flaky_category'] = AI_flaky_category

                    except json.JSONDecodeError as e:
                        logger.warning(f"Failed to parse FailureLevelInfo JSON for ICM {search_title}: {e}")
                        logger.error(f"Full traceback:\n{traceback.format_exc()}")
                        # Keep default values (False, "", "", "")
                    except Exception as e:
                        logger.warning(f"Error processing FailureLevelInfo for ICM {search_title}: {e}")
                        # Keep default values (False, "", "", "")
            else:
                logger.debug(f"No upload record found for ICM: {search_title}")
        logger.info("Found {} active IcMs in total.".format(len(active_icm_list)))

        for index, row in active_icm_df.iterrows():
            source_create_date = row['SourceCreateDate']
            title = row['Title']
            summary = row['FailureSummary']
            logger.info("{} Created at:{} {}".format(index + 1, source_create_date, title))
            logger.info("   Summary: {}".format(summary))

        logger.info(f"Saved {len(active_icm_df)} active IcMs to {ACTIVE_ICM_CSV}")
        active_icm_df.to_csv(ACTIVE_ICM_CSV, index=True)
        icm_count_dict = self.count_icm(active_icm_list)

        return icm_count_dict, active_icm_df

    def collect_common_summary_failure(self):
        """ The table header looks like this, save all of these information
        ModulePath,BranchName, Result,Summary
        """
        summary_response = self.kusto_connector.query_common_summary_results()
        summary_failures_df = dataframe_from_result_table(summary_response.primary_results[0])
        logger.debug(
            "Found {} failed test cases for common summary.".format(len(summary_response.primary_results[0])))
        summary_failures_df_after_filter = self.filter_testcase(summary_failures_df)
        logger.debug(
            "Found {} failed test cases for common summary after filtering.".format(
                len(summary_failures_df_after_filter)))
        return summary_failures_df_after_filter

    def collect_flaky_failure(self, query_testbed=False):
        """The table header looks like this, save all of these information
        project UploadTimestamp, Feature,  ModulePath, FilePath, TestCase, opTestCase, Result, BranchName,
        OSVersion, TestbedName, Asic, TopologyType, Summary, BuildId
        """
        flaky_response = self.kusto_connector.query_flaky_failure(query_testbed)
        flaky_df = dataframe_from_result_table(flaky_response.primary_results[0])
        logger.debug("Found {} flaky failed test cases in total on all branches.".format(len(flaky_df)))
        flaky_df_after_filter = self.filter_testcase(flaky_df)
        flaky_df_after_filter.to_csv(FLAKY_CSV, index=True)
        self.week_flaky_testcases_df = flaky_df_after_filter
        logger.debug(
            "Found {} flaky failed test cases in total on all branches after filtering.".format(
                len(self.week_flaky_testcases_df)))
        return flaky_df_after_filter

    def collect_consistent_failure(self):
        """The table header looks like this, save all of these information
        project BuildId, FullCaseName, ModulePath, TestCase, BranchName, Result, Attempt, Summary,
        OSVersion, TestbedName, Pipeline, HardwareSku, Topology, minAttempt, maxAttempt
        """
        consistent_response = self.kusto_connector.query_consistent_failure()
        consistent_df = dataframe_from_result_table(consistent_response.primary_results[0])
        logger.debug(
            "Found {} consistent failed test cases in total on all branches.".format(len(consistent_df)))
        consistent_df_after_filter = self.filter_testcase(consistent_df)
        consistent_df_after_filter.to_csv(CONSISTENT_CSV, index=True)
        self.week_consistent_testcases_df = consistent_df_after_filter
        logger.debug(
            "Found {} consistent failed test cases in total on all branches after filtering.".format(
                len(self.week_consistent_testcases_df)))
        return consistent_df_after_filter

    def collect_legacy_failure(self):
        failedcases_response = self.kusto_connector.query_legacy_failure()
        failures_df = dataframe_from_result_table(failedcases_response.primary_results[0])
        logger.debug(
            "Found {} legacy failed test cases in total on all branches.".format(len(failures_df)))
        failures_df_after_filter = self.filter_testcase(failures_df)
        failures_df_after_filter.to_csv(LEGACY_CSV, index=True)
        self.week_legacy_testcases_df = failures_df_after_filter
        logger.debug(
            "Found {} legacy failed test cases in total on all branches after filtering.".format(
                len(self.week_legacy_testcases_df)))
        return failures_df_after_filter

    def filter_testcase(self, testcase_df):
        case_df_copy = copy.deepcopy(testcase_df)
        column_look_up = {
            'branch': 'BranchName',
            'os_version': 'OSVersion',
            'topology': 'Topology',
            'asic': 'AsicType',
            'hwsku': 'HardwareSku',
            'hwsku_osversion': 'HardwareSku_OSVersion',
            'topology_hwsku': 'Topology_HardwareSku'
        }

        # Initialize valid_indexes to all rows
        valid_indexes = case_df_copy.index

        # replace all the sub types with their type names
        for level in configuration['level_priority']:
            if level == 'topology':
                # replace topology with topology type, if those topologies are not in the topology type list,
                # then filter out them
                column = column_look_up[level]
                # Create a set to track all topologies that have been matched to a type
                matched_topologies = set()
                # Find all unique topology values in the dataframe
                all_topologies = set(case_df_copy[column].unique())
                # Replace topologies with their type names
                for type_config in configuration["icm_decision_config"].get(level, {}).get("types", []):
                    type_list = type_config.get('testbed_{}'.format(level), [])
                    for single_type in type_list:
                        if single_type.startswith('REG'):
                            regex_str = single_type.split('_')[1]
                            # Find matching values using regex and add to matched set
                            matches = case_df_copy[case_df_copy[column].str.contains(
                                regex_str, regex=True)][column].unique()
                            matched_topologies.update(matches)
                            # Replace the matches with the type name
                            case_df_copy.loc[:, column] = case_df_copy[column].replace(
                                regex_str, type_config["name"], regex=True)
                        else:
                            # Add the exact match to the matched set
                            if single_type in case_df_copy[column].values:
                                matched_topologies.add(single_type)
                            # Replace with the type name
                            case_df_copy.loc[:, column] = case_df_copy[column].replace(
                                single_type, type_config["name"])

                # Identify topologies that weren't matched to any type
                unmatched_topologies = all_topologies - matched_topologies

                # For tracking and debugging
                if unmatched_topologies:
                    logger.info("Filtering out unmatched topologies: {}".format(unmatched_topologies))

                # Filter out rows with unmatched topologies
                for topology in unmatched_topologies:
                    case_df_copy = case_df_copy[case_df_copy[column] != topology]
                # Keep track of the indexes that should be kept after filtering
                valid_indexes = case_df_copy.index
                continue
            elif level != 'hwsku_osversion' and level != 'topology_hwsku':
                column = column_look_up[level]
                for type_config in configuration["icm_decision_config"].get(level, {}).get("types", []):
                    type_list = type_config.get('testbed_{}'.format(level), [])
                    for single_type in type_list:
                        if single_type.startswith('REG'):
                            regex_str = single_type.split('_')[1]
                            case_df_copy.loc[:, column] = case_df_copy[column].replace(
                                regex_str, type_config["name"], regex=True)
                        else:
                            case_df_copy.loc[:, column] = case_df_copy[column].replace(single_type, type_config["name"])
        case_df_copy['HardwareSku_OSVersion'] = case_df_copy['HardwareSku'] + '_' + case_df_copy['OSVersion']
        case_df_copy['Topology_HardwareSku'] = case_df_copy['Topology'] + '_' + case_df_copy['HardwareSku']
        for level in ['hwsku_osversion', 'topology_hwsku']:
            column = column_look_up[level]
            for type_config in configuration["icm_decision_config"].get(level, {}).get("types", []):
                type_list = type_config.get('testbed_{}'.format(level), [])
                for single_type in type_list:
                    if single_type.startswith('REG'):
                        regex_str = single_type[single_type.index('_')+1:]
                        case_df_copy.loc[:, column] = case_df_copy[column].replace(
                            regex_str, type_config["name"], regex=True)
                    else:
                        case_df_copy.loc[:, column] = case_df_copy[column].replace(single_type, type_config["name"])
        # First, filter the testcase_df to only keep rows that matched a topology type
        # (use the index from case_df_copy after it was filtered for topology matches)
        if 'topology' in configuration['level_priority']:
            filtered_testcase_df = testcase_df.loc[valid_indexes]
        else:
            filtered_testcase_df = testcase_df
        # reserve original BranchName, Topology, HardwareSku, OSVersion, AsicType information
        # and add additional columns for type names
        case_df_after_filter = copy.deepcopy(filtered_testcase_df)
        case_df_after_filter['HardwareSku_OSVersion'] = case_df_copy['HardwareSku_OSVersion']
        case_df_after_filter['Topology_HardwareSku'] = case_df_copy['Topology_HardwareSku']
        case_df_after_filter['BranchNameName'] = case_df_copy['BranchName']
        case_df_after_filter['OSVersionName'] = case_df_copy['OSVersion']
        case_df_after_filter['TopologyName'] = case_df_copy['Topology']
        case_df_after_filter['AsicTypeName'] = case_df_copy['AsicType']
        case_df_after_filter['HardwareSkuName'] = case_df_copy['HardwareSku']
        # remove all the excluded types
        case_df_after_filter = case_df_after_filter[
            (~case_df_after_filter['BranchNameName'].str[:BRANCH_PREFIX_LEN].isin(
                configuration['branch_excluded_types'])) &
            (~case_df_after_filter['OSVersionName'].isin(
                configuration['os_version_excluded_types'])) &
            (~case_df_after_filter['TopologyName'].isin(
                configuration['topology_excluded_types'])) &
            (~case_df_after_filter['AsicTypeName'].isin(
                configuration['asic_excluded_types'])) &
            (~case_df_after_filter['HardwareSkuName'].isin(
                configuration['hwsku_excluded_types'])) &
            (~case_df_after_filter['HardwareSku_OSVersion'].isin(
                configuration['hwsku_osversion_excluded_types'])) &
            (~case_df_after_filter['Topology_HardwareSku'].isin(
                configuration['topology_hwsku_excluded_types']))]

        return case_df_after_filter

    def analysis_process(self, case_info_dict):
        history_testcases, history_case_df = self.search_and_parse_history_results(
            case_info_dict)
        kusto_data = self.generate_kusto_data(case_info_dict, history_testcases, history_case_df)
        logger.info("There are {} IcM for case {} is_module_path={}.".format(
            len(kusto_data), case_info_dict["case_branch"], case_info_dict["is_module_path"]))
        for item in kusto_data:
            logger.info("IcM title: {}".format(item['subject']))
        return kusto_data

    def search_and_parse_history_results(self, case_info_dict):
        """The table header looks like this, save all of these information
        project UploadTimestamp, OSVersion, BranchName, HardwareSku, TestbedName, AsicType, Platform,
        Topology, Asic, TopologyType, Feature, TestCase, opTestCase, ModulePath, FullCaseName, Result
        """
        testcase = None
        test_case_branch = case_info_dict["case_branch"]
        is_module_path = case_info_dict["is_module_path"]
        if is_module_path:
            items = test_case_branch.split("#")
            module_path = items[0]
            branch = items[1]
            response = self.kusto_connector.query_history_results(
                testcase_name=None, module_path=module_path,
                is_common=self.common_trigger,
                is_legacy=self.legacy_trigger,
                is_consistent=self.consistent_trigger,
                is_flaky=self.flaky_trigger)
        else:
            items = test_case_branch.split("#")
            testcase = items[0].split('.')[-1]
            module_path = items[0][:-len(testcase)-1]
            branch = items[1]
            response = self.kusto_connector.query_history_results(
                testcase, module_path,
                is_common=False,
                is_legacy=self.legacy_trigger,
                is_consistent=self.consistent_trigger,
                is_flaky=self.flaky_trigger)
        case_df = dataframe_from_result_table(response.primary_results[0])

        case_df_after_filter = self.filter_testcase(case_df)

        case_df_after_filter.to_csv(ALL_RESUTLS_CSV, index=True)
        case_branch_df = case_df_after_filter[case_df_after_filter['BranchName'] == branch]

        history_testcases = {}
        if case_branch_df.shape[0] == 0:  # the branch is not included
            return history_testcases, case_df_after_filter
        history_testcases[test_case_branch] = {}
        history_testcases[test_case_branch]['latest_os_version'] = case_branch_df['OSVersion'].max()

        tb_results = self.calculate_success_rate(
            case_branch_df, 'TestbedName', 'testbed')
        asic_results = self.calculate_success_rate(
            case_branch_df, 'AsicType', 'asic')
        hwsku_results = self.calculate_success_rate(
            case_branch_df, 'HardwareSku', 'hwsku')
        os_results = self.calculate_success_rate(
            case_branch_df, 'OSVersion', 'os_version')
        topology_results = self.calculate_success_rate(
            case_branch_df, 'Topology', 'topology')

        # hwsku_topo_results = self.calculate_combined_success_rate(case_branch_df, 'hwsku_topo')

        if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
            # branch_df = case_branch_df[case_branch_df['BranchName'] == branch]
            # latest_osversion = branch_df['OSVersion'].max()
            # branch_df = branch_df[branch_df['OSVersion'] == latest_osversion]
            hwsku_osversion_results = self.calculate_combined_success_rate(
                case_branch_df, 'hwsku_osversion')
            topology_hwsku_reslut = self.calculate_combined_success_rate(
                case_branch_df, 'topology_hwsku')

        # Find out the latest failure row
        options = ['error', 'failure']
        fmt = '%Y-%m-%d %H:%M:%S'
        failed_df = case_branch_df[case_branch_df['Result'].isin(options)]
        latest_failure_timestamp_ori = None
        oldest_failure_timestamp_ori = None
        latest_failure_timestamp = None
        oldest_failure_timestamp = None
        if failed_df.shape[0] != 0:
            latest_row = failed_df.iloc[0]
            tb_results["latest_failure_testbed"] = latest_row['TestbedName']
            asic_results["latest_failure_asic"] = latest_row['AsicType']
            hwsku_results["latest_failure_hwsku"] = latest_row['HardwareSku']
            # hwsku_topo_results["latest_failure_hwsku_topo"] = latest_row['HardwareSku'] + \
            # "_" + latest_row['TopologyType']
            os_results["latest_failure_os_version"] = latest_row['OSVersion']
            topology_results["latest_failure_topology"] = latest_row['Topology']
            if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
                hwsku_osversion_results["latest_failure_hwsku_osversion"] = latest_row['HardwareSku'] + \
                    "_" + latest_row['OSVersion']
                topology_hwsku_reslut["latest_failure_topology_hwsku"] = latest_row['Topology'] + \
                    "_" + latest_row["HardwareSku"]
            latest_failure_timestr = ''
            oldest_failure_timestr = ''
            try:
                latest_failure_timestamp_ori = latest_row['UploadTimestamp']
                latest_failure_timestamp = latest_failure_timestamp_ori.to_pydatetime()
                latest_failure_timestr = latest_failure_timestamp.strftime(fmt)
                # Get the oldest failure row
                oldest_row = failed_df.iloc[-1]
                oldest_failure_timestamp_ori = oldest_row['UploadTimestamp']
                oldest_failure_timestamp = oldest_failure_timestamp_ori.to_pydatetime()
                oldest_failure_timestr = oldest_failure_timestamp.strftime(fmt)
                history_testcases[test_case_branch]['latest_failure_timestamp'] = latest_failure_timestr
                history_testcases[test_case_branch]['oldest_failure_timestamp'] = oldest_failure_timestr
            except ValueError as e:
                logger.error("{} Failed to convert the timestamp to datetime: {} ".format(test_case_branch, e))
                logger.error("{} latest_failure_timestamp_ori: {} latest_failure_timestamp: {}".format(
                    test_case_branch, latest_failure_timestamp_ori, latest_failure_timestamp))
                logger.error("{} oldest_failure_timestamp_ori: {} oldest_failure_timestamp: {}".format(
                    test_case_branch, oldest_failure_timestamp_ori, oldest_failure_timestamp))

        else:
            logger.error("Attention!!! There is no failure found case for {}.".format(test_case_branch))

        total_success_num = case_branch_df[case_branch_df['Result']
                                           == 'success'].shape[0]
        total_num = case_branch_df.shape[0]
        history_testcases[test_case_branch]['total_success_rate'] = "{}%/{}/{}".format(
            round(total_success_num * 100 / total_num), total_success_num, total_num)

        # history_testcases[test_case_branch]['repro_count'] =
        # self.search_testcases[test_case_branch].get("ReproCount", 0)
        history_testcases[test_case_branch]['per_testbed_info'] = tb_results
        history_testcases[test_case_branch]['per_os_version_info'] = os_results
        history_testcases[test_case_branch]['per_asic_info'] = asic_results
        history_testcases[test_case_branch]['per_topology_info'] = topology_results
        history_testcases[test_case_branch]['per_hwsku_info'] = hwsku_results
        # history_testcases[test_case_branch]['per_hwsku_topo_info'] = hwsku_topo_results
        if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
            history_testcases[test_case_branch]['per_hwsku_osversion_info'] = hwsku_osversion_results
            history_testcases[test_case_branch]['per_topology_hwsku_info'] = topology_hwsku_reslut

        module_path = case_branch_df.iloc[0]["ModulePath"]
        feature = case_branch_df.iloc[0]["Feature"]
        full_casename = case_branch_df.iloc[0]["FullCaseName"]
        history_testcases[test_case_branch]['testcase'] = testcase if testcase else module_path
        history_testcases[test_case_branch]['module_path'] = module_path
        history_testcases[test_case_branch]['full_casename'] = full_casename
        history_testcases[test_case_branch]['feature'] = feature
        history_testcases[test_case_branch]['branch'] = branch

        # Check if recent test cases all failed, but previous ones are success.
        # Threshold is recent_failure_tolerance_day in config file, in case of flaky case
        if latest_failure_timestamp_ori:
            time_df = case_branch_df[(case_branch_df['UploadTimestamp'] > latest_failure_timestamp_ori) & (
                case_branch_df['Result'] == 'success')]
            if time_df.shape[0] == 0:
                logger.info("{} Since {}, all test cases are failed.".format(
                    test_case_branch, latest_failure_timestamp))
                current_time = datetime.now(timezone.utc)
                td = current_time - oldest_failure_timestamp
                td_hours = int(round(td.total_seconds() / 3600))
                if round(td_hours / 24) > configuration['threshold']['recent_failure_tolerance_day']:
                    logger.info("{} All recent test cases  failed for more than {} days".format(
                        test_case_branch, configuration['threshold']['recent_failure_tolerance_day']))
                    history_testcases[test_case_branch]['is_recent_failure'] = True
        logger.info(
            "{} After success rate calculation".format(test_case_branch))
        self.print_analysis_table([history_testcases[test_case_branch]])
        return history_testcases, case_df_after_filter

    def calculate_combined_success_rate(self, data_df, combine_type):
        if combine_type == "topology_hwsku":
            topology_hwsku_results = {
                'success_rate': {},
                "consistent_failure_topology_hwsku": []
            }
            success_rate_result = {}
            sorted_results_dict = []
            for index, row in data_df.iterrows():
                column_value = row['Topology_HardwareSku']
                if column_value not in success_rate_result:
                    topology_hwsku_aggr_df = data_df[(data_df['Topology_HardwareSku'] == column_value)]
                    topology_hwsku_total_num = topology_hwsku_aggr_df.shape[0]
                    topology_hwsku_success = topology_hwsku_aggr_df[topology_hwsku_aggr_df['Result'] == 'success']
                    topology_hwsku_success_num = topology_hwsku_success.shape[0]
                    topology_hwsku_pass_rate = round(
                        topology_hwsku_success_num * 100 / topology_hwsku_total_num)
                    if topology_hwsku_pass_rate == 0:
                        topology_hwsku_results["consistent_failure_topology_hwsku"].append(
                            column_value)
                    success_rate_result.update({column_value: "{}%/{}/{}".format(
                        topology_hwsku_pass_rate, topology_hwsku_success_num, topology_hwsku_total_num)})
            for k, v in sorted(success_rate_result.items(), key=lambda item: int(item[1].split("%")[0])):
                sorted_results_dict.append(k + " : " + v)

            topology_hwsku_results['success_rate'] = sorted_results_dict
            return topology_hwsku_results

        elif combine_type == "hwsku_osversion":
            hwsku_osversion_results = {
                'success_rate': {},
                "consistent_failure_hwsku_osversion": []
            }
            success_rate_result = {}
            sorted_results_dict = []
            for index, row in data_df.iterrows():
                column_value = row['HardwareSku_OSVersion']
                if column_value not in success_rate_result:
                    hwsku_osversion_aggr_df = data_df[(data_df['HardwareSku_OSVersion'] == column_value)]
                    hwsku_osversion_total_num = hwsku_osversion_aggr_df.shape[0]
                    hwsku_osversion_success = hwsku_osversion_aggr_df[
                        hwsku_osversion_aggr_df['Result'] == 'success']
                    hwsku_osversion_success_num = hwsku_osversion_success.shape[0]
                    hwsku_osversion_pass_rate = round(
                        hwsku_osversion_success_num * 100 / hwsku_osversion_total_num)
                    if hwsku_osversion_pass_rate == 0:
                        hwsku_osversion_results["consistent_failure_hwsku_osversion"].append(
                            column_value)
                    success_rate_result.update({column_value: "{}%/{}/{}".format(
                        hwsku_osversion_pass_rate, hwsku_osversion_success_num, hwsku_osversion_total_num)})
            for k, v in sorted(success_rate_result.items(), key=lambda item: int(item[1].split("%")[0])):
                sorted_results_dict.append(k + " : " + v)

            hwsku_osversion_results['success_rate'] = sorted_results_dict
            return hwsku_osversion_results

    def calculate_success_rate(self, data_df, column_name, category):
        results_dict = {}
        success_rate_result = {}
        consistent_failure_list = []
        sorted_results_dict = []
        if category != 'testbed':
            column_name = column_name + 'Name'
        for index, row in data_df.iterrows():
            column_value = row[column_name]
            if column_value not in success_rate_result:
                aggr_df = data_df[data_df[column_name] == column_value]
                total_num = aggr_df.shape[0]
                success_df = aggr_df[aggr_df['Result'] == 'success']
                success_num = success_df.shape[0]
                pass_rate = round(success_num * 100 / total_num)
                if pass_rate == 0:
                    consistent_failure_list.append(column_value)
                success_rate_result.update(
                    {column_value: "{}%/{}/{}".format(pass_rate, success_num, total_num)})
        if category == "os_version":
            for k, v in sorted(success_rate_result.items(), key=lambda item: item[0]):
                sorted_results_dict.append(k + " : " + v)
        else:
            for k, v in sorted(success_rate_result.items(), key=lambda item: int(item[1].split("%")[0])):
                sorted_results_dict.append(k + " : " + v)
        results_dict['success_rate'] = sorted_results_dict
        results_dict["consistent_failure_" +
                     category] = consistent_failure_list
        return results_dict

    def generate_kusto_data(self, case_info_dict, history_testcases, history_case_df):
        kusto_table = []
        kusto_row_data = {
            'failure_level_info': {},
            'trigger_icm': False,
            'autoblame_id': ''
        }
        case_name_branch = case_info_dict["case_branch"]
        is_module_path = case_info_dict['is_module_path']
        is_common_summary = case_info_dict['is_common_summary']

        if is_module_path:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]

        if case_name_branch not in history_testcases:  # the case branch is not included
            return kusto_table

        kusto_row_data['testcase'] = case_name
        kusto_row_data['branch'] = history_testcases[case_name_branch]['branch']
        kusto_row_data['module_path'] = history_testcases[case_name_branch]['module_path']
        kusto_row_data['full_casename'] = history_testcases[case_name_branch]['full_casename']
        if 'summary' in case_info_dict:
            kusto_row_data['failure_summary'] = case_info_dict['summary']
        kusto_row_data['per_testbed_info'] = history_testcases[case_name_branch]['per_testbed_info']
        kusto_row_data['per_asic_info'] = history_testcases[case_name_branch]['per_asic_info']
        kusto_row_data['per_topology_info'] = history_testcases[case_name_branch]['per_topology_info']
        kusto_row_data['per_hwsku_info'] = history_testcases[case_name_branch]['per_hwsku_info']
        if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
            kusto_row_data['per_hwsku_osversion_info'] = history_testcases[case_name_branch]['per_hwsku_osversion_info']
            kusto_row_data['per_topology_hwsku_info'] = history_testcases[case_name_branch]['per_topology_hwsku_info']
        kusto_row_data['per_os_version_info'] = history_testcases[case_name_branch]['per_os_version_info']
        kusto_row_data['failure_level_info']['latest_failure_timestamp'] = (
            history_testcases[case_name_branch]['latest_failure_timestamp']
            if 'latest_failure_timestamp' in history_testcases[case_name_branch]
            else 'NO_FAILURE_TIMESTAMP')
        kusto_row_data['failure_level_info']['oldest_failure_timestamp'] = (
            history_testcases[case_name_branch]['oldest_failure_timestamp']
            if 'oldest_failure_timestamp' in history_testcases[case_name_branch]
            else 'NO_FAILURE_TIMESTAMP')

        kusto_row_data['failure_level_info']['total_success_rate_' +
                                             branch] = history_testcases[case_name_branch]['total_success_rate']
        for branch_name in configuration["branch"]["included_branch"]:
            if branch_name not in branch:
                case_branch_df = history_case_df[history_case_df['BranchName'].str[:BRANCH_PREFIX_LEN]
                                                 == branch_name]
                total_success_num = case_branch_df[case_branch_df['Result']
                                                   == 'success'].shape[0]
                total_num = case_branch_df.shape[0]
                if total_num == 0:
                    logger.info("{} is not ran on {}.".format(
                        case_name, branch_name))
                    continue
                else:
                    kusto_row_data['failure_level_info']['total_success_rate_' + branch_name] = "{}%/{}/{}".format(
                        round(total_success_num * 100 / total_num), total_success_num, total_num)

        if is_module_path:
            kusto_row_data['failure_level_info']['test_setup_failure'] = True
            kusto_row_data['failure_level_info']['is_module_path'] = True
        else:
            kusto_row_data['failure_level_info']['is_test_case'] = True
        if is_common_summary:
            kusto_row_data['failure_level_info']['is_common_summary'] = True
        if 'is_aggregated' in case_info_dict:
            kusto_row_data['failure_level_info']['is_aggregated'] = True
        # Check and set trigger icm flag
        history_case_branch_df = history_case_df[history_case_df['BranchName'] == branch]
        if self.flaky_trigger:
            # If the case is flaky, it will trigger icm
            kusto_table = self.trigger_flaky_icm(
                case_name_branch, kusto_row_data, case_info_dict)
        else:
            kusto_table = self.trigger_icm_new(
                case_name_branch, history_testcases, history_case_branch_df, kusto_row_data, case_info_dict)
        return kusto_table

    def generate_autoblame_ado_data(self, uploading_data_list):
        autoblame_table = []
        related_workitem = []
        for kusto_row_data in uploading_data_list:
            # Search related ADO work items with case name
            case_name = kusto_row_data['testcase']
            module_path = kusto_row_data['module_path']
            branch = kusto_row_data['branch']
            logger.debug("Start to search related ADO work item for case {} branch {}.".format(
                case_name, branch))

            # related_workitem = self.search_ADO([case_name, module_path], False)
            if len(related_workitem) == 0:
                logger.debug("Didn't find any related ADO work item for case {} module path {}.".format(
                    case_name, module_path))
            else:
                kusto_row_data['failure_level_info']['found_related_workitem'] = True
                logger.info("Found {} related ADO work item for case {} module path {}".format(
                    len(related_workitem), case_name, module_path))
                logger.debug(
                    "Related ADO work item:{}".format(related_workitem))

            # Search related commits with keywords and bracnh
            keywords = [case_name]
            keywords.extend(kusto_row_data['module_path'].split("."))
            tag = ''
            if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
                consistent_failure_os_version = kusto_row_data[
                    'per_os_version_info']["consistent_failure_os_version"]
                if consistent_failure_os_version and len(consistent_failure_os_version) > 0:
                    tag = consistent_failure_os_version[0]
                else:
                    tag = kusto_row_data['per_os_version_info']['latest_failure_os_version']

            fmt = '%Y-%m-%d %H:%M:%S'
            end_time = kusto_row_data['failure_level_info']['oldest_failure_timestamp']
            try:
                end_time = datetime.strptime(end_time, fmt)
            except ValueError as e:
                logger.error("{} {} Failed to convert the timestamp: {} ".format(case_name, branch, e))
                continue
            end_time_str = end_time.strftime(fmt)
            start_time = end_time - timedelta(days=7)
            start_time_str = start_time.strftime(fmt)
            logger.info("keywords={} tag={} start_time={}, end_time={}".format(
                keywords, tag, start_time_str, end_time_str))
            report_uuid, commit_results = self.search_autoblame(
                keywords, branch, tag, start_time_str, end_time_str)
            if report_uuid is not None:
                kusto_row_data['failure_level_info']['found_related_commit'] = True
                logger.info("Found {} related commits for case {} branch {} autoblame_id={}".format(
                    len(commit_results['commits']), case_name, branch, report_uuid))
                logger.debug("Related commits for case {} branch {}:{}".format(
                    case_name, branch, commit_results['commits']))
                autoblame_table.extend(commit_results['commits'])
            kusto_row_data["autoblame_id"] = report_uuid
        return autoblame_table

    def trigger_flaky_icm(self, case_name_branch, kusto_row_data, case_info_dict):
        kusto_table = []
        if case_info_dict["is_module_path"]:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]

        logger.info("Surface flaky case {} on branch {}".format(
            case_name, branch))
        kusto_row_data['failure_level_info']['is_flaky'] = True
        kusto_row_data['failure_level_info']['flaky_category'] = case_info_dict['failed_type']
        kusto_row_data['trigger_icm'] = True
        if 'AI_flaky_category' in case_info_dict:
            kusto_row_data['failure_level_info']['AI_flaky_category'] = case_info_dict['AI_flaky_category']
        if case_info_dict["is_module_path"]:
            kusto_row_data['subject'] = "[" + \
                module_path + "][" + branch + "]"
        else:
            kusto_row_data['subject'] = "[" + module_path + \
                "][" + case_name + "][" + branch + "]"
        kusto_table.append(kusto_row_data)
        return kusto_table

    def trigger_icm_new(self, case_name_branch, history_testcases, history_case_branch_df,
                        kusto_row_data, case_info_dict):

        level_priority = configuration["level_priority"]

        kusto_table = []
        prev_level_data = {
            'level_name': None,
            'data': {}
        }  # stores the data filtered from the previous level
        level_func_dict = {
            "branch": self.check_branch_level,
            "os_version": self.check_os_version_level,
            "asic": self.check_asic_level,
            "topology": self.check_topology_level,
            "hwsku": self.check_hwsku_level,
            "hwsku_osversion": self.check_hwsku_osversion_level,
            "topology_hwsku": self.check_topology_hwsku_level
        }
        for level in level_priority:
            case_data = (
                case_name_branch, history_testcases, history_case_branch_df,
                kusto_row_data, case_info_dict, prev_level_data, kusto_table
            )
            check_next_level, prev_level_data = level_func_dict[level](*case_data)
            if not check_next_level:
                break
        return kusto_table

    def set_level_values(self, prev_level_value, raw_data):
        # store level values in failure_level_info or generate condition dict
        for i, c in enumerate(prev_level_value.split("|")):
            if i == 0:   # do not need to record branch in failure_level_info
                continue
            raw_data[configuration['level_priority'][i+1]] = c
        return

    def build_icm_subject(self, case_name_branch, case_info_dict, prev_level_value, level_value):
        prev_level_subject = "[" + "][".join(prev_level_value.split("|")) + "]" if prev_level_value else ""
        if case_info_dict["is_module_path"]:
            module_path = case_name_branch.split("#")[0]
            logger.debug(
                "In build_icm_subject, prev_level_subject={}, level_value={}".format(
                    prev_level_subject, level_value))
            if not level_value:
                subject = "[" + module_path + "]" + prev_level_subject
            else:
                subject = "[" + module_path + "]" + prev_level_subject + "[" + level_value + "]"
            logger.debug("In build_icm_subject, subject={}".format(subject))
            return subject
        else:
            case_name = case_name_branch.split("#")[0].split('.')[-1]
            module_path = case_name_branch.split("#")[0][:-len(case_name)-1]
            if not level_value:
                subject = "[" + module_path + "][" + case_name + "]" + prev_level_subject
            else:
                subject = ("[" + module_path + "][" + case_name + "]" +
                           prev_level_subject + "[" + level_value + "]")
            return subject

    def check_branch_level(self, case_name_branch, history_testcases, history_case_branch_df,
                           kusto_row_data, case_info_dict, prev_level_data, kusto_table):
        """
        If total success rate for this case#branch is lower than threshold,
        it will generate one IcM with title [case][branch]
        """
        if case_info_dict["is_module_path"]:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]

        check_next_level = True
        if branch[:BRANCH_PREFIX_LEN] in configuration['branch_excluded_types']:
            check_next_level = False
            return check_next_level, prev_level_data

        total_success_rate = int(
            history_testcases[case_name_branch]['total_success_rate'].split("%")[0])

        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        branch_config = configuration["icm_decision_config"].get("branch", common_config)
        branch_threshold = branch_config.get("threshold", common_config["threshold"])
        if branch[:BRANCH_PREFIX_LEN] in configuration.get("branch_config", {}):
            branch_threshold = configuration["branch_config"][branch[:BRANCH_PREFIX_LEN]].get(
                "threshold", branch_threshold)
            branch_included = configuration["branch_config"][branch[:BRANCH_PREFIX_LEN]].get(
                "included", True)
            if not branch_included:
                check_next_level = False
                return check_next_level, prev_level_data

        if total_success_rate < branch_threshold:
            if total_success_rate == 0:
                logger.info("All cases for {} on branch {} failed in 30 days.".format(
                    case_name, branch))
                kusto_row_data['failure_level_info']['is_full_failure'] = True
            else:
                logger.info("Success rate of {} on branch {} is lower than {}.".format(
                    case_name, branch, branch_threshold))
                # kusto_row_data['failure_level_info']['is_regression'] = True
            has_result = True
            if self.legacy_trigger:
                _, has_result = self.deduper.is_in_weekly_failure(
                    case_name_branch, kusto_row_data, self.week_legacy_testcases_df)
            elif self.consistent_trigger:
                _, has_result = self.deduper.is_in_weekly_failure(
                    case_name_branch, kusto_row_data, self.week_consistent_testcases_df)
                kusto_row_data['failure_level_info']['is_consistent'] = True
            if not has_result:
                logger.info("{} is not in 7 days'result, ignore this branch.".format(
                    case_name_branch))
            else:
                kusto_row_data['trigger_icm'] = True
                kusto_row_data['subject'] = self.build_icm_subject(
                    case_name_branch, case_info_dict, prev_level_value=None, level_value=branch)
                kusto_table.append(kusto_row_data)
                check_next_level = False
                return check_next_level, prev_level_data
        prev_level_data['data'].update({
            branch: history_case_branch_df[history_case_branch_df['BranchName'] == branch]})
        prev_level_data['level_name'] = 'branch'
        return check_next_level, prev_level_data

    def check_os_version_level(self, case_name_branch, history_testcases, history_case_branch_df,
                               kusto_row_data, case_info_dict, prev_level_data, kusto_table):
        """
            Check if every os version has success rate lower than threshold
            For one specific os version, for release branches, only check its success rate when
            total case is higher than 3,
            for internal and master, only check its success rate when total case is higher than 2,
            otherwise ignore this os version.
        """
        if case_info_dict["is_module_path"]:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]
        if "internal" in branch or "master" in branch:
            internal_version = True
        else:
            internal_version = False
        check_next_level = True

        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        os_version_config = configuration["icm_decision_config"].get("os_version", common_config)
        os_version_threshold = os_version_config.get("threshold", common_config["threshold"])
        os_version_level_enable_icm = os_version_config.get("enable_icm", common_config["enable_icm"])
        if not os_version_level_enable_icm:
            return check_next_level, prev_level_data

        per_os_version_info = history_testcases[case_name_branch]["per_os_version_info"]
        total_case_minimum_release_version = configuration[
            'threshold']['total_case_minimum_release_version']
        total_case_minimum_internal_version = configuration[
            'threshold']['total_case_minimum_internal_version']

        latest_osversion = history_testcases[case_name_branch]['latest_os_version']
        if all(latest_osversion not in os_version_success_rate
               for os_version_success_rate in per_os_version_info["success_rate"]):
            return check_next_level, prev_level_data
        latest_osversion_success_rate_info = [
            os_version_success_rate for os_version_success_rate in per_os_version_info["success_rate"]
            if latest_osversion in os_version_success_rate][0]
        success_rate = latest_osversion_success_rate_info.split(":")[1].strip()
        if latest_osversion in configuration.get('os_version_config', {}):
            os_version_threshold = configuration["os_version_config"][latest_osversion].get(
                "threshold", os_version_threshold)
        total_number = int(success_rate.split("/")[2])
        pass_rate = int(success_rate.split("%")[0])
        if pass_rate < os_version_threshold:
            if ((internal_version and total_number >= total_case_minimum_internal_version) or
                    (not internal_version and total_number > total_case_minimum_release_version)):
                branch_df = history_case_branch_df[history_case_branch_df['BranchName'] == branch]
                latest_osversion_failed_df = branch_df[
                    (branch_df['Result'] != 'success') & (branch_df['OSVersion'] == latest_osversion)]
                if latest_osversion_failed_df.empty:
                    logger.info(
                        "{} All results for os_version {} are success. Ignore this os_version.".format(
                            case_name_branch, latest_osversion))
                    return check_next_level, prev_level_data
                latest_osversion_failed_time_df = latest_osversion_failed_df['UploadTimestamp'].dt.tz_convert(pytz.UTC)
                # check if any row in the DataFrame has a timestamp that is older than 7 days
                if (latest_osversion_failed_time_df < self.search_start_time).all():
                    logger.info(
                        "{} All failed results for os_version {} have a timestamp older than 7 days. "
                        "Ignore this os_version.".format(case_name_branch, latest_osversion))
                else:
                    logger.info(
                        "{} At least one result for os_version {} has a timestamp within the past 7 days.".format(
                            case_name_branch, latest_osversion))
                    condition = {}
                    condition['os_version'] = latest_osversion
                    has_result = True
                    if self.legacy_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data, self.week_legacy_testcases_df, condition)
                    elif self.consistent_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data, self.week_consistent_testcases_df, condition)
                        kusto_row_data['failure_level_info']['is_consistent'] = True
                    if not has_result:
                        logger.info(
                            "{} latest_osversion {} is not in 7 days'result, ignore this latest_osversion.".format(
                                case_name_branch, latest_osversion))
                    else:
                        # kusto_row_data['failure_level_info']['is_regression'] = True
                        kusto_row_data['subject'] = self.build_icm_subject(
                            case_name_branch, case_info_dict, prev_level_value=branch, level_value=None)
                        kusto_row_data['trigger_icm'] = True
                        kusto_table.append(kusto_row_data)
                        logger.info(
                            "{} os_version {} success_rate {} generate one IcM with title {}.".format(
                                case_name_branch, latest_osversion, success_rate, kusto_row_data['subject']))
                        check_next_level = False
                        return check_next_level, prev_level_data
            else:
                logger.info(
                    "{} os_version {} success_rate {} total case number is lower than threshold, "
                    "ignore this os version.".format(case_name_branch, latest_osversion, success_rate))
                return check_next_level, prev_level_data
        else:
            logger.info(
                "{} os_version {} success_rate {} is higher than threshold, ignore this os version.".format(
                    case_name_branch, latest_osversion, success_rate))
        return check_next_level, prev_level_data

    def check_topology_level(self, case_name_branch, history_testcases, history_case_branch_df,
                             kusto_row_data, case_info_dict, prev_level_data, kusto_table):
        next_level_data = {}
        check_next_level = True

        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        topology_config = configuration["icm_decision_config"].get("topology", common_config)
        topology_threshold = topology_config.get("threshold", common_config["threshold"])
        topology_level_enable_icm = topology_config.get("enable_icm", common_config["enable_icm"])
        if not topology_level_enable_icm:
            return check_next_level, prev_level_data

        for prev_level_value, df in prev_level_data['data'].items():
            filter_success_rate_results = self.calculate_success_rate(df, 'Topology', 'topology')
            logger.debug("{} success rate after filtering by {} {}: {}".format(
                        case_name_branch,
                        prev_level_data['level_name'],
                        prev_level_value.split("|")[-1], json.dumps(filter_success_rate_results, indent=4)))
            for topology_pass_rate in filter_success_rate_results["success_rate"]:
                topology = topology_pass_rate.split(":")[0].strip()
                if topology in configuration.get("topology_config", {}):
                    topology_threshold = configuration["topology_config"][topology].get("threshold", topology_threshold)
                else:
                    topology_threshold = topology_config.get("threshold", common_config["threshold"])
                success_rate = topology_pass_rate.split(":")[1].strip()
                topology_df = df[df['TopologyName'] == topology]
                if int(success_rate.split("%")[0]) == 100:
                    logger.info("{} The success rate on topology {} is 100%, skip it.".format(
                        case_name_branch, topology))
                    continue
                if int(success_rate.split("%")[0]) < topology_threshold:
                    topology_failed_df = topology_df[topology_df['Result'] != 'success']
                    if topology_failed_df.empty:
                        logger.info(
                            "{} All results for topology {} are success. Ignore this topology.".format(
                                case_name_branch, topology))
                        continue
                    topology_failed_time_df = topology_failed_df['UploadTimestamp'].dt.tz_convert(pytz.UTC)
                    # check if any row in the DataFrame has a timestamp that is older than 7 days
                    if (topology_failed_time_df < self.search_start_time).all():
                        logger.info(
                            "{} All failed results for topology {} have a timestamp older than 7 days. "
                            "Ignore this topology.".format(case_name_branch, topology))
                        continue
                    else:
                        logger.info(
                            "{} At least one result for topology {} has a timestamp within the past 7 days.".format(
                                case_name_branch, topology))

                    condition = {}
                    condition['topology'] = topology
                    self.set_level_values(prev_level_value, condition)
                    logger.debug(
                        f"{case_name_branch} topology level {topology}: condition=\n{json.dumps(condition, indent=4)}")

                    has_result = True
                    if self.legacy_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data, self.week_legacy_testcases_df, condition)
                    elif self.consistent_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data, self.week_consistent_testcases_df, condition)
                        kusto_row_data['failure_level_info']['is_consistent'] = True
                    if not has_result:
                        logger.info("{} topology {} is not in 7 days'result, ignore this topology.".format(
                            case_name_branch, topology))
                        continue
                    new_kusto_row_data_topology = copy.deepcopy(kusto_row_data)
                    # new_kusto_row_data_topology['failure_level_info']['is_regression'] = True
                    new_kusto_row_data_topology['trigger_icm'] = True
                    self.set_level_values(prev_level_value, new_kusto_row_data_topology['failure_level_info'])
                    new_kusto_row_data_topology['failure_level_info']['topology'] = topology
                    new_kusto_row_data_topology['subject'] = self.build_icm_subject(
                        case_name_branch, case_info_dict, prev_level_value, topology)
                    logger.debug(
                        "{} topology level: new_kusto_row_data_topology={} title={}".format(
                            case_name_branch,
                            json.dumps(new_kusto_row_data_topology['failure_level_info'], indent=4),
                            new_kusto_row_data_topology['subject']))
                    kusto_table.append(new_kusto_row_data_topology)
                    topology_level_index = configuration["level_priority"].index("topology")
                    # check if topology and all level befores it are included in subject
                    # skip branch and os_version
                    for level in configuration["level_priority"][2:topology_level_index+1]:
                        failure_info = new_kusto_row_data_topology['failure_level_info']
                        if (failure_info.get(level) and
                                (failure_info.get(level) not in
                                 new_kusto_row_data_topology['subject'])):
                            logger.error(
                                "{} topology level: topology {} mismatches title {}".format(
                                    case_name_branch,
                                    new_kusto_row_data_topology['failure_level_info']['topology'],
                                    new_kusto_row_data_topology['subject']))
                    # if case_info_dict["is_aggregated"]:
                    #     logger.info(
                    #         "{}: This is an aggregated case, skip further analysis, one IcM is enough.".format(
                    #             case_name_branch))
                    #     return kusto_table
                else:
                    level_name = prev_level_value + '|' + topology
                    next_level_data.update(
                        {level_name: topology_df})
        prev_level_data['data'] = next_level_data
        if configuration["icm_decision_config"].get("topology", common_config):
            prev_level_data['level_name'] = 'topology'
        return check_next_level, prev_level_data

    def check_asic_level(self, case_name_branch, history_testcases, history_case_branch_df, kusto_row_data,
                         case_info_dict, prev_level_data, kusto_table):

        next_level_data = {}
        check_next_level = True

        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        asic_config = configuration["icm_decision_config"].get("asic", common_config)
        asic_threshold = asic_config.get("threshold", common_config["threshold"])
        asic_level_enable_icm = asic_config.get("enable_icm", common_config["enable_icm"])
        if not asic_level_enable_icm:
            return check_next_level, prev_level_data

        for prev_level_value, df in prev_level_data['data'].items():
            # calculate the success rate at current level
            filter_success_rate_results = self.calculate_success_rate(df, 'AsicType', 'asic')
            logger.debug("{} success rate after filtering by {} {}: {}".format(
                        case_name_branch,
                        prev_level_data['level_name'],
                        prev_level_value.split("|")[-1], json.dumps(filter_success_rate_results, indent=4)))
            for asic_pass_rate in filter_success_rate_results["success_rate"]:
                asic = asic_pass_rate.split(":")[0].strip()
                if asic in configuration.get("asic_config", {}):
                    asic_threshold = configuration["asic_config"][asic].get("threshold", asic_threshold)
                else:
                    asic_threshold = asic_config.get("threshold", common_config["threshold"])
                success_rate = asic_pass_rate.split(":")[1].strip()
                asic_case_df = df[df['AsicTypeName'] == asic]
                if int(success_rate.split("%")[0]) == 100:
                    logger.info("{} The success rate on asic {} is 100%, skip it.".format(
                        case_name_branch, asic))
                    continue
                elif int(success_rate.split("%")[0]) < asic_threshold:
                    asic_failed_df = asic_case_df[asic_case_df['Result'] != 'success']
                    if asic_failed_df.empty:
                        logger.info(
                            "{} All results for asic {} are success. Ignore this asic.".format(
                                case_name_branch, asic))
                        continue
                    asic_failed_time_df = asic_failed_df['UploadTimestamp'].dt.tz_convert(pytz.UTC)
                    # check if any row in the DataFrame has a timestamp that is older than 7 days
                    if (asic_failed_time_df < self.search_start_time).all():
                        logger.info(
                            "{} All failed results for asic {} have a timestamp older than 7 days. "
                            "Ignore this asic.".format(case_name_branch, asic))
                        continue
                    else:
                        logger.info(
                            "{} At least one result for asic {} has a timestamp within "
                            "the past 7 days.".format(case_name_branch, asic))

                    condition = {}
                    condition['asic'] = asic
                    self.set_level_values(prev_level_value, condition)
                    logger.debug(
                        f"{case_name_branch} asic level {asic}: "
                        f"condition=\n{json.dumps(condition, indent=4)}")
                    has_result = True
                    if self.legacy_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data,
                            self.week_legacy_testcases_df, condition)
                    elif self.consistent_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data,
                            self.week_consistent_testcases_df, condition)
                        kusto_row_data['failure_level_info']['is_consistent'] = True
                    if not has_result:
                        logger.info(
                            "{} asic {} is not in 7 days'result, ignore this asic.".format(
                                case_name_branch, asic))
                        continue

                    new_kusto_row_data_asic = copy.deepcopy(kusto_row_data)
                    # new_kusto_row_data_asic['failure_level_info']['is_regression'] = True
                    new_kusto_row_data_asic['trigger_icm'] = True
                    self.set_level_values(prev_level_value, new_kusto_row_data_asic['failure_level_info'])
                    new_kusto_row_data_asic['failure_level_info']['asic'] = asic
                    new_kusto_row_data_asic['subject'] = self.build_icm_subject(
                        case_name_branch, case_info_dict, prev_level_value, asic)
                    logger.debug(
                        "{} asic level - {}: new_kusto_row_data_asic={} title={}".format(
                            case_name_branch, asic,
                            json.dumps(new_kusto_row_data_asic['failure_level_info'], indent=4),
                            new_kusto_row_data_asic['subject']))
                    kusto_table.append(new_kusto_row_data_asic)

                    asic_level_index = configuration["level_priority"].index("asic")
                    # check if asic and all levels before it are all included in the subject
                    # skip branch and os_version
                    for level in configuration["level_priority"][2:asic_level_index+1]:
                        if (new_kusto_row_data_asic['failure_level_info'].get(level) and
                            (new_kusto_row_data_asic['failure_level_info'].get(level) not in
                             new_kusto_row_data_asic['subject'])):
                            logger.error(
                                "{} asic level: asic {} mismatches title {}".format(
                                    case_name_branch,
                                    new_kusto_row_data_asic['failure_level_info']['asic'],
                                    new_kusto_row_data_asic['subject']))
                    # if case_info_dict["is_aggregated"]:
                    #     logger.info(
                    #         "{}: This is an aggregated case, skip further analysis, one IcM is enough.".format(
                    #             case_name_branch))
                    #     return kusto_table
                else:
                    # logger.debug("{} asic_case_df for asic {} is :{}".format(
                    #     case_name_branch, asic, asic_case_df))
                    level_name = prev_level_value + '|' + asic
                    next_level_data.update(
                        {level_name: asic_case_df})
        prev_level_data['data'] = next_level_data
        if configuration["icm_decision_config"].get("asic", common_config):
            prev_level_data['level_name'] = "asic"
        return check_next_level, prev_level_data

    def check_hwsku_level(self, case_name_branch, history_testcases, history_case_branch_df, kusto_row_data,
                          case_info_dict, prev_level_data, kusto_table):
        next_level_data = {}
        check_next_level = True

        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        hwsku_config = configuration["icm_decision_config"].get("hwsku", common_config)
        hwsku_threshold = hwsku_config.get("threshold", common_config["threshold"])
        hwsku__level_enable_icm = hwsku_config.get("enable_icm", common_config["enable_icm"])
        if not hwsku__level_enable_icm:
            return check_next_level, prev_level_data

        for prev_level_value, df in prev_level_data['data'].items():
            filter_success_rate_results = self.calculate_success_rate(df, 'HardwareSku', 'hwsku')
            logger.debug(
                "{} success rate after filtering by {} {}: {}".format(
                    case_name_branch, prev_level_data['level_name'],
                    prev_level_value.split("|")[-1],
                    json.dumps(filter_success_rate_results, indent=4)))
            for hwsku_pass_rate in filter_success_rate_results["success_rate"]:
                hwsku = hwsku_pass_rate.split(":")[0].strip()
                if hwsku in configuration.get("hwsku_config", {}):
                    hwsku_threshold = configuration["hwsku_config"][hwsku].get("threshold", hwsku_threshold)
                else:
                    hwsku_threshold = hwsku_config.get("threshold", common_config["threshold"])
                success_rate = hwsku_pass_rate.split(":")[1].strip()
                hwsku_df = df[df['HardwareSkuName'] == hwsku]
                if int(success_rate.split("%")[0]) == 100:
                    logger.info(
                        "{} The success rate on hwsku {} is 100%, skip it.".format(
                            case_name_branch, hwsku))
                    continue
                elif int(success_rate.split("%")[0]) < hwsku_threshold:
                    hwsku_failed_df = hwsku_df[hwsku_df['Result'] != 'success']
                    if hwsku_failed_df.empty:
                        logger.info(
                            "{} All results for hwsku {} are success. Ignore this hwsku.".format(
                                case_name_branch, hwsku))
                        continue
                    hwsku_failed_time_df = hwsku_failed_df['UploadTimestamp'].dt.tz_convert(pytz.UTC)
                    # check if any row in the DataFrame has a timestamp that is older than 7 days
                    if (hwsku_failed_time_df < self.search_start_time).all():
                        logger.info(
                            "{} All failed results for hwsku {} have a timestamp older than 7 days. "
                            "Ignore this hwsku.".format(case_name_branch, hwsku))
                        continue
                    else:
                        logger.info(
                            "{} At least one result for hwsku {} has a timestamp within "
                            "the past 7 days.".format(case_name_branch, hwsku))

                    condition = {}
                    self.set_level_values(prev_level_value, condition)
                    condition['hwsku'] = hwsku
                    logger.debug(
                        f"{case_name_branch} hwsku level {hwsku}: "
                        f"condition=\n{json.dumps(condition, indent=4)}")
                    has_result = True
                    if self.legacy_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data,
                            self.week_legacy_testcases_df, condition)
                    elif self.consistent_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data,
                            self.week_consistent_testcases_df, condition)
                        kusto_row_data['failure_level_info']['is_consistent'] = True
                    if not has_result:
                        logger.info(
                            "{} hwsku {} is not in 7 days'result, ignore this hwsku.".format(
                                case_name_branch, hwsku))
                        continue

                    new_kusto_row_data_hwsku = copy.deepcopy(kusto_row_data)
                    # new_kusto_row_data_hwsku['failure_level_info']['is_regression'] = True
                    new_kusto_row_data_hwsku['trigger_icm'] = True
                    self.set_level_values(
                        prev_level_value, new_kusto_row_data_hwsku['failure_level_info'])
                    new_kusto_row_data_hwsku['failure_level_info']['hwsku'] = hwsku
                    new_kusto_row_data_hwsku['subject'] = self.build_icm_subject(
                        case_name_branch, case_info_dict, prev_level_value, hwsku)
                    logger.debug(
                        "{} hwsku level: new_kusto_row_data_hwsku={} title={}".format(
                            case_name_branch,
                            json.dumps(new_kusto_row_data_hwsku['failure_level_info'], indent=4),
                            new_kusto_row_data_hwsku['subject']))
                    kusto_table.append(new_kusto_row_data_hwsku)

                    hwsku_level_index = configuration["level_priority"].index("hwsku")
                    # check if hwsku and all level befores it are included in subject
                    # skip branch and os_version
                    for level in configuration["level_priority"][2:hwsku_level_index+1]:
                        if (new_kusto_row_data_hwsku['failure_level_info'].get(level) and
                            (new_kusto_row_data_hwsku['failure_level_info'].get(level) not in
                             new_kusto_row_data_hwsku['subject'])):
                            logger.error(
                                "{} hwsku level: hwsku {} mismatches title {}".format(
                                    case_name_branch,
                                    new_kusto_row_data_hwsku['failure_level_info']['hwsku'],
                                    new_kusto_row_data_hwsku['subject']))
                    # if case_info_dict["is_aggregated"]:
                    #     logger.info("{}: This is an aggregated case, skip further analysis, "
                    #                 "one IcM is enough.".format(case_name_branch))
                    #     return kusto_table
                else:
                    level_name = prev_level_value + '|' + hwsku
                    next_level_data.update(
                        {level_name: hwsku_df})
        prev_level_data['data'] = next_level_data
        if configuration["icm_decision_config"].get("hwsku", common_config):
            prev_level_data['level_name'] = 'hwsku'
        return check_next_level, prev_level_data

    def check_hwsku_osversion_level(self, case_name_branch, history_testcases, history_case_branch_df, kusto_row_data,
                                    case_info_dict, prev_level_data, kusto_table):
        """
            check hwsku_osversion level for release branches
        """
        check_next_level = True
        if kusto_table:
            logger.debug("{} Found {} IcMs. Not check hwsku_osversion anymore.".format(
                case_name_branch, len(kusto_table)))
            logger.debug("{} found IcM: kusto_table={}".format(case_name_branch, json.dumps(kusto_table, indent=4)))
            check_next_level = False
            return check_next_level, prev_level_data
        logger.info("{} Not Found IcMs. Now check hwsku_osversion.".format(case_name_branch))

        if case_info_dict["is_module_path"]:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]

        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        hwsku_osversion_config = configuration["icm_decision_config"].get(
            "hwsku_osversion", common_config)
        hwsku_osversion_threshold = hwsku_osversion_config.get(
            "threshold", common_config["threshold"])
        hwsku_osversion_level_enable_icm = hwsku_osversion_config.get(
            "enable_icm", common_config["enable_icm"])
        if not hwsku_osversion_level_enable_icm:
            return check_next_level, prev_level_data
        if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
            # per_hwsku_osversion_info = history_testcases[case_name_branch]["per_hwsku_osversion_info"]
            branch_df = history_case_branch_df[history_case_branch_df['BranchName'] == branch]
            latest_osversion = history_testcases[case_name_branch]['latest_os_version']
            branch_df = branch_df[branch_df['OSVersion'] == latest_osversion]
            if branch_df.shape[0] == 0:      # latest os version is not included
                return check_next_level, prev_level_data

            hwsku_osversion_results = self.calculate_combined_success_rate(
                branch_df, 'hwsku_osversion')
            logger.debug(
                "{} combined hwsku and osversion success rate : {}".format(
                    case_name_branch, json.dumps(hwsku_osversion_results, indent=4)))
            for hwsku_osversion_pass_rate in hwsku_osversion_results["success_rate"]:
                hwsku_osversion = hwsku_osversion_pass_rate.split(":")[
                    0].strip()
                if hwsku_osversion in configuration.get("hwsku_osversion_config", {}):
                    hwsku_osversion_threshold = configuration["hwsku_osversion_config"][
                        hwsku_osversion].get("threshold", hwsku_osversion_threshold)
                else:
                    hwsku_osversion_threshold = hwsku_osversion_config.get(
                        "threshold", common_config["threshold"])
                hwsku = hwsku_osversion.split("_")[0]
                osversion = hwsku_osversion.split("_")[1]
                success_rate = hwsku_osversion_pass_rate.split(":")[1].strip()

                if int(success_rate.split("%")[0]) < hwsku_osversion_threshold:
                    hwsku_os_failed_df = branch_df[
                        (branch_df['Result'] != 'success') &
                        (branch_df['HardwareSku_OSVersion'] == hwsku_osversion)]
                    if hwsku_os_failed_df.empty:
                        logger.info(
                            "{} All results for hwsku_osversion {} are success. "
                            "Ignore this hwsku_osversion.".format(
                                case_name_branch, hwsku_osversion))
                        continue
                    hwsku_os_failed_time_df = hwsku_os_failed_df['UploadTimestamp'].dt.tz_convert(
                        pytz.UTC)
                    logger.info(
                        "{} hwsku_os_failed_df {} hwsku_os_failed_time_df "
                        "for hwsku_osversion {} is :{}".format(
                            case_name_branch, hwsku_os_failed_df,
                            hwsku_os_failed_time_df, hwsku_osversion))
                    # check if any row in the DataFrame has a timestamp that is older than 7 days
                    if (hwsku_os_failed_time_df < self.search_start_time).all():
                        logger.info(
                            "{} All failed results for hwsku_osversion {} have "
                            "a timestamp older than 7 days. "
                            "Ignore this hwsku_osversion.".format(
                                case_name_branch, hwsku_osversion))
                        continue
                    else:
                        logger.info(
                            "{} At least one result for hwsku_osversion {} has "
                            "a timestamp within the past 7 days.".format(
                                case_name_branch, hwsku_osversion))

                    condition = {}
                    condition['hwsku'] = hwsku
                    condition['os_version'] = osversion
                    has_result = True
                    if self.legacy_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data,
                            self.week_legacy_testcases_df, condition)
                    elif self.consistent_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data,
                            self.week_consistent_testcases_df, condition)
                        kusto_row_data['failure_level_info']['is_consistent'] = True
                    if not has_result:
                        logger.info(
                            "{} hwsku {} osversion {} is not in 7 days'result, "
                            "ignore this hwsku_osversion.".format(
                                case_name_branch, hwsku, osversion))
                        continue

                    new_kusto_row_data_hwsku_osversion = copy.deepcopy(kusto_row_data)
                    # new_kusto_row_data_asic['failure_level_info']['is_regression'] = True
                    new_kusto_row_data_hwsku_osversion['trigger_icm'] = True
                    new_kusto_row_data_hwsku_osversion['failure_level_info']['hwsku'] = hwsku
                    new_kusto_row_data_hwsku_osversion['failure_level_info']['os_version'] = osversion
                    new_kusto_row_data_hwsku_osversion['failure_level_info']['is_combined'] = True
                    new_kusto_row_data_hwsku_osversion['subject'] = self.build_icm_subject(
                        case_name_branch, case_info_dict,
                        prev_level_value=branch, level_value=hwsku_osversion)
                    logger.debug(
                        "{} hwsku osversion level: new_kusto_row_data_hwsku_osversion={} title={}".format(
                            case_name_branch,
                            json.dumps(new_kusto_row_data_hwsku_osversion['failure_level_info'], indent=4),
                            new_kusto_row_data_hwsku_osversion['subject']))
                    kusto_table.append(new_kusto_row_data_hwsku_osversion)
                    if (new_kusto_row_data_hwsku_osversion['failure_level_info']['hwsku'] not in
                            new_kusto_row_data_hwsku_osversion['subject'] or
                            new_kusto_row_data_hwsku_osversion['failure_level_info']['os_version'] not in
                            new_kusto_row_data_hwsku_osversion['subject']):
                        logger.error(
                            "{} hwsku osversion level: hwsku {} osversion {} mismatches title {}".format(
                                case_name_branch,
                                new_kusto_row_data_hwsku_osversion['failure_level_info']['hwsku'],
                                new_kusto_row_data_hwsku_osversion['failure_level_info']['os_version'],
                                new_kusto_row_data_hwsku_osversion['subject']))
                elif int(success_rate.split("%")[0]) == 100:
                    logger.debug(
                        "{} The success rate on hwsku_osversion {} is 100%, skip it.".format(
                            case_name_branch, hwsku_osversion))
                    continue
        if kusto_table:
            logger.debug(
                "{} Found {} IcMs. Not check next level anymore.".format(
                    case_name_branch, len(kusto_table)))
            logger.debug(
                "{} found IcM: kusto_table={}".format(
                    case_name_branch, json.dumps(kusto_table, indent=4)))
            check_next_level = False
        return check_next_level, prev_level_data

    def check_topology_hwsku_level(self, case_name_branch, history_testcases, history_case_branch_df, kusto_row_data,
                                   case_info_dict, prev_level_data, kusto_table):
        """
            Check topology_hwsku level for release branches
        """
        check_next_level = True
        if kusto_table:
            logger.debug("{} Found {} IcMs. Not check topology_hwsku anymore.".format(
                case_name_branch, len(kusto_table)))
            logger.debug("{} found IcM: kusto_table={}".format(case_name_branch, json.dumps(kusto_table, indent=4)))
            check_next_level = False
            return check_next_level, prev_level_data

        logger.info("{} Not Found IcMs. Now check topology_hwsku.".format(case_name_branch))

        if case_info_dict["is_module_path"]:
            items = case_name_branch.split("#")
            module_path = items[0]
            case_name = module_path
            branch = items[1]
        else:
            items = case_name_branch.split("#")
            case_name = items[0].split('.')[-1]
            module_path = items[0][:-len(case_name)-1]
            branch = items[1]
        # read configuration
        common_config = configuration["icm_decision_config"]["common"]
        topology_hwsku_config = configuration["icm_decision_config"].get("topology_hwsku", common_config)
        topology_hwsku_threshold = topology_hwsku_config.get("threshold", common_config["threshold"])
        topology_hwsku_level_enable_icm = topology_hwsku_config.get("enable_icm", common_config["enable_icm"])
        if not topology_hwsku_level_enable_icm:
            return check_next_level, prev_level_data

        # history_case_branch_df_copy = copy.deepcopy(history_case_branch_df)
        # for topology_config in configuration["icm_decision_config"].get("topology", {}).get("types", []):
        #     history_case_branch_df_copy.loc[:, 'Topology'] = \
        #         history_case_branch_df_copy['Topology'].replace(
        #             topology_config["testbed_topology"], topology_config["name"])

        if branch[:BRANCH_PREFIX_LEN] in configuration["branch"]["released_branch"]:
            # per_hwsku_topo_info = history_testcases[case_name_branch]["per_hwsku_topo_info"]
            branch_df = history_case_branch_df[history_case_branch_df['BranchName'] == branch]
            topology_hwsku_results = self.calculate_combined_success_rate(
                branch_df, 'topology_hwsku')
            for topology_hwsku_pass_rate in topology_hwsku_results["success_rate"]:
                topology_hwsku = topology_hwsku_pass_rate.split(":")[0].strip()
                if topology_hwsku in configuration.get("topology_hwsku_config", {}):
                    topology_hwsku_threshold = configuration["topology_hwsku_config"][topology_hwsku].get(
                        "threshold", topology_hwsku_threshold)
                else:
                    topology_hwsku_threshold = topology_hwsku_config.get("threshold", common_config["threshold"])
                last_underscore = topology_hwsku.rindex('_')
                topology = topology_hwsku[:last_underscore]
                hwsku = topology_hwsku[last_underscore+1:]
                success_rate = topology_hwsku_pass_rate.split(":")[1].strip()

                if int(success_rate.split("%")[0]) < topology_hwsku_threshold or self.consistent_trigger:
                    topology_hwsku_failed_df = branch_df[
                        (branch_df['Result'] != 'success') &
                        (branch_df['Topology_HardwareSku'] == topology_hwsku)]
                    if topology_hwsku_failed_df.empty:
                        logger.info(
                            "{} All results for topology_hwsku {} are success. Ignore this topology_hwsku.".format(
                                case_name_branch, topology_hwsku))
                        continue
                    topology_hwsku_failed_time_df = topology_hwsku_failed_df['UploadTimestamp'].dt.tz_convert(pytz.UTC)
                    logger.info(
                        "{} topology_hwsku_failed_df {} topology_hwsku_failed_time_df "
                        "for topology_hwsku {} is :{}".format(
                            case_name_branch, topology_hwsku_failed_df,
                            topology_hwsku_failed_time_df, topology_hwsku))
                    # check if any row in the DataFrame has a timestamp that is older than 7 days
                    if (topology_hwsku_failed_time_df < self.search_start_time).all():
                        logger.info(
                            "{} All failed results for topology_hwsku {} have a timestamp older than 7 days. "
                            "Ignore this topology_hwsku.".format(case_name_branch, topology_hwsku))
                        continue
                    else:
                        logger.info(
                            "{} At least one result for topology_hwsku {} has a timestamp "
                            "within the past 7 days.".format(case_name_branch, topology_hwsku))

                    condition = {}
                    condition['topology'] = topology
                    condition['hwsku'] = hwsku
                    has_result = True
                    if self.legacy_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data, self.week_legacy_testcases_df, condition)
                    elif self.consistent_trigger:
                        _, has_result = self.deduper.is_in_weekly_failure(
                            case_name_branch, kusto_row_data, self.week_consistent_testcases_df, condition)
                        kusto_row_data['failure_level_info']['is_consistent'] = True
                    if not has_result:
                        logger.info(
                            "{} topology {} hwsku {} is not in 7 days'result, ignore this topology_hwsku.".format(
                                case_name_branch, topology, hwsku))
                        continue

                    new_kusto_row_data_topology_hwsku = copy.deepcopy(kusto_row_data)
                    # new_kusto_row_data_asic['failure_level_info']['is_regression'] = True
                    new_kusto_row_data_topology_hwsku['trigger_icm'] = True
                    new_kusto_row_data_topology_hwsku['failure_level_info']['topology'] = topology
                    new_kusto_row_data_topology_hwsku['failure_level_info']['hwsku'] = hwsku
                    new_kusto_row_data_topology_hwsku['failure_level_info']['is_combined'] = True
                    new_kusto_row_data_topology_hwsku['subject'] = self.build_icm_subject(
                        case_name_branch, case_info_dict, prev_level_value=branch, level_value=topology_hwsku)
                    logger.debug(
                        "{} topology_hwsku level: is_consistent {} title={}: "
                        "new_kusto_row_data_topology_hwsku={}".format(
                            case_name_branch, self.consistent_trigger,
                            new_kusto_row_data_topology_hwsku['subject'],
                            json.dumps(new_kusto_row_data_topology_hwsku['failure_level_info'], indent=4)))
                    kusto_table.append(new_kusto_row_data_topology_hwsku)
                    if (new_kusto_row_data_topology_hwsku['failure_level_info']['topology'] not in
                            new_kusto_row_data_topology_hwsku['subject'] or
                            new_kusto_row_data_topology_hwsku['failure_level_info']['hwsku'] not in
                            new_kusto_row_data_topology_hwsku['subject']):
                        logger.error(
                            "{} topology_hwsku level: is consistent {} topology {} hwsku {} "
                            "mismatches title {}".format(
                                case_name_branch, self.consistent_trigger,
                                new_kusto_row_data_topology_hwsku['failure_level_info']['topology'],
                                new_kusto_row_data_topology_hwsku['failure_level_info']['hwsku'],
                                new_kusto_row_data_topology_hwsku['subject']))
                elif int(success_rate.split("%")[0]) == 100:
                    logger.debug(
                        "{} The success rate on topology_hwsku {} is 100%, skip it.".format(
                            case_name_branch, topology_hwsku))
                    continue
        if kusto_table:
            logger.debug("{} Found {} IcMs. Not check next level anymore.".format(
                case_name_branch, len(kusto_table)))
            logger.debug("{} found IcM: kusto_table={}".format(case_name_branch, json.dumps(kusto_table, indent=4)))
            check_next_level = False
        return check_next_level, prev_level_data

    def search_autoblame(self, keywords, branch, tag, starttime, endtime):
        """
        Search keywords in Autoblame II with specific repo and branch
        Call Auboblame's API to get results
        """
        valid_branches = configuration['auto_blame_branch']['branches']
        if branch not in valid_branches:
            logger.error(
                "Get autoblame response failed with invalid branch: {}".format(branch))
            return None, None
        branch_list = configuration['auto_blame_branch'][branch]
        repo_list = configuration['auto_blame_repo'][branch]
        return self.search_autoblame_upload(keywords, repo_list, branch_list, starttime, endtime, tag)

    def search_autoblame_upload(self, keywords, repo_list, branch_list, starttime, endtime, tag):
        """
        Search keywords in Autoblame II with specific repo and branch
        Call Auboblame's API to get results

        """
        reportid = str(uuid.uuid4())
        # keywords is a list
        res = {}
        res['reportid'] = reportid
        res['commits'] = []
        params = {}
        params['repo'] = repo_list
        params['branch'] = branch_list
        params['keywords'] = keywords
        params['starttime'] = starttime
        params['endtime'] = endtime
        params['tag'] = tag
        AUTO_BLAME_URL = 'https://sonic-webtools-backend-dev.azurewebsites.net/vue-admin-template/blame/analyzer'
        try:
            resp = requests.get(AUTO_BLAME_URL, params=params).json()
            item_list = resp.get('data')['items']
            upload_datas = []
            for report in item_list:
                report.update({
                    'reportid': reportid,
                    'keyword': ','.join(keywords)
                })
                upload_datas.append(report)

            # timestamp +items uuid,list
            # store to kusto
            if len(upload_datas) == 0:
                logger.debug("No commit found for keywords {} on branch {}".format(
                    keywords, branch_list))
                return None, None
            res['commits'] = upload_datas
        except Exception as e:
            logger.error(
                "Get autoblame response failed with exception: {}".format(repr(e)))
            logger.error(traceback.format_exc())
            return None, None
        return reportid, res

    def search_ADO(self, keywords, is_resolved_included=False):
        """
        Search title or content in ADO with keywords
        Call ADO's API to get results
        parent ID: 13410102
        keywords: not a single word for test case name, it should be a list, contains test case name and module path.
        is_resovled_included: True, all of results included Done ones. False, only return work items which is not Done.
        return results should be a list:
        The relation is OR, the return result contains related work items both for test case and module path.
        ID, title, URL, status, owner, tags.
        """
        result_list = []
        for child_dict in self.child_standby_list:
            child_title = child_dict["title"]
            if child_title == "No title":
                continue

            for keyword in keywords:
                if child_title.lower().find(keyword.lower()) != -1:
                    if is_resolved_included:
                        result_list.append(child_dict)
                    elif child_dict["status"] != "Done":
                        result_list.append(child_dict)
                    break

        return result_list

    def print_analysis_table(self, table):
        if not table:
            return
        try:
            case_table = prettytable.PrettyTable()
            if 'failure_level_info' in table[0].keys():
                header = ["Index", "TestInfo", "FailureLevelInfo", "PerAsicTestInfo", "PerTopologyTestInfo",
                          "PerHwskuTestInfo", 'PerTestbedTestInfo', 'PerOSVersionTestInfo']
            else:
                header = ["TestInfo", "PerAsicTestInfo", "PerTopologyTestInfo", "PerHwskuTestInfo",
                          'PerTestbedTestInfo', 'PerOSVersionTestInfo']
            if 'per_hwsku_osversion_info' in table[0].keys():
                header.append('PerHwskuOsversionTestInfo')
            if 'per_topology_hwsku_info' in table[0].keys():
                header.append('PerTopologyHwskuTestInfo')

            case_table.field_names = header
            case_table.align = "l"  # left align
            case_table.max_width = 1000  # maximun width of all columns
            for idx, case in enumerate(table):
                try:
                    FailureLevelInfo = []
                    PerHwskuOsversionTestInfo = []
                    content = []

                    if 'trigger_icm' not in case:
                        TestInfo = (case.get('testcase', '') + "\n" + case.get('module_path', '') +
                                    "\n" + case['branch'] + "\n" + case['latest_failure_timestamp'] +
                                    "\n" + case['oldest_failure_timestamp'] + "\n" + case.get('subject', '') +
                                    "\n" + "end")
                    else:
                        TestInfo = (case.get('testcase', '') + "\n" + case.get('module_path', '') +
                                    "\n" + case['branch'] + "\n" + "trigger_icm:" + str(case['trigger_icm']) +
                                    "\n" + case.get('subject', '') + "\n" + "end")
                    if 'failure_level_info' in case.keys():
                        FailureLevelInfo = json.dumps(
                            case['failure_level_info'], indent=4)

                    PerAsicTestInfo = json.dumps(case['per_asic_info'], indent=4)
                    PerTopologyTestInfo = json.dumps(case['per_topology_info'], indent=4)
                    PerHwskuTestInfo = json.dumps(case['per_hwsku_info'], indent=4)
                    PerTestbedTestInfo = json.dumps(
                        case['per_testbed_info'], indent=4)
                    if 'per_hwsku_osversion_info' in case.keys():
                        PerHwskuOsversionTestInfo = json.dumps(
                            case['per_hwsku_osversion_info'], indent=4)
                    PerOSVersionTestInfo = json.dumps(
                        case['per_os_version_info'], indent=4)
                    if 'per_topology_hwsku_info' in case.keys():
                        PerTopologyHwskuTestInfo = json.dumps(
                            case['per_topology_hwsku_info'], indent=4)

                    if 'FailureLevelInfo' in case_table.field_names:
                        content = [idx + 1, TestInfo, FailureLevelInfo, PerAsicTestInfo, PerTopologyTestInfo,
                                   PerHwskuTestInfo, PerTestbedTestInfo, PerOSVersionTestInfo]
                    else:
                        content = [TestInfo, PerAsicTestInfo, PerTopologyTestInfo,
                                   PerHwskuTestInfo, PerTestbedTestInfo, PerOSVersionTestInfo]
                    if 'PerHwskuOsversionTestInfo' in case_table.field_names:
                        content.append(PerHwskuOsversionTestInfo)
                    if 'PerTopologyHwskuTestInfo' in case_table.field_names:
                        content.append(PerTopologyHwskuTestInfo)
                    case_table.add_row(content)
                except Exception as e:
                    logger.error(
                        "Inside: Print analysis table failed with exception: {}".format(repr(e)))
                    logger.error(traceback.format_exc())
                    logger.info("table header length {}: {}".format(
                        len(case_table.field_names), case_table.field_names))
                    logger.info("table content length {}: {}".format(
                        len(content), content))
                    logger.info("case: {}".format(json.dumps(case, indent=4)))
                    continue

            case_table.hrules = prettytable.ALL
            case_table.vrules = prettytable.ALL

            print(case_table)
        except Exception as e:
            logger.error(
                "Outside: Print analysis table failed with exception: {}".format(repr(e)))
            logger.error(traceback.format_exc())
            logger.info("table header length {}: {}".format(
                len(case_table.field_names), case_table.field_names))
            logger.info("table content length {}: {}".format(
                len(content), content))
            logger.info("case: {}".format(json.dumps(case, indent=4)))

        return
