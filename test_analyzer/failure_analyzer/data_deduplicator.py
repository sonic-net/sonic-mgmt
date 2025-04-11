from config import configuration, logger, ICM_PREFIX, MIDDLE_FAILURES_CSV
import pytz
from datetime import datetime, timedelta
import json
import copy
import pandas as pd
import re
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import DBSCAN


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

    def deduplication(self, common_summary_new_icm_table, original_failure_dict, branches):
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
    def prepare_data_for_clustering(self, failure_new_icm_table):
        """
        Prepares data for clustering by removing duplicates and NaN values.
        """
        failures_df = pd.DataFrame(failure_new_icm_table, columns=['full_casename', 'subject', 'branch', 'failure_summary'])
        # Add topology, asic, hwsku and os_version columns from failure_level_info
        failures_df['topology'] = [item.get('failure_level_info', {}).get('topology', '') for item in failure_new_icm_table]
        failures_df['asic'] = [item.get('failure_level_info', {}).get('asic', '') for item in failure_new_icm_table]
        failures_df['hwsku'] = [item.get('failure_level_info', {}).get('hwsku', '') for item in failure_new_icm_table]
        failures_df['os_version'] = [item.get('failure_level_info', {}).get('os_version', '') for item in failure_new_icm_table]

        return failures_df

    def find_similar_summaries_and_count(self, dataframe_data, week_failure_df):
        """
        Groups similar failure summaries by branch and counts how many entries are in each group.
        Process cases with empty summaries by retrieving all their failure summaries from week_failure_df.
        Aggregates similar summaries and keeps representative cases.

        Args:
            dataframe_data: DataFrame with columns [full_casename, subject, branch, failure_summary, topology, asic, hwsku, os_version]
            week_failure_df: DataFrame containing all failure data with Summaries across branches and testbeds

        Returns:
            DataFrame containing filtered data with 'cluster', 'count', and 'aggregated' columns
        """
        # Create a copy and initialize the aggregated column
        df = dataframe_data.copy()
        df['aggregated'] = df['failure_summary'].apply(lambda x: False if pd.isna(x) or not x else True)

        # Track rows to drop and add
        rows_to_drop = []
        rows_to_add = []

        # STEP 1: Fill empty failure_summary entries with data from week_failure_df
        for idx, row in df.iterrows():
            if pd.isna(row['failure_summary']) or not row['failure_summary']:
                # Build match conditions
                match_conditions = (
                    (week_failure_df['FullCaseName'] == row['full_casename']) &
                    (week_failure_df['BranchName'] == row['branch'])
                )
                # Add additional match conditions if they exist
                if 'topology' in row and row['topology'] != '' and not pd.isna(row['topology']):
                    match_conditions &= (week_failure_df['TopologyName'] == row['topology'])
                if 'asic' in row and row['asic'] != '' and not pd.isna(row['asic']):
                    match_conditions &= (week_failure_df['AsicTypeName'] == row['asic'])
                if 'hwsku' in row and row['hwsku'] != '' and not pd.isna(row['hwsku']):
                    match_conditions &= (week_failure_df['HardwareSkuName'] == row['hwsku'])
                if 'os_version' in row and row['os_version'] != '' and not pd.isna(row['os_version']):
                    match_conditions &= (week_failure_df['OSVersionName'] == row['os_version'])

                # Get all matching records from week_failure_df
                matches = week_failure_df[match_conditions]

                if not matches.empty:
                    # Mark this row for deletion
                    rows_to_drop.append(idx)

                    # Create new rows for each match with non-empty summaries
                    for _, match_row in matches.iterrows():
                        if not pd.isna(match_row['Summary']) and match_row['Summary']:
                            new_row = row.copy()
                            new_row['failure_summary'] = match_row['Summary']
                            rows_to_add.append(new_row)
                            logger.info(f"Subject '{row['subject']}': Added new row with summary {new_row['failure_summary'][:80]}")

        # Apply the changes to the dataframe
        if rows_to_drop:
            df = df.drop(rows_to_drop, axis=0)

        if rows_to_add:
            df = pd.concat([df, pd.DataFrame(rows_to_add)], ignore_index=True)

        # Verify that we don't have empty summaries after processing
        empty_summary_rows = df[df['failure_summary'].isna() | (df['failure_summary'] == '')]
        if not empty_summary_rows.empty:
            logger.error(f"\nFound {len(empty_summary_rows)} rows with empty summaries after filling process:")
            for idx, row in empty_summary_rows.iterrows():
                logger.error(f"  - Subject '{row['subject']}': Case: {row['full_casename']}, Branch: {row['branch']}")

        else:
            logger.info("\nNo empty summaries found after filling process.")

        # Initialize the cluster column
        df['cluster'] = None

        # Process each branch separately for clustering
        for branch, branch_df in df.groupby('branch'):
            # Skip empty summaries
            to_cluster = branch_df[~branch_df['failure_summary'].isna() & (branch_df['failure_summary'] != '')]

            if to_cluster.empty:
                logger.error(f"Branch {branch}: No summaries to cluster")
                continue

            # Preprocess the summaries and save to a new column
            branch_df['failure_summary'] = branch_df['failure_summary'].apply(self.__preprocess_summary)

            # logger.info summaries before clustering for debugging
            logger.info(f"\nSummaries for branch {branch}:")
            for i, (idx, row) in enumerate(branch_df.iterrows()):
                logger.info(f"{i}: Subject '{row['subject']}': {row['failure_summary'][:100]}...")

            # Get the cluster assignments with a stricter eps value based on processed summaries
            clusters = self.cluster_summaries(branch_df['failure_summary'], eps=0.1, min_samples=1)

            # Update the failure_summary column in the main dataframe
            for i, idx in enumerate(branch_df.index):
                df.loc[idx, 'failure_summary'] = branch_df['failure_summary'].iloc[i]
            # logger.info clustering results for debugging
            logger.info(f"\nClustering results for branch {branch}:")
            for i, (idx, row) in enumerate(branch_df.iterrows()):
                logger.info(f"Subject '{row['subject']}': Summary {i} -> Cluster {clusters[i]}")

            # Assign cluster labels
            for i, idx in enumerate(branch_df.index):
                df.loc[idx, 'cluster'] = f"{branch}_{clusters[i]}"

        # Count entries in each cluster
        df['count'] = df.groupby('cluster')['cluster'].transform('count')
        df.to_csv(MIDDLE_FAILURES_CSV, index=True)

        # Identify representative rows for each cluster
        representative_rows = []
        seen_clusters = set()
        # Process clusters with aggregated=True first, as they are preferred representatives
        logger.info("\nProcessing clusters with aggregated=True as preferred representatives...")
        for idx, (cluster_id, cluster_df) in enumerate(df.groupby('cluster')):
            cluster_name = cluster_df['cluster'].iloc[0]
            cluster_size = len(cluster_df)

            logger.info(f"Cluster {idx+1}/{len(df['cluster'].unique())}: Cluster '{cluster_name}' with {cluster_size} entries")

            if cluster_name in seen_clusters:
                logger.info(f"  - Skipping cluster '{cluster_name}' (already processed)")
                continue

            # Try to find an aggregated=True row as representative
            aggregated_rows = cluster_df[cluster_df['aggregated']]
            logger.info(f"  - Found {len(aggregated_rows)} aggregated rows in this cluster")

            if not aggregated_rows.empty:
                # Use the first aggregated row as representative
                rep_row = aggregated_rows.iloc[0]
                representative_rows.append(rep_row)
                seen_clusters.add(cluster_name)
                logger.info(f"  - Added representative row with subject: '{rep_row['subject']}' to output")
            else:
                # If no aggregated=True rows, find a row with subject not in existing representatives
                existing_subjects = {r['subject'] for r in representative_rows}
                non_duplicate_rows = cluster_df[~cluster_df['subject'].isin(existing_subjects)]

                if not non_duplicate_rows.empty:
                    # Use the first row with a unique subject
                    rep_row = non_duplicate_rows.iloc[0]
                    representative_rows.append(rep_row)
                    seen_clusters.add(cluster_name)
                    logger.info(f"  - Added non-aggregated row with unique subject: '{rep_row['subject']}' to output")
                else:
                    # If all subjects already exist in representative_rows
                    logger.info(f"  - No subject for cluster: '{cluster_name}' to output")

            # For non-aggregated cases with multiple summaries that don't fit in existing clusters
            non_rep_cases = df[~df['aggregated'] & ~df['subject'].isin([r['subject'] for r in representative_rows])]

        # Group by subject and check if we need to keep these rows
        for case_name, case_df in non_rep_cases.groupby('subject'):
            unique_clusters = case_df['cluster'].unique()
            logger.info(f"Subject '{case_name}' has {len(unique_clusters)} clusters: {unique_clusters}")

            # Filter out clusters that are already in seen_clusters
            unseen_clusters = [cluster for cluster in unique_clusters if cluster not in seen_clusters]

            if not unseen_clusters:
                logger.info(f"  - Subject '{case_name}': All clusters are already processed, skipping")
                continue

            # If we still have only one unseen cluster after filtering
            if len(unseen_clusters) == 1:
                # Get the row with the unseen cluster
                unseen_row = case_df[case_df['cluster'] == unseen_clusters[0]].iloc[0]
                representative_rows.append(unseen_row)
                seen_clusters.add(unseen_clusters[0])
                logger.info(f"  - Subject '{case_name}': Added row with cluster '{unseen_clusters[0]}' to output")

            # If we still have multiple unseen clusters
            elif len(unseen_clusters) > 1:
                # Take the first row, set failure_summary to empty, and add to representative_rows
                representative_row = case_df.iloc[0].copy()
                representative_row['failure_summary'] = ''

                # Combine all unseen cluster names with a comma separator
                representative_row['cluster'] = ','.join(unseen_clusters)

                # Sum up the counts from all unique unseen clusters
                # Use drop_duplicates to count each cluster type only once
                unseen_cluster_df = case_df[case_df['cluster'].isin(unseen_clusters)].drop_duplicates('cluster')
                total_count = unseen_cluster_df['count'].sum()
                representative_row['count'] = total_count

                representative_rows.append(representative_row)
                logger.info(f"  - Subject '{case_name}': Added combined row with clusters '{representative_row['cluster']}' to output")

                # Add all unseen clusters to seen_clusters to avoid duplicates
                for cluster in unseen_clusters:
                    seen_clusters.add(cluster)
        # Check if all subjects in the original dataframe exist in representative_rows
        all_subjects = set(df['subject'])
        rep_subjects = set(r['subject'] for r in representative_rows)

        missing_subjects = all_subjects - rep_subjects
        if missing_subjects:
            logger.info(f"Note: {len(missing_subjects)} subjects from original dataframe are missing in representative rows:")
            for subject in missing_subjects:
                logger.info(f"  - Aggreated subject: '{subject}'")

        # Check for duplicate subjects in representative_rows
        subject_counts = {}
        for i, row in enumerate(representative_rows):
            subject = row['subject']
            if subject in subject_counts:
                subject_counts[subject].append(i)
            else:
                subject_counts[subject] = [i]

        # logger.info and handle duplicates
        duplicates = {subject: indices for subject, indices in subject_counts.items() if len(indices) > 1}
        if duplicates:
            logger.error(f"Warning: Found {len(duplicates)} subjects with duplicate entries in representative rows:")
            for subject, indices in duplicates.items():
                logger.error(f"  - Subject '{subject}' appears {len(indices)} times at indices: {indices}")
                # Keep only the first occurrence (you could implement a different strategy if needed)
                indices_to_remove = indices[1:]
                logger.info(f"  - Subject '{subject}': Keeping index {indices[0]}, removing indices {indices_to_remove}")
                # Remove duplicates in reverse order to avoid index shifting
                for idx in sorted(indices_to_remove, reverse=True):
                    representative_rows.pop(idx)
        # Return the final dataframe with representative rows
        return pd.DataFrame(representative_rows)

    def is_matched_active_icm(self, case_branch, target_summary, icm_branch, active_icm_df):
        """
        Check if the target_summary matches any summary in active_icm_df using clustering.
        Returns True and the matched row if a match is found, otherwise False and None.
        """
        active_icm_df['SourceCreateDate'] = pd.to_datetime(active_icm_df['SourceCreateDate'])
        valid_date = self.current_time - timedelta(days=configuration["threshold"]["summary_expiration_days"])

        valid_active_icm_df = active_icm_df[active_icm_df['SourceCreateDate'] >= valid_date]

        # Filter active_icm_df to only include rows with the same branch as the target_summary
        same_branch_df = valid_active_icm_df[valid_active_icm_df['Branch'] == icm_branch]

        if same_branch_df.empty:
            logger.info("{}: No active IcM found for branch {} in valid date scope".format(case_branch, icm_branch))
            return False, None

        # Prepare data for clustering
        # Create a DataFrame with the target summary and all active ICM summaries
        summaries = same_branch_df['FailureSummary'].tolist()
        summaries.append(target_summary)

        # Preprocess the summaries
        processed_summaries = [self.__preprocess_summary(s) for s in summaries]

        # Get the cluster assignments
        eps = configuration["threshold"]["eps"]
        clusters = self.cluster_summaries(processed_summaries, eps=eps, min_samples=1)

        # The target summary is the last one in the list
        target_cluster = clusters[-1]

        # Check if the target summary shares a cluster with any active ICM summary
        # (excluding noise points which have cluster label -1)
        if target_cluster != -1 and target_cluster in clusters[:-1]:
            # Find which active ICMs are in the same cluster
            same_cluster_indices = [i for i, c in enumerate(clusters[:-1]) if c == target_cluster]

            # Get the rows from same_branch_df that match these indices
            matched_rows = same_branch_df.iloc[same_cluster_indices]

            logger.debug("{}: Found {} matches in the same cluster".format(case_branch, len(matched_rows)))
            for index, row in matched_rows.iterrows():
                logger.debug("{}: Matched Row: Branch={}, CreatedDate={}\n Title={}\n Summary={}".format(
                    case_branch, icm_branch, row['SourceCreateDate'], row['Title'], row['FailureSummary']))

            # Return the first matched row
            return True, matched_rows.iloc[0]
        else:
            logger.info("{}: No matched IcM found for branch {} in valid date scope".format(case_branch, icm_branch))
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
                is_aggregated = self.is_same_cluster(failed_results_df, summary_col='Summary', eps=configuration["threshold"]["eps"], min_samples=1)
                if is_aggregated:
                    kusto_data['failure_summary'] = failed_results_df['Summary'].iloc[0]
                    logger.info("{}:{} {} {} {} Has similar summary and it can be aggregated: {}".format(case_branch, asic, topology, hwsku, osversion, kusto_data['failure_summary']))
                else:
                    kusto_data['failure_summary'] = ''
                    logger.info("{}:{} {} {} {} Doesn't have similar summary, so it can't be aggregated".format(case_branch, asic, topology, hwsku, osversion))
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
                    icm['trigger_icm'] = False
                    duplicated_icm_list.append(icm)
                    logger.info("{}: Found same title or higher title item in active IcM list, not trigger IcM:\n active IcM {}\t duplicated one {}".format(
                        case_branch, icm_title, icm['subject']))
                    break
            if not duplicated_flag and icm['failure_summary']:
                logger.info("{} has failure_summary:{}".format(case_branch, icm['failure_summary']))
                is_matched, matched_row = self.is_matched_active_icm(case_branch, icm['failure_summary'], branch, active_icm_df)
                if is_matched:
                    logger.info("{}: Found summary matched item in active IcM list, not trigger IcM:\n active IcM: {}\n summary:{}\n duplicated: {}\n summary:{}".format(
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
        # prefix with case and branch is also considered as a component
        # otherwise, only use level1 and level2 to check duplication is not enough
        # other case with same level1 and level2 will be considered as duplicated
        component.append(prefix)
        if level2.find('.') == -1:
            component.append(level2)
            level2 = None
            title2 = prefix
        else:
            level2 = level2[:level2.index('.')]
            if prefix.endswith("[" + level2 + "]"):
                title2 = prefix
            else:
                title2 = "{}[{}]".format(prefix, level2)

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


    def __preprocess_summary(self, text):
        """
        Lowercases, removes numbers and punctuation, and extra whitespace.
        Adjust this function if you have specific patterns to remove.
        """
        if pd.isna(text) or not text:
            return ''

        # text = text.lower()
        # text = re.sub(r'\d+', '', text)           # remove numbers
        # text = re.sub(r'[^\w\s]', '', text)         # remove punctuation
        # text = re.sub(r'\s+', ' ', text)            # collapse whitespace
        return text.strip()

    def cluster_summaries(self, summaries, eps=0.1, min_samples=1):
        """
        Cluster the list of summaries using TF-IDF vectorization and DBSCAN.
        eps: The maximum cosine distance for two summaries to be considered similar.
            You might need to tune this parameter.
        min_samples: Minimum samples in a cluster (set to 1 so every summary is in some cluster).
        Returns the cluster labels.
        """
        # Vectorize summaries with TF-IDF (removing common stopwords)
        vectorizer = TfidfVectorizer(stop_words='english')
        X = vectorizer.fit_transform(summaries)

        # Use DBSCAN with cosine distance (distance = 1 - cosine similarity)
        dbscan = DBSCAN(eps=eps, min_samples=min_samples, metric='cosine')
        clusters = dbscan.fit_predict(X)
        return clusters

    def is_same_cluster(self, df, summary_col='Summary', eps=0.1, min_samples=1):
        """
        Checks if all summaries in the dataframe belong to the same cluster.

        Args:
            df: DataFrame containing summaries to check
            summary_col: Column name containing the summaries
            eps: The maximum cosine distance for two summaries to be considered similar
            min_samples: Minimum samples in a cluster

        Returns:
            bool: True if all summaries belong to the same cluster, False otherwise
        """
        # If there's 0 or 1 row, they're trivially in the same cluster
        if len(df) <= 1:
            return True

        # Preprocess the summaries
        processed_summaries = df[summary_col].apply(self.__preprocess_summary)

        # Get the cluster assignments
        clusters = self.cluster_summaries(processed_summaries, eps=eps, min_samples=min_samples)
        logger.info(f"clusters:{clusters}")
        # Check if all cluster assignments are the same
        # We need to exclude any noise points (-1 in DBSCAN) from this check
        non_noise_clusters = clusters[clusters != -1]

        # If all points are noise, they're not in the same cluster
        if len(non_noise_clusters) == 0:
            return False

        # If there are non-noise points, check if they're all the same cluster
        return len(set(non_noise_clusters)) == 1