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
        self.max_ai_flaky_icm_limit = configuration['icm_limitation']['max_ai_flaky_icm_limit']
        self.max_flaky_icm_limit = configuration['icm_limitation']['max_flaky_icm_limit']

        # For each branch, set a limit for created IcMs
        default_icm_limit = configuration['icm_limitation']['default_branch_limit']
        for branch in configuration['branch']['included_branch']:
            icm_branch_limit_key = f"icm_{branch}_limit"
            # If there is a configured limit, that should take precedence to allow for overriding default
            icm_branch_limit = configuration['icm_limitation'].get(icm_branch_limit_key, default_icm_limit)
            setattr(self, icm_branch_limit_key, icm_branch_limit)

        self.HOST_RE = re.compile(
            r'^(?:[A-Za-z0-9]*(?:str|bjw)[A-Za-z0-9]*)'  # first part must contain 'str' or 'bjw'
            r'-'                         # first hyphen
            r'(?:[A-Za-z0-9]+(?:x\d+)?)'  # platform: alnum+, optional x+digits
            r'(?:-[A-Za-z0-9]+)*'        # any additional segments, hyphen + alnum+
            r'-(?:u\d+|\d+)$'            # final hyphen + either 'u' followed by digits or just digits
        )

    def deduplication(self, original_failure_dict, branches):
        """
        Deduplicate the IcM list, remove the duplicated IcM.
        """
        duplicated_icm_list = []
        unique_title = set()
        final_icm_list = []
        count_ai_flaky = 0  # Add counter for AI flaky cases
        count_flaky = 0  # Add counter for flaky failure type cases
        branch_counts = {branch: 0 for branch in branches}  # Initialize counts for each branch

        logger.info("limit the number of setup error cases to {}".format(self.setup_error_limit))
        logger.info("limit the number of general failure cases to {}".format(self.failure_limit))
        logger.info("limit the number of flaky failure cases to {}".format(self.max_flaky_icm_limit))
        logger.info("limit the number of AI flaky cases to {}".format(self.max_ai_flaky_icm_limit))

        # Logging limits for each branch
        for branch in branches:
            limit_name = f"icm_{branch}_limit"
            limit = getattr(self, limit_name, None)
            if limit is not None:
                logger.info(f"limit the number of {branch} cases to {limit}")

        for data in original_failure_dict:
            icm_table = data['table']
            failure_type = data['type']
            for candidator in icm_table:
                if candidator['subject'] in unique_title:
                    candidator['trigger_icm'] = False
                    duplicated_icm_list.append(candidator)
                    logger.info(f"Found duplicated item in appending IcM list, not trigger IcM for: "
                                f"{candidator['subject']}")
                    continue

                unique_title.add(candidator['subject'])
                duplicated_flag = False

                for uploading_new_icm in final_icm_list:
                    duplicated_flag = self.check_duplicates(uploading_new_icm['subject'], candidator)
                    if duplicated_flag:
                        duplicated_icm_list.append(candidator)
                        logger.info(f"Found lower case, not trigger IcM: the IcM in final_icm_list "
                                    f"{uploading_new_icm['subject']}, duplicated one {candidator['subject']}")
                        break
                    duplicated_flag = self.check_duplicates(candidator['subject'], uploading_new_icm)
                    if duplicated_flag:
                        logger.info(f"Found lower case, replace {uploading_new_icm['subject']} "
                                    f"in final_icm_list with {candidator['subject']}")
                        final_icm_list.remove(uploading_new_icm)
                        duplicated_icm_list.append(uploading_new_icm)
                        final_icm_list.append(candidator)
                        duplicated_flag = True
                        break

                if not duplicated_flag:
                    candidator_branch = candidator['branch']

                    # Check AI flaky limit
                    if failure_type == 'ai_flaky':
                        if count_ai_flaky >= self.max_ai_flaky_icm_limit:
                            logger.info(f"Reach the limit of AI flaky cases: {self.max_ai_flaky_icm_limit}, "
                                        f"ignore this IcM {candidator['subject']}")
                            candidator['trigger_icm'] = False
                            continue
                        count_ai_flaky += 1

                    # Check flaky failure type limit
                    if failure_type == 'flaky':
                        if count_flaky >= self.max_flaky_icm_limit:
                            logger.info(f"Reach the limit of flaky failure cases: {self.max_flaky_icm_limit}, "
                                        f"ignore this IcM {candidator['subject']}")
                            candidator['trigger_icm'] = False
                            continue
                        count_flaky += 1

                    # Check that this branch is part of a release we care about
                    # (i.e. 20231105, if we have specified 202311 in config)
                    candidator_branch_prefix_list = [
                        branch for branch in branch_counts.keys()
                        if candidator_branch.startswith(branch)]

                    if len(candidator_branch_prefix_list) > 0:
                        candidator_branch_prefix = candidator_branch_prefix_list[0]
                        branch_limit_attr = f"icm_{candidator_branch_prefix}_limit"
                        branch_limit = getattr(self, branch_limit_attr)
                        if branch_counts[candidator_branch_prefix] >= branch_limit:
                            logger.info(f"Reach the limit of {candidator_branch_prefix} case: "
                                        f"{branch_limit}, ignore this IcM {candidator['subject']}")
                            candidator['trigger_icm'] = False
                            continue
                        branch_counts[candidator_branch_prefix] += 1

                    logger.info(f"Add branch {candidator_branch} type {failure_type} : "
                                f"{candidator['subject']} to final_icm_list")
                    final_icm_list.append(candidator)

        logger.info(f"Count summary: ai_flaky {count_ai_flaky}, flaky {count_flaky}, " +
                    ", ".join(f"{branch} {count}" for branch, count in branch_counts.items()))
        for kusto_row_item in final_icm_list:
            self.check_subject_match(kusto_row_item)
        for kusto_row_item in duplicated_icm_list:
            self.check_subject_match(kusto_row_item)
        logger.debug(f"duplicated_icm_list={json.dumps(duplicated_icm_list, indent=4)}")
        logger.debug(f"final_icm_list={json.dumps(final_icm_list, indent=4)}")

        return final_icm_list, duplicated_icm_list

    def check_subject_match(self, kusto_row):
        """
        Check if the subject match with asic/hwsku/osversion
        """
        asic_name = (kusto_row['failure_level_info']['asic']
                     if 'asic' in kusto_row['failure_level_info'] else None)
        hwsku_name = (kusto_row['failure_level_info']['hwsku']
                      if 'hwsku' in kusto_row['failure_level_info'] else None)
        osversion_name = (kusto_row['failure_level_info']['osversion']
                          if 'osversion' in kusto_row['failure_level_info'] else None)
        subject_name = kusto_row['subject']
        if asic_name and asic_name not in subject_name:
            logger.error("In check_subject_match: asic {} not in subject {}".format(
                asic_name, subject_name))
        if hwsku_name and hwsku_name not in subject_name:
            logger.error("In check_subject_match: hwsku {} not in subject {}".format(
                hwsku_name, subject_name))
        if osversion_name and osversion_name not in subject_name:
            logger.error("In check_subject_match: osversion {} not in subject {}".format(
                osversion_name, subject_name))

        return

    def prepare_data_for_clustering(self, failure_new_icm_table):
        """
        Prepares data for clustering by removing duplicates and NaN values.
        """
        failures_df = pd.DataFrame(
            failure_new_icm_table,
            columns=['full_casename', 'subject', 'branch', 'failure_summary']
        )
        # Add topology, asic, hwsku and os_version columns from failure_level_info
        failures_df['topology'] = [
            item.get('failure_level_info', {}).get('topology', '') for item in failure_new_icm_table]
        failures_df['asic'] = [
            item.get('failure_level_info', {}).get('asic', '') for item in failure_new_icm_table]
        failures_df['hwsku'] = [
            item.get('failure_level_info', {}).get('hwsku', '') for item in failure_new_icm_table]
        failures_df['os_version'] = [
            item.get('failure_level_info', {}).get('os_version', '') for item in failure_new_icm_table]

        return failures_df

    def find_similar_summaries_and_count(self, dataframe_data, week_failure_df):
        """
        Groups similar failure summaries by branch and counts how many entries are in each group.
        Process cases with empty summaries by retrieving all their failure summaries from week_failure_df.
        Aggregates similar summaries and keeps representative cases.

        Args:
            dataframe_data: DataFrame with columns [full_casename, subject, branch, failure_summary,
                           topology, asic, hwsku, os_version]
            week_failure_df: DataFrame containing all failure data with Summaries across branches and testbeds

        Returns:
            DataFrame containing filtered data with 'cluster', 'count', and 'aggregated' columns
        """
        # Create a copy and initialize the aggregated column
        df = dataframe_data.copy()
        # Return early if the dataframe is empty
        if len(df) == 0:
            logger.info("No failure data to process - returning empty dataframes")
            return pd.DataFrame()
        df['aggregated'] = df['failure_summary'].apply(
            lambda x: False if pd.isna(x) or not x else True)
        # Create processed_summary column for storing preprocessed versions
        df['processed_summary'] = df['failure_summary'].copy()

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
                            new_row['failure_summary'] = match_row['Summary']  # Keep original summary as is
                            new_row['processed_summary'] = match_row['Summary']  # Will be processed later
                            rows_to_add.append(new_row)
                            logger.info(f"Subject '{row['subject']}': Added new row with summary "
                                        f"{new_row['failure_summary'][:80]}")

        # Apply the changes to the dataframe
        if rows_to_drop:
            df = df.drop(rows_to_drop, axis=0)

        if rows_to_add:
            df = pd.concat([df, pd.DataFrame(rows_to_add)], ignore_index=True)

        # Verify that we don't have empty summaries after processing
        empty_summary_rows = df[df['failure_summary'].isna() | (df['failure_summary'] == '')]
        if not empty_summary_rows.empty:
            logger.error(f"\nFound {len(empty_summary_rows)} rows with empty summaries after "
                         f"filling process:")
            for idx, row in empty_summary_rows.iterrows():
                logger.error(f"  - Subject '{row['subject']}': Case: {row['full_casename']}, "
                             f"Branch: {row['branch']}")

        else:
            logger.info("\nNo empty summaries found after filling process.")

        # Initialize the cluster column
        df['cluster'] = None

        # Create branch group column for clustering
        df['branch_group'] = df['branch'].apply(self.get_branch_group)

        # Process each branch group separately for clustering
        for branch_group, branch_group_df in df.groupby('branch_group'):
            # Skip empty summaries
            to_cluster = branch_group_df[
                ~branch_group_df['processed_summary'].isna() &
                (branch_group_df['processed_summary'] != '')]

            if to_cluster.empty:
                logger.error(f"Branch group {branch_group}: No summaries to cluster")
                continue

            # Log the actual branches being processed in this group
            actual_branches = set(branch_group_df['branch'].unique())
            logger.info(f"Processing branch group '{branch_group}' containing branches: {actual_branches}")

            # Preprocess the summaries and save to processed_summary column
            # This preserves the original failure_summary
            branch_group_df['processed_summary'] = branch_group_df['processed_summary'].apply(self.__preprocess_summary)

            # Log summaries before clustering for debugging
            logger.info(f"\nSummaries for branch group {branch_group}:")
            for i, (idx, row) in enumerate(branch_group_df.iterrows()):
                logger.info(f"{i}: Subject '{row['subject']}': {row['processed_summary'][:100]}...")

            # Get the cluster assignments with a stricter eps value based on processed summaries
            eps = configuration["threshold"]["eps"]
            clusters = self.cluster_summaries(branch_group_df['processed_summary'], eps=eps, min_samples=1)

            # Update the processed_summary column in the main dataframe
            for i, idx in enumerate(branch_group_df.index):
                df.loc[idx, 'processed_summary'] = branch_group_df['processed_summary'].iloc[i]

            # Log clustering results for debugging
            logger.info(f"\nClustering results for branch group {branch_group}:")
            for i, (idx, row) in enumerate(branch_group_df.iterrows()):
                logger.info(f"Subject '{row['subject']}': Summary {i} -> Cluster {clusters[i]}")

            # Assign cluster labels (include branch group in cluster name for uniqueness)
            for i, idx in enumerate(branch_group_df.index):
                df.loc[idx, 'cluster'] = f"{branch_group}_{clusters[i]}"

        # Count entries in each cluster
        df['count'] = df.groupby('cluster')['cluster'].transform('count')
        df.to_csv(MIDDLE_FAILURES_CSV, index=True)

        # Identify representative rows for each cluster
        representative_rows = []
        seen_clusters = set()
        # Process clusters with aggregated=True first, as they are preferred representatives
        logger.info("\nProcessing clusters with aggregated=True as preferred "
                    "representatives...")
        for idx, (cluster_id, cluster_df) in enumerate(df.groupby('cluster')):
            cluster_name = cluster_df['cluster'].iloc[0]
            cluster_size = len(cluster_df)

            logger.info(f"Cluster {idx+1}/{len(df['cluster'].unique())}: Cluster '{cluster_name}' "
                        f"with {cluster_size} entries")

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
                unseen_cluster_df = case_df[case_df['cluster'].isin(unseen_clusters)].drop_duplicates(
                    'cluster')
                total_count = unseen_cluster_df['count'].sum()
                representative_row['count'] = total_count

                representative_rows.append(representative_row)
                logger.info(f"  - Subject '{case_name}': Added combined row with clusters "
                            f"'{representative_row['cluster']}' to output")

                # Add all unseen clusters to seen_clusters to avoid duplicates
                for cluster in unseen_clusters:
                    seen_clusters.add(cluster)
        # Check if all subjects in the original dataframe exist in representative_rows
        all_subjects = set(df['subject'])
        rep_subjects = set(r['subject'] for r in representative_rows)

        missing_subjects = all_subjects - rep_subjects
        if missing_subjects:
            logger.info(f"Note: {len(missing_subjects)} subjects from original dataframe are missing "
                        f"in representative rows:")
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
        duplicates = {subject: indices for subject, indices in subject_counts.items()
                      if len(indices) > 1}
        if duplicates:
            logger.error(f"Warning: Found {len(duplicates)} subjects with duplicate entries in representative rows:")
            for subject, indices in duplicates.items():
                logger.error(f"  - Subject '{subject}' appears {len(indices)} times at indices: {indices}")
                # Keep only the first occurrence (you could implement a different strategy if needed)
                indices_to_remove = indices[1:]
                logger.info(f"  - Subject '{subject}': Keeping index {indices[0]}, "
                            f"removing indices {indices_to_remove}")
                # Remove duplicates in reverse order to avoid index shifting
                for idx in sorted(indices_to_remove, reverse=True):
                    representative_rows.pop(idx)
        # Return the final dataframe with representative rows
        return pd.DataFrame(representative_rows)

    def get_branch_group(self, branch):
        """
        Group master and internal branches together, keep others separate.
        Also group branches with same 6-digit prefix (e.g., 20250510 and 20250505 -> 202505)
        """
        if branch.lower() in ['master', 'internal']:
            return 'master_internal'
        else:
            # Check if branch starts with digits (like 20250510, 20250505)
            if branch.isdigit() and len(branch) >= 6:
                # Return the first 6 digits as the group identifier
                return branch[:6]
            else:
                # For other branches, return as-is
                return branch

    def is_matched_active_icm(self, case_branch, target_summary, icm_branch, active_icm_df):
        """
        Check if the target_summary matches any summary in active_icm_df using clustering.
        Returns True and the matched row if a match is found, otherwise False and None.
        """
        active_icm_df['SourceCreateDate'] = pd.to_datetime(active_icm_df['SourceCreateDate'])
        valid_date = self.current_time - timedelta(days=configuration["threshold"]["summary_expiration_days"])

        valid_active_icm_df = active_icm_df[active_icm_df['SourceCreateDate'] >= valid_date]

        # Get the branch group for the target ICM branch
        target_branch_group = self.get_branch_group(icm_branch)

        # Filter active_icm_df to only include rows with the same branch group as the target_summary
        # For master/internal, this will match both branches; for others, use branch group logic
        if target_branch_group == 'master_internal':
            same_branch_df = valid_active_icm_df[
                valid_active_icm_df['Branch'].str.lower().isin(['master', 'internal'])]
        else:
            # For numeric branches, match by branch group (first 6 digits)
            # For other branches, match exactly
            same_branch_df = valid_active_icm_df[
                valid_active_icm_df['Branch'].apply(self.get_branch_group) == target_branch_group]

        if same_branch_df.empty:
            logger.info("{}: No active IcM found for branch group {} (branch: {}) in valid date scope"
                        .format(case_branch, target_branch_group, icm_branch))
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

            logger.debug("{}: Found {} matches in the same cluster"
                         .format(case_branch, len(matched_rows)))
            for index, row in matched_rows.iterrows():
                logger.debug("{}: Matched Row: Branch={}, BranchGroup={}, CreatedDate={}\n "
                             "Title={}\n Summary={}".format(
                                 case_branch, row['Branch'], target_branch_group,
                                 row['SourceCreateDate'], row['Title'], row['FailureSummary']))

            # Return the first matched row
            return True, matched_rows.iloc[0]
        else:
            logger.info("{}: No matched IcM found for branch group {} (branch: {}) in valid date scope"
                        .format(case_branch, target_branch_group, icm_branch))
            return False, None

    def is_same_with_active_icm_by_gpt(self, target_summary, active_icm_df):
        """
        Check if the target_summaryis is same with any of summary in active_icm_df by Chatgpt
        """
        # TODO:
        pass

    def is_in_weekly_failure(self, case_branch, kusto_data, week_failed_testcases_df, condition={}):
        if week_failed_testcases_df is None:
            logger.info("week_failed_testcases_df is None")
            return kusto_data, False

        week_failed_testcases_df_copy = week_failed_testcases_df.copy()  # Create a copy of the DataFrame
        for topology_config in configuration["icm_decision_config"]["topology"]["types"]:
            week_failed_testcases_df_copy['Topology'] = week_failed_testcases_df_copy['Topology'].replace(
                topology_config["testbed_topology"], topology_config["id"])

        # Add conditional filters if they exist
        asic = condition.get('asic')
        topology = condition.get('topology')
        hwsku = condition.get('hwsku')
        osversion = condition.get('osversion')
        logger.info("{}: asic={}, topology={}, hwsku={}, osversion={}"
                    .format(case_branch, asic, topology, hwsku, osversion))

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
        logger.debug(f"query_string={query_string}")
        # Apply the combined filters to get the filtered DataFrame
        failed_results_df = week_failed_testcases_df_copy.query(query_string)

        logger.debug("{} failed_results_df=\n{}".format(case_branch, failed_results_df[['TestCase', 'Summary']]))
        if len(failed_results_df) == 0:
            logger.error(f"{case_branch}: with asic:{asic} topology:{topology} hwsku:{hwsku} "
                         f"osversion:{osversion}, No failed results found in 7 days results, "
                         f"don't trigger IcM.")
            return failed_results_df, False
        return failed_results_df, True

    def set_failure_summary(self, kusto_data_list, week_failed_testcases_df):
        if week_failed_testcases_df is None:
            logger.info("week_failed_testcases_df is None")
            return kusto_data_list
        for kusto_data in kusto_data_list:
            condition = {}
            case_branch = kusto_data['module_path'] + '.' + kusto_data['testcase'] + "#" + kusto_data['branch']
            condition['asic'] = kusto_data['failure_level_info'].get('asic')
            condition['topology'] = kusto_data['failure_level_info'].get('topology')
            condition['hwsku'] = kusto_data['failure_level_info'].get('hwsku')
            condition['osversion'] = kusto_data['failure_level_info'].get('osversion')
            logger.debug(f"{case_branch}: with condition={condition} Setting failure summary...")
            failed_results_df, _ = self.is_in_weekly_failure(case_branch, kusto_data,
                                                             week_failed_testcases_df, condition)
            case_branch = (kusto_data['module_path'] + '.' + kusto_data['testcase'] +
                           "#" + kusto_data['branch'])
            asic = kusto_data['failure_level_info'].get('asic')
            topology = kusto_data['failure_level_info'].get('topology')
            hwsku = kusto_data['failure_level_info'].get('hwsku')
            osversion = kusto_data['failure_level_info'].get('osversion')
            if len(failed_results_df) > 0:
                is_aggregated = self.is_same_cluster(failed_results_df, summary_col='Summary',
                                                     eps=configuration["threshold"]["eps"],
                                                     min_samples=1)
                if is_aggregated:
                    kusto_data['failure_summary'] = failed_results_df['Summary'].iloc[0]
                    logger.info("{}:{} {} {} {} Has similar summary and it can be aggregated: {}"
                                .format(case_branch, asic, topology, hwsku, osversion,
                                        kusto_data['failure_summary']))
                else:
                    kusto_data['failure_summary'] = ''
                    logger.info("{}:{} {} {} {} Doesn't have similar summary, so it can't be aggregated"
                                .format(case_branch, asic, topology, hwsku, osversion))
            else:
                kusto_data['failure_summary'] = ''
                kusto_data['trigger_icm'] = False
                logger.error("{}: No failed results found in 7 days results, don't trigger IcM. "
                             "Ignore it.".format(case_branch))
        no_summary_count = sum(1 for icm in kusto_data_list if 'failure_summary' not in icm)
        has_summary_count = sum(1 for icm in kusto_data_list if 'failure_summary' in icm)
        logger.info("{}:Number of cases without failure_summary:{}".format(case_branch, no_summary_count))
        logger.info("{}:Number of cases with failure_summary:{}".format(case_branch, has_summary_count))
        return kusto_data_list

    def deduplicate_summary_with_active_icm(self, aggregated_df, active_icm_df):
        """
        Check if any summary in aggregated_df has the same cluster with summaries in active_icm_df.
        Only check active ICMs created within summary_expiration_days for the same branch.
        Return aggregated_df with duplicated entries removed and a separate DataFrame with duplicated entries.
        """
        if aggregated_df.empty:
            logger.info("aggregated_df is empty, returning empty DataFrames")
            return aggregated_df, pd.DataFrame()

        if active_icm_df.empty:
            logger.info("active_icm_df is empty, no need to check duplication")
            return aggregated_df, pd.DataFrame()

        # Get summary_expiration_days from configuration
        summary_expiration_days = configuration["threshold"]["summary_expiration_days"]
        current_time = self.current_time

        # Filter active_icm_df to only include recent entries (within summary_expiration_days)
        cutoff_date = current_time - timedelta(days=summary_expiration_days)

        recent_active_icm_df = active_icm_df[
            (pd.to_datetime(active_icm_df['SourceCreateDate']) >= cutoff_date) &
            (active_icm_df['FailureSummary'].notna()) &
            (active_icm_df['FailureSummary'] != '')
        ]

        if recent_active_icm_df.empty:
            logger.info("No recent active ICMs with valid summaries found")
            return aggregated_df, pd.DataFrame()

        # Group by branch group to process each branch group separately
        deduplicated_rows = []
        duplicated_rows = []

        # Create branch groups for aggregated_df
        aggregated_df_copy = aggregated_df.copy()
        aggregated_df_copy['branch_group'] = aggregated_df_copy['branch'].apply(
            self.get_branch_group)

        for branch_group, branch_group_aggregated_df in aggregated_df_copy.groupby(
                'branch_group'):
            logger.info(f"Processing branch group: {branch_group}")

            # Filter recent active ICMs for the same branch group
            if branch_group == 'master_internal':
                branch_active_icm_df = recent_active_icm_df[
                    recent_active_icm_df['Branch'].str.lower().isin(['master', 'internal'])]
            else:
                # For numeric branches, match by branch group (first 6 digits)
                # For other branches, match exactly
                branch_active_icm_df = recent_active_icm_df[
                    recent_active_icm_df['Branch'].apply(self.get_branch_group) == branch_group]

            if branch_active_icm_df.empty:
                logger.info(f"No recent active ICMs found for branch group {branch_group}")
                deduplicated_rows.extend(branch_group_aggregated_df.to_dict('records'))
                continue

            # Log the actual branches being compared in this group
            aggregated_branches = set(branch_group_aggregated_df['branch'].unique())
            active_icm_branches = set(branch_active_icm_df['Branch'].unique())
            logger.info(f"Aggregated branches in group: {aggregated_branches}")
            logger.info(f"Active ICM branches in group: {active_icm_branches}")

            # Extract summaries for clustering
            aggregated_summaries = branch_group_aggregated_df['failure_summary'].dropna().tolist()
            active_icm_summaries = branch_active_icm_df['FailureSummary'].tolist()

            if not aggregated_summaries or not active_icm_summaries:
                logger.info(f"No valid summaries found for branch group {branch_group}")
                deduplicated_rows.extend(branch_group_aggregated_df.to_dict('records'))
                continue

            # Preprocess summaries
            aggregated_summaries_processed = [self.__preprocess_summary(s)
                                              for s in aggregated_summaries]
            active_icm_summaries_processed = [self.__preprocess_summary(s)
                                              for s in active_icm_summaries]

            # Combine all summaries for clustering
            all_summaries = aggregated_summaries_processed + active_icm_summaries_processed

            # Perform clustering
            eps = configuration["threshold"]["eps"]
            clusters = self.cluster_summaries(all_summaries, eps=eps, min_samples=1)

            # Identify clusters containing active ICM summaries
            active_icm_clusters = set(clusters[len(aggregated_summaries_processed):])

            # Filter aggregated summaries that don't belong to active clusters
            aggregated_clusters = clusters[:len(aggregated_summaries_processed)]

            # Create mapping from aggregated summary index to cluster
            valid_aggregated_indices = branch_group_aggregated_df.index[
                branch_group_aggregated_df['failure_summary'].notna()].tolist()

            removed_count = 0
            for i, (orig_idx, cluster) in enumerate(zip(valid_aggregated_indices, aggregated_clusters)):
                row_dict = branch_group_aggregated_df.loc[orig_idx].to_dict()

                if cluster not in active_icm_clusters:
                    # Keep this row as it doesn't match any active ICM cluster
                    deduplicated_rows.append(row_dict)
                else:
                    duplicated_rows.append(row_dict)
                    removed_count += 1
                    # Find the matched active ICM record for this cluster
                    matched_active_icm = None
                    for j, active_cluster in enumerate(clusters[len(aggregated_summaries_processed):]):
                        if active_cluster == cluster:
                            matched_active_icm = branch_active_icm_df.iloc[j]
                            break

                    if matched_active_icm is not None:
                        logger.info(f"Marking as duplicate: subject '{row_dict.get('subject', 'N/A')}' - "
                                    f"matches active ICM cluster {cluster}")
                        logger.info(f"  Matched active ICM title: "
                                    f"'{matched_active_icm.get('Title', 'N/A')}'")
                        logger.info(f"  Matched active ICM summary: "
                                    f"'{matched_active_icm.get('FailureSummary', 'N/A')}'")
                        logger.info(f"  Duplicated row summary: "
                                    f"'{row_dict.get('failure_summary', 'N/A')}'")

                    else:
                        logger.info(f"Marking as duplicate: subject '{row_dict.get('subject', 'N/A')}' - "
                                    f"matches active ICM cluster {cluster} (no specific match found)")

            # Add rows with empty failure_summary (they can't be duplicates)
            empty_summary_rows = branch_group_aggregated_df[
                (branch_group_aggregated_df['failure_summary'].isna()) |
                (branch_group_aggregated_df['failure_summary'] == '')]
            for _, empty_row in empty_summary_rows.iterrows():
                empty_row_dict = empty_row.to_dict()
                logger.debug(f"Branch group {branch_group}: found empty summary row, "
                             f"append it to deduplicated_rows: {empty_row_dict.get('subject', 'N/A')}")
                deduplicated_rows.append(empty_row_dict)

            logger.info(f"Branch group {branch_group}: Found {removed_count} entries that match active ICM clusters")

        # Create new DataFrames from deduplicated and duplicated rows
        if deduplicated_rows:
            deduplicated_df = pd.DataFrame(deduplicated_rows)
        else:
            deduplicated_df = pd.DataFrame(columns=aggregated_df.columns)
            logger.info("All entries were marked as duplicates, deduplicated_df is empty.")

        if duplicated_rows:
            duplicated_df = pd.DataFrame(duplicated_rows)
        else:
            duplicated_df = pd.DataFrame()
            logger.info("No duplicated entries found.")

        logger.info(f"Total entries before deduplication with active IcM summaries: {len(aggregated_df)}")
        logger.info(f"Total entries after deduplication with active IcM summaries: {len(deduplicated_df)}")
        logger.info(f"Total duplicated entries found: {len(duplicated_df)}")

        return deduplicated_df, duplicated_df

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
                    logger.info("{}: Found same title or higher title item in active IcM list, "
                                "not trigger IcM:\n active IcM {}\t duplicated one {}"
                                .format(case_branch, icm_title, icm['subject']))
                    break
            if not duplicated_flag and icm['failure_summary']:
                logger.info("{} has failure_summary:{}"
                            .format(case_branch, icm['failure_summary']))
                is_matched, matched_row = self.is_matched_active_icm(
                        case_branch, icm['failure_summary'], branch, active_icm_df)
                if is_matched:
                    logger.info("{}: Found summary matched item in active IcM list, not trigger IcM:\n "
                                "active IcM: {}\n summary:{}\n duplicated: {}\n summary:{}"
                                .format(case_branch, matched_row['Title'], matched_row['FailureSummary'],
                                        icm['subject'], icm['failure_summary']))

                    icm['trigger_icm'] = False
                    duplicated_icm_list.append(icm)
                    duplicated_flag = True
                    continue
            if not duplicated_flag:
                logger.info("Got new IcM for this run: {} idx = {}"
                            .format(icm['subject'], idx))
                new_icm_list.append(icm)
                new_icm_count += 1
        updated_icm_count_dict = copy.deepcopy(icm_count_dict)
        logger.info("{}: There are {} new IcMs for this run".format(
            case_branch, new_icm_count))
        return new_icm_list, duplicated_icm_list, updated_icm_count_dict

    def combined_level_split(self, title):
        """
        Split the title for combined level
        e.g. split [case_a][branch_b][hwskuA_20240510.16] into [case_a][branch_b][hwskuA] and
             [case_a][branch_b][20240510.16]
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
            # [case_a][20240510][topologyA_hwskuC] is duplicated with [case_a][20240510][topologyA][asicB][hwskuC]
            if all(component in active_icm_title for component in components):
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

        text = text.lower()
        # text = re.sub(r'\d+', '', text)           # remove numbers
        # text = re.sub(r'[^\w\s]', '', text)         # remove punctuation
        # Pattern to match timestamps in both formats:
        # 1. At start of line: YYYY MMM DD HH:MM:SS.mmmmmm
        # 2. In middle of line: YYYY-MM-DD HH:MM:SS.mmmmmm
        # 3. Delta format: 0:00:00.039462
        timestamp_patterns = [
            r'^\d{4}\s+[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\.\d+\s+',  # Start of line format
            r'\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+',  # Middle of line format
            r'\d+:\d{2}:\d{2}\.\d+'  # Delta format
        ]

        # Process each line
        cleaned_lines = []
        for line in text.split('\n'):
            if line.strip():  # Skip empty lines
                # Remove timestamps
                for pattern in timestamp_patterns:
                    line = re.sub(pattern, '', line)

                # Pattern to match hostname with various delimiters
                # Matches: (start of line or space or hyphen or [ or " or ' or :) + hostname +
                # (space or quote or angle bracket or square bracket or - or , or })
                hostname_pattern = (r'(?:^|\s+|-|\[|"|\'|:)(' + self.HOST_RE.pattern[1:-1] +
                                    r')(?=[\s\'">\]]|-|,|}|$)')

                # Remove hostnames
                line = re.sub(hostname_pattern, '', line)
                cleaned_lines.append(line)
        cleaned_lines = '\n'.join(cleaned_lines)
        if "traceback" in cleaned_lines or "analyze_logs" in cleaned_lines:
            # logger.info("Remove numbers from summary since it's a traceback or analyze log")
            cleaned_lines = re.sub(r'\d+', '', cleaned_lines)           # remove numbers
        return cleaned_lines

    def cluster_summaries(self, summaries, eps=0.1, min_samples=1):
        """
        Cluster the list of summaries using TF-IDF vectorization and DBSCAN.
        eps: The maximum cosine distance for two summaries to be considered similar.
            You might need to tune this parameter.
        min_samples: Minimum samples in a cluster (set to 1 so every summary is in some cluster).
        Returns the cluster labels.

        Note: The input summaries should already be preprocessed.
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

    def deduplicate_dataframe_clusters(self, reference_df, target_df):
        """
        Compare two aggregated dataframes and remove duplicated cluster entries from target_df.
        Only removes duplicates when they are from the same branch group.
        Special handling: "master" and "internal" branches are treated as the same group.

        Args:
            reference_df: DataFrame containing reference test cases to compare against
            target_df: DataFrame containing target test cases to be deduplicated

        Returns:
            deduplicated_target_df: DataFrame with target cases that don't belong to the same clusters
                                as reference cases
        """
        if reference_df.empty or target_df.empty:
            logger.info("Either reference_df or target_df is empty, returning original target_df")
            return target_df

        # Convert branch values to strings in both dataframes
        reference_df['branch'] = reference_df['branch'].astype(str)
        target_df['branch'] = target_df['branch'].astype(str)

        # Create branch group columns
        reference_df_copy = reference_df.copy()
        target_df_copy = target_df.copy()
        reference_df_copy['branch_group'] = reference_df_copy['branch'].apply(self.get_branch_group)
        target_df_copy['branch_group'] = target_df_copy['branch'].apply(self.get_branch_group)

        # Process each branch group separately
        all_indices_to_drop = []

        for branch_group in target_df_copy['branch_group'].unique():
            logger.info(f"\nProcessing branch group: {branch_group}")

            # Get dataframes for current branch group
            branch_reference_df = reference_df_copy[reference_df_copy['branch_group'] == branch_group]
            branch_target_df = target_df_copy[target_df_copy['branch_group'] == branch_group]

            if branch_reference_df.empty or branch_target_df.empty:
                logger.info(f"No data to compare for branch group {branch_group}")
                continue

            # Log the actual branches being compared in this group
            ref_branches = set(branch_reference_df['branch'].unique())
            target_branches = set(branch_target_df['branch'].unique())
            logger.info(f"Reference branches in group: {ref_branches}")
            logger.info(f"Target branches in group: {target_branches}")

            # Extract failure summaries for current branch group
            reference_summaries = branch_reference_df['failure_summary'].dropna().tolist()
            target_summaries = branch_target_df['failure_summary'].dropna().tolist()

            if not reference_summaries or not target_summaries:
                logger.info(f"No valid failure summaries found in branch group {branch_group}")
                continue

            logger.info(f"Processing {len(reference_summaries)} reference summaries and "
                        f"{len(target_summaries)} target summaries for branch group {branch_group}")

            # Preprocess all summaries
            reference_summaries_processed = [self.__preprocess_summary(s) for s in reference_summaries]
            target_summaries_processed = [self.__preprocess_summary(s) for s in target_summaries]

            # Create a mapping from index to processed summary for target_df
            target_summary_mapping = {}
            valid_indices = branch_target_df.index[branch_target_df['failure_summary'].notna()]
            for idx, summary in zip(valid_indices, target_summaries_processed):
                target_summary_mapping[idx] = summary

            # Combine all summaries for clustering
            all_summaries_processed = reference_summaries_processed + target_summaries_processed

            # Perform clustering on all summaries
            eps = configuration["threshold"]["eps"]
            clusters = self.cluster_summaries(all_summaries_processed, eps=eps, min_samples=1)

            # Identify clusters containing reference failures
            reference_clusters = set(clusters[:len(reference_summaries_processed)])

            # Map each target summary to its cluster
            target_clusters = clusters[len(reference_summaries_processed):]

            # Create a mapping from target summary index to its cluster
            target_cluster_mapping = {}
            valid_target_indices = branch_target_df.index[branch_target_df['failure_summary'].notna()]
            for i, summary_idx in enumerate(valid_target_indices):
                if i < len(target_clusters):
                    target_cluster_mapping[summary_idx] = target_clusters[i]

            # Identify indices of target rows to drop (those that belong to reference clusters)
            branch_indices_to_drop = []
            for idx, cluster in target_cluster_mapping.items():
                if cluster in reference_clusters:
                    branch_indices_to_drop.append(idx)
                    target_row = target_df.loc[idx]
                    logger.debug(f"Found duplicate cluster for subject: {target_row['subject']}")
                    logger.debug(f"Target branch: {target_row['branch']}")
                    logger.debug(f"Branch group: {branch_group}")
                    logger.debug(f"Cluster ID: {cluster}")
                    logger.debug(f"Summary: {target_row['failure_summary']}")

            all_indices_to_drop.extend(branch_indices_to_drop)
            logger.info(f"Branch group {branch_group}: Removed {len(branch_indices_to_drop)} "
                        f"target entries with clusters matching reference cases")

        # Create a copy of target_df without the duplicate clusters
        deduplicated_target_df = target_df.drop(all_indices_to_drop)

        logger.info(f"\nTotal removed: {len(all_indices_to_drop)} "
                    f"target entries with clusters matching reference cases")
        logger.info(f"Total kept: {len(deduplicated_target_df)} unique target entries")

        return deduplicated_target_df

    def filter_out_icm_list(self, failure_type, original_icm_table, aggregated_df, trigger_icm=True):
        if len(aggregated_df) == 0:
            logger.error(f"No aggregated {failure_type} failure cases found, please check the data.")
            subject_to_summary = {}
        else:
            # Create a mapping from subject to failure_summary
            subject_to_summary = dict(zip(aggregated_df['subject'], aggregated_df['failure_summary']))

        # Update original_icm_table items with the aggregated failure_summary and trigger_icm
        aggregated_icm_list = []
        for item in original_icm_table:
            if item['subject'] in subject_to_summary:
                if item['failure_summary'] == '' or not item['failure_summary']:
                    logger.debug(f"{failure_type}: {item['subject']} summary is empty, "
                                 f"will use the one in the aggregated_dedup_df")
                    item['failure_summary'] = subject_to_summary[item['subject']]
                elif item['failure_summary'] != subject_to_summary[item['subject']]:
                    logger.debug(f"{failure_type}: {item['subject']} summary is not same as "
                                 f"the one in the aggregated_dedup_df")
                    logger.debug(f"  - Original: {item['failure_summary']}")
                    logger.debug(f"  - Updated: {subject_to_summary[item['subject']]}")
                    item['failure_summary'] = subject_to_summary[item['subject']]

                if trigger_icm is False:
                    original_trigger_icm = item.get('trigger_icm')
                    item['trigger_icm'] = False
                    logger.debug(f"{failure_type}: {item['subject']} updating trigger_icm from "
                                 f"{original_trigger_icm} to {item['trigger_icm']}")
                else:
                    original_trigger_icm = item.get('trigger_icm')
                    if original_trigger_icm is not True:
                        logger.error(f"{failure_type}: {item['subject']} trigger_icm is not True, "
                                     f"which is not expected!!! Pay attention!!!")
                aggregated_icm_list.append(item)

        # Final verification: Check trigger_icm values in the result
        if aggregated_icm_list:
            trigger_icm_counts = {}
            for item in aggregated_icm_list:
                val = item.get('trigger_icm', 'missing')
                trigger_icm_counts[val] = trigger_icm_counts.get(val, 0) + 1
            logger.debug(f"{failure_type}: Final aggregated_icm_list "
                         f"trigger_icm distribution: {trigger_icm_counts}")

        return aggregated_icm_list

    def process_aggregated_failures(self, failure_type, original_icm_table, failure_duplicated_icm_table,
                                    analyzer, analysis_csv, aggregated_csv, dedup_csv):
        """
        Common function to process aggregated failure dataframes and create ICM lists.

        Args:
            failure_type (str): Type of failure ("legacy", "consistent", "flaky")
            original_icm_table (list): Original ICM table before aggregation
            failure_duplicated_icm_table (list): List to append duplicated ICM entries to
            analyzer: DataAnalyzer instance

        Returns:
            tuple: (aggregated_icm_list, subject_to_summary_dict)
        """
        logger.info(f"=================Start aggregation for {failure_type} failures=================")
        prepared_df = self.prepare_data_for_clustering(original_icm_table)
        prepared_df.to_csv(analysis_csv, index=False)
        if failure_type == "legacy":
            logger.info("Processing legacy failures")
            aggregated_df = self.find_similar_summaries_and_count(prepared_df, analyzer.week_legacy_testcases_df)
        elif failure_type == "consistent":
            logger.info("Processing consistent failures")
            aggregated_df = self.find_similar_summaries_and_count(prepared_df, analyzer.week_consistent_testcases_df)
        elif failure_type == "flaky":
            logger.info("Processing flaky failures")
            aggregated_df = self.find_similar_summaries_and_count(prepared_df, analyzer.week_flaky_testcases_df)
        aggregated_df.to_csv(aggregated_csv, index=False)
        logger.debug("The count of {} failure cases before aggregation: {} after:{}".format(
            failure_type, len(prepared_df), len(aggregated_df)))
        logger.info(f"=================Deduplicating {failure_type} aggregated df against active IcM=================")
        aggregated_dedup_df, duplicated_df = self.deduplicate_summary_with_active_icm(
                aggregated_df, analyzer.active_icm_df)
        aggregated_dedup_df.to_csv(dedup_csv, index=False)
        logger.debug(f"{failure_type}: Found {len(aggregated_dedup_df)} real {failure_type} failures "
                     f"after deduplication")
        logger.debug(f"{failure_type}:Found {len(duplicated_df)} duplicated {failure_type} failures "
                     f"after deduplication with active IcM")

        # Convert duplicated_df to list format and add to failure_duplicated_icm_table
        if not duplicated_df.empty:
            duplicated_list = self.filter_out_icm_list(
                    failure_type, original_icm_table, duplicated_df, trigger_icm=False)
            failure_duplicated_icm_table.extend(duplicated_list)
            logger.info(f"Added {len(duplicated_list)} active ICM duplicated {failure_type} entries "
                        f"to failure_duplicated_icm_table")

        aggregated_icm_list = self.filter_out_icm_list(failure_type, original_icm_table, aggregated_dedup_df)
        logger.info(f"Found {len(aggregated_icm_list)} aggregated {failure_type} IcMs after deduplication, "
                    f"before aggregation: {len(original_icm_table)}")
        logger.info(f"=================End aggregation for {failure_type} failures=================")
        return aggregated_icm_list, aggregated_dedup_df
