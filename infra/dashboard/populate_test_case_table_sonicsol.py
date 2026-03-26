import psycopg2
from psycopg2.extras import execute_values
import sys
import argparse
import requests
import logging
import json
from datetime import datetime
import yaml
from db_tool_sonicsol import PostgresDBConnectionSonicSol
import os

def _convert_keys_to_strings_and_lower(d):
    """Recursively convert all keys in a dictionary to lowercase strings."""
    if isinstance(d, dict):
        return {str(key).lower(): _convert_keys_to_strings_and_lower(value) for key, value in d.items()}
    elif isinstance(d, list):
        return [_convert_keys_to_strings_and_lower(item) for item in d]
    else:
        return d

def _get_test_categories(file_path):
    """
    Retrieves and organizes test categories from a YAML file located in a specified workspace directory.

    Functionality:
    - reads the file specified in TESTFILE
    - if yaml, then go through each test category specified in yaml to identify which test belongs to which category

    Returns:
    - A dictionary (`test_categories_all`) where each key is a test tag, and each value is a list of 
      formatted test category strings.

    Example Output:

	baseline:
		- test_pre-test
		- fib.test_fib
        ...
	fwd:
		- everflow.test_everflow_testbed
		- route.test_default_route
        ...
	plt:
		- platform_tests.test_reboot
		- platform_tests.api.test_chassis
		- platform_tests.test_cpu_memory_usage
        ...
    """

    with open(file_path) as f:
        test_cases_yaml = yaml.safe_load(f)
    
    test_cases_yaml = _convert_keys_to_strings_and_lower(test_cases_yaml)
    
    test_categories_all = {}
    for test_tag in test_cases_yaml:
        test_categories = set()
        for topo in test_cases_yaml[test_tag]:
            for platform in test_cases_yaml[test_tag][topo]:
                for test_case in test_cases_yaml[test_tag][topo][platform]:
                    test_category_snippet = test_case.split('.py')[0]
                    test_category_snippet = test_category_snippet.replace('/', '.')
                    test_categories.add(test_category_snippet)
        test_categories_all[test_tag] = test_categories

    return test_categories_all   


def _add_additional_info(test_cases, report_link):
    new_test_cases = []

    for test_case in test_cases:
        new_test_case = test_case
        new_test_case['pipeline_type'] = None
        new_test_case['pr_repo_name'] = None
        new_test_case['pr_id'] = None
        new_test_case['pr_link'] = None
        new_test_case['report_link'] = report_link

        new_test_cases.append(new_test_case)

    return new_test_cases

def _get_spytest_test_cases_json(spytest_report_url, directory_name, use_backup=False):
    test_cases_info_json = "/var/www/html/logs/solution_test/" + directory_name + "/test_cases_info.json"
    if use_backup: 
        test_cases_info_json = "/var/www/html/logs/solution_test_dev/" + directory_name + "/test_cases_info.json"
    res_json = ""

    with open(test_cases_info_json, 'r') as f:
        res_json = json.load(f)

    print(res_json["script_data"][0]["SCRIPT_NAME"])

    return res_json

#spytest has many failure types, consolidate into one
def _spytest_parse_state(raw_state):
    if raw_state == "Pass":
        return "Passed" 
    elif raw_state in ["Skip", "TGenFail", "ScriptError"]:
        return "Skipped"
        
    return raw_state

def analyze_test_case(test_case_full_name, state, p2_results, sanity_type, image_id, db, sku=None, next_image=None): 

    curr_state = state[0]
    if isinstance(state, str): 
        curr_state = state 
    
    key_cond = {
        "stream": p2_results[2],
        #"project": p2_results[3], <-- Is not in test_case table. Should I include? 
        "platform": p2_results[0],
        "test_case_full_name": test_case_full_name,
        "sanity_type": sanity_type,
        "image_id": image_id
    }
    if sanity_type == 'sonic-mgmt': 
        key_cond["sku"] = sku

    test_case = db.find_one("test_case", key_data=key_cond, column_list=["state", "id"], sort_column_list=["start_time"])

    if next_image != None: 
        key_cond["image_id"] = next_image
        curr_state = db.find_one("test_case", key_data=key_cond, column_list=["state", "id"], sort_column_list=["start_time"])
        curr_state = curr_state[0][0]

    analysis = "No Difference" # Default value 

    if test_case is not None: 
        if curr_state == "Passed" and test_case[0] != "Passed": # Failed after passing 
            analysis = "New Pass"
        elif curr_state != "Passed":
            has_jira = db.find_one("jira_ids", {"test_case_id": test_case[1]}, column_list=["jira_id", "jira_status"])
            if has_jira is not None and len(has_jira) > 0 and has_jira[1] not in ("Resolved", "Closed", "PR Raised"):
                analysis = "Maybe: JIRA " + has_jira[0]
            elif test_case[0] == "Error" and curr_state == "Failed": 
                analysis = "Prev Run: Error"
            elif test_case[0] == "Failed" and curr_state == "Error":
                analysis = "Prev Run: Failed"
            elif test_case[0] == "Passed": 
                analysis = "Regression" 
    else:
        analysis = "New Test Case"

    if next_image != None: 
        key_cond["id"] = curr_state[0][1]
        db.update("test_case", key_data=key_cond, updated_data={"analysis": analysis})

    return analysis

def analyze_all_test_cases(build_id, test_case_names, test_state_map, p2_results, sanity_type, lt_image, image_id, db, sku=None, gt_image=None):
    """
    Batch-optimized test case analysis.
    Fetches all test_case and jira data at once, performs in-memory analysis,
    and then updates results in bulk.
    """
    
    stream = p2_results[2]
    platform = p2_results[0]
    project = p2_results[3]
    
    image_arr = [image_id]
    if lt_image: 
        image_arr.append(lt_image)
    if gt_image:
        image_arr.append(gt_image)

    try:
        db.conn.commit()
        print("Forced DB commit before analysis to ensure visibility.")
    except Exception as e:
        print(f"Commit failed before analysis: {e}")
    
    sanity_rows = db.find_many(
        "management_full_run_test",
        key_data={
            "p2build_job_id": {"$in": image_arr},
            "platform": platform,
            "stream": stream,
            "sanity_type": sanity_type
            },
        column_list=["build_id", "p2build_job_id"]
    )

    image_to_sanity = {r[1]: r[0] for r in sanity_rows}
    sanity_ids = list(image_to_sanity.values())

    # --------------------------
    # 1. Prefetch all relevant data
    # --------------------------
 
    key_filter = {
        "test_case_full_name": {"$in": test_case_names},
        "image_id": {"$in": image_arr},
        "platform": platform,
        "stream": stream,
        "sanity_type": sanity_type
    }

    if sanity_type in ['sonic-mgmt-hw', 'spytest-hw']: 
        key_filter["sku"] = sku 
        key_filter["parent_sanity_id"] = {"$in": sanity_ids} 

    all_cases = db.find_many(
        "test_case",
        key_data=key_filter,
        column_list=["id", "image_id", "test_case_full_name", "state", "start_time"],
        sort_column_list=["start_time"],
        sort_rule="DESC NULLS LAST"
    )
    
    print(f"Found {len(all_cases)} test_case rows matching key_filters")
    print(f"Expected {len(test_case_names)} test names x {len(image_arr)} images = ~{len(test_case_names) * len(image_arr)} possible matches")
    ids = [c[0] for c in all_cases]
    print(len(ids), len(set(ids)))

    # Keep only the most recent per (test_name, image)
    cases = {}
    for c in all_cases:
        key = (c[2], c[1])  # (test_case_full_name, image_id)
        if key not in cases or not cases[key]["start_time"]:  # first one is most recent due to start_time DESC and makes sure start_time is not NULL
            cases[key] = {"id": c[0], "state": c[3], "start_time": c[4]}

    # Prefetch JIRA info once
    all_jiras = db.find_many("jira_ids", {}, column_list=["test_case_id", "jira_id", "jira_status"])
    jira_lookup = {j[0]: {"jira_id": j[1], "jira_status": j[2]} for j in all_jiras}

    # Collect only tests that need last-passed, with their per-test cutoff (current start_time)
    need_last_passed = {}
    for test_name in test_case_names:
        curr_state = test_state_map[test_name][0].lower() if not isinstance(test_state_map[test_name], str) else test_state_map[test_name].lower()
        curr_case = cases.get((test_name, image_id))
        if curr_case and curr_case.get("start_time") and curr_state != 'passed':
            need_last_passed[test_name] = curr_case["start_time"]

    last_passed_map = {}
    if need_last_passed:
        max_cutoff = max(need_last_passed.values())

        # Pull only "Passed" rows for the subset of tests that need it,
        # and only rows strictly before the latest cutoff among them.
        # Sorted DESC so the first row we see per test is the answer.
        passed_rows = db.find_many(
            "test_case",
            key_data={
                "platform": platform,
                "stream": stream,
                "sanity_type": sanity_type,
                "test_case_full_name": {"$in": list(need_last_passed.keys())},
                "state": "Passed"
            },
            column_list=["test_case_full_name", "image_id", "start_time"],
            sort_column_list=["start_time"],
            sort_rule="DESC NULLS LAST"
        )

        # First seen (DESC) per test_name that is < its own cutoff wins
        for tname, img, st in passed_rows:
            if st is None:
                continue
            cutoff = need_last_passed.get(tname)
            if cutoff and tname not in last_passed_map and st < cutoff:
                last_passed_map[tname] = img

    # --------------------------
    # 2. In-memory analysis
    # --------------------------
    updates = []  # for bulk DB update
    results_out = {}

    for test_name in test_case_names:
        curr_state = test_state_map[test_name][0].lower() if not isinstance(test_state_map[test_name], str) else test_state_map[test_name].lower()

        curr_case = cases.get((test_name, image_id))
        lt_case = {}
        gt_case = {}

        if lt_image: 
            lt_case = cases.get((test_name, lt_image), {})
        if gt_image: 
            gt_case = cases.get((test_name, gt_image), {})

        # ---- Analyze lt_image (current) ----
        analysis = "No Difference"

        # CASE 1: missing or invalid current case
        if not curr_case or curr_case.get("start_time") is None:
            analysis = "N/A"
            results_out[test_name] = analysis
            continue

        # CASE 2: skipped or invalid current state
        if curr_state in (None, "skipped"):
            analysis = "N/A"

        # CASE 3: has lt_case (compare to previous)
        elif len(lt_case) > 0:
            prev_state = lt_case["state"].lower()

            # Skip cases with bad data
            if prev_state in (None, "skipped"):
                analysis = "N/A"
            elif curr_state == "passed" and prev_state != "passed":
                analysis = "New Pass"
            elif curr_state != "passed":
                jira_info = jira_lookup.get(lt_case["id"])
                if jira_info and jira_info["jira_status"] not in ("Resolved", "Closed", "PR Raised"):
                    analysis = "Maybe: JIRA " + jira_info["jira_id"]
                elif prev_state == "error" and "fail" in curr_state:
                    analysis = "Prev Run: Error"
                elif "fail" in prev_state and curr_state == "error":
                    analysis = "Prev Run: Failed"
                elif prev_state == "passed":
                    analysis = "Regression"
        # CASE 4: new test (no lt_case)
        else:
            if curr_state == "passed":
                analysis = "New Test Case"
            else:
                analysis = "New Test Case - No Previous Data"

        # ---- Append last passed image id (or "Never Passed") for Failed/Skipped/Error ----
        suffix = " - Never Passed"
        if curr_state.lower() != "passed" and "-" not in analysis:
            lp = last_passed_map.get(test_name)
            if lp: 
                suffix = f" - {lp}"

            analysis = f"{analysis}{suffix}"

        # ---- Store results safely (avoid duplicates) ----
        if curr_case.get("id") not in {u["id"] for u in updates}:
            updates.append({"id": curr_case["id"], "analysis": analysis})
        results_out[test_name] = analysis

        # ---- Re-analyze gt_image if exists ----
        if len(gt_case) > 0:
            next_state = gt_case["state"].lower()
            next_analysis = "No Difference"

            if next_state in (None, "skipped"):
                next_analysis = f"N/A{suffix}"
            elif curr_state == "passed" and next_state != "passed":
                next_analysis = f"Regression - {image_id}"
            elif curr_state != "passed" and next_state == "passed":
                next_analysis = "New Pass"
            elif "fail" in next_state and curr_state == "Error":
                next_analysis = f"Prev Run: Error{suffix}"
            elif next_state == "error" and "fail" in curr_state:
                next_analysis = f"Prev Run: Failed{suffix}"

            updates.append({"id": gt_case["id"], "analysis": next_analysis})

    # ---- Final safety guard: no null analyses ----
    updated_ids = {u["id"] for u in updates}

    missing_in_updates = [
        c for (tcf, key_image_id), c in cases.items() 
        if c["id"] not in updated_ids and key_image_id == image_id
    ]

    if missing_in_updates:
        print(f"⚠️ Found {len(missing_in_updates)} current test_case rows with no updates. Setting analysis='N/A'.")
        for m in missing_in_updates:
            updates.append({"id": m["id"], "analysis": "N/A"})

    print(f"Total updates prepared: {len(updates)} | Unique IDs: {len({u['id'] for u in updates})}")

    # --------------------------
    # 3. Bulk update in DB
    # --------------------------
    if updates:
        db.update_many("test_case", updates)

    return results_out


def _traverse_through_spytest_test_cases_json(spytest_test_cases_json, p2_results, image_id, lt_image, db, gt_image=None):
    test_cases = []
    test_names = []
    test_state_map = {}

    for curr_test_cases_obj in spytest_test_cases_json["script_data"]:
        for test_suite in curr_test_cases_obj["TC_INFO"]:
            state = _spytest_parse_state(test_suite["state"])

            """
            analysis = ""
            if gt_image == None: 
                analysis = analyze_test_case(test_suite["test_case_full_name"], state, p2_results, "solution-test", lt_image, db)
            else: # Re-check analysis for next image if new image is being inserted in between
                rewrite_analysis = analyze_test_case(test_suite["test_case_full_name"], state, p2_results, "solution-test", image_id, db, gt_image)
            """

            if isinstance(state, str): 
                curr_state = state 
            else: 
                curr_state = state[0]

            test_names.append(test_suite["test_case_full_name"])
            test_state_map[test_suite["test_case_full_name"]] = curr_state

            test_case_info = {
                "start_time": test_suite["start_time"],
                "end_time": test_suite["end_time"],
                "state": state,
                "test_category": test_suite["test_category"],
                "test_case_name": test_suite["test_case_name"],
                "test_case_full_name": test_suite["test_case_full_name"],
                "test_tag": "unknown",
                "test_script_name": test_suite["test_script_name"],
                "test_script_full_name": test_suite["test_script_full_name"]
            }
            test_cases.append(test_case_info)
    
    return test_cases, test_names, test_state_map

def retrieve_spytest_test_cases(spytest_report_url, directory_name, p2_results, image_id, lt_image, db, gt_image=None, use_backup=False):
    spytest_test_cases_json = _get_spytest_test_cases_json(spytest_report_url, directory_name, use_backup)

    print("IN RETRIEVE SPYTEST TEST CASES FUNCTION ")

    test_cases, test_names, test_state_map = _traverse_through_spytest_test_cases_json(spytest_test_cases_json, p2_results, image_id, lt_image, db, gt_image)
    if not test_cases:
        return 1, None

    report_link = "http://10.28.109.58/logs/solution_test//"+directory_name+"/dashboard.html"
    test_cases = _add_additional_info(test_cases, report_link)

    return 0, test_cases, test_names, test_state_map

def write_test_cases_into_db(test_cases, sanity_id, image_id, p2_results, db):
    job_base_name = "soltest_upload_to_dashboard" #os.environ["JOB_BASE_NAME"]
    
    sql = """
        INSERT INTO test_case 
            (
                parent_sanity_id, 
                parent_job_base_name, 
                start_time, 
                end_time, 
                state, 
                test_category, 
                test_case_name, 
                test_case_full_name, 
                test_tag, 
                platform, 
                topology, 
                pipeline_type, 
                sanity_type, 
                stream, 
                pr_repo_name, 
                pr_id, 
                pr_link,
                report_link,
                run_hw,
                image_id,
                test_script_name,
                test_script_full_name
            ) 
        VALUES %s
    """

    #create values list:
    values = []

    for test_case in test_cases:
        values.append(
            (
                sanity_id,
                job_base_name,
                test_case['start_time'],
                test_case['end_time'],
                test_case['state'],
                test_case['test_category'],
                test_case['test_case_name'],
                test_case['test_case_full_name'],
                test_case.get('test_tag'),
                p2_results[0],
                p2_results[1],
                test_case.get('pipeline_type'),
                "solution-test",
                p2_results[2],
                test_case.get('pr_repo_name'),
                test_case.get('pr_id'),
                test_case.get('pr_link'),
                test_case.get('report_link'),
                "True", 
                image_id,
                test_case.get('test_script_name'),
                test_case.get('test_script_full_name')
            )
        )

    for test_case in test_cases:
        test_case_name_trunc = test_case['test_case_name']
        if len(test_case_name_trunc) > 50:
            test_case_name_trunc = '...' + test_case_name_trunc[-50:]

    ret = db.execute_values(sql, values)

    return ret

def get_report_link(key_data, db):
    result_sum = db.find_one("management_full_run_test", key_data, column_list=["result_sum"])
    print("result_sum: {}".format(result_sum[0]))
    if 'report_link' not in result_sum[0]:
        return None

    report_link = result_sum[0]['report_link']
    return report_link



def populate_test_case_table(parent_sanity_id, directory_name, image_id, lt_image, db, gt_image=None, use_backup=False):
    
    key_data = {
        "build_id": parent_sanity_id
    }

    p2_results = db.find_one("management_full_run_test", key_data, column_list=["platform", "topology", "stream", "project"])  

    spytest_report_url = get_report_link(key_data, db)
    print("spytest_report_url: {}".format(spytest_report_url))
    if not spytest_report_url:
        print("Failed at step: get_report_link! report link is empty")
        sys.exit(1)
        
    ret, test_cases, test_names, test_state_map = retrieve_spytest_test_cases(spytest_report_url, directory_name, p2_results, image_id, lt_image, db, gt_image, use_backup)
    print("ret: {}".format(ret))
    if ret != 0:
        print("Failed at step: retrieve_spytest_test_cases!")
        sys.exit(ret)

    ret = write_test_cases_into_db(test_cases, parent_sanity_id, image_id, p2_results, db)

    sanity_type = 'solution-test'
    sku = None 

    analyze_all_test_cases(parent_sanity_id, test_names, test_state_map, p2_results, sanity_type, lt_image, image_id, db, sku, gt_image) 