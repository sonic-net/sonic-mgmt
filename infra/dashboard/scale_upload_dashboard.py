import psycopg2
from psycopg2.extras import execute_values
import sys
import argparse
import requests
import logging
import json
from datetime import datetime
import yaml
import os
from db_tool_sonicsol import PostgresDBConnectionSonicSol
sys.path.append(os.path.dirname(os.path.realpath(__file__)) + "/..")


def add_scale_params(build_id, directory_name, platform, p2build_job_id, image_created, npu): 

    scale_json_file = "/var/www/html/logs/solution_test/"+directory_name+"/perf_and_scale.json"

    try:
        with open(scale_json_file, 'r') as file:
            # Load the JSON data into a Python dictionary
            data = json.load(file)
            
        db = PostgresDBConnectionSonicSol(False)

        test_cases = data.keys()
        test_cases_data = []

        project = data.pop('project', None)

        run_urls = []
        run_dict = {}
        run_dict["build_id"] = build_id
        run_dict["result_url_array"] = {}
        run_dict["result_url_array"]["append"] = []
        run_dict["result_url_array"]["append"].append(f"https://sonic-grafana.cisco.com/d/ef43a9bf-9a9e-4437-946c-3c00a651bf77/perf-and-scale-dashboard?orgId=1&from=now-30d&to=now&timezone=browser&var-platform={platform}&var-image_id={p2build_job_id}&var-project={project}")
        run_dict["result_url_array"]["append"].append(f"https://sonic-grafana.cisco.com/d/02fc6a49-ba76-4132-a329-ace5a46aedc7/solution-test-results?var-project={npu}&var-build_job_date={image_created}&var-platform=$__all")    
        run_urls.append(run_dict)

        for tc in test_cases: 
            tc_old = tc
            tc_new = tc.replace("::", ".")

            tc_id = db.find_one("test_case", key_data={"parent_sanity_id": build_id, "test_case_name": tc_new}, column_list=["id"])
            scenario_name = data[tc_old]["scenario_name"]
            scenario_type = data[tc_old]["scenario_type"]
            scenario_desc = data[tc_old]["scenario_desc"]

            for test_type in data[tc_old].keys():
                if test_type == "scale" or test_type == "performance": 
                    for feature in data[tc_old][test_type]: 
                        test_case_info = {
                            "test_case_id": tc_id[0], 
                            "type": 1, # checks if type is being properly assigned
                            "scenario_name": scenario_name,
                            "scenario_type": scenario_type,
                            "scenario_desc": scenario_desc,
                            "feature": feature, 
                            "actual": data[tc_old][test_type][feature]["actual"],
                            "expected": data[tc_old][test_type][feature]["expected"],
                            "feature_result": None,
                            "feat_traffic_result": None,
                            "failure_reason": data[tc_old][test_type][feature]["failure_reason"],
                            "project": project
                        } 

                        if test_case_info["actual"] is None: 
                            test_case_info["actual"] = 0

                        if data[tc_old][test_type][feature]["traffic_result"] == "Pass": 
                            test_case_info["feat_traffic_result"] = True
                        else:
                            test_case_info["feat_traffic_result"] = False

                        if test_type == "scale":  
                            test_case_info["feature_result"] = data[tc_old][test_type][feature]["result"]
                            
                        elif test_type == "performance":
                            test_case_info["type"] = 0

                        test_cases_data.append(test_case_info)
    
        db.close_connection() 
        return test_cases_data, run_urls

    except FileNotFoundError:
        print(f"Error: The file {scale_json_file} was not found.")


def write_scale_test_case_params_into_db(test_cases):

    db = PostgresDBConnectionSonicSol(False)

    sql = """
        INSERT INTO scale_tc_params 
            (
                test_case_id, 
                type, 
                scenario_name, 
                scenario_type,
                scenario_desc,
                feature, 
                actual, 
                expected, 
                feature_result,
                feat_traffic_result, 
                failure_reason, 
                project
            ) 
        VALUES %s
    """

    #create values list:
    values = []

    for test_case in test_cases:
        values.append(
            (
                test_case['test_case_id'],
                test_case['type'],
                test_case['scenario_name'],
                test_case['scenario_type'],
                test_case['scenario_desc'],
                test_case['feature'],
                test_case['actual'],
                test_case['expected'],
                test_case['feature_result'],
                test_case['feat_traffic_result'],
                test_case['failure_reason'],
                test_case['project']
            )
        )

    ret = db.execute_values(sql, values)

    db.close_connection()

    return ret


def write_scale_run_urls(run_urls):

    db = PostgresDBConnectionSonicSol(False)

    ret = db.update_many_varchar_array_ops("management_full_run_test", run_urls, key_column="build_id")

    db.close_connection()

    return ret 

