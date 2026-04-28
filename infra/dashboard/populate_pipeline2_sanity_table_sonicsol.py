#import psycopg2
#from psycopg2.extras import execute_values
import sys
import argparse
import os
import re
import json
import tarfile
import yaml
import requests
import time
from datetime import datetime
from db_tool_sonicsol import PostgresDBConnectionSonicSol
import soltest_upload_dashboard
from scale_upload_dashboard import add_scale_params, write_scale_test_case_params_into_db, write_scale_run_urls
from populate_test_case_table_sonicsol import populate_test_case_table

""" 
Set up for when Jenkins is done

PLATFORM = os.environ['PLATFORM']
TOPOLOGY  = os.environ['TOPOLOGY']
PIPELINE_TYPE = (os.environ["PIPELINE_TYPE"]).lower()
SANITY_TYPE = os.environ['SANITY_TYPE']
RUN_HW = os.environ["RUN_HW"] == 'true'
"""


if __name__ == '__main__': 

    argparser = soltest_upload_dashboard._create_parser()
    args = vars(argparser.parse_args())
    topo_yaml = args['topo_yaml'] # Not used by us!
    topology = args['topology']
    platform = args['platform']
    script_file = args['script_file'] # Would ONLY be used if no logs_path argument given!
    run_label = args['run_label']
    run_desc = args['run_desc']
    logs_path = args['logs_path']
    dev = args['dev']
    npu = args['npu']
    curr_server = args['curr_server']
    
    dir_path, p2build_job_id, stream, release, contains_pns = soltest_upload_dashboard.main(curr_server, topo_yaml, topology, platform, script_file, run_label, logs_path, run_desc, dev)

    error = False 
    # initializing the variables 
    directory_name = ""
    try: 
        directory_name = dir_path.split('/')[-1]
    except Exception: 
        raise Exception("Spytest Result Directory already exists!")
        error = True

    if error == False: 
        use_backup = False
        if '_dev' in dir_path.split('/')[-2]: 
            use_backup = True
        tarball_link = ""
        result_sum = {}
        report_link = ""
        platform = ""
        topology = ""
        build_start = ""
        build_end = ""
        status = ""
        label = ""
        description = ""

        result_sum_path = os.path.join(dir_path, "results.json")

        # Read the results.json file
        with open(result_sum_path, "r") as file:
            result_sum = json.load(file)
            # Assuming the JSON contains a field named 'report_link'
            report_link = result_sum.get("report_link", "N/A")
            tarball_link = result_sum.get("log_tarball_link", "N/A")
            platform = result_sum.get("platform", "N/A")
            topology = result_sum.get("topology", "N/A")
            build_start = result_sum.get("build_start", "N/A")
            build_end = result_sum.get("build_end", "N/A")
            status = result_sum.get("status", "N/A")
            label = result_sum.get("run_label", "N/A")
            description = result_sum.get("run_desc", "N/A")

            # Remove unwanted fields from the summary
            for key in ["sonic_image_link", "log_tarball_link", "platform", "topology", "build_start", "build_end", "status", "run_label", "run_desc"]:
                if key in result_sum:
                    del result_sum[key]
        
        # Get Image Created Column Data (Possibly Join together)
        db_image = PostgresDBConnectionSonicSol(use_backup=False)
        result = db_image.find_one("pipeline2_build", key_data={"build_id": p2build_job_id}, column_list=["repo_info", "deb_version", "build_start"])

        repo = result[0]

        sonic_hash = repo['sonic-buildimage']['hash']
        platform_hash = repo['platform-cisco-8000']['hash']

        deb_version = result[1]

        image_created = result[2].date()

        db_image.close_connection()
        
        # Populating Management Full Run Test Table 
        db = PostgresDBConnectionSonicSol(use_backup)

        # Getting Build id to use for populating test_case and result_sum 
        build_id_result = db.get_next_sequence_value("mgmt_full_run_test_build_id_seq")
        build_id = 0

        if build_id_result == None:
            raise Exception("Issue with build_id creation!!!")
        else:
            build_id = build_id_result[0][0]

        # See if previous images are even possible
        image_record = db.get_images(stream, npu, platform, p2build_job_id)
        #print(image_record)

        key_data = {
            "build_id": build_id, 
            "job_base_name": "soltest_upload_to_dashboard", 
            "build_start": build_start,
            "platform": platform,
            "platform_name": platform,
            "topology": topology,
            "sanity_type": "solution-test",
            "stream": stream,
            "p2build_job_id": p2build_job_id,
            "build_end": build_end,
            "build_state": status,
            "report_link": report_link,
            "log_tarball_link": tarball_link,
            "label": label,
            "description": description,
            "release": release,
            "project": npu, 
            "image_created": image_created
            # build_url: jenkins_url, 
        }

        db.insert("management_full_run_test", key_data)

        # updating the result_sum separately since is dict type
        db.update("management_full_run_test", key_data = {"build_id": build_id}, updated_data = {"result_sum":result_sum})

        # Get closest previous image
        lt_image = 0
        if len(image_record) > 0: 
            less_than_image = db.get_closest_image_id(stream, npu, platform, p2build_job_id)
            if less_than_image == None: 
                raise Exception(f"Was not able to find an image id less than {image_id}!!")
            else: 
                lt_image = less_than_image[0][0]
        
        if lt_image == 0:
            lt_image = None

        # Get closest next image (IF POSSIBLE)
        gt_image = 0
        great_than_image = db.get_closest_image_id(stream, npu, platform, p2build_job_id, than_type="greater")
        if len(great_than_image) > 0: 
            gt_image = great_than_image[0][0]  

        if gt_image == 0: 
            gt_image = None

        # Populating Test Case Table
        print("POPULATING TEST CASE TABLE!! ------- ")
        populate_test_case_table(build_id, directory_name, p2build_job_id, lt_image, db, gt_image, use_backup) # Adding image id to test_case as well - to make dashboard queries easier.
        print("populate_pipeline2_sanity_table_sonicsol.py completed! Successfully populated database and dashboard!!")

        db.close_connection()

        if contains_pns: 
            print("Adding Scale test parameters!")
            test_cases, run_urls = add_scale_params(build_id, directory_name, platform, p2build_job_id, image_created, npu)
            # print(test_cases)
            ret1 = write_scale_test_case_params_into_db(test_cases)
            ret2 = write_scale_run_urls(run_urls)
            sys.exit(ret1)
            sys.exit(ret2)
     
    

