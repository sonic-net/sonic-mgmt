import datetime
import os
import sys

import numpy as np
import pandas as pd
from jinja2 import Environment


jinja2_template_str = """<!DOCTYPE html>
<html>
<head>
    <title>Test Execution Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        .summary { margin-bottom: 20px; }
        .summary p { font-size: 16px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        table, th, td { border: 1px solid #ccc; }
        th, td { padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .scripts-table a { text-decoration: none; color: #0066cc; }
        .scripts-table a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <h1>Test Execution Report</h1>
    <div class="summary">
        <p><strong>Suite Start Time:</strong> {{ suite_start_time }}</p>
        <p><strong>Suite Finish Time:</strong> {{ suite_finish_time }}</p>
        <p><strong>Total Suite Time:</strong> {{ total_suite_time }}</p>
        <p><strong>Total Test Cases:</strong> {{ total_test_cases }}</p>
        <p><strong>Pass Percentage:</strong> {{ pass_percentage|round(2) }}%</p>
        <p><strong>Fail Percentage:</strong> {{ fail_percentage|round(2) }}%</p>
        <p><strong>Software Versions:</strong> {{ software_versions }}</p>
    </div>
    <!--<h2>Pass/Fail Chart</h2>-->
    <!--<img src="{{ graph_image }}" alt="Pass/Fail Chart">-->
    <h2>Scripts Executed</h2>
    {{ scripts_table|safe }}
    {% if failed_test_cases_table %}
    <h2>Failed Test Cases</h2>
    {{ failed_test_cases_table|safe }}
    {% else %}
    <p>No failed test cases.</p>
    {% endif %}
</body>
</html>

"""

#datetime.strptime(datetime_str, '%m/%d/%y %H:%M:%S')
date_format = '%Y-%m-%d %H:%M:%S'
def get_test_execution_data(script_data: list):
    data = []
    for item in script_data:
        script: dict = item
        script_dict = {}
        script_dict['Script Name'] = script.get('SCRIPT_NAME')
        script_dict['Simulator'] = script.get('SIM_ID')
        script_dict['Start Time'] = script.get('EXEC_START_TIME', None)
        script_dict['End Time'] = script.get('EXEC_COMPLETION_TIME', None)
        script_dict['Execution Time'] = script.get('EXECUTION_TIME', None)
        script_dict['Total Test Cases'] = script.get('TOTAL_TEST', None)
        script_dict['Test Cases Failed'] = script.get('FAILED_TEST', 'Skipped')
        script_dict['Test Cases Passed'] = script.get('PASSED_TEST', 'Skipped')
        script_dict['Skipped Test'] = script.get('SKIPPED_TEST', 0)
        script_dict['Software Versions'] = script.get('SOFTWARE_VERSION', 0)
        script_dict['DUT Failure'] = script.get('DUT_FAIL', 0)
        script_dict['Command Failure'] = script.get('CMD_FAIL', 0)
        script_dict['Config Failure'] = script.get('CONFIG_FAIL', 0)
        script_dict['TGEN Failure'] = script.get('TGEN_FAIL', 0)
        script_dict['Pass Percentage'] = script.get('SUCCESS_RATE', None)
        script_dict['Log File'] = script.get('LOG_REPORT', None)

        data.append(script_dict)

    return data

# Format total suite time
def format_timedelta(td):
    total_seconds = int(td.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours}:{minutes:02}:{seconds:02}"

def rest_of_operations(data, orig_data, failed_data, dest="./", sim_log=None):
    report_file = "test_execution_report.html"
    # Create a DataFrame from the scripts data
    df = pd.DataFrame(data)
    orig_df = pd.DataFrame(orig_data)

    # Format the 'Log File' column to be HTML links
    df["Log File"] = df["Log File"].apply(
        lambda x: (
            f'<a href="{x}">View Log</a>' if x else "Skipped"
        )
    )
    #print(df["Log File"])

    # Calculate total suite time
    suite_start_time = pd.to_datetime(orig_df["EXEC_START_TIME"]).min()
    suite_finish_time = pd.to_datetime(orig_df["EXEC_COMPLETION_TIME"]).max()
    total_suite_time = suite_finish_time - suite_start_time

    # Format suite start and finish times
    suite_start_time_str = suite_start_time.strftime("%Y-%m-%d %H:%M:%S")
    suite_finish_time_str = suite_finish_time.strftime("%Y-%m-%d %H:%M:%S")

    total_suite_time_str = format_timedelta(total_suite_time)

    # Calculate total test cases and pass/fail percentages using numpy
    total_passed = df["Test Cases Passed"].sum()
    total_test_cases = df["Total Test Cases"].sum()
    total_failed = total_test_cases - total_passed

    pass_fail_array = np.array([total_passed, total_failed])
    percentages = pass_fail_array / total_test_cases * 100
    pass_percentage, fail_percentage = percentages

    software_versions = df['Software Versions'][0]
    df.pop('Software Versions')

    failed_test_cases = []
    for sim, data in failed_data.items():
        #script_name = row["Script Name"]
        for item in data:
            script_name, test_case, log = item
            failed_test_cases.append(
                {"Simulator": sim, "Script Name": script_name, "Failed Test Case": (test_case, log)}
            )

    failed_df = pd.DataFrame(failed_test_cases)
    if failed_test_cases:
        failed_df["Failed Test Case"] = failed_df['Failed Test Case'].apply(failed_tc_df_map)
        #print(failed_df)

    # Initialize Jinja2 environment
    env = Environment()
    template = env.from_string(jinja2_template_str)
    '''
    if sim_log:
        sim_log = f'<a href="{sim_log}">View SIM Log</a>'
    '''
    # Render the HTML report
    rendered_html = template.render(
        suite_start_time=suite_start_time_str,
        suite_finish_time=suite_finish_time_str,
        total_suite_time=total_suite_time_str,
        total_test_cases=total_test_cases,
        pass_percentage=pass_percentage,
        fail_percentage=fail_percentage,
        software_versions=software_versions,
        #suite_log=sim_log,
        scripts_table=df.to_html(classes="scripts-table", index=False, escape=False),
        failed_test_cases_table=failed_df.to_html(
            classes="failed-tests-table", index=False, escape=False
        ),
        #graph_image="pass_fail_pie_chart.png",
    )

    # Write the HTML report to a file
    with open(f"{dest}/{report_file}", "w") as f:
        f.write(rendered_html)

    print(f"Test execution report generated: '{dest}/{report_file}'")


def failed_tc_df_map(testcase):
    tc, log = testcase
    return f'<a href="{log}">{tc}</a>' if log else "Not Available"


def process_script_dates(failed_data):
    new_failed_data = {}
    for sim, data in failed_data.items():
        if not data:
            continue
        new_failed_data[sim] = data

    return new_failed_data

def generate_test_report(scripts_data, failed_data, suite_data: dict = {}, sim_data: dict = {}, dest="./", log=None):
    new_failed_data = process_script_dates(failed_data)
    data = get_test_execution_data(scripts_data)
    rest_of_operations(data, scripts_data, new_failed_data, dest=dest, sim_log=log)

if __name__ == '__main__':
    scripts_data, failed_data = {}, {}
    generate_test_report(scripts_data, failed_data)

