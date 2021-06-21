#### Allure server plugin usage example

Below is described possibility of allure_server plugin usage.

##### Structure
allure_server plugin allows to upload allure report data to allure server

Plugin parse pytest arguments:
- "allure_server_addr" - Allure server address: IP/domain name, by default None
- "allure_server_port" - Allure server port, by default 5050
- "allure_server_project_id" - Allure server project ID, by default current timestamp used as project ID


##### How it works
By default if no allure server related atgs provided - plugin will do nothing.

If provided "allure_server_addr" option provided - then plugin will check if "allure_report_dir" option provided and then
it will do:
- create project on allure server(if does not exist)
- upload results to allure server
- generate report on allure server

Finally you will see allure report url in test logs.
Example: "Allure report URL: http://1.2.3.4:5050/allure-docker-service/projects/162159947324/reports/1/index.html"
