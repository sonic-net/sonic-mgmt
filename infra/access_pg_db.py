import logging
import time
import csv
import sys
import os
import json
import csv
import psycopg2
from psycopg2 import sql

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class PostgresDB:
    def __init__(self, dbname, user, password, host='localhost', port='5432', max_retries=5, retry_delay=5):
        self.dbname = dbname
        self.user = user
        self.password = password
        self.host = host
        self.port = port
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.conn = None

        self._connect_postgres_db()

    def _connect_postgres_db(self):
        attempts = 0
        while attempts < self.max_retries:
            try:
                self.conn = psycopg2.connect(
                    dbname=self.dbname,
                    user=self.user,
                    password=self.password,
                    host=self.host,
                    port=self.port
                )
                self.conn.autocommit = True
                logging.info(f"Successfully connected to database {self.dbname}")
                return
            except psycopg2.Error as e:
                attempts += 1
                logging.error(f"Failed to connect to database {self.dbname}. Attempt {attempts}/{self.max_retries}. Error: {e}")
                if attempts < self.max_retries:
                    logging.info(f"Retrying in {self.retry_delay} seconds...")
                    time.sleep(self.retry_delay)
                else:
                    logging.critical("All retry attempts exhausted. Cannot connect to database.")
                    raise

    def __del__(self):
        if self.conn:
            logging.info("Closing database connection.")
            self.conn.close()

    def insert_data(self, table_name, data):
        """
        Insert a single row (dict) into the specified table.
        Keys of 'data' should match column names.
        """
        if not self.conn:
            logging.error("No active DB connection.")
            return
        columns = data.keys()
        values = [data[col] for col in columns]

        insert_query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
            sql.Identifier(table_name),
            sql.SQL(', ').join(map(sql.Identifier, columns)),
            sql.SQL(', ').join(sql.Placeholder() * len(columns))
        )

        try:
            with self.conn.cursor() as cur:
                cur.execute(insert_query, values)
                logging.info(f"Inserted row into {table_name}: {data}")
        except psycopg2.Error as e:
            logging.error(f"Error inserting data into {table_name}: {e}")

def transform_csv_col_db_col(json_file, kwargs):
    with open(json_file, 'r') as j_file:
        data = json.load(j_file)

    csv_file = 'tc_data.csv'
    csv_data_file = open(csv_file, 'w')
    csv_writer = csv.writer(csv_data_file)
    tc_data = data['script_data']
    count = 0
    for tc in tc_data:
        new_dict = {}
        tc.update(kwargs)
        new_dict['job_base_name'] = tc['job_base_name']
        new_dict['test_suite_name'] = tc['SCRIPT_NAME']
        new_dict['simulator'] = tc['SIM_ID']
        new_dict['start_time'] = tc['EXEC_START_TIME']
        new_dict['execution_time'] = tc['EXECUTION_TIME']
        new_dict['total_test_cases'] = tc['TOTAL_TEST']
        new_dict['test_cases_passed'] = tc['PASSED_TEST']
        new_dict['skipped_test'] = tc['SKIPPED_TEST']
        new_dict['pass_percentage'] = tc['SUCCESS_RATE']
        new_dict['log_file'] = tc['LOG_REPORT']
        new_dict['user_id'] = tc['user_id']
        new_dict['build_id'] = tc['build_id']

        if count == 0:
            header = new_dict.keys()
            csv_writer.writerow(header)
            count += 1
        csv_writer.writerow(new_dict.values())

    if not (os.path.exists(csv_file) and os.path.isfile(csv_file)):
        return None

    print("returning csv file")
    return csv_file

def trigger(json_file, job_base_name='pipeline1_sanity', build_id=18296):
    # Database connection parameters
    dbname = "grafana_cloudDB"
    user = "grafanaci"
    password = "Grafanaci321!"
    host = "cygci-pgdb.igslb.cisco.com"
    port = "9538"

    # Initialize DB connection
    db = PostgresDB(dbname=dbname, user=user, password=password, host=host, port=port)

    # CSV file and table details
    #csv_file = "data.csv"  # path to your CSV file
    #json_file = sys.argv[1]
    user = os.getlogin()
    # job_base_name = 'pipeline1_sanity'
    # build_id = 18296
    kwargs = {'job_base_name': job_base_name,
              'build_id': build_id,
              'user_id': user}
    csv_file = transform_csv_col_db_col(json_file, kwargs)
    table_name = "sonic_test_summary"

    # The CSV is expected to have the columns (in any order that you define below):
    # job_base_name, test_suite_name, simulator, start_time, execution_time, total_test_cases, test_cases_passed, skipped_test,
    # pass_percentage, log_file, user_id, build_id

    # Example CSV header:
    # job_base_name,test_suite_name,simulator,start_time,execution_time,total_test_cases,test_cases_passed,skipped_test,pass_percentage,log_file,user_id,build_id

    # NOTE: If your CSV columns differ in order or name, adjust accordingly.
    with open(csv_file, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            # Convert fields as necessary
            # For example, pass_percentage might need to be float:
            if 'pass_percentage' in row:
                row['pass_percentage'] = float(row['pass_percentage']) if row['pass_percentage'] else None

            # Convert total_test_cases, test_cases_passed, and skipped_test to int if needed
            for int_col in ['total_test_cases', 'test_cases_passed', 'skipped_test']:
                if int_col in row and row[int_col] != '':
                    row[int_col] = int(row[int_col])
                else:
                    row[int_col] = None

            # If execution_time is stored as a string like '0:08:33', Postgres INTERVAL can parse a string like 'HH:MM:SS'
            # Ensure it's in a suitable format. If CSV is already in HH:MM:SS, it's fine:
            # If needed, you can manipulate the format here.

            db.insert_data(table_name, row)

def main():
    print("Exiting")
    # trigger('test.json')

if __name__ == "__main__":
    main()
