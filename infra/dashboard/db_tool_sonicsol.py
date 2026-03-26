#!/usr/bin/python3
import re
import time
from collections import OrderedDict
from dashboard_utils import singleton, SysTools
import psycopg2
from psycopg2 import extras
import json
import os

NOT_NULL = "not_null"
PG_CONN_RETRY_LIMIT = int(os.getenv('PG_CONN_RETRY_LIMIT', '10'))

# table name
Management_full_run_test = 'management_full_run_test'
Pipeline_tester = 'pipeline-tester'
tables = [Management_full_run_test] 

class CollKeyErrorSonicSol(KeyError):
    pass

class PostgresDBConnectionSonicSol(object):
    """
    This class is used to connect DB
    """

    def __init__(self, use_backup):
        """
        Connect to db
        :return:
        """
        self.conn, self.cur = self._connect_postgres_db(use_backup)
        self._create_tables()

    def __del__(self):
        self.cur.close()
        self.conn.close()

    @staticmethod
    def _connect_postgres_db(use_backup=False):
        """
        Create a connection to postgres db
        :param:
        :return:
        """
        user = SysTools.resolve_string("sonicci")
        password = os.getenv("WHITEBOX_POSTGRES_DB_PROD_PASSWORD")
        host = SysTools.resolve_string("whitbx-pgdb.cisco.com")
        port = SysTools.resolve_string("9538")
        database = SysTools.resolve_string("sonicci_prod")
        if use_backup: 
            database = SysTools.resolve_string("sonicci_dev")
        retries = 0

        while retries < PG_CONN_RETRY_LIMIT:
            try:
                conn = psycopg2.connect(database=database,user=user,password=password,host=host,port=port, connect_timeout=30)
                cur = conn.cursor()
                print("======= Connected to DB successfully ======= {} {}".format(cur, conn))
                return conn, cur
            except(Exception, psycopg2.DatabaseError) as err:
                print(err)
                retries += 1
                print("======= Attempt {} to connect to DB =======".format(retries))
                if retries >= PG_CONN_RETRY_LIMIT:
                    raise err

                time.sleep(10)

    def _create_tables(self):
        create_table_cmds = [
            "CREATE TABLE " + Management_full_run_test + "(job_base_name VARCHAR(32), build_id INT,\
            stream VARCHAR(64), build_start TIMESTAMP NOT NULL, build_end TIMESTAMP,\
            build_state VARCHAR(32), build_url VARCHAR(128), sonic_image_link VARCHAR(256),\
            result_sum jsonb, result_url VARCHAR(128), p2build_job_id INT, sanity_type VARCHAR(32),\
            report_link VARCHAR(128), log_tarball_link VARCHAR(128), sku VARCHAR(32)\
            PRIMARY KEY(job_base_name, build_id))",
        ]
        try:
            for table_name, create_table_cmd in zip(tables, create_table_cmds):
                # create table one by one
                find_table_cmd = "select count(*) from pg_class where relname = '" + table_name + "'"
                self.cur.execute(find_table_cmd)
                results=self.cur.fetchone()
                if results[0] == 0:
                    self.cur.execute(create_table_cmd)
        except(Exception, psycopg2.DatabaseError) as err:
            self.conn.rollback()
            return -1
        self.conn.commit()
        return 0

    def execute_values(self, sql, values):
        #print("------ in execute_values function ------")
        if not self.conn or self.conn.closed:
            print(f"Connection is not active. Reconnecting...")
            self.connect()
            if not self.conn:
                return None 

        attempt = 0
        while attempt < 2:
            try:
                extras.execute_values(self.cur, sql, values)
                break
            except(Exception, psycopg2.DatabaseError) as err:
                if re.search("server closed the connection", str(err)):
                    self.conn, self.cur = self._connect_postgres_db()
                    attempt += 1
                    continue
                else:
                    self.conn.rollback()
                    print("======= ROLLEDBACK =======")
                    print(err)
                    return -1

        self.conn.commit()
        #print("======= Connected to DB successfully =======")
        return 0

    def execute(self, sql, params=None):
        if not self.conn or self.conn.closed:
            print(f"Connection is not active. Reconnecting...")
            self.connect()
            if not self.conn:
                return None 

        attempt = 0
        #print("------ in execute function ------")
        while attempt < 2:
            try:
                if params: 
                    self.cur.execute(sql, params) 
                else: 
                    self.cur.execute(sql) 
                break
            except(Exception, psycopg2.DatabaseError) as err:
                if re.search("server closed the connection", str(err)):
                    self.conn, self.cur = self._connect_postgres_db()
                    attempt += 1
                    continue
                else:
                    self.conn.rollback()
                    #print("======= ROLLEDBACK =======")
                    print(err)
                    return -1

        if not sql.strip().lower().startswith("select"):
            self.conn.commit()
        #print("======= Connected to DB successfully =======")
        return 0

    def insert(self, table_name, key_data):
        """
        Insert a new row to table
        :param 
         table_name:
         key_data: dict
        :return: 0 if success, -1 if failure
        """
        column_str = ""
        value_str = ""
        for key, value in key_data.items():
            column_str = column_str + str(key) + ","
            value_str = value_str + "'" + str(value) + "',"
        column_str = column_str.strip(',')
        value_str = value_str.strip(',')
        sql = "INSERT INTO " + table_name + "(" + column_str + ") VALUES(" + value_str + ")"
        print("======= SQL QUERY: {}".format(sql))
        return self.execute(sql)

    def update(self, table_name, key_data, updated_data):
        """
        Update rows in table
        :param
         table_name:
         key_data: dict, search condition
         updated_data: dict
        :return: 0 if success, -1 if failure
        """
        sql = "UPDATE " + table_name + " SET "
        for column, value in updated_data.items():
            if isinstance(value, list):
                sql = "%s %s = ARRAY %s," % (sql, column, value)
            else:
                if isinstance(value,dict):
                    value = json.dumps(value)
                sql = "%s %s = '%s'," % (sql, column, value)
        sql = sql.strip(',')
        sql = sql + " WHERE "
        conjunction = ""
        for key, value in key_data.items():
            sql = "%s%s%s = '%s'" % (sql, conjunction, key, value)
            conjunction = " and "

        print("======= UPDATED SQL QUERY: {}".format(sql))
        return self.execute(sql)


    def update_many(self, table_name, updates, key_column="id"):
        """
        Batch update multiple rows efficiently using CASE WHEN.
        Example of updates:
            [{"id": 1, "analysis": "A"}, {"id": 2, "analysis": "B"}]
        """
        if not updates:
            return

        update_columns = list(updates[0].keys())
        update_columns.remove(key_column)

        ids = [upd[key_column] for upd in updates]

        # Build CASE expressions and parameter list
        set_clauses = []
        params = []

        for col in update_columns:
            case_sql = "CASE"
            for upd in updates:
                case_sql += " WHEN {} = %s THEN %s".format(key_column)
                params.append(upd[key_column])
                params.append(upd[col])
            case_sql += f" ELSE {col} END"
            set_clauses.append(f"{col} = {case_sql}")

        # WHERE clause parameters (for IN)
        where_placeholders = ", ".join(["%s"] * len(ids))
        params.extend(ids)

        sql = f"UPDATE {table_name} SET {', '.join(set_clauses)} WHERE {key_column} IN ({where_placeholders})"

        #print("\nUPDATE QUERY:")
        #print(sql)
        #print("PARAMS:", params)

        return self.execute(sql, params)

    
    def update_many_by_key(self, table_name, updates, key_column):
        """
        Batch update multiple rows efficiently using CASE WHEN.

        Example:
            updates = [
                {"jira_id": "MIGSOFTWAR-123", "jira_status": "Done", "title": "Fixed bug"},
                {"jira_id": "MIGSOFTWAR-456", "jira_status": "Blocked", "title": "Need input"},
            ]

        key_column:
            "jira_id"
        """
        if not updates:
            return

        update_columns = list(updates[0].keys())
        if key_column not in update_columns:
            raise ValueError(f"Key column '{key_column}' missing from updates")

        update_columns.remove(key_column)

        if not update_columns:
            raise ValueError("No columns to update")

        keys = [upd[key_column] for upd in updates]

        set_clauses = []
        params = []

        for col in update_columns:
            case_sql = "CASE"
            for upd in updates:
                case_sql += f" WHEN {key_column} = %s THEN %s"
                params.append(upd[key_column])
                params.append(upd[col])
            case_sql += f" ELSE {col} END"
            set_clauses.append(f"{col} = {case_sql}")

        where_placeholders = ", ".join(["%s"] * len(keys))
        params.extend(keys)

        sql = f"""
            UPDATE {table_name}
            SET {', '.join(set_clauses)}
            WHERE {key_column} IN ({where_placeholders})
        """

        return self.execute(sql, params)


    def delete(self, table_name, key_data):
        """
        Delete rows in table
        :param
         table_name:
         key_data: dict, search condition
        :return: 0 if success, -1 if failure
        """
        sql = "DELETE FROM " + table_name + " WHERE "
        conjunction = ""
        for key, value in key_data.items():
            sql = "%s%s%s = '%s'" % (sql, conjunction, key, value)
            conjunction = " and "
        return self.execute(sql)


    def find(self, table_name, key_data=None, column_list=None, sort_column_list=None, sort_rule="DESC"):
        """
        Query db data, return rows which match the query condition
        :param
         table_name:
         key_data: dict, query condition
         sort: list, e.g. [('build_id', DESC)]
        :return: query results, None if query fails
        """
        column_str = "*"
        if column_list != None:
            column_str = ",".join(column_list)
        sql = "SELECT " + column_str + " FROM " + table_name + " "
        if key_data:
            sql = "%sWHERE " % sql
            conjunction = ""
            for key, value in key_data.items():
                if value == None:
                    sql = "%s%s%s IS NULL" % (sql, conjunction, key)
                    conjunction = " and "
                elif value == NOT_NULL:
                    sql = "%s%s%s IS not NULL" % (sql, conjunction, key)
                    conjunction = " and "
                else:
                    sql = "%s%s%s = '%s'" % (sql, conjunction, key, value)
                    conjunction = " and "
        if sort_column_list != None:
            sql = sql + " ORDER BY " 
            for sort_column in sort_column_list:
                sql = sql + sort_column + ","
            sql = sql.strip(',')
            sql = sql + " " + sort_rule

        rt = self.execute(sql)
        if rt != 0:
            return None
        return self.cur.fetchall()


    def find_one(self, table_name, key_data=None, column_list=None, sort_column_list=None, sort_rule="DESC"):
        """
        Query db data, return the first record which matches the query condition
        :param
         table_name:
         key_data: dict, query condition
         sort_column_list: e.g. ['build_id']
        :return: one row as tuple, None if query fails
        """
        results = self.find(table_name, key_data, column_list, sort_column_list, sort_rule)
        if results != None and len(results) != 0:
            print(f"SQL FIND_ONE RESULT ====== {results[0]}")
            return results[0]
        return None
    

    def find_many(self, table_name, key_data=None, column_list=None, sort_column_list=None, sort_rule="DESC"):
        """
        Query db data and return multiple rows that match the condition.
        Supports IN filters and parameterized queries for safety.
        """
        column_str = "*"
        if column_list:
            column_str = ", ".join(column_list)

        sql = f"SELECT {column_str} FROM {table_name}"
        params = []
        clauses = []

        # --- WHERE filters ---
        if key_data:
            for key, value in key_data.items():
                if value is None:
                    clauses.append(f"{key} IS NULL")
                elif isinstance(value, (list, tuple, set)):
                    placeholders = ", ".join(["%s"] * len(value))
                    clauses.append(f"{key} IN ({placeholders})")
                    params.extend(list(value))
                elif isinstance(value, dict) and "$in" in value:
                    placeholders = ", ".join(["%s"] * len(value["$in"]))
                    clauses.append(f"{key} IN ({placeholders})")
                    params.extend(value["$in"])
                else:
                    clauses.append(f"{key} = %s")
                    params.append(value)

        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        # --- ORDER BY ---
        if sort_column_list:
            sql += " ORDER BY " + ", ".join(sort_column_list) + f" {sort_rule}"

        # --- Execute safely ---
        rt = self.execute(sql, params)
        if rt != 0:
            return None
        return self.cur.fetchall()
       
        

    def get_next_sequence_value(self, seq_name):
        # Execute the SQL query to get the next value from the sequence
        # We use SELECT nextval() to retrieve the value
        rt = self.execute(f"SELECT nextval('{seq_name}');")
        if rt != 0:
            return None
        return self.cur.fetchall()
    

    def get_images(self, stream, npu, platform, p2build_job_id):
        sql = "SELECT DISTINCT p2build_job_id FROM management_full_run_test WHERE stream = '" + stream + "' AND project = '" + npu + "' AND platform = '" + platform + "' AND p2build_job_id < " + str(p2build_job_id) + ";"

        print(f"QUERY FOR FINDING IF IMAGES EXIST FOR THIS STREAM+PROJECT+PLATFORM: {sql}")
        rt = self.execute(sql)
        if rt != 0:
            return None
        return self.cur.fetchall()


    def get_closest_image_id(self, stream, project, platform, image_id, than_type="lesser"):
        # Execute the SQL query to get the closest value (lesser and greater) than the given image_id 
        sql = "SELECT p2build_job_id FROM management_full_run_test WHERE p2build_job_id "

        if than_type == "greater":
            sql += "> " 
        else: 
            sql += "< "
        
        sql += str(image_id) + " AND stream = '" + stream + "' AND project = '" + project + "' AND platform = '" + platform + "' ORDER BY p2build_job_id "

        if than_type == "greater":
            sql += "ASC "
        else:
            sql += "DESC "
        
        sql += "LIMIT 1;"

        print(f"QUERY FOR FINDING CLOSEST IMAGE: {sql}")
        rt = self.execute(sql)
        if rt != 0:
            return None
        return self.cur.fetchall()


    def close_connection(self): 
        if self.cur:
            self.cur.close()
        if self.conn:
            self.conn.close()


class PostgresTableSonicSol(object):
    """
    This class is a basic Postgresdb table operation sets.
    Basic table functions like update, query_one
    """

    def __init__(self, table_name, use_backup=False):
        """
        Get the db connect info
        :param:
        :return:
        """
        if not table_name:
            raise TableKeyError("Table Name can't be null")
        self.dbConn = PostgresDBConnectionSonicSol(use_backup)
        self.table_name = table_name
        #log.debug("PostgresTable Table Name is %s", self.table_name)

    def update(self, key_data, updated_data):
        """
        Update the db data, if key_data not exist in table, insert new row
        :param key_data:
        :param updated_data:
        :return:
        """
        if not updated_data:
            raise ValueError(
                "Updating table with invalid update data: %s" % self.table_name)
        
        if not key_data:
            raise CollKeyErrorSonicSol(
                "Updating table with invalid key data: %s" % self.table_name)

        num_match = 0
        rows = self.dbConn.find(self.table_name, key_data)
        if rows != None:
            num_match = len(rows)
        # #log.debug("get current row num_match %d", num_match)

        if num_match == 0:
            #log.debug("Match 0 row, insert a new one")
            res = self.dbConn.insert(self.table_name, updated_data)
            #res2 = self.dbConn.update(self.table_name, key_data, updated_data)

            if res != 0:
                return res
        elif num_match > 1:
            #log.error("Match %d rows, duplicate records in table %s" % (num_match, self.table_name))
            return -1
        
        res = self.dbConn.update(self.table_name, key_data, updated_data)
        return res

    def delete(self, key_data):
        """
        Delete the db data row if key_data matches
        :param key_data:
        :return:
        """
        if not key_data:
            raise CollKeyErrorSonicSol(
                "Delete entry from table %s with invalid key data: %s" % (self.table_name, key_data))

        res = self.dbConn.delete(self.table_name, key_data)
        return res

    def query(self, key_data=None, column_list=None, sort_column_list=None, sort_rule="DESC"):
        """
        Query db records, return all records which match the query condition
        :param key_data: dict, query condition
        :param column_list: query columns
        :return: tuple
        """
        # Check if we have to restrict the query to only consider staging records
        if SysTools.is_dev_env():
            if not key_data:
                key_data = {}
            if key_data.get('env_type') is None:
                key_data['env_type'] = SysTools.get_current_env_type()
        else:
            if key_data and 'env_type' in key_data:
                key_data.pop('env_type')
            
        if not sort_column_list:
            rows = self.dbConn.find(self.table_name, key_data, column_list)
        else:
            rows = self.dbConn.find(self.table_name, key_data, column_list, sort_column_list, sort_rule)

        #log.debug("query result:")
        #log.debug(rows)

        return rows

    def query_one(self, key_data=None, column_list=None, sort_column_list=None, sort_rule="DESC"):
        """
        Query a db record, return the latest record which matches the query condition
        :param key_data: dict, query condition
        :param column_list: query columns
        :return: tuple
        """

        if not sort_column_list:
            row = self.dbConn.find_one(self.table_name, key_data, column_list)
        else:
            # #log.debug("query one record with sort_list %s" % sort_column_list)
            row = self.dbConn.find_one(self.table_name, key_data, column_list, sort_column_list, sort_rule)

        # #log.debug("query one %s" % type(row))
        #log.debug("query result:")
        #log.debug(row)

        return row
        """
        set aborted job's end time
        """
        key_data = {
            self.BUILD_ID: build_id
        }
        changed_data = {
            self.BUILD_STATE: state
        }
        self.update(key_data, changed_data)