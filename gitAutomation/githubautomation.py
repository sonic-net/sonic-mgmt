import requests
import csv
from pprint import pprint
import pandas as pd
import json
import sys

data = list()
for i in range(1,50):
    params = {"state": "all","page": i}
    token = sys.argv[1]
    url="https://wwwin-github.cisco.com/api/v3/repos/whitebox/sonic-buildimage/issues"
    headers = {'Authorization': token}
    r = requests.get(url, headers=headers, params=params)
    if r.status_code != 200:
        raise Exception(r.text)
    for bug in r.json():
        with open('bugslist.csv', 'a') as bugslist:
            try:
                fieldnames = ['Title', 'Created', 'Closed', 'State', 'BugID', 'RaisedBy', 'AssignedTo', 'Labels']
                writer = csv.DictWriter(bugslist, fieldnames=fieldnames)
                writer.writerow({'Title': bug['title'], 'Created': bug['created_at'], 'Closed':bug['closed_at'],'State': bug['state'],
                                 'BugID': bug['number'], 'RaisedBy': bug['user']['login'],
                                 'AssignedTo': bug['assignee']['login'], 'Labels':[ele['name'].encode('ascii') for ele in bug['labels']] })
            except:
                pass

        # Creating JSON File
        try:
            bugDict = {"BugID":bug['number'], 'Title': bug['title'], 'Created at': bug['created_at'], 'Closed at':bug['closed_at'],'State': bug['state'],
                                      'RaisedBy': bug['user']['login'],
                                     'AssignedTo': bug['assignee']['login'], 'Labels':[ele['name'] for ele in bug['labels']] }
            data.append(bugDict)
        except:
            pass

with open('bugslist.json', 'w') as outfile:
    json.dump(data, outfile)




#Creating Headers
file = pd.read_csv("bugslist.csv")
headerList=['Title', 'Created', 'Closed', 'State', 'BugID', 'RaisedBy', 'AssignedTo', 'Labels']
file.to_csv("bugslist.csv", header=headerList, index=False)
file2 = pd.read_csv("bugslist.csv")
print(file2)



