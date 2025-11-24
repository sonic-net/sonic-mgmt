


# Setup

Create virtualenv
```
python3 -m venv ingest-venv
```

Install dependencies
```
. ingest-venv/bin/activate
pip install -r requirements.txt
```

# Run

If you have azure cli installed and logged in run:
```
python3 ingest_reboot_data.py --auth-mode azcli
```

Otherwise, use
```
python3 ingest_reboot_data.py
```

which will print a link and code that you need to copy-paste into the browser to authenticate


# Notes

Historically this data was stored in `https://chinaazure.kusto.windows.net/` but has since moved to `https://sonicrepodatadev.westus.kusto.windows.net/` which is the default cluster.

If you want to publish data into the old cluster then run with:
```
python3 ingest_reboot_data.py --auth-mode azcli --cluster-uri https://chinaazure.kusto.windows.net/ --ingest-database SonicInsights
```

## Running as crontab

In your terminal, run `crontab -e` to open up your crontab file. Then add a line like the following (DONT FORGET TO MODIFY YOUR PATH):

```
0 0 * * * bash -c 'cd ~/src/sonic-mgmt-int/test_reporting/jupyter-notebooks/RebootDataIngestor && source ingest-venv/bin/activate && python3 ingest_reboot_data.py --auth-mode azcli >> RebootDataIngestor.log 2>&1'
```

This will run the script daily at midnight and output the logs to RebootDataIngestor.log adjacent to the script.
