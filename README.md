# Jamf Pro Database Decrypt

This project allows you to query for and decrypt content from the Jamf Pro Database.

Obviously, you'll need access to your running Jamf Pro MySQL Database -- so either an on-prem instance or a copy of the database will be required.


# Credit

Initial reverse engineering and code created by [dmaasland](https://github.com/dmaasland), so this is obviously a fork of his project.

I have heavily customized this original work to make it more easily approachable to Jamf Pro Admins and also added a method to support filtering the database for desired information instead of (only) dumping the entire database.  Additional improvements and customizations from the original project were also made.


# Setup

```shell

# Create a directory to clone project into
mkdir "Jamf Pro DB Decrypt" && cd "Jamf Pro DB Decrypt"

# Clone this repository
git clone https://github.com/MLBZ521/jamf_pro_db_decrypt.git .

# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
source .venv/bin/activate

# Install the required packages:
pip install jasypt4py mysql-connector-python pycryptodomex sshtunnel

# Or, install the specific versions used during development
# pip install -r ./requirements.txt
```


# Example usage

```python

from jamf_pro_db_decrypt import JamfProDatabase

# Initialize an JPS DB Object
jpsdb = JamfProDatabase(use_ssh=True)

# Get the entire Cloud DP table and store it, as a dict, in a variable
cdp = jpsdb.query(table="cloud_distribution_point")

# Get the DP where ID = 3 and print to stdout in the standard MySQL CLI table format
jpsdb.query("distribution_points", record_filter = {"distribution_point_id": 3}, out_as_table=True )

# Get the computer where ID = 1234 and store it, as a dict, in a variable
jpsdb.query("computers", record_filter = {"computer_id": 12345})

# Dump all tables with encrypted fields to individual <table>.html files
jpsdb.dump_encrypted_tables(out="~/jamf_pro_db_decrypt/decrypted_tables")

# It's also possible to provide an encrypted string directly to be decrypted
decrypted_string = jpsdb.decrypt("<encrypted_string>")
```
