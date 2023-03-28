#!/usr/bin/env python3

import base64
import configparser
import contextlib
import sys
import os

import jasypt4py
import mysql.connector
import sshtunnel

from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES
from Cryptodome.Util import Padding


__about__ = "https://github.com/MLBZ521/jamf_pro_db_decrypt"
__updated__ = "3/27/2023"
__version__ = "1.0.0"


class Configuration(dict):
	"""A class that creates a simple object to hold configuration details."""

	def __init__(self, load: os.path):
		self.config = {}
		self.load_config(config=load)


	def add(self, key, value):
		self.config[key] = value


	def get(self, key):
		return self.config.get(key, None)


	def load_config(self, *args, **kwargs):
		"""A simple function to parse a configuration file and load it into an object.

		Returns:
			Configuration: A Configuration object container containing the configuration details.
		"""

		# Create a configparser instance
		config = configparser.ConfigParser()
		config_file = kwargs.get("config")

		if config_file != None and os.path.exists(config_file):
			# Read in the configuration file
			config.read(config_file)

		else:
			raise FileNotFoundError("\nError:  Unable to locate configuration file.\n")

		for section in config.sections():
			for key in config[section]:
				self.add(f"{section}.{key}", config[section].get(key))

		return self.config


class QueryMySQL():
	"""A class that creates a Context Manager to interact with a MySQL database."""

	def __init__(self, hostname, database, username, password,
		port=3306, dictionary=True, timeout=10, verbose=True
	):
		self.hostname = hostname
		self.username = username
		self.password = password
		self.database = database
		self.port = port
		self.dictionary = dictionary
		self.timeout = timeout
		self.verbose = verbose


	def __enter__(self):
		"""Opens a connection to the database.

		Returns:
			db_cursor: A database cursor instance
		"""

		self.__verbose__(
			f"Connecting to the {self.database} database on host {self.hostname}...",
			end=""
		)

		self.db_connection = mysql.connector.MySQLConnection(
			host = self.hostname,
			user = self.username,
			password = self.password,
			db = self.database,
			port = self.port
		)

		self.__verbose__("Connected!")
		self.db_cursor = self.db_connection.cursor(buffered=True, dictionary=self.dictionary)
		return self.db_cursor


	def __exit__(self, exc_type, exc_value, exc_traceback):
		"""Commits and closing connection to the database"""

		# Commit the transaction
		self.db_connection.commit()

		# Close the cursor
		self.db_cursor.close()

		# Close the connection
		self.db_connection.close()

		self.__verbose__("Closed DB Connection!")


	def __verbose__(self, message, end="\n", file=sys.stdout):
		"""Handles verbose messaging

		Args:
			message (str): A message to be printed.
			end (str, optional): A string that will be appended after the last value of `message`.
				Defaults to newline (i.e. `\\n`).
			file (file-like object (stream), optional): Where the message will be sent.
				Defaults to the current sys.stdout.
		"""

		if self.verbose:
			print(message, end=end, file=file)


class SSHTunnel():
	"""A class that creates a Context Manager for an SSH Tunnel."""

	def __init__(self, hostname, username, password, remote_bind_address=('127.0.0.1', 3306),
		local_bind_address = ('127.0.0.1', 3306), port = 22,
		ssh_key=None, allow_agent=False, verbose=True
	):
		self.hostname = hostname
		self.port = port
		self.username = username
		self.password = password
		self.remote_bind_address = remote_bind_address
		self.local_bind_address = local_bind_address
		self.ssh_key = ssh_key
		self.allow_agent = allow_agent
		self.verbose = verbose

		self.client = sshtunnel.SSHTunnelForwarder(
			(self.hostname, self.port),
			ssh_username = self.username,
			ssh_password = self.password,
			# ssh_pkey = self.ssh_key,
			remote_bind_address = self.remote_bind_address,
			local_bind_address = self.local_bind_address,
			allow_agent = self.allow_agent
		)


	def __enter__(self):
		"""Opens a SSH Tunnel to the host.

		Returns:
			ssh client: A ssh tunnel forwarder instance.
		"""

		self.start()
		return self.client


	def __exit__(self, exc_type, exc_value, exc_traceback):
		"""Context Manager method to handle exiting."""

		self.close()


	def __verbose__(self, message, end="\n", file=sys.stdout):
		"""Handles verbose messaging

		Args:
			message (str): A message to be printed.
			end (str, optional): A string that will be appended after the last value of `message`.
				Defaults to newline (i.e. `\\n`).
			file (file-like object (stream), optional): Where the message will be sent.
				Defaults to the current sys.stdout.
		"""

		if self.verbose:
			print(message, end=end, file=file)


	def active(self):
		"""Determine if the SSH Tunnel is currently open.

		Returns:
			bool: Returns True if the tunnel is open/connected.
		"""

		return self.client.is_active


	def close(self):
		"""Handles closing the SSH Tunnel"""

		self.client.close()
		self.__verbose__("SSHTunnel closed!")


	def start(self):
		"""Opens a SSH Tunnel to the host.

		Returns:
			ssh client: A ssh tunnel forwarder instance.
		"""

		self.__verbose__(
			f"SSHing into host {self.hostname}...",
			end=""
		)

		if not self.active():
			self.client.start()

		self.__verbose__("Connected!")


class JamfProDatabase():
	"""Creates an object that allows interaction with the
		Jamf Pro Database to decrypt it's contents."""

	def __init__(self, config_file=".secrets", use_ssh=True, verbose=True):
		self.verbose = verbose
		self.use_ssh = use_ssh
		self.session_key = None
		self.jamf_db_cursor = None

		# Load secrets
		self.config = Configuration(load=os.path.abspath(config_file))

		# There are hard-coded in the Jamf Pro software
		# (PasswordServiceImpl.class and PasswordServiceImpl$Encrypter.class)
		self.storage_key = "2M#84->)y^%2kGmN97ZLfhbL|-M:j?"
		self.salt = b"\xA9\x9B\xC8\x32\x56\x35\xE3\x03"
		self.iterations = 19

		if self.use_ssh:
			self._init_ssh_tunnel()

		self.session_key = self._get_session_key()


	def _init_ssh_tunnel(self):
		"""Setup and start an SSH Tunnel."""

		if self.use_ssh:
			self.ssh_tunnel = SSHTunnel(
				hostname = self.config.get("jps.prod.database_hostname"),
				port = int(self.config.get("ssh.port")),
				username = self.config.get("ssh.username"),
				password = self.config.get("ssh.password"),
				# ssh_pkey="~/.ssh/<...>",
				# remote_bind_address = ('127.0.0.1', 3306),
				# local_bind_address = ('127.0.0.1', 3306)
				allow_agent=False,
				verbose=self.verbose
			)
			self.ssh_tunnel.start()
		else:
			self.ssh_tunnel = contextlib.nullcontext()


	def _init_db_connection(self):
		"""Setup a MySQL database cursor."""

		# Create connection manager
		self.jamf_db_cursor = QueryMySQL(
			hostname = "127.0.0.1",
			# hostname = self.ssh_tunnel.client.local_bind_address,
			# hostname = self.ssh_tunnel.local_bind_host,
			# port = self.ssh_tunnel.local_bind_port,
			database = self.config.get("jps.prod.database_name"),
			username = self.config.get("jps.prod.database_username"),
			password = self.config.get("jps.prod.database_password"),
			dictionary = True,
			verbose=self.verbose
		)


	def __query(self, query_statement: str, close_ssh=True):
		"""Internal method to query the database.

		Args:
			query_statement (str): A SQL formatted query statement.
			close_ssh (bool, optional): Whether or not the SSH Tunnel should be closed
				after the query is performed. Defaults to True.

		Returns:
			(dict, dict): Two dict's are returned, one of the SQL query results, the other a dict
				containing meta data of the results (specifically the row count and column names).
		"""

		if self.use_ssh and not self.ssh_tunnel.active():
			self.ssh_tunnel.client.restart()

		if not self.jamf_db_cursor:
			self._init_db_connection()

		with self.jamf_db_cursor as _query:
			_query.execute(f"{query_statement}")
			results = _query.fetchall()
			meta_data = { "rowcount": _query.rowcount, "column_names": _query.column_names }

		if self.use_ssh and close_ssh:
			self.ssh_tunnel.close()

		return results, meta_data


	def _get_session_key(self):
		"""Gets the encrypted encryption key from the database to decrypt it.

		Returns:
			str: The decryption key.
		"""

		# Get encrypted session key from database
		results, _ = self.__query(
			"SELECT \
				FROM_BASE64(encryption_key) AS encryption_key, \
				encryption_type \
			FROM encryption_key \
			;"
		)

		encryption_key = results[0].get("encryption_key")
		encryption_type = results[0].get("encryption_type")

		# Check if it's AES
		if encryption_type != 1:
			print("Unsupported encryption method", exit_code=3)

		# Decrypt the session key
		return self.decrypt(encryption_key, self.storage_key)


	def decrypt(self, encrypted_value, decryption_key=None):
		"""Decrypt the passed encrypted text with the passed decryption key.

		Args:
			encrypted_value (str): Encrypted string.
			decryption_key (str, optional): Decryption string.
				Defaults to None.

		Returns:
			str: The decrypted string from the encrypted string.
		"""

		if not decryption_key:
			decryption_key = (self.session_key).decode("utf-8")

		# Generate key and IV
		generator = jasypt4py.generator.PKCS12ParameterGenerator(SHA256)
		key, iv = generator.generate_derived_parameters(decryption_key, self.salt, self.iterations)

		# Do actual decryption
		cipher = AES.new(key, AES.MODE_CBC, iv)

		try:
			plain_text = Padding.unpad(cipher.decrypt(encrypted_value), AES.block_size)
		except IndexError:
			plain_text = cipher.decrypt(encrypted_value)

		# Return decrypted data
		return plain_text


	def query(self, table: str, record_filter: dict = "", out_as_table=False):
		"""Get a table's contents, optionally filtering for a record,
			if it has encrypted fields and return decrypted.

		Args:
			table (str): A table in the Jamf Pro database.
			record_filter (dict, optional): A dict value to filter a table by.  The key
				in the table will be used as the column filter and the dict value will be
				used as the column value.
				Defaults to "" (or no filter value).

		Returns:
			dict: A dictionary of the table if it had encrypted columns
		"""

		# Query for the specified table and verify there is encrypted data
		encrypted_data, _ = self.__query(
			f"SELECT COLUMN_NAME \
				FROM INFORMATION_SCHEMA.COLUMNS \
				WHERE \
					TABLE_SCHEMA = '{self.config.get('jps.prod.database_name')}' \
					AND TABLE_NAME = '{table}' \
					AND COLUMN_NAME like '%_encrypted%' \
			;",
			close_ssh = False
		)

		if encrypted_data:
			print(f"Found encrypted data in table '{table}', decrypting...")

			if record_filter:
				key = list(record_filter)[0]
				value = record_filter.get(key)
				record_filter = f" where {key} = {value}"

			results, _ = self.__query(f"SELECT * FROM {table}{record_filter};")

			decrypted_results = []

			for record in results:

				new_record = {}

				for key, value in record.items():

					if value and key.endswith("_encrypted"):
						key = key.replace('_encrypted', '_decrypted')

						decrypted_contents = self.decrypt(base64.b64decode(value))

						if key.find("key") != -1:
							decrypted_contents = base64.b64encode(decrypted_contents)

						decrypted_contents = (decrypted_contents).decode()
						value = decrypted_contents

					new_record[key] = value
				decrypted_results.append(new_record)

			if out_as_table:
				return self.format_as_table(decrypted_results)

			return decrypted_results

		else:
			print(f"No encrypted data found in table `{table}`, rows {encrypted_data}")


	def dump_encrypted_tables(self, out: os.path = os.path.curdir):
		"""Dump all tables that contain encrypted values to html files.

		Args:
			out (os.path, optional): A directory where results will be saved.
				Defaults to os.path.curdir.
		"""

		tables, _ = self.__query(
			f"SELECT DISTINCT TABLE_NAME \
				FROM INFORMATION_SCHEMA.COLUMNS \
				WHERE \
					TABLE_SCHEMA = '{self.config.get('jps.prod.database_name')}' \
					AND COLUMN_NAME LIKE '%_encrypted%' \
			;",
			close_ssh = False
		)

		try:

			out = os.path.abspath(out)
			if not os.path.exists(os.path.abspath(out)):
				os.makedirs(os.path.abspath(out))

			for table in tables:

				table = table.get("TABLE_NAME")

				table_contents, query_details = self.__query(
					f"SELECT * FROM {table};", close_ssh = False)

				if query_details.get("rowcount") == 0:
					# Table doesn't have any records.
					continue

				html_filename = f"{out}/{os.path.basename(table)}.html"

				with open(f"{html_filename}", "w") as html_file:

					html_file.write(
						"<!DOCTYPE html>\n<html>\n\t<head>\n\t\t<meta charset=\"UTF-8\">"
						f"{self.__init_css()}\n\t</head>\n\t<body>\n\t\t<table>\n\t\t\t<tbody>"
						"\n\t\t\t\t<tr>\n"
					)

					for column in query_details.get("column_names"):

						if column.endswith("_encrypted"):
							column = column.replace('_encrypted', '_decrypted')

						html_file.write(f"\t\t\t\t\t<th>{column}</th>\n")

					html_file.write("\t\t\t\t</tr>\n")

					for row in table_contents:
						html_file.write("\t\t\t\t<tr>\n")

						for column, value in row.items():

							if column.endswith("_encrypted"):

								if value:
									decrypted_contents = self.decrypt(base64.b64decode(value))

									if column.find("key") != -1:
										decrypted_contents = base64.b64encode(decrypted_contents)

									html_file.write(
										f"\t\t\t\t\t<td>{(decrypted_contents).decode()}</td>\n")

								else:
									html_file.write(f"\t\t\t\t\t<td></td>\n")

							else:
								try:
									html_file.write(f"\t\t\t\t\t<td>{str(value)}</td>\n")
								except UnicodeDecodeError:
									html_file.write(f"\t\t\t\t\t<td>{value.encode('hex')}</td>\n")

						html_file.write("\t\t\t\t</tr>\n")

					html_file.write("\t\t\t</tbody>\n\t\t</table>\n\t</body>\n</html>")

		except Exception as error:
			raise(error)

		finally:
			self.ssh_tunnel.close()


	def __init_css(self):
		"""Simply returns a CSS style block for an HTML page."""

		return """
		<style type="text/css">
			tbody th {
				border: 1px solid #000;
			}
			tbody td {
				border: 1px solid #ababab;
				border-spacing: 0px;
				padding: 4px;
				border-collapse: collapse;
				overflow: hidden;
				text-overflow: ellipsis;
				max-width: 200px;
			}
			body {
				font-family: verdana;
			}
			table {
				font-size: 13px;
				border-collapse: collapse;
				width: 100%;
			}
			tbody tr:nth-child(odd) td {
				background-color: #eee;
			}
			tbody tr:hover td {
				background-color: lightblue;
			}
		</style>"""


	def format_as_table(self, results: list):
		"""Takes the the results of a SQL Query and outputs it in the format
			of a text based table, similar to that of a cli tool to stdout.

		Borrowed and modified from source:  https://stackoverflow.com/a/69181604

		Args:
			results (list): The results of a SQL Query in a dictionary format.

		Returns:
			str: The str formatted into a table.
		"""

		if not len(results):
			return []

		# Add col headers length to widths
		max_widths = {key: len(key) for key in results[0].keys()}

		# Add max content lengths to widths
		for row in results:
			for key in row.keys():
				if len(str(row[key])) > max_widths[key]:
					max_widths[key] = len(str(row[key]))

		widths = [max_widths[key] for key in results[0].keys()]
		pipe = "|"
		separator = "+"

		for w in widths:
			pipe += f" %-{w}.{w}s |"
			separator += "-" * w + "--+"

		visual_table = f"{separator}\n" + pipe % tuple(results[0].keys()) + f"\n{separator}\n"

		for row in results:
			visual_table += pipe % tuple(row.values()) + "\n"

		visual_table += f"{separator}\n"

		print(visual_table)
