# This file is the actual code for the custom Python dataset threatfox_ioc

# import the base class for the custom dataset
from dataiku.connector import Connector
import csv
import io
import zipfile
import requests

"""
A custom Python dataset is a subclass of Connector.

The parameters it expects and some flags to control its handling by DSS are
specified in the connector.json file.
"""
class ThreatFoxConnector(Connector):

    def __init__(self, config, plugin_config):
        # Pass the parameters to the base class
        Connector.__init__(self, config, plugin_config)

        # Get target dataset params
        self.ioc_type = self.config.get("ioc_type")

    def get_read_schema(self):
        """
        Returns the schema that this connector generates when returning rows.

        The returned schema may be None if the schema is not known in advance.
        In that case, the dataset schema will be infered from the first rows.

        If you do provide a schema here, all columns defined in the schema
        will always be present in the output (with None value),
        even if you don't provide a value in generate_rows

        The schema must be a dict, with a single key: "columns", containing an array of
        {'name':name, 'type' : type}.

        Example:
            return {"columns" : [ {"name": "col1", "type" : "string"}, {"name" :"col2", "type" : "float"}]}

        Supported types are: string, int, bigint, float, double, date, boolean
        """

        # In this example, we don't specify a schema here, so DSS will infer the schema
        # from the columns actually returned by the generate_rows method
        return None

    def generate_rows(self, dataset_schema=None, dataset_partitioning=None,
                            partition_id=None, records_limit = -1):
        """
        The main reading method.

        Returns a generator over the rows of the dataset (or partition)
        Each yielded row is a dictionary, indexed by column name.

        The dataset schema and partitioning are given for information purpose.
        """
        # Download zipped file from TreatFox
        response = requests.get("https://threatfox.abuse.ch/export/csv/"+ self.ioc_type +"/full/", verify=False)
        
        # Extract IOC csv from zip file
        with zipfile.ZipFile(io.BytesIO(response.content)) as thezip:
            csvString = thezip.read('full_'+ self.ioc_type +'.csv')
        
        # Create an in-memory file-like object from the csvString
        s=str(csvString,'utf-8')
        data = io.StringIO(s)
        
        # Read CSV and stream rows
        columnNames = [ "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","reference","tags","anonymous","reporter" ]
        csv_reader  = csv.DictReader(filter(lambda row: row[0]!='#', data), fieldnames=columnNames, quotechar='"', doublequote=False, skipinitialspace=True)
  
        for v in csv_reader:
            yield v
  


    def get_writer(self, dataset_schema=None, dataset_partitioning=None,
                         partition_id=None):
        raise NotImplementedError


    def get_partitioning(self):
        raise NotImplementedError


    def list_partitions(self, partitioning):
        return []


    def partition_exists(self, partitioning, partition_id):
        raise NotImplementedError


    def get_records_count(self, partitioning=None, partition_id=None):
        raise NotImplementedError


class CustomDatasetWriter(object):
    def __init__(self):
        pass

    def write_row(self, row):
        raise NotImplementedError

    def close(self):
        pass
