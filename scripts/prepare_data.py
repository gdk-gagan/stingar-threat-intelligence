# 2 hours for one month of data locally
import pandas as pd
import numpy as np
import ast

import dns.resolver
import dns.reversename
from time import time
import datetime
import pickle

import argparse

import time
import warnings
warnings.filterwarnings('ignore')

parser = argparse.ArgumentParser(
                    prog='Ingest stingar data from API',
                    description='Download data as csv for each hour')
parser.add_argument('--year')           # positional argument
parser.add_argument('--month') 
parser.add_argument('--day') 
parser.add_argument('--ndays') 
parser.add_argument('--input')
parser.add_argument('--output') 

args = parser.parse_args()
# print(args.year, args.month, args.day, args.ndays, args.input, args.output)

year = int(args.year)
month = int(args.month)
start_day = int(args.day)
n_days = int(args.ndays)
output_path = args.output
input_path = args.input

# Validity checks for year, month, day
try:
    datetime.datetime(year=year,month=month,day=start_day)
except Exception as e:
    print("Invalid date")
    raise Exception

# Function to convert string representation to list
def convert_to_list(string):
    return ast.literal_eval(string)

# Define a function to extract values
def extract_values(creds_list):
#     creds_list = ast.literal_eval(creds)
    usernames = [entry['username'] for entry in creds_list]
    passwords = [entry['password'] for entry in creds_list]
    successes = [entry['success'] for entry in creds_list]
    return usernames, passwords, successes

# Define a function to fill missing dst_port based on protocol
def fill_dst_port(row):
    if row['protocol'] == 'http':
        return 80
    elif row['protocol'] == 'ftp':
        return 21
    else:
        return row['dst_port']

def get_clean_df(data):
    '''Performs several cleaning steps'''

    # 1. Clean column names
    data = data.rename({'@timestamp':'event_time'}, axis=1)
    
    # 2. Select features
    cols = ['app', 'src_ip', 'src_port', 'protocol', 
            'id','event_time', 'start_time', 'end_time',
           'dst_port', 'dst_ip', 'sensor_hostname', 'sensor_uuid', 
           'hp_data_session', 'hp_data_credentials', 'hp_data_commands',
           'hp_data_request', 'hp_data_response']

    df = data.loc[:, cols]

    # 3. Fill missing values (for dst port use protocol)
    df['dst_port'] = df.apply(fill_dst_port, axis=1)

#     df['hp_data_session'] = df['hp_data_session'].fillna(0)
    df['hp_data_credentials'] = df['hp_data_credentials'].fillna("[]")
    df['hp_data_commands'] = df['hp_data_commands'].fillna("[]")
    # df['hp_data_request'] = df['hp_data_request'].fillna("''")
    # df['hp_data_response'] = df['hp_data_response'].fillna("''")

    # 4. Data type cleaning
    df['event_time'] = pd.to_datetime(df['event_time'])
    df['start_time'] = pd.to_datetime(df['start_time'])
    df['end_time'] = pd.to_datetime(df['end_time'])
    df['src_port'] = df['src_port'].astype(object)
    df['dst_port'] = df['dst_port'].astype(int).astype(object)

    # 5. Apply the function to create a new column
    df['hp_data_commands'] = df['hp_data_commands'].apply(convert_to_list)
    df['hp_data_credentials'] = df['hp_data_credentials'].apply(convert_to_list)

    # 6. Extract username, password from hp_data_credentials
    df[['username', 'password', 'success']] = df['hp_data_credentials'].apply(lambda x: pd.Series(extract_values(x)))
    return df

def load_cache_from_file():
    try:
        with open('cache.pkl', 'rb') as file:
            return pickle.load(file)
    except FileNotFoundError:
        return {}

def save_cache_to_file(cache):
    with open('cache.pkl', 'wb') as file:
        pickle.dump(cache, file)

def dns_ip_to_hostname(ip: str) -> str:
    """
    Get hostname for given IP address
    :param ip: str | IP address
    :return hostname: str | Hostname registered to the IP address
    """
    if ip in CACHE:
            return CACHE[ip]
        
    try:
        hostname = (dns.resolver.resolve(dns.reversename.from_address(ip), "PTR")[0]).to_text()
    except:
        hostname = "NA"
        
    CACHE[ip] = hostname
    return hostname

def apply_dns_ip_to_hostname_column(df: pd.DataFrame, ip_col: str, hostname_col: str) -> pd.DataFrame:
    """
    Add a hostname column based on the IP address column
    :param df: pd.DataFrame
    :param ip_col: str | Column with IP addresses
    :param hostname_col: str | Column name for hostnames
    :return: pd.DataFrame | with hostname a new column
    """
    start_time = time.time()
    df_unique = pd.DataFrame({ip_col: df[ip_col].unique()})
    print(f"Adding hostname to IP addresses")
    try:
        df_unique[hostname_col] = df_unique[ip_col].apply(dns_ip_to_hostname)
        result_df = df.merge(df_unique, on=ip_col, how="left")
    except Exception as e:
        print(f"Error looking up dns hostname with exception {e}")
        raise
    
    print(f"Took {time.time() - start_time} seconds")
    print(f"Found hostnames for {result_df[result_df[hostname_col]!='NA'].count()[0]}/{len(df_unique)} IPs, {(result_df[result_df[hostname_col]!='NA'].count()[0] *100 /result_df.shape[0]).round(2)}%")
    return result_df


import geoip2.database

# Creating class for maxmind utils
class MaxMindUtils:
    def __init__(self, db_file_path):
        self.db_file_path = db_file_path
        self.reader = None

    def open_reader(self):
        try:
            self.reader = geoip2.database.Reader(self.db_file_path)
        except Exception as e:
            raise Exception(f"Error opening MaxMind reader: {str(e)}")

    def close_reader(self):
        if self.reader:
            self.reader.close()

    def get_city_by_ip(self, ip):
        if not self.reader:
            raise Exception("MaxMind reader is not open. Call open_reader() first.")
        
        try:
            response = self.reader.city(ip)
            response_dict = {
                'country_code': response.country.iso_code,
                'country': response.country.name,
                'city': response.city.name,
                'postal_code': response.postal.code,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'registered_country': response.registered_country.name
                #'registered_country_confidence': response.registered_country.confidence
            }
            return response_dict
        except Exception as e:
            raise Exception(f"Error performing MaxMind lookup: {str(e)}")
            
    def get_asn_by_ip(self, ip):
        if not self.reader:
            raise Exception("MaxMind reader is not open. Call open_reader() first.")
        
        try:
            response = self.reader.asn(ip)
            response_dict = {'asn':response.autonomous_system_number,
                     'asn_org':response.autonomous_system_organization
                        }
        
            return response_dict
        except Exception as e:
            raise Exception(f"Error performing MaxMind lookup: {str(e)}")
        

def main():
    # Load cache
    script_start = time.time()

    end_day = start_day + n_days
    for day in range(start_day, end_day): 
        day_loop_start = time.time()
        for hour in range(0, 24):
            print("\nReading data ... ")
            data = pd.read_csv(f"{input_path}/events_{year}_{month:02d}_{day:02d}_{hour:02d}.csv")
            print("Cleaning data ... ")
            clean_df = get_clean_df(data) 
            print("Performing DNS lookup ...")
            dns_df = apply_dns_ip_to_hostname_column(clean_df, 'src_ip', 'hostname')

            city_db = 'maxmind/GeoLite2-City_20231013/GeoLite2-City.mmdb'
            asn_db = 'maxmind/GeoLite2-ASN_20231013/GeoLite2-ASN.mmdb'

            city_reader = MaxMindUtils(city_db)
            city_reader.open_reader()

            asn_reader = MaxMindUtils(asn_db)
            asn_reader.open_reader()

            print("Performing Maxmind lookup ... ")
            try:
                city_df = dns_df.join(dns_df['src_ip'].apply(lambda x: pd.Series(city_reader.get_city_by_ip(x))))
                asn_df = city_df.join(city_df['src_ip'].apply(lambda x: pd.Series(asn_reader.get_asn_by_ip(x))))

                asn_df.to_csv(f"{output_path}/events_{year}_{month:02d}_{day:02d}_{hour:02d}.csv", index=False)
                print(f"File saved as - events_{year}_{month:02d}_{day:02d}_{hour:02d}.csv.")

            except Exception as e:
                print(f"Error: {e}")
            finally:
                city_reader.close_reader()
                asn_reader.close_reader()  
        
        print(f"Time to clean data for {day}-{month}: {time.time() - day_loop_start}")

    print(f"\nOverall execution time : {(time.time() - script_start)/60} minutes")

if __name__=='__main__':
    CACHE = load_cache_from_file() # global variable
    main()