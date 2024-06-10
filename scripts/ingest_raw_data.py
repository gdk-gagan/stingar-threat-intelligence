import requests
import numpy as np
import pandas as pd
import json
from urllib.parse import unquote
import argparse
import datetime
import time

start_time = time.time()

parser = argparse.ArgumentParser(
                    prog='Ingest stingar data from API',
                    description='Download data as csv for each hour')
parser.add_argument('--year')           # positional argument
parser.add_argument('--month') 
parser.add_argument('--day') 
parser.add_argument('--ndays') 
parser.add_argument('--output') 

args = parser.parse_args()
print(args.year, args.month, args.day, args.ndays, args.output)

year = int(args.year)
month = int(args.month)
start_day = int(args.day)
n_days = int(args.ndays)
output_path = args.output

# Validity checks for year, month, day
try:
    datetime.datetime(year=year,month=month,day=start_day)
except Exception as e:
    print("Invalid date")
    raise Exception

alerts = []

start_min = 0
start_sec = 0
start_microsecond = 0
end_min = 59
end_sec = 59
end_microsecond = 999999

def get_formatted_date(year, month, day, hour, minute, sec, microsec):
    date_format = f'{year}-{month:02d}-{day:02d}T{hour:02d}%3A{minute:02d}%3A{sec:02d}.{microsec:06d}Z'
    return date_format

end_day = start_day + n_days
for day in range(start_day, end_day): 
    for hour in range(0, 24):
        start_date = get_formatted_date(year, month, day, hour, start_min, start_sec, start_microsecond)
        end_date = get_formatted_date(year, month, day, hour, end_min, end_sec, end_microsecond)

        print(f"\nDownloading data for {year}-{month:02d}-{day:02d} {hour:02d} ... ")
        # using max value for rows_per_page
        url = f"https://107.23.47.127:8443/api/v2/sessions?from_date={start_date}&to_date={end_date}&show_data=true&show_ttylog=false&rows_per_page=10000"
        payload = {}
        headers = {
          'accept': 'application/json',
          'api-key': 'cPsQiImDaHUsdD5NDDaNjSTLsl9zusL1'
        }
        print(url)
        # Add verify=False to handle the SSL certi error
        # Refer - https://stackoverflow.com/questions/51390968/python-ssl-certificate-verify-error
        response = requests.request("GET", url, headers=headers, data=payload, verify=False)

        data = response.text

        json_data = json.loads(data)
        print(f"Got {json_data['data']['count']} records ...")

        # Extracting 'documents' list from the JSON data
        documents = json_data['data']['documents']

        # Creating a DataFrame
        df = pd.json_normalize(documents, sep='_')
        
        if(df.empty):
            alerts.append(unquote(start_date))
            print(f"No data.")
            continue

        all_columns = ['app', 'src_ip', 'src_port', 'start_time', 'protocol',
                       '@timestamp', 'fluentd_tag', 'end_time', 'dst_port', 'dst_ip', 'id',
                       'hp_data_credentials', 'hp_data_session', 'hp_data_client_height',
                       'hp_data_key_fingerprint', 'hp_data_transport',
                       'hp_data_unknown_commands', 'hp_data_version', 'hp_data_client_width',
                       'hp_data_uploads', 'hp_data_urls', 'hp_data_con_type', 'hp_data_files',
                       'hp_data_arch', 'hp_data_commands', 'hp_data_kex_enc_cs',
                       'hp_data_kex_key_algorithms', 'hp_data_kex_lang_cs',
                       'hp_data_kex_mac_cs', 'hp_data_kex_hassh_algorithms',
                       'hp_data_kex_comp_cs', 'hp_data_kex_hassh',
                       'hp_data_kex_kex_algorithms', 'sensor_hostname', 'sensor_uuid',
                       'sensor_asn', 'sensor_tags_misc', 'hp_data_request',
                       'hp_data_event_type', 'hp_data_response', 'hp_data_kex']
        
        if len(df.columns) < 41:
            add_cols = list(set(all_columns)-set(df.columns.to_list()))   
            df[add_cols] = np.nan
        
        df = df.loc[:, all_columns]

        print(f"Converted json to df with {df.shape} records ...")

        save_to_path = f"{output_path}/events_{year}_{month:02d}_{day:02d}_{hour:02d}.csv"
        df.to_csv(save_to_path) 
        print(f"Saved dataframe to file {save_to_path}")

# save alerts to file
alerts_df = pd.DataFrame(alerts, columns=['timestamp'])
alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
alerts_df.to_csv(f"{output_path}/alerts_{year}_{month}_{start_day}_to_{end_day}.csv")  

print(f"\nNo data for following times - ")
for alert in alerts:
    print(alert)

print(f"Time to execute : {time.time() - start_time}")