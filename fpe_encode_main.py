import pandas as pd
import logging
import re
import os
import sys
import base64
import hvac
from fpe_encode_utility import transform_encode,transform_decode, split_string,is_length_valid,custom_tokenize_preprocessing,custom_detokenize_preprocessing
from datetime import datetime
from loguru import logger
from custom_ff31_alphabet_helper import ff31_alpha_helper
import  logging
import requests

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

date_timestamp = datetime.utcnow().timestamp()
log_parent_path = '/home/develop/vault-data-protection-demo'
log_folder='log'


info_logging_format = '%(message)s'
data_logging_format = '%(asctime)s :  %(message)s'


def setup_logger(file_name,info_level,logging_format):
    info_logger = logging.getLogger(__name__)
    info_logger.setLevel(logging.INFO)
    info_handler = logging.FileHandler(filename=file_name,mode="w")
    info_handler.setLevel(info_level)
    info_logger.addHandler(info_handler)
    formatter = logging.Formatter(logging_format)
    info_handler.setFormatter(formatter)
    return info_logger

info_logger = setup_logger('/'.join([log_parent_path, log_folder, "info.log"]),logging.INFO,info_logging_format)
#data_logger = setup_logger('/'.join([log_parent_path, log_folder, "data.log"]),logging.ERROR,data_logging_format)

data_log_full_path = f"{'/home/develop/vault-data-protection-demo/log/'}data_{date_timestamp}.log"
logger.add(f"{data_log_full_path}",format="{message}",mode="w")

try:
    os.environ["VAULT_TOKEN"]
except KeyError:
    print("Please set the environment variable VAULT_TOKEN")
    sys.exit(1)

#Helper method to perform base64 encoding across Python 2.7 and Python 3.X
def base64ify(bytes_or_str):
    if sys.version_info[0] >= 3 and isinstance(bytes_or_str, str):
        input_bytes = bytes_or_str.encode('utf8')
    else:
        input_bytes = bytes_or_str

    output_bytes = base64.urlsafe_b64encode(input_bytes)
    if sys.version_info[0] >= 3:
        return output_bytes.decode('ascii')
    else:
        return output_bytes

vault_fpe_mount = 'transform'
vault_fpe_role = 'issuer_role'
vault_fpe_transformation = 'trp-simple-transform'

#intiate hvac client
def connect_client():
    client = hvac.Client(
        url='https://edm-projects-sdrma.us-east-1.trp-shared-dev.awstrp.net:8200',
        token=os.environ['VAULT_TOKEN'],
        verify=False,
    )
    if client.is_authenticated():
        logging.info('authenticated successfully')
    else:
        logging.error('error while authenticate')
        raise Exception("Unable to Authenticate")

    return client

#read csv file using pandas
def csv_preprocesing(csv_path,str_split_size):
    csv_file = pd.read_csv(csv_path, sep='|',
                           index_col=False, )
    '''transforming data'''
    selected_coloumns = csv_file[["id", "START_DATE", "DOMAIN", "ID_BPL_ENTITY", "LEI_NAME", "LEI_MASTER",]]
    selected_coloumns['LEI_NAME'].astype(str)
    selected_coloumns['LEI_MASTER'].astype(str)
    selected_coloumns = selected_coloumns.dropna()
    return selected_coloumns

#Remove any trailing or leading spaces in the data value to be Tokenized  text.strip, checking for alphanumeric characters
def preprocess(row,column_name, client,str_split_size):
    try:
        text = row[column_name]

        text= text.strip()
        if len(text) >0:
            res = bool(re.search(r"\s", text.strip()))
            if res:
                logging.info('string contains spaces removing spaces')
                text = text.replace(" ", '')

            if text.isalnum():
                print('''Go for tokenization''')

                print('Checking id the length is under 25')
                #is_length_valid(text,25)


                token = tokenizing_data(text, client)



                return token
            else:
                '''log error'''
                logging.error('not pure alpha numaric bypass tokenization')
                return "not tokinized"
        else:
            raise Exception("Data is empty")
    except Exception as e:
        # (template - Time,
        #  < FileName >, < message type >, column name, data value, data row, < message description >

        #current_time_in_utc =round( datetime.utcnow().timestamp())
        current_time_in_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%m:%d")
        logger.error(f'{current_time_in_utc} : {str(e.__str__())} : {column_name} : {text} : {row}')

#encrypt text data, text:str = palin text
def tokenizing_data(plaintext, client):
    try:
        # print(transit_mount,tokenize_role,plaintext,transformation_name)
        encode_response = client.secrets.transform.encode(
            mount_point=vault_fpe_mount,
            role_name=vault_fpe_role,
            value=plaintext,
            transformation=vault_fpe_transformation,
        )
        logging.error(encode_response['data']['encoded_value'])
        print("My Encoded Value")
        print(encode_response['data']['encoded_value'])
        de_tokinize(encode_response['data']['encoded_value'], client)
        return encode_response['data']['encoded_value']  # fpe or token
    except Exception as e:
        logging.error(str(e))
        print("My Error Token")
        print(str(e))

#decrypt tokinzed data, ciphertext:str = encrypetd data
def de_tokinize(encoded_value, client):
    try:
        decode_response = client.secrets.transform.decode(
            mount_point=vault_fpe_mount,
            role_name=vault_fpe_role,
            value=encoded_value,
            transformation=vault_fpe_transformation,
        )
        print("My Decoded Value")
        print(decode_response['data']['decoded_value'])
        return decode_response['data']['decoded_value']
    except Exception as e:
        logging.error(str(e))

def main() -> object:
    no_of_rows = int(input("Enter no of rows: "))
    file_name = '/home/develop/vault-data-protection-demo/encrypt_entity_data_3.csv'
    str_split_size = 27
    min_len = 3
    client = connect_client()
    info_logger.info(f'Input FileName : {file_name} \nNumber of  rows to be  processed : {no_of_rows}') #TODO info.log
    info_logger.info(f'Minimum length of plain text to encode is {min_len}')
    info_logger.info(f'Maximum length of plain text to encode is {str_split_size}')
    info_logger.info(f'The data log to be found in  {data_log_full_path}')

    selected_coloums = csv_preprocesing(file_name,str_split_size)
    selected_coloumns = selected_coloums[:no_of_rows].copy()
    info_logger.info("\n ")
    info_logger.info("FOR LEI_NAME: ")
    selected_coloumns['LEI_NAME'].apply(
        lambda row: ff31_alpha_helper(c1='0', c2='z', other=' ', plaintext=row, version='0.0.1',logger=info_logger))
    info_logger.info("\n ")
    info_logger.info("FOR LEI_MASTER: ")
    selected_coloumns['LEI_MASTER'].apply(
        lambda row: ff31_alpha_helper(c1='0', c2='z', other=' ', plaintext=row, version='0.0.1',logger=info_logger))
    selected_coloumns['FPE_ENCODE_LEI_NAME'] = selected_coloumns.apply(
        lambda row: transform_encode(row=row,column_name='LEI_NAME', vault_client=client,
                                   vault_transform_mount=vault_fpe_mount,
                                   vault_transform_role=vault_fpe_role,
                                   vault_transformation_name=vault_fpe_transformation,max_range=str_split_size),axis=1)
    selected_coloumns['FPE_ENCODE_LEI_MASTER'] = selected_coloumns.apply(
        lambda row: transform_encode(row=row,column_name='LEI_MASTER', vault_client=client,
                                   vault_transform_mount=vault_fpe_mount,
                                   vault_transform_role=vault_fpe_role,
                                   vault_transformation_name=vault_fpe_transformation,max_range=str_split_size),axis=1)
    selected_coloumns.to_csv('/home/develop/vault-data-protection-demo/tokenized_data2.csv', sep='|',index=False)

if __name__ == '__main__':
    main()
