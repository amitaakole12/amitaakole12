import logging
import re
from datetime import datetime
from loguru import logger
from utility import is_length_valid

#Checks if size<2 then throws an error, or else tokenizes it and logs the error in data log file.
def transform_encode(
        row,column_name,
        vault_client,
        vault_transform_mount,
        vault_transform_role,
        vault_transformation_name,max_range
):
    plaintext=row[column_name]
    is_length_greater_than_2 = is_length_valid(plaintext, 2)
    print(f"Checking if the length is greater than 2 : {is_length_greater_than_2} ")
    try:
        if is_length_greater_than_2:

             length_greater_than_25 =  is_length_valid(plaintext,max_range)
             print(f"The length of the text to be encoded :{len(plaintext)}")
             print(f"Is the original length of text can be tokenised successfully : {not length_greater_than_25}")

             if length_greater_than_25 :
                new_text = split_string(plaintext,max_range)
                print(f"Original String Split into : {new_text}")
             else:
                 new_text =[plaintext]
             new_encoded_string = []

             for each_text in new_text:

                try:
                    encode_response = vault_client.secrets.transform.encode(
                        mount_point=vault_transform_mount,
                        role_name=vault_transform_role,
                        value=each_text,
                        transformation=vault_transformation_name,
                    )
                    new_encoded_string.append(encode_response['data']['encoded_value'])  # fpe or token

                except Exception as e:
                    msg = f"id : {row['id']} |column {column_name} cannot be encoded as it contains nonalphanumeric values |{column_name} : {plaintext} : vales after split :{new_text}"
                    logger.error(msg)
                    return ''
             print('Successfully encoded the values')
             print('-==============================================================-')
             print('-==============================================================-')
             return '$'.join(new_encoded_string)

        else:
            msg = f"id : {row['id']} |column {column_name} Value less than 2 , cannot be encoded |{column_name} : {plaintext}"
            logger.error(msg)
            return ""
    except Exception as ec:
        msg = f"id : {row['id']} |column {column_name}  |{column_name} : {plaintext}"
        print(msg)
        logger.error(msg)
        raise ec

#If encoding is done, then checks the size and detokenizes
def transform_decode(
        fpe, vault_client,
        vault_transform_mount,
        vault_transform_role,
        vault_transformation_name):
    if fpe =='Value less than 2 , cannot be encoded' or is_length_valid(fpe, 2):
        decode_response = vault_client.secrets.transform.decode(
            mount_point=vault_transform_mount,
            role_name=vault_transform_role,
            value=fpe,
            transformation=vault_transformation_name,
        )
        return decode_response['data']['decoded_value']
    else:
        return "Value less than 2 , cannot be encoded"

#Splits the encoded value as per size of record value​
def split_string(str_val, split_length,min_range=3):
    print(f'Spliting the string based on the size {split_length}')

    response = [str_val[each:each + split_length] for each in range(0, len(str_val), split_length)]

    reminder = len(str_val)%split_length
    if reminder > 0 and reminder <= min_range:
        last_but_1 = response[-2]
        last = response[-1]

        last = last_but_1[-min_range:] + last
        last_but_1 = last_but_1[:-min_range]

        response[-1]=last
        response[-2] = last_but_1

    return response


    #return [str_val[each:each + split_length] for each in range(0, len(str_val), split_length)]

#Checks the length of encoded value​
def is_length_valid(str_val, req_length):
    return len(str_val) >= req_length

#Joins the splitted tokenized part to display it as one value
def custom_tokenize_preprocessing(row,column_name,client,tokenizing_data,delimiter=' '):
    text = row[column_name]
    modified_text_list = text.split(delimiter)
    result = [preprocess_1(each,client,tokenizing_data) for each in modified_text_list]
    concatinated_res = '_'.join(result)
    print(concatinated_res)
    return concatinated_res

#Split datavalues, merged back into single field and detokenizes the encoded values
def custom_detokenize_preprocessing(tokenized_data, client, vault_tokenize_mount, vault_tokenize_role,
                                    vault_tokenize_transformation, delimiter='_'):

    '''
                    Split datavalues, merged back into single field --
                Amita Akole  -- 1:Split on space
                Amit -- 2validation
                 sdjuh tyui 3:tokenization
                 4:   sdjuh+tyui=sdjuh_tyui
                 Post process
                sdjuh_tyui = sdjuh+tyui

                Detokenize
    :return:
    '''
    try :
        if tokenized_data=='_':
            return ''
        modified_text_list = tokenized_data.split(delimiter)
        result = [custom_de_tokinize(each,vault_tokenize_mount,vault_tokenize_role,vault_tokenize_transformation,client) for each in modified_text_list]
        print(f'AFter detokentize :{result}')
        concatinated_res = ' '.join(result)
        print(concatinated_res)
        return concatinated_res
    except Exception as ex:
        print(tokenized_data)
        print(result)
        print(ex)
        raise ex


def preprocess_1(text, client,tokenizing_data,string_split_size):
    try:
        text= text.strip()
        if len(text) >0:
            res = bool(re.search(r"\s", text.strip()))
            if res:
                logging.info('string contains spaces removing spaces')
                text = text.replace(" ", '')

            if text.isalnum():
                print('''Go for tokenization''')

                print(f"Checking for length greater than {string_split_size}")

                if not is_length_valid(text,string_split_size):
                    custom_tokenize_preprocessing()

                return text
            else:
                '''log error'''
                logging.error('not pure alpha numaric bypass tokenization')
                return "not tokinized"
        else:
            raise Exception("Data is empty")
    except Exception as e:
        # (template - Time,
        #  < FileName >, < message type >, column name, data value, data row, < message description > --TODO

        #current_time_in_utc =round( datetime.utcnow().timestamp())
        current_time_in_utc = datetime.utcnow().strftime("%Y-%m-%d %H:%m:%d")
        logger.error(f'{current_time_in_utc} : {str(e.__str__())} :  {text} ')
        return text
