#!/usr/bin/python3.8
#This script is used with Zabbix as an API Monitor for Channel Network

import argparse
import requests
import json
import sys

TIMEOUT=10

def get_authorization_token(url, credentials):
    """
    Gets the Authorization token from UAM
    :params url: UAM Endpoint
    :params credentials: user credentials
    :return: access_token
    """
    
    payload = {'username': credentials['username'],
               'password' : credentials['password'],
               'grant_type' : 'password',
               'client_secret' : 'f13b8c37-6f40-4dbf-ab12-527c89d62e08',
               'client_id': 'ChannelNetwork'}

    auth_token = {}
    try:
        response = requests.post(url, data=payload, timeout=TIMEOUT)
        auth_token['result'] = response.json()
        
    except Exception as e:
        auth_token['error'] = str(e)

    return auth_token


def ping_channel_network(url, access_token):
    """
    Pings channel network graphql endpoint using the
    access_token and returns the response
    :param url: Channel Network GraphQL endpoint
    :param access_token: access token for authorization
    :return: response from the endpoint
    """
    
    headers = { 'Authorization': 'Bearer ' + access_token,
                'Content-Type': 'application/json'}

    payload = "{\"query\":\"{about {env version timestamp }}\", \
               \"variables\":{}}"
      
    status = {}
    try:
        response = requests.post(url, headers=headers, data = payload, timeout=TIMEOUT)
        status['result'] = response.json()
        
    except Exception as e:
        status['error'] = str(e)
    
    return status
    
   
def validate_response(response, expected_val):
    """
    Validates if the version number, environment,
    and the timestamp in the recieved data meet
    the expectations
    :param response: response from ChannelNetwork Endpoint
    :return: Success or Error
    """
    status = 'success'
    res_env = response['data']['about']['env']
    res_version = response['data']['about']['version']
    res_time = response['data']['about']['timestamp']

    if res_env != expected_val['environment'] \
        or res_version != expected_val['version'] \
        or res_time <= 0:
            status = 'error'

    return status
    
    
if __name__ == "__main__":

    # Create a parser to get parameters
    # passed from the command line
    parser = argparse.ArgumentParser(
        description='A simple Channel Network API Monitor'
    )
    
    parser.add_argument(
        'uri_uam', 
        help='URL to fetch Authorization token'
    )
    parser.add_argument(
        'username',
        help='Username associated with the token'
    )
    parser.add_argument(
        'password', 
        help='Password corresponding to the username'
    )
    parser.add_argument(
        'uri_cn', 
        help='Channel Network Endpoint to get status from'
    )
    parser.add_argument(
        'environment', 
        help='Channel Network Environment this script is testing'
    )
    parser.add_argument(
        'version', 
        help='Channel Network version this script is testing'
    )
    args = parser.parse_args()
    
    URL_UAM = args.uri_uam
    URL_CN = args.uri_cn
    credentials = {}
    credentials['username'] = args.username
    credentials['password'] = args.password
    
    # These are the expected values from the 
    # ChannelNetwork Endpoint
    expected_params = {}
    expected_params['environment'] = args.environment
    expected_params['version'] = args.version
    
    # Get the Authorization token from UAM
    # based on the credentials passed as 
    # parameters to this script
    auth_token = get_authorization_token(URL_UAM, credentials)

    if 'error' in auth_token:
        sys.exit(auth_token['error'])
    else:
        #print(auth_token['result'])
        pass
        
    # Use the acccess token in the 
    # request header sent to the 
    # GraphQL API to get the status
    access_token = auth_token['result']['access_token']
    
    status = ping_channel_network(URL_CN, access_token) 
    
    if 'error' in status:
        sys.exit(status['error'])
    else:
        #print(status['result'])
        pass
    
    # Inspect the status from Channel Network
    validation_result = validate_response(status['result'], expected_params)
    print(validation_result)
