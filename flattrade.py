import os
import json
import httpx
import yaml
import pyotp
import asyncio
import hashlib
import logging
from datetime import datetime
from urllib.parse import urlparse, parse_qs

logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)


HOST = "https://auth.flattrade.in"
API_HOST = "https://authapi.flattrade.in"

routes = {
    "session" : f"{API_HOST}/auth/session",
    "ftauth" : f"{API_HOST}/ftauth",
    "apitoken" : f"{API_HOST}/trade/apitoken",
}

headers = {
    "Accept": "application/json",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.5",
    "Host": "authapi.flattrade.in",
    "Origin": f"{HOST}",
    "Referer": f"{HOST}/",
}



def encode_item(item):
    encoded_item = hashlib.sha256(item.encode()).hexdigest() 
    return encoded_item

async def get_authcode(user, password, totp, apikey, apisecret):

    async with httpx.AsyncClient(http2= True, headers= headers) as client:
        response =  await client.post(
                routes["session"]
            )
        if response.status_code == 200:
            sid = response.text

            response =  await client.post(
                routes["ftauth"],
                json = {
                        "UserName": user,
                        "Password": encode_item(password),
                        "App":"",
                        "ClientID":"",
                        "Key":"",
                        "APIKey": apikey,
                        "PAN_DOB": pyotp.TOTP(totp).now(),
                        "Sid" : sid
                        }
                    )    
            
            if response.status_code == 200:
                redirect_url = response.json().get("RedirectURL", "")

                query_params = parse_qs(urlparse(redirect_url).query)
                if 'code' in query_params:
                    code = query_params['code'][0]
                    logging.info(code)

                    response = await client.post(
                        routes["apitoken"],
                        json = {
                            "api_key": apikey,
                            "request_code": code, 
                            "api_secret": encode_item(f"{apikey}{code}{apisecret}")
                            }
                        )

                    if response.status_code == 200:
                        token = response.json().get("token", "")
                        return token
                    else:
                        logging.info(response.json())
            else:
                logging.info(response.json())
        else:
            logging.info(response.text)


async def get_session_token():

    with open('cred.yml') as f:
        cred = yaml.load(f, Loader=yaml.FullLoader)

    user = cred["USER"]
    password = cred["PWD"]
    totp = cred["TOTP_KEY"]
    apikey = cred["API_KEY"]
    apisecret = cred["API_SECRET"]

    token = await get_authcode(user, password, totp, apikey, apisecret)

    return user, password, token

def manage_session_data(filename, data=None, operation="w"):
    with open(filename, operation) as json_file:
        if operation == "w":
            json.dump(
                data, 
                json_file,
                indent= 4
            )
        else:
            data = json.load(json_file)
            return data

def check_session_token(hard_refresh= False):

    session_config = os.path.join(os.path.dirname(__file__), 'login_config.json') 
    current_date = datetime.now().strftime("%d-%m-%Y")

    if hard_refresh:
        user, password, token = asyncio.run(get_session_token())
        session_data = {
            "date" : current_date,
            "userid" : user,
            "password" : password,
            "token" : token,
        }
        manage_session_data(
            filename=session_config,
            data = session_data
            )
        return user, password,token

    if os.path.exists(session_config):
        session_data = manage_session_data(
            filename=session_config,
            operation= "r"
            )
        if session_data["date"] == current_date:
            return session_data["userid"], session_data["password"], session_data["token"]
        else:
            user, password, token = asyncio.run(get_session_token())
            session_data = {
                "date" : current_date,
                "userid" : user,
                "password" : password,
                "token" : token,
            }
            manage_session_data(
                filename=session_config,
                data = session_data
                )
            return user, password,token
    else:
        user, password, token = asyncio.run(get_session_token())
        session_data = {
            "date" : current_date,
            "userid" : user,
            "password" : password,
            "token" : token,
        }
        manage_session_data(
            filename=session_config,
            data = session_data
            )
        return user, password, token




