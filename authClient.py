
import requests
import time
import jwt
from datetime import datetime, timedelta
#requests.urllib3.disable_warnings(requests.urllib3.exceptions.SubjectAltNameWarning)
#requests.urllib3.disable_warnings(requests.urllib3.exceptions.InsecureRequestWarning)
JSON_RPC_PORT=1450
JSON_RPC_IP='10.39.0.11'
TIME_FORMAT="%Y-%m-%d %H:%M:%S"
CERT_PATH="lib/AIVC.pem"
AUTH_URL=f"https://{JSON_RPC_IP}:{JSON_RPC_PORT}/jsonrpc"

def login(email,pwd):
    payload = {
        "method": "login",
        "params": [email,pwd],
        "jsonrpc": "2.0",
        "id": 0,
    }
    try:
        response = requests.post(AUTH_URL, json=payload, verify=CERT_PATH,timeout=1).json()
    except requests.exceptions.ConnectionError:
        return False, "Failed To Connect Authentication Server"
    if not "result" in response:
        return False, "No Result"
    return response['result']

def changePwd(email,prevPwd,newPwd):
    payload = {
        "method": "changePwd",
        "params": [email,prevPwd,newPwd],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(AUTH_URL, json=payload, verify=CERT_PATH).json()
    print(response)
def register(email):
    payload = {
        "method": "register",
        "params": [email],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(AUTH_URL, json=payload, verify=CERT_PATH).json()
    print(response)

def passed(email):
    payload = {
        "method": "passTest",
        "params": ['AIVCmaster','topgloveAIVCmaster',email],
        "jsonrpc": "2.0",
        "id": 0,
    }
    response = requests.post(AUTH_URL, json=payload, verify=CERT_PATH).json()
    print(response)


def verifyToken(token):
    try:
        decodedToken=jwt.decode(token,"AIVCjwt55",algorithms=["HS256"])
    except jwt.exceptions.DecodeError as e:
        return False, f'Decode Error: {e}'
    except  jwt.exceptions.InvalidSignatureError as e:
        return False, f'Invalid Token: {e}'
    if 'expireAt' in decodedToken:
        expireTime= datetime.strptime(decodedToken['expireAt'], TIME_FORMAT)
        if datetime.now()>expireTime:
            return False, f"Token Expired at {decodedToken['expireAt']}"
        else:#Verified token
            return True, decodedToken
    else:
        return False, 'Invalid Format'
