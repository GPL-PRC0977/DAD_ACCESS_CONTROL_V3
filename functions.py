from flask import session, request, jsonify
from google.cloud import secretmanager
import requests
import json
from datetime import datetime
import sys
import os
from dotenv import load_dotenv
from zoneinfo import ZoneInfo
import uuid
import requests
import time

load_dotenv()

# domain = "https://control-center-ednpoints-740032229271.us-west1.run.app/control_center"
domain = "http://127.0.0.1:5001/control_center"

secret_project_id = os.getenv('EP_PROJECT_ID')
secret_id = os.getenv('secret_id')

api_key_cache = None
home_dashboard_cache = None
user_dashboard_cache = {}
employee_master_cache = None
module_cache = {}
user_validation = False
CACHE_TIMEOUT = 600 # Cache timeout in seconds (10 minutes)

# API KEY PREPARATION //////////////////////////////////////////////////////////////////
def get_secret(project_id: str, secret_id: str) -> str:
    client = secretmanager.SecretManagerServiceClient()
    secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/latest"
    response = client.access_secret_version(name=secret_name)
    return response.payload.data.decode("UTF-8")

def get_api_key():
    global api_key_cache
    if api_key_cache:
        print("Using api key from cache...")
        return api_key_cache
    else:
        print("Retrieving API key...")
        api_key_cache = get_secret(project_id=secret_project_id, secret_id=secret_id)
        return api_key_cache
    
key = get_api_key()
# END OF API KEY PREPARATION /////////////////////////////////////////////////////////////


# VALIDATE USER FUNCTION ////////////////////////////////////////////////////////////////////
def validate_user(user):
    try:
        if not isinstance(user, dict):
            print("Invalid user object.")
            return False

        user_email = user.get('email')

        if not user_email:
            return False

        username = user_email.split('@')[0]

        payload = json.dumps({"param": username})
        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }

        url = f"{domain}/admin"
        response = requests.post(url, headers=headers, data=payload)

        if response.status_code != 200:
            return False

        try:
            admin_list = response.json().get('data', [])
        except ValueError:
            return False

        if not admin_list:
            return False

        admin_details = admin_list[0]

        if 'hcm_id' not in admin_details or 'role_type' not in admin_details:
            return False

        session['admin_details'] = {
            'hcm_id': admin_details['hcm_id'],
            'role_type': admin_details['role_type']
        }

        return True

    except Exception as e:
        return False
# EBD OF VALIDATE USER FUNCTION ///////////////////////////////////////////////////////////    


# USER VALIDATION FUNCTION //////////////////////////////////////////////////////////////////
# def validate_user(user):
#     if not isinstance(user, dict):
#         print("Invalid user data format.")
#         return False
    
#     user_email = user.get("email")
#     if not user_email:
#         print("User email is missing.")
#         return False
    
#     username = user_email.split("@")[0]

#     payload = json.dumps({"param": username})
#     headers = {
#         'X-API-KEY': key,
#         'Content-Type': 'application/json'
#     }

#     url = f"{domain}/admin"
#     response = requests.post(url, headers=headers, data=payload)

#     if response.status_code == 200:
#         print("User validation successful.")
#         return True
#     else:
#         print(f"User validation failed with status code {response.status_code}: {response.text}")
#         return False
# END OF USER VALIDATION FUNCTION //////////////////////////////////////////////////////////


# GET HOME DASHBOARD DATA FUNCTION //////////////////////////////////////////////////////////
def get_home_dashboard_data(mode):
    global home_dashboard_cache

    print(f"Mode: {mode}")

    if mode:
        print("Refreshing home dashboard data...")
        home_dashboard_cache = None

    if home_dashboard_cache:
        print(f"Refreshing home dashboard using cache data...")
        return home_dashboard_cache

    headers = {
        'X-API-KEY': key,
        'Content-Type': 'application/json'
    }

    url = f"{domain}/get_home_dashboard"
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        print("Home dashboard data retrieval successful.")
        home_dashboard_cache = response.json()
        return response.json()
    else:
        print(f"Home dashboard data retrieval failed with status code {response.status_code}: {response.text}")
        return None
# END OF GET HOME DASHBOARD DATA FUNCTION //////////////////////////////////////////////////////////


# GET USER DASHBOARD DATA FUNCTION /////////////////////////////////////////////////////////////
# def get_user_dashboard_data(app_id):
#     headers = {
#         'X-API-KEY': key,
#         'Content-Type': 'application/json'
#     }

#     payload = {"app_id": app_id}

#     url = f"{domain}/get_user_dashboard_master"
#     response = requests.get(url, headers=headers, params=payload)

#     if response.status_code == 200:
#         print("User dashboard data retrieval successful.")
#         return response.json()
#     else:
#         print(f"User dashboard data retrieval failed with status code {response.status_code}: {response.text}")
#         return None

def get_user_dashboard_data(app_id):

    # if app_id in user_dashboard_cache:
    #     cached_data, timestamp = user_dashboard_cache[app_id]

    #     if time.time() - timestamp < CACHE_TIMEOUT:
    #         print("Returning cached data.")
    #         return cached_data
    #     else:
    #         print("Cache expired. Fetching new data.")

    headers = {
        'X-API-KEY': key,
        'Content-Type': 'application/json'
    }

    payload = {"app_id": app_id}
    url = f"{domain}/get_user_dashboard_master"

    response = requests.get(url, headers=headers, params=payload)

    if response.status_code == 200:
        print("User dashboard data retrieval successful.")
        data = response.json()

        # user_dashboard_cache[app_id] = (data, time.time())

        return data
    else:
        print(f"User dashboard data retrieval failed with status code {response.status_code}: {response.text}")
        return None

# END OF GET USER DASHBOARD DATA FUNCTION //////////////////////////////////////////////////////////


# GET EMPLOYEE MASTER DATA FUNCTION /////////////////////////////////////////////////////////////
def get_employee_by_id(hcm_id):
    try:
        global employee_master_cache

        # if employee_master_cache:
        #     print("Getting hcm master from cache...")
        #     return employee_master_cache

        print(f"Getting employee master...")
        # url = f"https://hcm-search-employee-740032229271.us-west1.run.app/all_employees"
        url = "http://127.0.0.1:5002/employee"

        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }

        payload = {
            "hcm_id": hcm_id
        }

        response = requests.post(url, headers=headers, json=payload)

        print("Status Code:", response.status_code)

        if response.status_code == 200:
            employee_master_cache = response.json()
            return response.json()
        else:
            print("Response:", response.text)
            return None

    except Exception as e:
        print(f"Error: {e}")
# END OF GET EMPLOYEE MASTER DATA FUNCTION //////////////////////////////////////////////////////////

# GET MODULES BY APP ID FUNCTION /////////////////////////////////////////////////////////////
def get_modules(app_id):
    try:
        if app_id in module_cache:
            module_cached_data, timestamp = module_cache[app_id]

            if time.time() - timestamp < CACHE_TIMEOUT:
                print("Returning cached data.")
                return module_cached_data
            else:
                print("Cache expired. Fetching new data.")

        url = f"{domain}/get_modules"

        payload = {
            "app_id": app_id
        }
        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }

        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            data = response.json()

            modules = data.get("data", []) if isinstance(data, dict) else []
            module_cache[app_id] = (modules, time.time())
            
            return modules
        else:
            print(
                f"Module fetch failed: {response.status_code} - {response.text}")
            return []
    except Exception as e:
        return []
# END OF GET MODULES BY APP ID FUNCTION //////////////////////////////////////////////////////////


# COPY ACCESS FUNCTION //////////////////////////////////////////////////////////////////
def fn_copy_access(app_id, from_email, to_email):
    try:
        print(f"Copying access from {from_email} to {to_email}")
        url = f"{domain}/copy_access"

        payload = {
            "app_id": app_id,
            "from_email": from_email,
            "to_email": to_email
        }
        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            print(response.text)
        else:
            print(response.status_code - response.text)

        return response

    except Exception as e:
        print(f"Error: {e}")

def save_application(hidden_app_id, function_mode, application_name, app_url, app_description, status, owner, modules, created_by):
    try:
        if function_mode == "modify":
            app_id = hidden_app_id
        else:
            app_id = str(uuid.uuid4())

        print(f"Function Mode: {function_mode} - {app_id}")

        if status == "True":
            bool_status = True
        else:
            bool_status = False
        
        url = f"{domain}/save_application_data"
        payload = {
            "app_id": app_id,
            "function_mode": function_mode,
            "application_name": application_name,
            "app_url": app_url,
            "app_description": app_description,
            "status": bool_status,
            "owner": owner,
            # "permissions": permissions,
            "modules": modules,
            "created_by": created_by
        }

        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code == 200:
            print(f"Application successfully saved: {response.text}")
        else:
            print(
                f"Failed to save application: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"Error during saving application data.")

def save_user_access(data):
    try:
        print(f"Received Data: {data}")
        url = f"{domain}/save_user_access"

        payload = {
            "data": data
        }
        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            print(response.text)
        else:
            print(response.status_code - response.text)

        return response

    except Exception as e:
        print(f"Error: {e}")

def save_webapp_user_access(data):
    try:
        print(f"Received Data: {data}")
        url = f"{domain}/save_webapp_user_access"

        payload = {
            "data": data
        }
        headers = {
            'X-API-KEY': key,
            'Content-Type': 'application/json'
        }
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code == 200:
            print(response.text)
        else:
            print(response.status_code - response.text)

        return response

    except Exception as e:
        print(f"Error: {e}")

def get_application_details(app_id):
    headers = {
        'X-API-KEY': key,
        'Content-Type': 'application/json'
    }

    payload = {"app_id": app_id}
    url = f"{domain}/get_app_details"

    try:
        response = requests.get(url, headers=headers, params=payload, timeout=10)
        
        if response.status_code == 200:
            data = response.json()

            return data
        else:
            print(f"Failed. Status: {response.status_code}, Response: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return None

def get_user_access_details(app_id, email):
    headers = {
        'X-API-KEY': key,
        'Content-Type': 'application/json'
    }

    params = {"app_id": app_id, "email": email}
    url = f"{domain}/get_user_access_details"

    try:
        response = requests.get(url, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()

            print(f"Data: {data}")

            return data
        else:
            print(f"Failed. Status: {response.status_code}, Response: {response.text}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request Error: {e}")
        return None