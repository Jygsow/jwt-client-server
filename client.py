import requests
import time
import json
import jwt

BASE_URL = "http://127.0.0.1:5000"
username = "user"
password = "password"
TOKEN_FILE = "token.json"

def get_jwt_token(username, password):
    url = f"{BASE_URL}/login"
    headers = {"Content-Type": "application/json"}
    data = {"username": username, "password": password}
    response = requests.post(url, json=data, headers=headers)
    
    if response.status_code == 200:
        token = response.json().get("access_token")
        print(jwt.decode(token, options={"verify_signature": False}))
        refresh_token = response.cookies.get('refresh_token')
        with open(TOKEN_FILE, 'w') as f:
            json.dump({"token": token, "refresh_token": refresh_token, "timestamp": time.time()}, f)
        return token
    else:
        print("Failed to authenticate:", response.json().get("message"))
        return None

def load_token():
    try:
        with open(TOKEN_FILE, 'r') as f:
            data = json.load(f)
            token = data.get("token")
            if time.time() < float(jwt.decode(token, options={"verify_signature": False})['exp']):
                return token
            else:
                print("Token has expired, refreshing...")
                return refresh_access_token(data.get("refresh_token"))
    except FileNotFoundError:
        return None

def refresh_access_token(refresh_token):
    url = f"{BASE_URL}/refresh"
    response = requests.post(url, cookies={'refresh_token': refresh_token})
    
    if response.status_code == 200:
        new_token = response.json().get("access_token")
        with open(TOKEN_FILE, 'w') as f:
            json.dump({"token": new_token, "refresh_token": refresh_token, "timestamp": time.time()}, f)
        return new_token
    else:
        print("Failed to refresh token:", response.json().get("message"))
        return None

def access_protected_endpoint(token):
    url = f"{BASE_URL}/protected"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(url, headers=headers)
    
    if response.status_code == 200:
        return response.json()
    else:
        print("Failed to access protected endpoint:", response.json().get("message"))
        return None

def main():
    token = load_token()
    if not token:
        token = get_jwt_token(username, password)
    
    if token:
        print("JWT Token:", token)
        response = access_protected_endpoint(token)
        if response:
            print("Protected Endpoint Response:", response)

if __name__ == "__main__":
    main()