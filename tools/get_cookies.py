import requests

# Create session
session = requests.Session()

# Login
login_url = "http://localhost/login.php"
login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
}

response = session.post(login_url, data=login_data)
print(f"Login status: {response.status_code}")

# Get PHPSESSID
cookies = session.cookies.get_dict()
phpsessid = cookies.get('PHPSESSID', 'NOT_FOUND')
print(f"PHPSESSID={phpsessid}")

# Also check security cookie
security = cookies.get('security', 'NOT_FOUND')
print(f"security={security}")

# Save to file for use by scanner
with open('cookies.txt', 'w') as f:
    f.write(f"PHPSESSID={phpsessid}; security=low")
    
print("Cookie saved to cookies.txt")
