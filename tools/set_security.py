import requests

# Create session and login
session = requests.Session()
login_data = {
    'username': 'admin',
    'password': 'password',
    'Login': 'Login'
}
session.post("http://localhost/login.php", data=login_data)

# Set security level to Low
security_url = "http://localhost/security.php"
security_data = {
    'security': 'low',
    'submit': 'Submit'
}
response = session.post(security_url, data=security_data)
print(f"Security level set to Low - Status: {response.status_code}")

# Get updated cookies
cookies = session.cookies.get_dict()
phpsessid = cookies.get('PHPSESSID')
print(f"PHPSESSID={phpsessid}")

# Save updated cookies
with open('cookies.txt', 'w') as f:
    f.write(f"PHPSESSID={phpsessid}; security=low")
    
print("Cookies updated in cookies.txt")
