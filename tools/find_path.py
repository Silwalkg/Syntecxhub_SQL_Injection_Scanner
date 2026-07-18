import requests

session = requests.Session()

# Login
login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
session.post("http://localhost/login.php", data=login_data)

# Set security
security_data = {'security': 'low', 'submit': 'Submit'}
session.post("http://localhost/security.php", data=security_data)

# Try different paths
paths = [
    "/vulnerabilities/sqli/",
    "/vulnerabilities/sqli/index.php",
    "/dvwa/vulnerabilities/sqli/",
    "/vulnerabilities/sqli_blind/",
]

for path in paths:
    response = session.get(f"http://localhost{path}")
    if response.status_code == 200:
        print(f"Found! Path: {path}")
        print(response.text[:300])
        break
    else:
        print(f"404 on {path}")
