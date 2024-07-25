import requests
import json
import html

import time 
import argparse

parser = argparse.ArgumentParser(
                    prog='endPOINTout',
                    description='Simple CLI tool for API endpoint testing',
                    epilog='Built by ChalkingCode')

parser.add_argument('-u','--url', help='url for api endpoint you are testing')
parser.add_argument('-hd','--headers', help='headers needed for your request. If a header is needed for your request you can use this flag')
parser.add_argument('-time','--time', help='Time in between each  request this flag is needed for rate limiting test')
parser.add_argument('-num','--numreq', help='numreq or num flag is needed for rate limiting test this will be the total number of requests you would like to make')
parser.add_argument('-sql','--sqlpay', help='sql payload for custom sql injection testing. This flag is needed when conducting custom sql test')
parser.add_argument('-xss','--xsspay', help='xss payload for custom xss testing. This flag is needed when conducting custom xss test')
parser.add_argument('-nosql','--nosqlpay', help='nosql payload for custom nosql injection testing. This flag is needed when runnning custom nosql test')
parser.add_argument('-t','--test', help='test you would like to run on your endpoint', choices=['sql_injection', 'no_sql_injection', 'authenticated_request', 'unauthenticated_request', 'session_cookie', 'security_headers', 'cors', 'rate_limiting', 'xss', 'tls_ssl', 'custom_xss', 'custom_nosql_injection', 'custom_sql_injection'])
args = vars(parser.parse_args())
url = args['url']

def main(args):
    if args['test'] == 'sql_injection':
        test_sql_injection(args)
    elif args['test'] == 'no_sql_injection':
        test_nosql_injection(args)
    elif args['test'] == 'session_cookie':
        check_session_cookie_security(args)
    elif args['test'] == 'security_headers':
        check_security_headers(args)
    elif args['test'] == 'authenticated_request':
        test_authenticated_request(args)
    elif args['test'] == 'unauthenticated_request':
        test_unauthenticated_request(args)
    elif args['test'] == 'cors':
        test_cors(args)
    elif args['test'] == 'rate_limiting':
        test_rate_limiting_and_traffic_handling(args)
    elif args['test'] == 'xss':
        test_xss(args)
    elif args['test'] == 'tls_ssl':
        check_tls_ssl_configuration(args)
    elif args['test'] == 'custom_sql_injection':
        custom_test_sql_injection(args)
    elif args['test'] == 'custom_nosql_injection':
        custom_test_nosql_injection(args)
    elif args['test'] == 'custom_xss':
        custom_test_xss(args)
    else:
        print("Wrong arg choice please look at endpointout.py -h")    

def test_sql_injection(args):
    # SQL injection payloads
    sql_payloads = [
        "1'; DROP TABLE users--",
        "admin'--",
        "'; SELECT * FROM sensitive_data--",
        " 1 = 1 -- ",
        # Add more SQL injection payloads as needed
    ]
    you_sure = input(f"Are you sure your allowed to test this endpoint for sql injection yes/no? if so these are the payloads {sql_payloads} ")
    if you_sure == "no":
        print("Ok thanks for being truthful go get permission and come back")
    else:
        for payload in sql_payloads:
            params = payload
            response = requests.post(url, data=params)
            print(response.headers)
            print(f"POST request with SQL injection payload '{payload}': Status code {response.status_code}")
        # Optionally, check response content or headers for validation

# Function to test NoSQL injection
def test_nosql_injection(args):
    # NoSQL injection payloads
    nosql_payloads = [
        {"username": {"$gt": ""}, "password": {"$gt": ""}},
        {"username": {"$ne": None}, "password": {"$ne": None}},
        # Add more NoSQL injection payloads as needed
    ]
    you_sure = input(f"Are you sure your allowed to test this endpoint for sql injection yes/no? if so these are the payloads {nosql_payloads} ")
    if you_sure == "no":
        print("Ok thanks for being truthful go get permission and come back")
    else:
        for payload in nosql_payloads:
            response = requests.post(url, json=payload)
            print(f"POST request with NoSQL injection payload {payload}: Status code {response.status_code}")

# Function to test SQL injection
def custom_test_sql_injection(args):
    # SQL injection payloads
    payload = args['sqlpay']
    params = {'username': payload, 'password': 'password'}
    response = requests.post(url, data=params)
    print(f"POST request with SQL injection payload '{payload}': Status code {response.status_code}")

# Function to test NoSQL injection
def custom_test_nosql_injection(args):
    # NoSQL injection payloads
    payload = args['nosqlpay']
    response = requests.post(url, json=payload)
    print(f"POST request with NoSQL injection payload {payload}: Status code {response.status_code}")

# Function to test authenticated requests
def test_authenticated_request(args):
    headers = {"x-apikey": "api_key", "accept": "application/json"}
    print(f"Making a request with the following headers {headers}")
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        print(f"Invalid headers with Status code {response.status_code} you may want to do more authentication testing")
    else:
        print(f"Unauthenticated GET request: Status code {response.status_code}")

# Function to test unauthenticated requests
def test_unauthenticated_request(args):
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Looks like you can make a unauthenticated GET request: Status code {response.status_code}")
    else:
        print(f"Looks like you were denied no unauthenticated GET requests for you: Status code {response.status_code}")


# Function to check session or cookie security
def check_session_cookie_security(args):
    # Send a request to the API endpoint
    headers = args['headers']
    response = requests.get(url, headers=headers)

    # Get the cookies from the response
    cookies = response.cookies
    print(cookies)
    print(f"Checking session or cookie security for URL: {url}\n")

    # Iterate over each cookie and check its attributes
    for cookie in cookies:
        print(f"Cookie Name: {cookie.name}")
        print(f"  Value: {cookie.value}")
        print(f"  Domain: {cookie.domain}")
        print(f"  Path: {cookie.path}")
        print(f"  Secure: {'Yes' if cookie.secure else 'No'}")
        print(f"  HTTP Only: {'Yes' if cookie.secure else 'No'}")
        print(f"  Expiry: {cookie.expires} UTC")
        print("")


# Function to check security headers
def check_security_headers(args):
    headers = args['headers']
    response = requests.get(url, headers=headers)

    # List of security headers to check
    security_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-XSS-Protection',
        'X-Frame-Options'
    ]

    print(f"Checking security headers for URL: {url}\n")
    for header in security_headers:
        if header in response.headers:
            print(f"{header}: {response.headers[header]}")
        else:
            print(f"{header}: Not found")


# Function to test CORS configuration
def test_cors(args):
    # Test with a valid origin
    headers = args['headers']
    response = requests.get(url, headers=headers)
    print(f"GET request with valid origin '{origin}': Status code {response.status_code}")
    print(f"Access-Control-Allow-Origin header: {response.headers.get('Access-Control-Allow-Origin')}")


def test_xss(args):
    # XSS payloads
    xss_payloads = [
        '<script>alert("XSS Vulnerability");</script>',
        '<img src="invalid-image" onerror="alert(\'XSS Vulnerability\');">',
        '<svg/onload=alert("XSS Vulnerability")>',
        # Add more XSS payloads as needed
    ]
    you_sure = input(f"Are you sure your allowed to test this endpoint for sql injection yes/no? if so these are the payloads {xss_payloads} ")
    
    if you_sure == "no":
        print("Ok thanks for being truthful go get permission and come back")
    else:
        for payload in xss_payloads:
            params = {'input': payload}
            response = requests.get(url, params=params)
            print(response.text)
            print(f"GET request with XSS payload '{payload}': Status code {response.status_code}")
            # Check response content for evidence of XSS vulnerability
            if payload in response.text:
                print(f"XSS vulnerability detected in response for payload: '{payload}'")
            else:
                print(f"No XSS vulnerability detected for payload: '{payload}'")

# Function to test XSS vulnerabilities
def custom_test_xss(args):
    # XSS payloads
    payload = args['xsspay'] 
    params = {'input': payload}
    response = requests.get(url, params=params)
    print(f"GET request with XSS payload '{payload}': Status code {response.status_code}")
    # Check response content for evidence of XSS vulnerability
    if payload in response.text:
        print(f"XSS vulnerability detected in response for payload: '{payload}'")
    else:
        print(f"No XSS vulnerability detected for payload: '{payload}'")


# Function to test rate limiting and high traffic handling
def test_rate_limiting_and_traffic_handling(args):
    # Simulate high volume of traffic
    num_requests = int(args['numreq'])  # Number of requests to send
    interval = int(args['time'])    # Interval between each request in seconds
    print(f"Testing rate limiting and traffic handling for URL: {url}\n")

    for i in range(num_requests):
        try:
            response = requests.get(url)
            print(f"Request {i+1}: Status code {response.status_code}")
        except requests.exceptions.RequestException as e:
            print(f"Request {i+1}: Exception - {str(e)}")

        time.sleep(interval)  # Wait for the interval before sending the next request

if __name__ == '__main__':
    main(args)
