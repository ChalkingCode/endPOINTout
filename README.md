# endPOINTout
A super simple CLI tool for simple API endpoint security tests


## Table of contents
* [Intro](#intro)
* [Features](#features)
* [Setup](#setup)
* [HowTo](#howto)

## Intro

Only use this on Endpoints you have permission to run tests on. 

When testing an API endpoint to ensure it is secure, you should focus on various aspects of security to cover potential vulnerabilities. Here are a few  areas you should test:

Input Validation:

Test that the endpoint correctly validates input parameters, such as query parameters, headers, and request bodies.
Check for handling of invalid inputs, such as incorrect data types, unexpected characters, or missing parameters.

Authentication and Authorization:

Verify that the endpoint enforces proper authentication mechanisms (e.g., API keys, OAuth tokens) and that unauthenticated requests are rejected.
Test authorization by sending requests with different roles or permissions to ensure that users can only access resources they are authorized to.

Sensitive Data Exposure:

Ensure that sensitive information, such as passwords, API keys, or personal data, is not exposed in error messages, logs, or responses.
Check that responses do not include more data than necessary and adhere to the principle of least privilege.

SQL Injection and NoSQL Injection:

Attempt SQL injection attacks by sending malicious SQL code in parameters to check if the endpoint properly sanitizes inputs or uses parameterized queries.
Similarly, test for NoSQL injection vulnerabilities if your API interacts with NoSQL databases.

Cross-Site Scripting (XSS):

Test for XSS vulnerabilities by injecting JavaScript or HTML into input fields and checking if the endpoint sanitizes and escapes special characters in responses.

Cross-Origin Resource Sharing (CORS):

Verify that CORS policies are correctly configured to prevent unauthorized cross-origin requests if applicable.

Security Headers:

Check for the presence of security headers such as Strict-Transport-Security, Content-Security-Policy, X-Content-Type-Options, X-XSS-Protection, and X-Frame-Options. Ensure they are correctly configured to mitigate various types of attacks.

Session Management and Cookies:

If your API uses sessions or cookies, test their security by ensuring they are secure, HTTP-only, and have appropriate expiration times.

Rate Limiting and Denial of Service (DoS) Protection:

Verify that rate limiting is enforced to prevent abuse and DoS attacks. Test if the endpoint gracefully handles high volumes of traffic.
Logging and Monitoring:

Check that security-related events (e.g., failed login attempts, access to sensitive resources) are logged and monitored appropriately.

TLS/SSL Configuration:

Ensure that TLS (or SSL) is correctly implemented to encrypt data in transit and protect against man-in-the-middle attacks.

API Documentation:

Review API documentation to ensure that security requirements (e.g., authentication methods, expected headers) are clearly documented for developers.


## Features
- CLI tool that allows you to run simple api security tests 
- Output unique results from simple api security tests

## Setup

### Prerequisites

#### Enviroment
```
1.) ensure you have python 3.x installed
$ python3 -m venv /path/you/want/the/env/in
$ source /path/you/want/the/env/in/bin/activate
```
#### Clone repository

        $ git clone https://github.com/ChalkingCode/endPOINTout.git
        $ cd endPOINTout


#### Install Packages on env
```
requests


# This only needs to be ran once per env
$ pip install -r requirements.txt
```

## HowTo

```
$ python endpointout.py -h
usage: endPOINTout [-h] [-u URL] [-hd HEADERS] [-time TIME] [-num NUMREQ] [-sql SQLPAY] [-xss XSSPAY] [-nosql NOSQLPAY]
                   [-t {sql_injection,no_sql_injection,authenticated_request,unauthenticated_request,session_cookie,security_headers,cors,rate_limiting,xss,tls_ssl,custom_xss,custom_nosql_injection,custom_sql_injection}]

Simple CLI tool for API endpoint testing

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     url for api endpoint you are testing
  -hd HEADERS, --headers HEADERS
                        headers needed for your request. If a header is needed for your request you can use this flag
  -time TIME, --time TIME
                        Time in between each request this flag is needed for rate limiting test
  -num NUMREQ, --numreq NUMREQ
                        numreq or num flag is needed for rate limiting test this will be the total number of requests you would like to make
  -sql SQLPAY, --sqlpay SQLPAY
                        sql payload for custom sql injection testing. This flag is needed when conducting custom sql test
  -xss XSSPAY, --xsspay XSSPAY
                        xss payload for custom xss testing. This flag is needed when conducting custom xss test
  -nosql NOSQLPAY, --nosqlpay NOSQLPAY
                        nosql payload for custom nosql injection testing. This flag is needed when runnning custom nosql test
  -t {sql_injection,no_sql_injection,authenticated_request,unauthenticated_request,session_cookie,security_headers,cors,rate_limiting,xss,tls_ssl,custom_xss,custom_nosql_injection,custom_sql_injection}, --test {sql_injection,no_sql_injection,authenticated_request,unauthenticated_request,session_cookie,security_headers,cors,rate_limiting,xss,tls_ssl,custom_xss,custom_nosql_injection,custom_sql_injection}
                        test you would like to run on your endpoint

Built by ChalkingCode

$ python endpointout.py -u http://127.0.0.1:5000/tasks -t rate_limiting -num 10 -time 1
Testing rate limiting and traffic handling for URL: http://127.0.0.1:5000/tasks

Request 1: Status code 200
Request 2: Status code 200
Request 3: Status code 200
Request 4: Status code 200
Request 5: Status code 200
Request 6: Status code 200
Request 7: Status code 200
Request 8: Status code 200
Request 9: Status code 200
Request 10: Status code 200

$ python endpointout.py -u http://127.0.0.1:5000/tasks -t security_headers
Checking security headers for URL: http://127.0.0.1:5000/tasks

Strict-Transport-Security: Not found
Content-Security-Policy: Not found
X-Content-Type-Options: Not found
X-XSS-Protection: Not found
X-Frame-Options: Not found

$ python endpointout.py -u http://127.0.0.1:5000/tasks -t sql_injection
Are you sure your allowed to test this endpoint for sql injection yes/no? if so these are the payloads ["1'; DROP TABLE users--", "admin'--", "'; SELECT * FROM sensitive_data--", ' 1 = 1 -- '] yes
{'Server': 'Werkzeug/3.0.3 Python/3.9.6', 'Date': 'Thu, 25 Jul 2024 18:17:51 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '215', 'Connection': 'close'}
POST request with SQL injection payload '1'; DROP TABLE users--': Status code 415
{'Server': 'Werkzeug/3.0.3 Python/3.9.6', 'Date': 'Thu, 25 Jul 2024 18:17:51 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '215', 'Connection': 'close'}
POST request with SQL injection payload 'admin'--': Status code 415
{'Server': 'Werkzeug/3.0.3 Python/3.9.6', 'Date': 'Thu, 25 Jul 2024 18:17:51 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '215', 'Connection': 'close'}
POST request with SQL injection payload ''; SELECT * FROM sensitive_data--': Status code 415
{'Server': 'Werkzeug/3.0.3 Python/3.9.6', 'Date': 'Thu, 25 Jul 2024 18:17:51 GMT', 'Content-Type': 'text/html; charset=utf-8', 'Content-Length': '215', 'Connection': 'close'}
POST request with SQL injection payload ' 1 = 1 -- ': Status code 415

$ python endpointout.py -u http://127.0.0.1:5000/tasks -t no_sql_injection
Are you sure your allowed to test this endpoint for sql injection yes/no? if so these are the payloads [{'username': {'$gt': ''}, 'password': {'$gt': ''}}, {'username': {'$ne': None}, 'password': {'$ne': None}}] yes
POST request with NoSQL injection payload {'username': {'$gt': ''}, 'password': {'$gt': ''}}: Status code 400
POST request with NoSQL injection payload {'username': {'$ne': None}, 'password': {'$ne': None}}: Status code 400
```
