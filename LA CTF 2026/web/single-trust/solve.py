import requests
import base64
import json
import urllib.parse

# URL of the challenge
URL = "https://single-trust.chall.lac.tf/"

# 1. Known prefix of the original plaintext
KNOWN_PREFIX = b'{"tmpfile":"/tmp/pastestore/'

# 2. Target plaintext we want to inject
TARGET_PLAINTEXT = b'{"tmpfile":"/flag.txt"}'

def fix_padding(s):
    """Adds missing = symbols for correct base64 decoding"""
    return s + '=' * ((4 - len(s) % 4) % 4)

def solve():
    s = requests.Session()
    
    print("[*] Getting a valid cookie...")
    try:
        r = s.get(URL)
    except Exception as e:
        print(f"[-] Connection error: {e}")
        return

    if 'auth' not in s.cookies:
        print("[-] Failed to get auth cookie")
        return

    # Requests usually decodes URL-encoding, but let's be safe
    auth_cookie = urllib.parse.unquote(s.cookies['auth'])
    
    parts = auth_cookie.split('.')
    if len(parts) != 3:
        print(f"[-] Invalid cookie format: {auth_cookie}")
        return

    iv_b64 = parts[0]
    # auth_tag_b64 = parts[1] 
    ct_b64 = parts[2]

    try:
        ct = base64.b64decode(fix_padding(ct_b64))
    except Exception as e:
        print(f"[-] Base64 decode error: {e}")
        return
    
    print(f"[*] Original ciphertext (len={len(ct)})")

    # 3. Recover the Keystream
    keystream = bytearray()
    limit = min(len(ct), len(KNOWN_PREFIX))
    
    for i in range(limit):
        k = ct[i] ^ KNOWN_PREFIX[i]
        keystream.append(k)

    # 4. Encrypt target plaintext
    new_ct = bytearray()
    for i in range(len(TARGET_PLAINTEXT)):
        c = TARGET_PLAINTEXT[i] ^ keystream[i]
        new_ct.append(c)

    # Encode back to base64 and strip padding (to match server format)
    new_ct_b64 = base64.b64encode(new_ct).decode().rstrip('=')
    print(f"[*] Forged ciphertext: {new_ct_b64}")

    # 5. Brute-force AuthTag (Truncated Tag Attack)
    print("[*] Starting 1-byte tag brute-force...")
    
    for tag_byte in range(256):
        fake_tag = bytes([tag_byte])
        fake_tag_b64 = base64.b64encode(fake_tag).decode().rstrip('=')

        forged_cookie = f"{iv_b64}.{fake_tag_b64}.{new_ct_b64}"

        headers = {
            "Cookie": f"auth={forged_cookie}"
        }
        
        try:
            resp = requests.get(URL, headers=headers, timeout=3)
            
            # If tag is accepted, server reads /flag.txt
            if "there's no paste data yet!" not in resp.text:
                print(f"\n[+] Success! Tag found: {tag_byte} (Hex: {hex(tag_byte)})")
                print("="*20 + " RESPONSE " + "="*20)
                
                start_marker = '<textarea name="content">'
                end_marker = '</textarea>'
                
                if start_marker in resp.text:
                    content = resp.text.split(start_marker)[1].split(end_marker)[0]
                    print(content)
                else:
                    print(resp.text)
                return 
            
            if tag_byte % 20 == 0:
                print(f"\rProgress: {tag_byte}/255", end='', flush=True)
                
        except Exception as e:
            pass

if __name__ == "__main__":
    solve()